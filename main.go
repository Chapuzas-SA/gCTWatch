package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"flag"
	"os"
	"regexp"

	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	CertTransp "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
)

// Gestion de fuentes y logs
type CTLogSource struct {
	Source     string
	Client     *client.LogClient
	LastSize   uint64
	WindowSize uint64
}

type CTLogsManager struct {
	logListURL   string
	sources      []CTLogSource
	filtering    map[string]*regexp.Regexp
	context      context.Context
	cancel       context.CancelFunc
	PollInterval time.Duration
	OutputChan   chan CertTransp.LogEntry
	wg           sync.WaitGroup
}

type RegexConfig map[string]string        // categoría -> expresión regular
type RegexRules map[string]*regexp.Regexp // compiladas

// Punto de entrada
func main() {

	var rulesFile = flag.String("rules", "rules.json", "Ruta al fichero JSON con las reglas de regex")
	rules, err := LoadRules(*rulesFile)
	flag.Parse()

	manager, err := NewLogManager(loglist3.LogListURL, rules)
	if err != nil {
		panic(err)
	}
	if err := manager.NormalizeLogs(); err != nil {
		panic(err)
	}
	manager.StartStreaming()

	time.Sleep(10 * time.Minute)

	manager.StopStreaming()
}

// Carga reglas de filtrado
func LoadRules(path string) (RegexRules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw RegexConfig
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	compiled := make(RegexRules)
	for tag, expr := range raw {
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("error compilando regex para %s: %w", tag, err)
		}
		compiled[tag] = re
	}
	return compiled, nil
}

// "Constructor"
func NewLogManager(url string, rules RegexRules) (*CTLogsManager, error) {
	ctx, cancel := context.WithCancel(context.Background())
	mng := &CTLogsManager{
		logListURL:   url,
		filtering:    rules,
		context:      ctx,
		cancel:       cancel,
		PollInterval: 5 * time.Second,
		OutputChan:   make(chan CertTransp.LogEntry, 1000),
	}
	return mng, nil
}

// Ciclo de vida
func (mngr *CTLogsManager) NormalizeLogs() error {
	ll, err := mngr.fetchLogList()
	if err != nil {
		return err
	}
	for _, operator := range ll.Operators {
		for _, log := range operator.Logs {
			mngr.initLogSource(log.URL, log.Description, log.State, log.TemporalInterval.EndExclusive, log.MMD)
		}
		for _, log := range operator.TiledLogs {
			mngr.initLogSource(log.MonitoringURL, log.Description, log.State, log.TemporalInterval.EndExclusive, log.MMD)
		}
	}
	return nil
}

// stream
func (mngr *CTLogsManager) StartStreaming() {
	go mngr.consumeLogOutputs(5)
	for i := range mngr.sources {
		mngr.wg.Add(1)
		go mngr.consumeLogInputs(&mngr.sources[i])
	}
}

func (mngr *CTLogsManager) StopStreaming() {
	mngr.cancel()
	mngr.wg.Wait()
	close(mngr.OutputChan)
}

// Tratamiento

// Obtener JSON original y convertirlo en LogList3
func (mngr *CTLogsManager) fetchLogList() (*loglist3.LogList, error) {
	formattedMsg := "failed to fetch CT log list: %w"
	resp, err := http.Get(mngr.logListURL)
	if err != nil {
		return nil, fmt.Errorf(formattedMsg, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(formattedMsg, err)
	}

	ll, err := loglist3.NewFromJSON(body)
	if err != nil {
		return nil, fmt.Errorf(formattedMsg, err)
	}
	return ll, nil
}

// Descarta no usables
func (mngr *CTLogsManager) isUsableLog(desc string, state *loglist3.LogStates, endExclusive time.Time, mmd int32) bool {
	now := time.Now()
	// Fake log
	if strings.Contains(desc, "bogus") || strings.Contains(desc, "placeholder") {
		return false
	}
	// Inactivo
	if state.LogStatus() == loglist3.RetiredLogStatus || state.LogStatus() == loglist3.RejectedLogStatus {
		return false
	}
	// No actual
	if now.After(endExclusive) {
		return false
	}
	// Latencia > 24h
	if mmd > 86400 {
		return false
	}
	return true
}

// Conversión a CTLogSource
func (mngr *CTLogsManager) initLogSource(source string, desc string, state *loglist3.LogStates, endExclusive time.Time, mmd int32) error {
	if mngr.isUsableLog(desc, state, endExclusive, mmd) {
		client, err := client.New(source, &http.Client{}, jsonclient.Options{})
		if err != nil {
			return fmt.Errorf("failed to create client for %s: %w", desc, err)
		}
		sth, err := client.GetSTH(mngr.context)
		if err != nil {
			return fmt.Errorf("failed to get STH for %s: %w", desc, err)
		}
		lsrc := CTLogSource{WindowSize: 1000, LastSize: sth.TreeSize, Source: source, Client: client}
		mngr.sources = append(mngr.sources, lsrc)
		return nil
	}
	return fmt.Errorf("Inusable source log %s", desc)
}

// Obtener entradas de log en base a "paginacion"
func (mngr *CTLogsManager) fetchEntries(source *CTLogSource) error {

	sth, err := source.Client.GetSTH(mngr.context)
	if err != nil {
		return fmt.Errorf("failed to get STH: %w", err)
	}
	if sth.TreeSize == source.LastSize {
		return nil
	}
	start := source.LastSize
	end := start + source.WindowSize
	if end > sth.TreeSize {
		end = sth.TreeSize
	}
	entries, err := source.Client.GetEntries(mngr.context, int64(start), int64(end))
	if err != nil {
		return fmt.Errorf("failed to get entries: %w", err)
	}
	for _, entry := range entries {
		select {
		case mngr.OutputChan <- entry:
		default:
			fmt.Println("WARNING: Dropping log entry, channel full")
		}
	}
	return nil

}

// Gestión de solicitud de nuevas entradas cada "pollInterval" segundos
func (mngr *CTLogsManager) consumeLogInputs(source *CTLogSource) {
	defer mngr.wg.Done()
	pollInterval := mngr.PollInterval
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	if err := mngr.fetchEntries(source); err != nil {
	}
	for {
		select {
		case <-mngr.context.Done():
			return
		case <-ticker.C:
			if err := mngr.fetchEntries(source); err != nil {
			}
		}
	}
}

// Aplica filtros
func (mngr *CTLogsManager) checkCertMatch(cert *x509.Certificate) (bool, string) {
	found := false
	var tag string
	var re *regexp.Regexp
	for tag, re = range mngr.filtering {
		if re.MatchString(cert.Subject.CommonName) {
			found = true
			break
		}
	}
	return found, tag
}

// Acciones a realizar con certificados obtenidos
func (mngr *CTLogsManager) consumeLogOutputs(workers int) {
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-mngr.context.Done():
					return
				case entry := <-mngr.OutputChan:

					if entry.X509Cert == nil {
						continue
					}
					cert, err := x509.ParseCertificate(entry.X509Cert.Raw)
					if err != nil {
						continue
					}

					found, tag := mngr.checkCertMatch(cert)
					if !found {
						continue
					}

					c := ConvertCertificate(cert)
					d, err := json.Marshal(c)
					if err != nil {
						continue
					}
					fmt.Printf("%sn", tag, string(d))
				}
			}
		}()
	}
	wg.Wait()
}
