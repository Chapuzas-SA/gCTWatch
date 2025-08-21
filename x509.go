package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"time"
)

/* X509 */
type CertificateJSON struct {
	//Raw                     string `json:"raw"` // base64
	//RawSubjectPublicKeyInfo string `json:"raw_subject_public_key_info"`
	//RawSubject              string `json:"raw_subject"`
	//RawIssuer               string `json:"raw_issuer"`

	Signature          string `json:"signature"` // base64
	SignatureAlgorithm string `json:"signature_algorithm"`

	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	PublicKey          string `json:"public_key"` // placeholder

	Version      int       `json:"version"`
	SerialNumber string    `json:"serial_number"` // decimal
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`

	KeyUsage    []string `json:"key_usage"`
	ExtKeyUsage []string `json:"ext_key_usage"`

	IsCA                  bool `json:"is_ca"`
	MaxPathLen            int  `json:"max_path_len"`
	MaxPathLenZero        bool `json:"max_path_len_zero"`
	BasicConstraintsValid bool `json:"basic_constraints_valid"`

	SubjectKeyId   string `json:"subject_key_id"`
	AuthorityKeyId string `json:"authority_key_id"`

	DNSNames       []string `json:"dns_names"`
	EmailAddresses []string `json:"email_addresses"`
	IPAddresses    []string `json:"ip_addresses"`
	URIs           []string `json:"uris"`

	OCSPServer            []string `json:"ocsp_server"`
	IssuingCertificateURL []string `json:"issuing_certificate_url"`

	UnhandledCriticalExtensions []string `json:"unhandled_critical_extensions"`
	PolicyIdentifiers           []string `json:"policy_identifiers"`
}

func ConvertCertificate(cert *x509.Certificate) CertificateJSON {
	toHex := func(b []byte) string {
		return base64.StdEncoding.EncodeToString(b)
	}
	toOID := func(oids []asn1.ObjectIdentifier) []string {
		var out []string
		for _, oid := range oids {
			out = append(out, oid.String())
		}
		return out
	}
	toIP := func(ips []net.IP) []string {
		var out []string
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out
	}
	toURI := func(uris []*url.URL) []string {
		var out []string
		for _, u := range uris {
			out = append(out, u.String())
		}
		return out
	}
	toKU := func(ku x509.KeyUsage) []string {
		flags := []struct {
			flag x509.KeyUsage
			name string
		}{
			{x509.KeyUsageDigitalSignature, "DigitalSignature"},
			{x509.KeyUsageContentCommitment, "ContentCommitment"},
			{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
			{x509.KeyUsageDataEncipherment, "DataEncipherment"},
			{x509.KeyUsageKeyAgreement, "KeyAgreement"},
			{x509.KeyUsageCertSign, "CertSign"},
			{x509.KeyUsageCRLSign, "CRLSign"},
			{x509.KeyUsageEncipherOnly, "EncipherOnly"},
			{x509.KeyUsageDecipherOnly, "DecipherOnly"},
		}
		var out []string
		for _, f := range flags {
			if ku&f.flag != 0 {
				out = append(out, f.name)
			}
		}
		return out
	}
	toEKU := func(eku []x509.ExtKeyUsage) []string {
		m := map[x509.ExtKeyUsage]string{
			x509.ExtKeyUsageAny:                            "Any",
			x509.ExtKeyUsageServerAuth:                     "ServerAuth",
			x509.ExtKeyUsageClientAuth:                     "ClientAuth",
			x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
			x509.ExtKeyUsageEmailProtection:                "EmailProtection",
			x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
			x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
			x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
			x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
			x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
			x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftSGC",
			x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeSGC",
			x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MSCommercialCodeSigning",
			x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MSKernelCodeSigning",
		}
		var out []string
		for _, k := range eku {
			if name, ok := m[k]; ok {
				out = append(out, name)
			} else {
				out = append(out, fmt.Sprintf("Unknown(%d)", k))
			}
		}
		return out
	}

	return CertificateJSON{
		//Raw:                         toHex(cert.Raw),
		//RawSubjectPublicKeyInfo:     toHex(cert.RawSubjectPublicKeyInfo),
		//RawSubject:                  toHex(cert.RawSubject),
		//RawIssuer:                   toHex(cert.RawIssuer),
		Signature:                   toHex(cert.Signature),
		SignatureAlgorithm:          cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm:          cert.PublicKeyAlgorithm.String(),
		PublicKey:                   fmt.Sprintf("%T", cert.PublicKey),
		Version:                     cert.Version,
		SerialNumber:                cert.SerialNumber.String(),
		Issuer:                      cert.Issuer.String(),
		Subject:                     cert.Subject.String(),
		NotBefore:                   cert.NotBefore,
		NotAfter:                    cert.NotAfter,
		KeyUsage:                    toKU(cert.KeyUsage),
		ExtKeyUsage:                 toEKU(cert.ExtKeyUsage),
		IsCA:                        cert.IsCA,
		MaxPathLen:                  cert.MaxPathLen,
		MaxPathLenZero:              cert.MaxPathLenZero,
		BasicConstraintsValid:       cert.BasicConstraintsValid,
		SubjectKeyId:                toHex(cert.SubjectKeyId),
		AuthorityKeyId:              toHex(cert.AuthorityKeyId),
		DNSNames:                    cert.DNSNames,
		EmailAddresses:              cert.EmailAddresses,
		IPAddresses:                 toIP(cert.IPAddresses),
		URIs:                        toURI(cert.URIs),
		OCSPServer:                  cert.OCSPServer,
		IssuingCertificateURL:       cert.IssuingCertificateURL,
		UnhandledCriticalExtensions: toOID(cert.UnhandledCriticalExtensions),
		PolicyIdentifiers:           toOID(cert.PolicyIdentifiers),
	}
}
