APP_NAME := gCTWatch   # <-- aquí defines el nombre del binario
BUILD_DIR := bin
LDFLAGS := -s -w

.PHONY: all build clean tidy fmt lint run

all: build

## Compilar
build:
	@echo ">> Compilando $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME) ./...

## Ejecutar
run: build
	@./$(BUILD_DIR)/$(APP_NAME)

## Limpiar binarios
clean:
	@echo ">> Limpiando binarios..."
	@rm -rf $(BUILD_DIR)

## Ordenar dependencias
tidy:
	@echo ">> Ejecutando go mod tidy..."
	@go mod tidy

## Formatear código
fmt:
	@echo ">> Formateando código..."
	@go fmt ./...

