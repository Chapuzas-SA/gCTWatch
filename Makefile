APP_NAME := gCTWatch 
BUILD_DIR := bin
LDFLAGS := -s -w

.PHONY: all build clean tidy fmt lint run

all: build

## Compilar
build:
	@echo ">> Compilando $(APP_NAME)..."
	@mkdir -p $(BUILD_DIR)
	@go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(APP_NAME) ./...

run: build
	@./$(BUILD_DIR)/$(APP_NAME)

clean:
	@echo ">> Limpiando binarios..."
	@rm -rf $(BUILD_DIR)

tidy:
	@echo ">> Ejecutando go mod tidy..."
	@go mod tidy

fmt:
	@echo ">> Formateando código..."
	@go fmt ./...

