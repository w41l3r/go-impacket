TOOLS     := scorch haunt whisper refract
BUILD_DIR := bin

.PHONY: all clean install lint test

all: $(TOOLS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(TOOLS): $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$@ ./cmd/$@

clean:
	rm -rf $(BUILD_DIR)

install: all
	install -m 755 $(BUILD_DIR)/* /usr/local/bin/

lint:
	go vet ./...

test:
	go test ./...
