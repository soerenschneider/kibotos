BUILD_DIR = builds
BINARY_NAME = kibotos
CHECKSUM_FILE = checksum.sha256
SIGNATURE_KEYFILE = ~/.signify/github.sec
# renovate: datasource=docker depName=openbao/openbao
VAULT_IMAGE ?= openbao/openbao:2.7.2

# Reproducible builds: pin the compiler to the toolchain declared in go.mod, strip
# local paths and VCS metadata, and clear the build ID so identical sources yield
# identical binaries regardless of where they're built. -s -w strip the symbol table
# and DWARF data, which stack traces do not need.
export GOTOOLCHAIN = $(shell awk '/^toolchain/ {print $$2}' go.mod)
export CGO_ENABLED = 0
export GOFLAGS =
BUILD_FLAGS = -trimpath -buildvcs=false
LDFLAGS = -s -w -buildid= -X 'main.BuildVersion=$(VERSION)' -X 'main.CommitHash=$(COMMIT_HASH)'
GO_BUILD = go build $(BUILD_FLAGS) -ldflags="$(LDFLAGS)"

build: version-info
	$(GO_BUILD) -o $(BINARY_NAME) .

# compile builds without reading version info from git; the Dockerfile uses it.
# VERSION, COMMIT_HASH and OUTPUT must be passed, GOOS and GOARCH set in the environment.
compile:
	GOAMD64=v1 GOARM64=v8.0 $(GO_BUILD) -o $(OUTPUT) .

docker-build: version-info
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT_HASH=$(COMMIT_HASH) -t $(BINARY_NAME) .

install: build
	cp $(BINARY_NAME) ~/bin/

tests:
	go test ./... -race -covermode=atomic -coverprofile=coverage.out
	go tool cover -html=coverage.out -o=coverage.html
	go tool cover -func=coverage.out -o=coverage.out

# Starts a Vault dev server in Docker. Override the image with VAULT_IMAGE=openbao/openbao:2.7.2.
integration-tests:
	VAULT_IMAGE=$(VAULT_IMAGE) go test ./... -tags integration -count=1 -race

# Same as CI. The integration tag compiles every file, so one run covers all of them.
lint:
	golangci-lint run --build-tags integration ./...

clean:
	rm -rf ./$(BUILD_DIR) $(BINARY_NAME) coverage.out coverage.html

# The checksums list bare file names, so "sha256sum -c" works in the download directory.
release: check-tree clean version-info cross-build
	cd $(BUILD_DIR) && LC_ALL=C sha256sum $(BINARY_NAME)-* > $(CHECKSUM_FILE)

# Signs keyless and writes $(CHECKSUM_FILE).sigstore.json. The signature is only
# trusted when made by the release workflow, so this only runs in CI.
sign:
	@if [ "$$CI" != "true" ]; then \
		echo "keyless signatures are only trusted from the release workflow"; false; \
	fi
	cosign sign-blob --yes --bundle $(BUILD_DIR)/$(CHECKSUM_FILE).sigstore.json $(BUILD_DIR)/$(CHECKSUM_FILE)

# Run on the release tag after the release workflow has published it: rebuilds the
# release, checks that it is byte-identical to the published one, and adds a signify
# signature of the published checksums. Nothing the workflow uploaded is replaced, so
# its cosign signature stays valid.
signed-release: check-tag release
	gh release download "$(VERSION)" --pattern $(CHECKSUM_FILE) --output $(BUILD_DIR)/$(CHECKSUM_FILE).published --clobber
	cmp $(BUILD_DIR)/$(CHECKSUM_FILE) $(BUILD_DIR)/$(CHECKSUM_FILE).published || \
		{ echo 'Local build differs from the published release'; false; }
	pass keys/signify/github | signify -S -s $(SIGNATURE_KEYFILE) -m $(BUILD_DIR)/$(CHECKSUM_FILE)
	gh release upload "$(VERSION)" $(BUILD_DIR)/$(CHECKSUM_FILE).sig --clobber

check-tree:
	@test -z "$$(git status --porcelain)" || { echo 'Dirty work tree'; false; }

check-tag:
	@git describe --tags --exact-match >/dev/null || { echo 'HEAD is not a release tag'; false; }

# Stdlib only and no cgo, so every target cross-compiles from any host.
cross-build: build-linux build-darwin

build-darwin: version-info
	GOOS=darwin GOARCH=arm64                $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64   .

build-linux: version-info
	GOOS=linux GOARCH=amd64 GOAMD64=v1      $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64    .
	GOOS=linux GOARCH=arm GOARM=6           $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-armv6    .
	GOOS=linux GOARCH=arm64 GOARM64=v8.0    $(GO_BUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-aarch64  .

version-info:
	$(eval VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo "dev"))
	$(eval COMMIT_HASH := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown"))

fmt:
	gofmt -l -w .

.PHONY: build compile docker-build install tests integration-tests lint clean release sign signed-release check-tree check-tag cross-build build-darwin build-linux version-info fmt
