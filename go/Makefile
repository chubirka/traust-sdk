CONTRACTS_REPO := https://github.com/traust-security/traust-contracts.git
CONTRACTS_REF := 1660eda596d0f43e764670aa577a3633a59ac9b9
CONTRACTS_CACHE := $(or $(XDG_CACHE_HOME),$(HOME)/.cache)/traust-sdk/contracts
CONTRACTS_SOURCE := $(CONTRACTS_CACHE)/checkout-$(CONTRACTS_REF)
ENUMS_DIR := $(CONTRACTS_SOURCE)/enums/v1
SCHEMAS_DIR := $(CONTRACTS_SOURCE)/schemas/v1
STORAGE_DIR := $(CONTRACTS_SOURCE)/storage/v1
FIXTURES_DIR := $(CONTRACTS_SOURCE)/tests/fixtures/storage
STORAGE_SAMPLES := $(CONTRACTS_SOURCE)/tests/storage_samples.py
OUT_DIR := ./v1/enums
ROOT := ..
GO_CI := python3 $(ROOT)/ci/lang/go/ci.py
export PATH := $(shell go env GOPATH)/bin:$(PATH)

.PHONY: contracts generate test test-integration check-drift fmt fmt-check vet lint security tools

contracts:
	@set -eu; \
	if [ ! -d "$(CONTRACTS_SOURCE)/.git" ]; then \
	  rm -rf "$(CONTRACTS_SOURCE)"; \
	  mkdir -p "$(CONTRACTS_SOURCE)"; \
	  git -C "$(CONTRACTS_SOURCE)" init --quiet; \
	  git -C "$(CONTRACTS_SOURCE)" remote add origin "$(CONTRACTS_REPO)"; \
	fi; \
	if ! git -C "$(CONTRACTS_SOURCE)" cat-file -e "$(CONTRACTS_REF)^{commit}" 2>/dev/null; then \
	  git -C "$(CONTRACTS_SOURCE)" fetch --quiet --no-tags --depth=1 origin "$(CONTRACTS_REF)"; \
	fi; \
	git -C "$(CONTRACTS_SOURCE)" checkout --quiet --detach --force "$(CONTRACTS_REF)"; \
	git -C "$(CONTRACTS_SOURCE)" clean -ffdqx

generate: contracts
	go run ./internal/generate -enums "$(ENUMS_DIR)" -out "$(OUT_DIR)" -schemas "$(SCHEMAS_DIR)" -types ./v1/types -validate ./v1/validate/schemas_gen.go -storage "$(STORAGE_DIR)" -storage-out ./v1/storage -storage-fixtures "$(FIXTURES_DIR)" -storage-samples "$(STORAGE_SAMPLES)" -contracts-ref "$(CONTRACTS_REF)"

test:
	go test ./...

test-integration:
	go test -count=1 -v ./v1/storage/...

check-drift: generate
	@git diff --exit-code $(OUT_DIR) ./v1/types/ ./v1/validate/schemas_gen.go ./v1/storage/operations.go ./v1/storage/projection_identifiers.go ./v1/storage/schema.go ./v1/storage/queries.go ./v1/storage/storagetest/testdata/ || (echo "ERROR: generated files are out of date; run 'make generate' and commit" && exit 1)

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

vet:
	go vet ./...

lint:
	golangci-lint run ./...

tools:
	$(GO_CI) tools

security:
	$(GO_CI) security
