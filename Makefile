# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

ENSURE_GARDENER_MOD := $(shell go get github.com/gardener/gardener@$$(go list -m -f "{{.Version}}" github.com/gardener/gardener))
GARDENER_HACK_DIR   := $(shell go list -m -f "{{.Dir}}" github.com/gardener/gardener)/hack
REPO_ROOT           := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
HACK_DIR            := $(REPO_ROOT)/hack
VERSION             := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION   := $(VERSION)-$(shell git rev-parse HEAD)


LD_FLAGS := "-w $(shell EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) bash $(HACK_DIR)/get-build-ld-flags.sh)"

TOOLS_DIR := $(REPO_ROOT)/hack/tools
include $(GARDENER_HACK_DIR)/tools.mk

# additional tools
include hack/tools.mk

.PHONY: format
format: $(GOIMPORTS) $(GOIMPORTSREVISER)
	@bash $(GARDENER_HACK_DIR)/format.sh ./cmd ./pkg ./imagevector

.PHONY: test
test:
	go test -cover ./...

.PHONY: clean
clean:
	@bash $(GARDENER_HACK_DIR)/clean.sh ./cmd/... ./pkg/...

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT) $(TYPOS)
	go vet ./...
	@REPO_ROOT=$(REPO_ROOT) bash $(GARDENER_HACK_DIR)/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/...

	@bash $(GARDENER_HACK_DIR)/check-typos.sh
	@bash $(GARDENER_HACK_DIR)/check-file-names.sh

.PHONY: tidy
tidy:
	@GO111MODULE=on go mod tidy
	@cp $(GARDENER_HACK_DIR)/sast.sh $(HACK_DIR)/sast.sh && chmod +xw $(HACK_DIR)/sast.sh

.PHONY: gen-styles
gen-styles: $(TAILWINDCSS)
	@./hack/gen-styles.sh

.PHONY: generate
generate:
	$(MAKE) gen-styles
	$(MAKE) format

.PHONY: check-generate
check-generate:
	@bash $(GARDENER_HACK_DIR)/check-generate.sh $(REPO_ROOT)

.PHONY: sast
sast: tidy $(GOSEC)
	@$(HACK_DIR)/sast.sh

.PHONY: sast-report
sast-report: tidy $(GOSEC)
	@$(HACK_DIR)/sast.sh --gosec-report true

.PHONY: test-cov
test-cov:
	@bash $(GARDENER_HACK_DIR)/test-cover.sh ./cmd/... ./pkg/...

.PHONY: test-clean
test-clean:
	@bash $(GARDENER_HACK_DIR)/test-cover-clean.sh

.PHONY: verify
verify: format check test sast

.PHONY: verify-extended
verify-extended: check-generate check format test test-cov test-clean sast-report

#### BUILD ####

.PHONY: build
build:
	@$(REPO_ROOT)/hack/build.sh

.PHONY: build-linux-amd64
build-linux-amd64:
	@$(REPO_ROOT)/hack/build.sh "linux-amd64"

.PHONY: build-linux-arm64
build-linux-arm64:
	@$(REPO_ROOT)/hack/build.sh "linux-arm64"

.PHONY: build-darwin-amd64
build-darwin-amd64:
	@$(REPO_ROOT)/hack/build.sh "darwin-amd64"

.PHONY: build-darwin-arm64
build-darwin-arm64:
	@$(REPO_ROOT)/hack/build.sh "darwin-arm64"

.PHONY: build-windows-amd64
build-windows-amd64:
	@$(REPO_ROOT)/hack/build.sh "windows-amd64"
