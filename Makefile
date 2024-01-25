# SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0

NAME              := diki
NAME_OPS          := diki-ops
REGISTRY          := europe-docker.pkg.dev/gardener-project/releases/gardener
REPO_ROOT         := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
HACK_DIR          := $(REPO_ROOT)/hack
VERSION           := $(shell cat "$(REPO_ROOT)/VERSION")
EFFECTIVE_VERSION := $(VERSION)-$(shell git rev-parse HEAD)
GOARCH            ?= $(shell go env GOARCH)

# TODO: remove this once g/g updates to this or newer version
GOIMPORTSREVISER_VERSION = v3.4.0


LD_FLAGS := "-w $(shell EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) bash $(HACK_DIR)/get-build-ld-flags.sh)"

TOOLS_DIR := $(REPO_ROOT)/hack/tools
include $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/tools.mk

# additional tools
include hack/tools.mk

.PHONY: run
run:
	go run -ldflags $(LD_FLAGS) \
	./cmd/diki run \
	--config=$(CONFIG) \
	--rule-id=$(RULE_ID) \
	--provider=gardener \
	--ruleset-id=disa-kubernetes-stig \
	--ruleset-version=v1r11

.PHONY: docker-images
docker-images:
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(REGISTRY)/$(NAME):$(EFFECTIVE_VERSION) -t $(REGISTRY)/$(NAME):latest -f Dockerfile -m 6g --target $(NAME) .
	@docker build --build-arg EFFECTIVE_VERSION=$(EFFECTIVE_VERSION) --build-arg TARGETARCH=$(GOARCH) -t $(REGISTRY)/$(NAME_OPS):$(EFFECTIVE_VERSION) -t $(REGISTRY)/$(NAME_OPS):latest -f Dockerfile -m 6g --target $(NAME_OPS) .

.PHONY: format
format: $(GOIMPORTS) $(GOIMPORTSREVISER)
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/format.sh ./cmd ./pkg ./imagevector

.PHONY: test
test:
	go test -cover ./...

.PHONY: clean
clean:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/clean.sh ./cmd/... ./pkg/...

.PHONY: check
check: $(GOIMPORTS) $(GOLANGCI_LINT)
	go vet ./...
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check.sh --golangci-lint-config=./.golangci.yaml ./cmd/... ./pkg/...

.PHONY: revendor
revendor:
	@GO111MODULE=on go mod tidy
	@GO111MODULE=on go mod vendor
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/*
	@chmod +x $(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/.ci/*

.PHONY: gen-styles
gen-styles: $(TAILWINDCSS)
	@./hack/gen-styles.sh

.PHONY: generate
generate:
	$(MAKE) gen-styles
	$(MAKE) format

.PHONY: check-generate
check-generate:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/check-generate.sh $(REPO_ROOT)

.PHONY: test-cov
test-cov:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test-cover.sh ./cmd/... ./pkg/...

.PHONY: test-clean
test-clean:
	@$(REPO_ROOT)/vendor/github.com/gardener/gardener/hack/test-cover-clean.sh

.PHONY: verify
verify: format check test

.PHONY: verify-extended
verify-extended: check-generate check format test test-cov test-clean

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
