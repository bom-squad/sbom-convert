RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
TEMPDIR = ./.tmp

ORG_NAME=$(shell git config --get remote.origin.url  |  cut -d/ -f4)
ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

ifeq "$(strip $(VERSION))" ""
 override VERSION = $(shell git describe --always --tags --dirty)
endif

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: bootstrap
bootstrap: $(TEMPDIR) ## Bootstrap build tools
	GOBIN=$(shell realpath $(TEMPDIR)) go install github.com/goreleaser/goreleaser@main

.PHONY: binary
binary: ## Build snapshot binaries only
	$(call title,Building snapshot artifacts)
	# build release snapshots
	ORG_NAME=$(ORG_NAME) $(TEMPDIR)/goreleaser build --single-target --clean --snapshot --config $(TEMPDIR)/goreleaser.yaml

.PHONY: build
build: ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	# build release snapshots
	ORG_NAME=$(ORG_NAME) BUILD=true BUILD_GIT_TREE_STATE=$(GITTREESTATE) $(TEMPDIR)/goreleaser release --debug ${BUILD:+--skip-publish2} --skip-publish --skip-sign --clean --snapshot --config $(TEMPDIR)/goreleaser.yaml


.PHONY: upstream-protobom
upstream-protobom: ## Upstream protobom library
	go get github.com/bom-squad/protobom@main

.PHONY: unittest
unittest: ## Run unittests
	go test -count=1 -v ./... -run='^(Test[^F])' -args -max_test_count=100 -test_spdx_keyvalue=false -test_spdx_json=true -test_cdx_json=true

.PHONY: fuzztest
fuzztest: ## Run fuzzing tests
	go test --fuzz=Fuzz pkg/convert/convert_fuzzing_test.go -args -seed_input=fuzz_seed_spdx.json