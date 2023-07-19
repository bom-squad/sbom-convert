RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
TEMPDIR = ./.tmp
SNAPSHOTDIR=./snapshot


ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif
ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
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
	@DIR=$(SNAPSHOTDIR) make mod-goreleaser
	# build release snapshots
	$(TEMPDIR)/goreleaser build --clean --snapshot --config $(TEMPDIR)/goreleaser.yaml

.PHONY: build
build: ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)
	@DIR=$(SNAPSHOTDIR) make mod-goreleaser
	# build release snapshots
	BUILD=true BUILD_GIT_TREE_STATE=$(GITTREESTATE) $(TEMPDIR)/goreleaser release --debug ${BUILD:+--skip-publish2} --skip-publish --skip-sign --clean --snapshot --config $(TEMPDIR)/goreleaser.yaml


.PHONY: mod-goreleaser 
mod-goreleaser:
	# create a config with the dist dir overridden
	echo "dist: $(DIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

.PHONY: upstream-protobom
upstream-protobom: ## Upstream protobom library
	go get github.com/bom-squad/protobom@main

.PHONY: generate
generate:  ## Generate all plugins
	go run -tags=dev main.go generate all

.PHONY: generate-github
generate-github:  ## Generate github action
	go run -tags=dev main.go generate github

.PHONY: generate-readme
generate-readme: ## Generate reademe doc
	go run -tags=dev main.go generate readme

.PHONY: unittest
unittest: ## Run unittests
	go test -count=1 -v ./...
	
.PHONY: clean-readme
clean-readme:
	rm -rf doc

.PHONY: clean-github
clean-generate: clean-readme
	rm -rf ci_generate

