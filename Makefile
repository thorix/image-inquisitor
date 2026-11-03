SHELL := /bin/bash
VERSION ?= $(shell cat ./VERSION)
REGISTRY := ghcr.io/bartlettc22
DOCKER_IMAGE := $(REGISTRY)/image-inquisitor:$(VERSION)
GO_VERSION ?= 1.27.3
GO_DIGEST ?= sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b
GOLANGCI_VERSION := golangci/golangci-lint:v1.60.3
GO_FILES_NO_VENDOR := $(shell find ./* -name "*.go" -not -path "./vendor/*")
TRIVY_VERSION ?= 0.76.1
TRIVY_DIGEST ?= sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
DEBIAN_DIGEST ?= sha256:d74df7598108a173a621eda4d58a2adbf850b2d9a9d81bc2cca1a6c21174a880
DOCKER_RUN_FLAGS := --rm -u $$(id -u $${USER}):$$(id -g $${USER})

.PHONY: build-image
build-image:
	DOCKER_BUILDKIT=1 docker build \
	--build-arg VERSION=$(VERSION) \
	--build-arg GO_VERSION=$(GO_VERSION) \
	--build-arg TRIVY_VERSION=$(TRIVY_VERSION) \
	--build-arg GO_DIGEST=$(GO_DIGEST) \
	--build-arg TRIVY_DIGEST=$(TRIVY_DIGEST) \
	--build-arg DEBIAN_DIGEST=$(DEBIAN_DIGEST) \
	-t $(DOCKER_IMAGE) \
	.

publish-image: build-image
	docker push $(DOCKER_IMAGE)

.PHONY: dev-run
dev-run:
	go run ./... \
	--log-level=debug \
	--log-json=true \
	--image-sources file \
	--source-id test \
	--report-outputs=summary,summaryImageCombined,summaryRegistry,imageSummary,imageRegistry,imageVulnerabilities,imageKubernetes \
	--include-kubernetes-namespaces=prometheus \
	--image-source-file-path=$$(pwd)/test/images.txt

.PHONY: fmt-check
fmt-check: ## List files whose formatting differs from gofmt's.
	test -z $(shell gofmt -l $(GO_FILES_NO_VENDOR))

.PHONY: lint-check
lint-check: ## Run golangci-lint linter.
	mkdir -p $$HOME/.cache/go-build; \
	mkdir -p -v $$HOME/.cache/golangci-lint; \
	docker run $(DOCKER_RUN_FLAGS) \
		-v $$PWD:/src \
		-w /src \
		-v $$HOME/.cache/go-build:/.cache/go-build \
		-v $$HOME/.cache/golangci-lint:/.cache/golangci-lint \
		-e GOLANGCI_LINT_CACHE=/.cache/golangci-lint \
		-e GOCACHE=/.cache/go-build \
		$(GOLANGCI_VERSION) golangci-lint run --timeout=4m

.PHONY: vendor
vendor: ## Tidy and vendor dependencies.
	go mod tidy
	go mod vendor

.PHONY: clean
clean:
	rm -rf ./test/trivy-results

.PHONY: test
test: ## Run unit and integration tests.
	go test -v -covermode=atomic -cover ./...
