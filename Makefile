.DEFAULT_GOAL := help
Owner := youyo
Name := postfix-log-parser
Repository := "github.com/$(Owner)/$(Name)"
GithubToken := ${GITHUB_TOKEN}
Version := $(shell git describe --tags --abbrev=0)

## Setup
setup:
	GO111MODULE=off go get -v github.com/Songmu/goxz/cmd/goxz
	GO111MODULE=off go get -v github.com/tcnksm/ghr
	GO111MODULE=off go get -v github.com/jstemmer/go-junit-report

## Run tests
test:
	go test -v -cover \
		$(shell go list ./...)

## Execute `go run`
run:
	go run \
		$(Name)/main.go ${OPTION}

## Vendoring
vendoring:
	go mod download

## Build
build:
	go get
	goxz -os=darwin,linux -arch=amd64 -d=pkg ./$(Name)

## Release
release:
	ghr -t ${GithubToken} -u $(Owner) -r $(Name) --replace $(Version) pkg/

## Remove packages
clean:
	rm -rf pkg/

## Show help
help:
	@make2help $(MAKEFILE_LIST)

.PHONY: help
.SILENT:
