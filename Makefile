PROJECTNAME=$(shell basename "$(PWD)")
GOBASE=$(shell pwd)
PORT_HTTP=3000

.PHONY: all build-debug

build-debug:
	@go mod tidy
	@CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -race -x -ldflags \
		"-X github.com/roysitumorang/sadia/config.AppName=$(PROJECTNAME) \
		-X github.com/roysitumorang/sadia/config.Commit=$(shell git rev-list -1 HEAD) \
		-X github.com/roysitumorang/sadia/config.Build=$(shell date +%FT%T%:z)"

build-release:
	@go mod tidy
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -ldflags \
		"-X github.com/roysitumorang/sadia/config.AppName=$(PROJECTNAME) \
		-X github.com/roysitumorang/sadia/config.Commit=$(shell git rev-list -1 HEAD) \
		-X github.com/roysitumorang/sadia/config.Build=$(shell date +%FT%T%:z)"

run: build-debug stop
	@-nohup $(GOBASE)/$(PROJECTNAME) run > /dev/null 2>&1 & echo " > $(PROJECTNAME) is available at port $(PORT_HTTP) and PID $$!"

stop:
	@-lsof -t -i :$(PORT_HTTP) | xargs --no-run-if-empty kill

doc:
	@echo Starting swagger generating
	@swag fmt -d ./ --exclude ./docs && swag init -g *.go

upgrade-dependencies:
	@echo Upgrading dependencies
	@go get -u ./... && go mod tidy
