.PHONY: all gen lint fmt format

help: # Show help for each of the Makefile recipes.
	@grep -E '^[a-zA-Z0-9 -]+:.*#'  Makefile | sort | while read -r l; do printf "\033[1;32m$$(echo $$l | cut -f 1 -d':')\033[00m:$$(echo $$l | cut -f 2- -d'#')\n"; done

all: build gen

gen: build # generate proto files for grpc
	./scripts/gen-grpc.sh

lint: # lint proto files for grpc
	./scripts/buf.sh lint

format:
	buf format -w

fmt: # lint proto files for grpc
	./scripts/buf.sh format -w

build:
	mkdir -p bin
	go build -o bin/protoc-gen-pbzap cmd/main.go

