## Usage: 

go_files := $(wildcard cmd/*.go)
path := $(shell pwd)

all: clean build

clean:
	@-rm -rf ./build

build:
	@-mkdir ./build
	go build -v -ldflags="-s -w" -o build/certificateapi ${go_files}
