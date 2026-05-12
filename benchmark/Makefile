.PHONY: all build clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -o gen/gen ./gen
	CGO_ENABLED=0 go build -trimpath -o sampler/sampler ./sampler

clean:
	rm -f gen/gen sampler/sampler results/*.csv
