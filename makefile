IMAGE ?= v3rm1n
DOCKERFILE := docker/dockerfile
DOCKER_RUN := docker run --rm \
	-u $(shell id -u):$(shell id -g) \
	-v $(CURDIR):/project \
	-w /project \
	$(IMAGE)

.PHONY: all image scanner firmware format clean

all: scanner firmware

image:
	docker build -f $(DOCKERFILE) -t $(IMAGE) .

scanner: image
	$(DOCKER_RUN) make -C scanner

firmware: image
	$(DOCKER_RUN) make -C firmware

format: image
	$(DOCKER_RUN) clang-format -i scanner/*.[ch] firmware/*/main/*.c

clean:
	rm -rf build
