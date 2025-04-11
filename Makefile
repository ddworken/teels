.PHONY: build run stop

build:
	rm *.eif || true
	docker build -t hello_nitro -f hello_world_demo/Dockerfile .
	nitro-cli build-enclave --docker-uri hello_nitro --output-file hello_nitro.eif

run:
	nitro-cli run-enclave --eif-path hello_nitro.eif --memory 2048 --cpu-count 1 --enclave-cid 16 --debug-mode
	sudo socat tcp-listen:80,fork,reuseaddr vsock-connect:16:80

stop:
	nitro-cli terminate-enclave --all
