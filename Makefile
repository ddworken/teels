.PHONY: build debug-run stop socat-run socat-stop

build:
	rm *.eif || true
	docker build -t hello_nitro -f hello_world_demo/Dockerfile .
	nitro-cli build-enclave --docker-uri hello_nitro --output-file hello_nitro.eif

socat-run:
	sudo socat vsock-listen:8002,fork,reuseaddr tcp-connect:acme-staging-v02.api.letsencrypt.org:443 &
	# sudo socat vsock-listen:8002,fork,reuseaddr tcp-connect:acme-v02.api.letsencrypt.org:443 &
	sudo socat tcp-listen:80,fork,reuseaddr,keepalive vsock-connect:16:80,keepalive 2>&1 > /dev/null &
	sudo socat tcp-listen:443,fork,reuseaddr,keepalive vsock-connect:16:443,keepalive 2>&1 > /dev/null &


debug-run: socat-run
	nitro-cli run-enclave --eif-path hello_nitro.eif --memory 2048 --cpu-count 1 --enclave-cid 16

stop: socat-stop 
	nitro-cli terminate-enclave --all

socat-stop:
	sudo killall socat || true

# sudo socat vsock-listen:17,fork,reuseaddr tcp-connect:127.0.0.1:80 2>&1 > /dev/null &
