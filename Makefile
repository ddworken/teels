.PHONY: build debug-run stop socat-run socat-stop prod-run nitro-stop release

build:
	rm *.eif || true
	docker build -t hello_nitro -f hello_world_demo/Dockerfile .
	nitro-cli build-enclave --docker-uri hello_nitro --output-file hello_nitro.eif

socat-run: socat-stop
	sudo socat vsock-listen:8002,fork,reuseaddr tcp-connect:acme-staging-v02.api.letsencrypt.org:443 &
	# sudo socat vsock-listen:8002,fork,reuseaddr tcp-connect:acme-v02.api.letsencrypt.org:443 &
	sudo socat tcp-listen:80,fork,reuseaddr,keepalive vsock-connect:16:80,keepalive 2>&1 > /dev/null &
	sudo socat tcp-listen:443,fork,reuseaddr,keepalive vsock-connect:16:443,keepalive 2>&1 > /dev/null &


debug-run: socat-run nitro-stop
	nitro-cli run-enclave --eif-path hello_nitro.eif --memory 2048 --cpu-count 1 --enclave-cid 16

stop: socat-stop nitro-stop 

nitro-stop:
	nitro-cli terminate-enclave --all

socat-stop:
	sudo killall socat || true

# Download and run the production EIF from GHCR
prod-run: socat-run nitro-stop
	rm hello_nitro.eif || true
	curl -L -o hello_nitro.eif https://github.com/ddworken/teels/releases/download/v0.`cat VERSION`/enclave.eif
	nitro-cli run-enclave --eif-path hello_nitro.eif --memory 2048 --cpu-count 1 --enclave-cid 16

release:
	# Bump the version
	expr `cat VERSION` + 1 > VERSION
	git add VERSION
	git commit -m "Release v0.`cat VERSION`" --no-verify
	git push
	gh release create v0.`cat VERSION` --generate-notes
	git push && git push --tags

# sudo socat vsock-listen:17,fork,reuseaddr tcp-connect:127.0.0.1:80 2>&1 > /dev/null &
