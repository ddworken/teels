.PHONY: build debug-run stop

build:
	rm *.eif || true
	cd vsock-tcp-proxy && cargo build --bin exclave-proxy --release
	docker build -t hello_nitro -f hello_world_demo/Dockerfile .
	nitro-cli build-enclave --docker-uri hello_nitro --output-file hello_nitro.eif

debug-run:
	# RUST_BACKTRACE=1 vsock-tcp-proxy/target/release/exclave-proxy --vsock-addr 16:1616 --ip-addr `dig +short A acme-staging-v02.api.letsencrypt.org | grep . | grep -v org | grep -v com | head -n 1`
	sudo socat vsock-listen:8002,fork,reuseaddr tcp-connect:acme-staging-v02.api.letsencrypt.org:443 &
	sudo socat tcp-listen:80,fork,reuseaddr,keepalive vsock-connect:16:80,keepalive 2>&1 > /dev/null &
	sudo socat tcp-listen:443,fork,reuseaddr,keepalive vsock-connect:16:443,keepalive 2>&1 > /dev/null &
	nitro-cli run-enclave --eif-path hello_nitro.eif --memory 2048 --cpu-count 1 --enclave-cid 16 --debug-mode

stop:
	nitro-cli terminate-enclave --all
	sudo killall socat || true
	sudo killall enclave-proxy || true

# sudo socat vsock-listen:17,fork,reuseaddr tcp-connect:127.0.0.1:80 2>&1 > /dev/null &
