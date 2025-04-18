.PHONY: build debug-run stop prod-run nitro-stop release configure share-aws-creds dev-rsync

debug-build:
	rm *.eif || true
	docker build -t hello_nitro -f hello_world_demo/Dockerfile .
	nitro-cli build-enclave --docker-uri hello_nitro --output-file hello_nitro.eif


debug-run: nitro-stop share-aws-creds
	nitro-cli run-enclave --eif-path hello_nitro.eif --memory 2048 --cpu-count 1 --enclave-cid 16

stop: nitro-stop 

nitro-stop:
	nitro-cli terminate-enclave --all || true

# Download and run the production EIF from GHCR
# To specify a version: make prod-run VERSION_OVERRIDE=42
prod-run: nitro-stop share-aws-creds
	rm -f hello_nitro.eif || true
	curl -L -o hello_nitro.eif https://github.com/ddworken/teels/releases/download/v0.$${VERSION_OVERRIDE:-$$(cat VERSION)}/enclave.eif
	nitro-cli run-enclave --eif-path hello_nitro.eif --memory 2048 --cpu-count 1 --enclave-cid 16

release:
	# Bump the version
	expr `cat VERSION` + 1 > VERSION
	git add VERSION
	git commit -m "Release v0.`cat VERSION`" --no-verify
	git push
	gh release create v0.`cat VERSION` --generate-notes
	git push && git push --tags

configure:
	# Install dependencies
	sudo yum install -y docker git go socat htop rust cargo 
	sudo service docker start
	sudo usermod -a -G docker ec2-user
	sudo dnf install aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel -y
	sudo usermod -aG ne ec2-user

	# Configure git
	git config --global user.name "David Dworken"
	git config --global user.email "david@daviddworken.com"

	# Install hiSHtory :) 
	curl https://hishtory.dev/install.py | python3 -

	# Configure nitro enclaves
	sudo cp configs/nitro-allocator.yaml /etc/nitro_enclaves/allocator.yaml
	sudo systemctl enable --now nitro-enclaves-allocator.service

	# Install socat-proxy service
	sudo cp scripts/socat-proxy.service /etc/systemd/system/
	sudo systemctl daemon-reload
	sudo systemctl enable socat-proxy
	sudo systemctl start socat-proxy

	# Login to GitHub (required for prod-run)
	type -p yum-config-manager >/dev/null || sudo yum install -y yum-utils
	sudo yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
	sudo yum install -y gh
	gh auth login

	# Re-authenticating is needed for group changes for docker
	echo "Please exit your SSH session and log back in..."

share-aws-creds:
	while true; do \
	  AWS_ACCESS_KEY_ID=$$(aws configure get aws_access_key_id); \
	  AWS_SECRET_ACCESS_KEY=$$(aws configure get aws_secret_access_key); \
	  AWS_SESSION_TOKEN=$$(aws configure get aws_session_token); \
	  AWS_REGION=$$(aws configure get region); \
	  echo "Sending AWS credentials to enclave..."; \
	  if [ -z "$$AWS_ACCESS_KEY_ID" ] || [ -z "$$AWS_SECRET_ACCESS_KEY" ]; then \
	    echo "Error: AWS credentials are not set in aws configure"; \
	    exit 1; \
	  fi; \
	  echo "{\"AWS_ACCESS_KEY_ID\": \"$$AWS_ACCESS_KEY_ID\", \"AWS_SECRET_ACCESS_KEY\": \"$$AWS_SECRET_ACCESS_KEY\", \"AWS_SESSION_TOKEN\": \"$$AWS_SESSION_TOKEN\", \"AWS_REGION\": \"$$AWS_REGION\"}" | \
	    socat -v - vsock-connect:16:1337; \
	  sleep 5; \
	done & echo $$! > .share-aws-creds.pid

dev-rsync:
	while true; do \
		rsync -av * ec2-user@35.154.65.5:~/teels/ --exclude nsm-cli/target/; \
		sleep 0.5; \
	done

fmt:				## Format all files
	gofumpt -l -w -extra cert_provisioner/ cert_verifier/ hello_world_demo/
	gci write --custom-order -s standard -s 'Prefix(github.com/ddworken/teels)' -s default --skip-generated cert_provisioner/ cert_verifier/ hello_world_demo/
