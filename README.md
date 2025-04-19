# Teels 

Teels is a portmanteau of TEE and TLS that allows binding a TLS cert to a TEE attestation in a publicly verifiable way. Ultimately, this makes it possible to have fully verifiable web apps where users can browse to a web app and rest easy knowing that the web app is only running known publicly auditable code. See [this blog post](https://blog.daviddworken.com/posts/teels/) for a more detailed description of the context and how this works. 

## Getting Started 

1. Create a new host name for your TEE-based application, in my case I'll be using `verified.teels.dev`.
2. Create a new EC2 Nitro instance (for my own testing I've been using a `c7g.large` in `ap-south-1` since it is currently the cheapest nitro-compatible instance).
3. Update the DNS records for your application domain and all subdomains (i.e. `verified.teels.dev` and `*.verified.teels.dev`) to point to your Nitro instance.
4. From the EC2 instance, run `make configure` to install the various dependencies required for teels
5. Run `make prod-run` to start up an instance of the code in `hello_world_demo/` to host a basic hello-world type server in a TEE with a variety of demo utility pages.
6. From another machine, run `VERIFIED_HOST_NAME=verified-dev.teels.dev go run cert_verifier/cert_verifier.go` to verify the TLS cert for your newly hosted TLS instance. 

## Demo Instance

A demo instance with some useful tools is available at [`verified.teels.dev`](https://verified.teels.dev). To audit the TLS certs for this hostname and ensure they're all bound to code in this repo, run:

```
VERIFIED_HOST_NAME=verified.teels.dev go run cert_verifier/cert_verifier.go audit
```

If you'd like to check the live certificate (which may not be live in CT logs yet), run:

```
VERIFIED_HOST_NAME=verified.teels.dev go run cert_verifier/cert_verifier.go live
```

Note: For cost savings reasons, the demo instance is hosted on an AWS Spot instance, so it may have intermittent downtime.

## TODO

This is currently prototype-quality code that is not production ready. Before using for a production system, it should be carefully audited and improved from both security and reliability POVs.

From a security POV, there are a number of places where this could be improved:

1. Rather than relying on crt.sh for querying CT logs, this code could directly consume CT logs
2. Rather than pulling allowed PCRs for GitHub releases, this code could check the accompanying sigstore signatures