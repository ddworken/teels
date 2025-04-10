```
docker build -t hello-nitro -f hello_world_demo/Dockerfile .
nitro-cli build-enclave --docker-uri hello-nitro --output-file hello-nitro.eif
```