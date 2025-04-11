# Build stage for nsm-cli
FROM golang:1.23-alpine AS nsm-builder

# Install Rust, Cargo, and build dependencies
RUN apk add --no-cache rustup build-base
RUN rustup-init -y --default-toolchain stable && \
    source $HOME/.cargo/env && \
    rustup default stable

WORKDIR /app

# Copy and build nsm-cli
COPY nsm-cli/ ./nsm-cli/
WORKDIR /app/nsm-cli
RUN source $HOME/.cargo/env && cargo build --release

# Build stage for Go application
FROM golang:1.23-alpine AS go-builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
COPY vndr/ ./vndr/
RUN go mod download

# Copy the source code
COPY hello_world_demo/main.go ./

# Build the Go application
RUN go build -o /enclave-server

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy only the necessary binaries from previous stages
COPY --from=nsm-builder /app/nsm-cli/target/release/nsm-cli /app/
COPY --from=go-builder /enclave-server /app/

EXPOSE 8888

CMD [ "/app/enclave-server" ]