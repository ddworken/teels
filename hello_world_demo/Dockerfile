FROM golang:1.23-alpine

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY hello_world_demo/main.go ./

RUN go build -o /enclave-server

EXPOSE 8888

CMD [ "/enclave-server" ]