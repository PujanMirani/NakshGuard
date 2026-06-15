# build stage — compiles the binary
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o nakshguard .

# runtime stage — tiny final image
FROM alpine:latest
# ca-certificates is required for HTTPS to OpenAI/Anthropic.
# without it every forwarded request fails with x509 errors.
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/nakshguard .
COPY proxy.yaml .
EXPOSE 8080
CMD ["./nakshguard"]
