# syntax=docker/dockerfile:1.4
FROM golang:1.23.3 AS builder
WORKDIR /app
COPY . .

ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN go build -o /app/identity-server ./cmd/identity-server

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/identity-server .
COPY cmd/config/application/config.yaml ./config.yaml
RUN chmod +x ./identity-server
EXPOSE 8080


ENV SMTP_USERNAME=""
ENV SMTP_FROM_ADDRESS=""
ENV VIGILO_SERVER_MODE=docker

RUN --mount=type=secret,id=smtp_password \
    --mount=type=secret,id=token_issuer \
    --mount=type=secret,id=token_private_key \
    --mount=type=secret,id=token_public_key \
    --mount=type=secret,id=crypto_secret_key 

CMD ["./identity-server"]