# syntax=docker/dockerfile:1.4
FROM golang:1.23.3 AS builder
WORKDIR /app
COPY . .

ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN --mount=type=secret,id=SMTP_USERNAME \
    --mount=type=secret,id=SMTP_FROM_ADDRESS \
    --mount=type=secret,id=SMTP_PASSWORD \
    --mount=type=secret,id=TOKEN_ISSUER \
    --mount=type=secret,id=TOKEN_PRIVATE_KEY \
    --mount=type=secret,id=TOKEN_PUBLIC_KEY \
    echo "Secrets available at /run/secrets/*. These are build-time only."

RUN go build -o /app/identity-server ./cmd/identity-server

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/identity-server .
COPY cmd/config/application/config.yaml ./config.yaml
COPY .env .env
RUN chmod +x ./identity-server
EXPOSE 8080

CMD ["./identity-server"]
