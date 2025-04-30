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

CMD ["./identity-server"]