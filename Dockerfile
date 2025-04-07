FROM golang:1-21-alpine AS builder
WORKDIR /app
COPY . .
RUN cd/cmd/identity-server && go build -o /identity-server

FROM alpine:latest
WORKDIR /app
COPY --from=builder /identity-server .
COPY cmd/identity-server/config.yaml ./config.yaml
EXPOSE 8080

ENV VIGILO_SERVER_MODE=docker
CMD ["./identity-server"]