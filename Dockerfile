FROM node:20-alpine AS ui-builder
WORKDIR /app
COPY ui/ ./
RUN npm install
RUN npm run build

FROM golang:latest AS builder
WORKDIR /app
COPY . .

ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN go build -o /app/identity-server ./cmd/identity-server

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/identity-server .
COPY --from=builder /app/cmd/config/application/config.yaml ./config.yaml
COPY --from=ui-builder /app/build ./ui/build

RUN chmod +x ./identity-server
EXPOSE 8080

ENV VIGILO_SERVER_MODE=docker
ENV REACT_BUILD_PATH=/app/ui/build

CMD ["./identity-server"]
