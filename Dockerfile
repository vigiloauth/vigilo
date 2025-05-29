# Build Backend SPA
FROM node:20-alpine AS ui-builder
WORKDIR /app
COPY backend/ui/ ./
RUN npm install
RUN npm run build

# Build Backend
FROM golang:latest AS builder
WORKDIR /app
COPY backend/ ./backend/

ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

WORKDIR /app/backend
RUN go build -o /app/identity-server ./cmd/identity-server

# Final Image
FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/identity-server .
COPY --from=builder /app/backend/cmd/config/application/config.yaml ./config.yaml
COPY --from=ui-builder /app/build ./ui/build

RUN chmod +x ./identity-server
EXPOSE 8080

ENV VIGILO_SERVER_MODE=docker
ENV REACT_BUILD_PATH=/app/ui/build

CMD ["./identity-server"]
