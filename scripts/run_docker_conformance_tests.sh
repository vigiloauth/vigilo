#!/bin/bash

# This script creates a new docker container specifically for the
# OIDC conformance tests.

set -e # Exit on any error.

CONTAINER_NAME="vigilo-auth-conformance"
IMAGE_NAME="vigilo-auth"
TAG_NAME="conformance"
CONTAINER_PORT=8081

# Stop all running containers
echo "Stopping all running Docker containers..."
docker stop $(docker ps -q) 2>/dev/null || true

# Remove all containers (not just running ones)
echo "Removing all Docker containers..."
docker rm $(docker ps -a -q) 2>/dev/null || true

# Build the Docker image
echo "Building Docker image..."
cd ..
docker build -t $IMAGE_NAME:$TAG_NAME .

# Run the container
echo "Starting conformance test container..."
docker run -p $CONTAINER_PORT:$CONTAINER_PORT --name $CONTAINER_NAME \
  --env-file .env \
  $IMAGE_NAME:$TAG_NAME