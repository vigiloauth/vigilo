#!/bin/bash

# This script creates a new docker container specifically for the 
# OIDC conformance tests.

set -e  # Exit on any error.

CONTAINER_NAME="vigilo-auth-oidc-conformance-tests"
IMAGE_NAME="vigilo-auth"
TAG_NAME="oidc-conformance-tests"
CONTAINER_PORT=8081

# Stop and remove only the specific container if it exists
echo "Cleaning up any existing test containers..."
docker rm -f $CONTAINER_NAME:$TAG_NAME 2>/dev/null || true

# Build the Docker image
echo "Building Docker image..."
docker build -t $IMAGE_NAME:$TAG_NAME .

# Run the container
echo "Starting conformance test container..."
docker run -p $CONTAINER_PORT:$CONTAINER_PORT --name $CONTAINER_NAME \
  --env-file .env \
  $IMAGE_NAME:$TAG_NAME

echo "Container started successfully. Running on port $CONTAINER_PORT"