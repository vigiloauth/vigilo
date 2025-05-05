#!/bin/bash

# This script builds the Docker image and pushes it to the repository.

IMAGE_NAME="vigilo-auth"
TAG_NAME="latest-dev"
DOCKER_REPO="vigiloauth"

FULL_IMAGE="$DOCKER_REPO/$IMAGE_NAME:$TAG_NAME"

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

# Tag the image for the repository
echo "Tagging Docker image as $FULL_IMAGE..."
docker tag $IMAGE_NAME:$TAG_NAME $FULL_IMAGE

# Login to Docker
echo "Logging in to Docker..."
docker login

# Push the image
echo "Pushing Docker image to repository..."
docker push $FULL_IMAGE
