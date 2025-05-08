#!/bin/bash

# This script builds the Docker image and pushes it to the repository.

IMAGE_NAME="vigilo-auth"
TAG_NAME="latest-dev"
DOCKER_REPO="vigiloauth"

FULL_IMAGE="$DOCKER_REPO/$IMAGE_NAME:$TAG_NAME"

# Build the Docker image
echo "Building Docker image..."
cd ..
docker build \
    --cache-from $FULL_IMAGE \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    -t $IMAGE_NAME:$TAG_NAME .

# Tag the image for the repository
echo "Tagging Docker image as $FULL_IMAGE..."
docker tag $IMAGE_NAME:$TAG_NAME $FULL_IMAGE

# Login to Docker
echo "Logging in to Docker..."
docker login

# Push the image
echo "Pushing Docker image to repository..."
docker push $FULL_IMAGE
