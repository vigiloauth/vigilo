#!/bin/bash

docker rm -f $(docker ps -aq)

docker build -t vigilo-auth:local .

docker run -p 8080:8080 --name vigilo-auth-local \
  --env-file .env \
  vigilo-auth:local