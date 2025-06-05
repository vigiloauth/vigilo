#!/bin/bash -eu

cd $SRC/$PROJECT_NAME

go mod download

compile_go_fuzzer ./tests/fuzz FuzzNewClientAuthorizationRequest fuzz_client_authorization