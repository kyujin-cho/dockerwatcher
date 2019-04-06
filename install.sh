#!/bin/bash

if ! [ -x "$(command -v docker)" ]; then
    echo "Error: docker is not installed." >&2
    exit 1
fi 
if ! [ -x "$(command -v git)" ]; then
    echo "Error: git is not installed." >&2
    exit 1
fi 

echo "Starting MySQL server on docker container..."
docker run --name dockerserve-mongo -p 127.0.0.1:42932:27017 -d mongo:latest
echo "Installation complete!"