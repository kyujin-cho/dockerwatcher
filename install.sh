#!/bin/bash

if ! [ -x "$(command -v docker)" ]; then
    echo "Error: docker is not installed." >&2
    exit 1
fi 
if ! [ -x "$(command -v git)" ]; then
    echo "Error: git is not installed." >&2
    exit 1
fi 
if ! [ -x "$(command -v node)" ]; then
    echo "Error: node is not installed." >&2
    exit 1
fi

if ! [ -x "$(command -v pug)" ]; then 
    echo "Installing pug-cli via NPM..."
    npm i -g pug-cli
fi

echo "Starting MongoDB server on using docker..."
docker run --name dockerserve-mongo -p 127.0.0.1:42932:27017 -d mongo:latest
echo "Installation complete!"
