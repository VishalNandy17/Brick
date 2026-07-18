#!/bin/bash

# Install Chaincode Script
# Installs the brick chaincode on peers

set -e

CHANNEL_NAME="mychannel"
CHAINCODE_NAME="brickcc"
CHAINCODE_VERSION="1.0"

echo "Installing chaincode $CHAINCODE_NAME..."

# Set environment variables
export FABRIC_CFG_PATH=$(pwd)/../config
export CORE_PEER_TLS_ENABLED=false
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_ADDRESS=peer0.org1.brick.local:7051

# Install on peer0
echo "Installing on peer0.org1.brick.local..."
peer lifecycle chaincode install chaincode.tar.gz

# Install on peer1
export CORE_PEER_ADDRESS=peer1.org1.brick.local:7051
echo "Installing on peer1.org1.brick.local..."
peer lifecycle chaincode install chaincode.tar.gz

echo "Chaincode installed successfully!"
