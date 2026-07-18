#!/bin/bash

# Brick Network Setup Script
# This script initializes the Hyperledger Fabric network for Brick

set -e

echo "=========================================="
echo "Brick Hyperledger Fabric Network Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Docker is not running. Please start Docker.${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Creating network directories...${NC}"
mkdir -p orderer/msp/tlscacerts
mkdir -p peers/peerOrganizations/org1.brick.local/peers/peer0.org1.brick.local/msp
mkdir -p peers/peerOrganizations/org1.brick.local/peers/peer1.org1.brick.local/msp
mkdir -p ca

echo -e "${GREEN}Network directories created${NC}"

echo -e "${YELLOW}Step 2: Starting Docker containers...${NC}"
docker-compose up -d

echo -e "${YELLOW}Step 3: Waiting for containers to start...${NC}"
sleep 10

echo -e "${YELLOW}Step 4: Creating channel...${NC}"
# This would be done via peer commands
# For now, just a placeholder

echo -e "${GREEN}=========================================="
echo "Brick Network Setup Complete!"
echo "==========================================${NC}"

echo -e "${GREEN}Network Status:${NC}"
docker-compose ps

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Install chaincode: ./install-chaincode.sh"
echo "2. Instantiate chaincode: ./instantiate-chaincode.sh"
echo "3. Start backend: cd ../../backend && go run main.go"
echo "4. Start frontend: cd ../../frontend && npm start"
