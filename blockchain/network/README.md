# Network Configuration Files

## Hyperledger Fabric Network Setup

This directory contains configuration for the Brick blockchain network.

## Prerequisites

- Docker & Docker Compose
- Hyperledger Fabric binaries

## Directory Structure

```
network/
├── docker-compose.yml      # Docker Compose configuration
├── setup.sh               # Setup script
├── install-chaincode.sh   # Chaincode installation script
├── orderer/               # Orderer MSP and configuration
├── peers/                 # Peer MSP and configuration
└── ca/                    # Certificate Authority configuration
```

## Network Topology

### Organizations
- **Org1** (Organization 1)
  - Orderer: orderer.brick.local
  - Peers: peer0.org1.brick.local, peer1.org1.brick.local
  - CA: ca.org1.brick.local

### Channels
- **mychannel** - Main application channel

### Chaincode
- **brickcc** - Brick smart contract

## Configuration

### Orderer Configuration

The orderer is configured with:
- Ordering mechanism: Solo (single orderer)
- Block size: 2MB
- Absolute max bytes: 10MB

### Peer Configuration

Peers are configured with:
- World State Database: CouchDB
- Logging Level: INFO
- Chaincode Logging Level: INFO

### CA Configuration

The Certificate Authority is configured for:
- User enrollment
- Organization registration
- Certificate generation

## Starting the Network

```bash
# Setup network
./setup.sh

# Start network
docker-compose up -d

# View logs
docker-compose logs -f

# Stop network
docker-compose down
```

## Creating Channel

```bash
export CHANNEL_NAME=mychannel
export FABRIC_CFG_PATH=$(pwd)

# Create channel genesis block
configtxgen -profile OneOrgChannel -outputCreateChannelTx \
  ./channel-artifacts/${CHANNEL_NAME}.tx -channelID $CHANNEL_NAME

# Create channel
peer channel create -o orderer.brick.local:7050 \
  -c $CHANNEL_NAME -f ./channel-artifacts/${CHANNEL_NAME}.tx
```

## Joining Peers to Channel

```bash
# Join peer0
CORE_PEER_ADDRESS=peer0.org1.brick.local:7051 \
peer channel join -b ${CHANNEL_NAME}.block

# Join peer1
CORE_PEER_ADDRESS=peer1.org1.brick.local:7051 \
peer channel join -b ${CHANNEL_NAME}.block
```

## Notes

- First time setup may take a few minutes
- Ensure all ports are available (7050, 7051, 7053, 7054, 5984)
- For production, consider using Org0 and Org1 with multiple orderers
- TLS is disabled for development; enable for production

## References

- [Hyperledger Fabric Documentation](https://hyperledger-fabric.readthedocs.io/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
