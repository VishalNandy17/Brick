# Quick Start Guide - Brick Hyperledger Fabric Application

## Prerequisites

Before starting, ensure you have:
- Docker & Docker Compose installed
- Go 1.21+
- Node.js 18+
- Git

## Installation

### Step 1: Clone/Setup Repository
```bash
cd D:\
# Project already created at D:\brick
cd brick
```

### Step 2: Install Dependencies

**Backend:**
```bash
cd backend
go mod download
```

**Frontend:**
```bash
cd frontend
npm install
```

### Step 3: Start Blockchain Network

```bash
cd blockchain/network
# For Linux/Mac
bash setup.sh

# For Windows
# Manually create directories and run docker-compose
docker-compose up -d
```

### Step 4: Start Backend Server

```bash
cd backend
go run main.go
```

Server will start on: http://localhost:8080

### Step 5: Start Frontend Application

```bash
cd frontend
npm start
```

Frontend will open at: http://localhost:3000

## Using Docker Compose (Recommended)

```bash
# Build and start all services
docker-compose up --build

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## API Endpoints

### Health Check
```
GET http://localhost:8080/api/health
```

### Blockchain
```
GET /api/blockchain/query?key=<key>
POST /api/blockchain/invoke
GET /api/blockchain/history/<key>
```

### Users
```
GET /api/users
POST /api/users
GET /api/users/<id>
PUT /api/users/<id>
DELETE /api/users/<id>
```

### Transactions
```
GET /api/transactions
POST /api/transactions
GET /api/transactions/<id>
```

## Project Structure

```
D:\brick/
├── backend/                    # Go REST API
│   ├── config/                # Configuration
│   ├── handlers/              # HTTP handlers
│   ├── middleware/            # Authentication/CORS
│   ├── models/                # Data models
│   ├── main.go               # Entry point
│   └── go.mod
├── blockchain/               # Hyperledger Fabric
│   ├── chaincode/            # Smart contracts
│   │   ├── brick.go         # Main chaincode
│   │   └── go.mod
│   └── network/              # Network config
│       ├── docker-compose.yml
│       ├── setup.sh
│       └── install-chaincode.sh
├── frontend/                 # React UI
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── App.js          # Main app
│   │   ├── index.js        # Entry point
│   │   └── App.css         # Styles
│   ├── public/             # Static files
│   └── package.json
├── .env                     # Environment variables
├── docker-compose.yml       # Docker orchestration
├── Dockerfile.backend       # Backend container
├── Dockerfile.frontend      # Frontend container
├── Makefile                # Build commands
└── README.md               # Documentation
```

## Environment Variables

Edit `.env` file in project root:

```
SERVER_PORT=8080
FABRIC_CFG_PATH=../blockchain/config
CHANNEL_NAME=mychannel
CHAINCODE_NAME=brickcc
PEER_HOST=localhost
PEER_PORT=7051
CA_HOST=localhost
CA_PORT=7054
ORG_NAME=Org1
ORG_MSPID=Org1MSP
ADMIN_USER=admin
ADMIN_PASSWORD=adminpw
```

## Chaincode Deployment

### Build Chaincode
```bash
cd blockchain/chaincode
go build
```

### Package Chaincode
```bash
peer lifecycle chaincode package brickcc.tar.gz \
  --path ./blockchain/chaincode \
  --lang golang \
  --label brickcc_1
```

### Install on Peers
```bash
peer lifecycle chaincode install brickcc.tar.gz
```

### Approve for Organization
```bash
peer lifecycle chaincode approveformyorg \
  --channelID mychannel \
  --name brickcc \
  --version 1.0 \
  --package-id <PACKAGE_ID>
```

### Commit Chaincode
```bash
peer lifecycle chaincode commit \
  --channelID mychannel \
  --name brickcc \
  --version 1.0
```

## Common Commands

```bash
# View Makefile commands
make help

# Install dependencies
make install-deps

# Build Docker images
make build

# Start all services
make run

# Stop all services
make stop

# View logs
make logs

# Clean everything
make clean
```

## Testing

### Test Backend
```bash
cd backend
go test ./...
```

### Test Frontend
```bash
cd frontend
npm test
```

## Troubleshooting

### Port already in use
```bash
# Find process using port
netstat -ano | findstr :8080

# Kill process (Windows)
taskkill /PID <PID> /F
```

### Docker connection issues
```bash
# Restart Docker daemon
sudo systemctl restart docker

# Check Docker logs
docker logs <container_id>
```

### Go module issues
```bash
go clean -modcache
go mod tidy
go mod download
```

### Frontend build issues
```bash
rm -rf node_modules package-lock.json
npm install
npm start
```

## Production Deployment

1. Update `.env` with production values
2. Build images:
   ```bash
   docker build -f Dockerfile.backend -t brick:backend .
   docker build -f Dockerfile.frontend -t brick:frontend .
   ```
3. Push to registry:
   ```bash
   docker tag brick:backend myregistry/brick:backend
   docker push myregistry/brick:backend
   ```
4. Deploy using Kubernetes or Docker Swarm

## Support

For issues or questions, check:
- Backend logs: `docker logs brick-backend`
- Frontend logs: `docker logs brick-frontend`
- Blockchain logs: `docker logs brick-blockchain`

## License

MIT License
