# Building and Testing Brick Application

## Prerequisites

- Go 1.21+
- Node.js 18+
- Docker & Docker Compose
- Make (optional, but recommended)

## Backend Build

### Development Build

```bash
cd backend
go build -o brick-server main.go
./brick-server
```

### Production Build

```bash
cd backend
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o brick-server main.go
```

### Docker Build

```bash
docker build -f Dockerfile.backend -t brick:backend .
docker run -p 8080:8080 brick:backend
```

## Frontend Build

### Development Build

```bash
cd frontend
npm install
npm start
```

This starts the development server at http://localhost:3000

### Production Build

```bash
cd frontend
npm run build
```

Build output is in `build/` directory.

### Docker Build

```bash
docker build -f Dockerfile.frontend -t brick:frontend .
docker run -p 3000:3000 brick:frontend
```

## Chaincode Build

```bash
cd blockchain/chaincode
go build
```

### Package for Deployment

```bash
peer lifecycle chaincode package brick.tar.gz \
  --path ./blockchain/chaincode \
  --lang golang \
  --label brickcc_1
```

## Testing

### Backend Tests

```bash
cd backend
go test ./...
go test -v ./...        # Verbose output
go test -cover ./...    # With coverage
```

### Frontend Tests

```bash
cd frontend
npm test
npm test -- --coverage  # With coverage
```

### Integration Testing

```bash
# Start all services
docker-compose up -d

# Run integration tests
cd tests
go test ./...
```

## Performance Testing

### Load Testing Backend

```bash
# Using Apache Bench
ab -n 1000 -c 10 http://localhost:8080/api/health

# Using wrk
wrk -t4 -c100 -d30s http://localhost:8080/api/health
```

### Stress Testing Blockchain

```bash
# Generate many transactions
cd backend
go run stress-test.go
```

## Code Quality

### Backend Code Analysis

```bash
cd backend
go vet ./...
go fmt ./...
golangci-lint run ./...
```

### Frontend Code Analysis

```bash
cd frontend
npm run lint
npm run format
```

## Building with Makefile

```bash
make help              # Show all commands
make install-deps     # Install all dependencies
make build             # Build all components
make test              # Run all tests
make clean             # Clean build artifacts
```

## Continuous Integration

### GitHub Actions

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on: [push, pull_request]

jobs:
  backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
        with:
          go-version: 1.21
      - run: cd backend && go test ./...

  frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-node@v2
        with:
          node-version: 18
      - run: cd frontend && npm install && npm test
```

## Docker Compose Full Stack

```bash
# Build all images
docker-compose build

# Start services
docker-compose up -d

# View services
docker-compose ps

# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Stop services
docker-compose down

# Clean volumes
docker-compose down -v
```

## Deployment Checklist

- [ ] All tests passing
- [ ] Code review completed
- [ ] Environment variables configured
- [ ] Database migrations applied
- [ ] SSL certificates generated
- [ ] Backup strategy in place
- [ ] Monitoring configured
- [ ] Logging configured
- [ ] Security audit completed

## Troubleshooting Build Issues

### Go Module Issues
```bash
go clean -modcache
go mod tidy
go mod download
```

### Node Module Issues
```bash
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
```

### Docker Build Issues
```bash
# Clear Docker cache
docker system prune -a

# Rebuild without cache
docker-compose build --no-cache
```

## Next Steps

1. Configure `.env` file
2. Start blockchain network
3. Deploy chaincode
4. Start backend and frontend
5. Access UI at http://localhost:3000

For more information, see [QUICKSTART.md](../QUICKSTART.md)
