.PHONY: help setup build run stop clean test logs cloud-build cloud-backend cloud-frontend verify

help:
	@echo "BRICK — Blockchain Identity & Access Management"
	@echo "================================================"
	@echo "Cloud mode (no Docker):"
	@echo "  make cloud-build      - Build backend + chaincode + frontend"
	@echo "  make cloud-backend    - Run Go API gateway (cloud ledger)"
	@echo "  make cloud-frontend   - Run Next.js dev server"
	@echo "  make verify           - Verify setup (PowerShell)"
	@echo ""
	@echo "Docker mode (requires Docker):"
	@echo "  make build            - Build Docker containers"
	@echo "  make run              - Start all services via Docker"
	@echo "  make blockchain       - Start Fabric network"
	@echo "  make stop             - Stop Docker services"
	@echo "  make logs             - View Docker logs"
	@echo ""
	@echo "General:"
	@echo "  make install-deps     - Install Go + npm dependencies"
	@echo "  make test             - Run tests"
	@echo "  make clean            - Clean build artifacts"

setup:
	@echo "Setting up Brick project..."
	mkdir -p brick
	cd brick && go mod download
	cd frontend && npm install

install-deps:
	@echo "Installing dependencies..."
	cd backend && go mod download
	cd frontend && npm install
	@echo "Dependencies installed!"

build:
	@echo "Building Brick application..."
	docker-compose build
	@echo "Build complete!"

run:
	@echo "Starting Brick application..."
	docker-compose up -d
	@echo "Brick is running!"
	@echo "Backend: http://localhost:8080"
	@echo "Frontend: http://localhost:3000"

cloud-build:
	@echo "Building BRICK (cloud mode, no Docker)..."
	mkdir -p tmp
	cd backend && GOTMPDIR=../tmp TEMP=../tmp TMP=../tmp go build -buildvcs=false -o brick .
	cd blockchain/chaincode && GOTMPDIR=../../tmp TEMP=../../tmp TMP=../../tmp go build -buildvcs=false .
	cd frontend && npm run build
	@echo "Cloud build complete!"

cloud-backend:
	@echo "Starting backend (cloud ledger mode)..."
	cd backend && go run -buildvcs=false .

cloud-frontend:
	@echo "Starting Next.js frontend..."
	cd frontend && npm run dev

verify:
	powershell -ExecutionPolicy Bypass -File verify-setup.ps1

backend: cloud-backend

frontend: cloud-frontend

blockchain:
	@echo "Starting blockchain network..."
	cd blockchain/network && docker-compose up -d
	@echo "Blockchain network started!"

stop:
	@echo "Stopping Brick application..."
	docker-compose down
	@echo "Stopped!"

clean:
	@echo "Cleaning up..."
	docker-compose down -v
	rm -rf backend/vendor
	rm -rf frontend/node_modules
	rm -rf frontend/build
	@echo "Clean complete!"

test:
	@echo "Running tests..."
	cd backend && go test ./...
	cd frontend && npm test

logs:
	docker-compose logs -f

dev-backend:
	@echo "Running backend in development mode..."
	cd backend && go run main.go

dev-frontend:
	@echo "Running frontend in development mode..."
	cd frontend && npm run dev

ps:
	docker-compose ps

env-setup:
	@echo "Setting up environment variables..."
	cp .env.example .env
	@echo "Environment file created! Please update .env with your configuration."
