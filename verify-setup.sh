#!/bin/bash

# Brick Project Setup Verification Script
# Verifies all necessary components are in place

echo "================================================"
echo "Brick Project Setup Verification"
echo "================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1"
    else
        echo -e "${RED}✗${NC} $1 (MISSING)"
    fi
}

check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} $1/"
    else
        echo -e "${RED}✗${NC} $1/ (MISSING)"
    fi
}

echo -e "${YELLOW}Backend Files:${NC}"
check_file "backend/main.go"
check_file "backend/go.mod"
check_file "backend/config/config.go"
check_file "backend/models/user.go"
check_file "backend/models/transaction.go"
check_file "backend/handlers/blockchain.go"
check_file "backend/handlers/user.go"
check_file "backend/handlers/transaction.go"
check_file "backend/middleware/auth.go"
check_file "backend/middleware/cors.go"
check_file "backend/middleware/logging.go"

echo ""
echo -e "${YELLOW}Frontend Files:${NC}"
check_file "frontend/package.json"
check_file "frontend/src/index.js"
check_file "frontend/src/App.js"
check_file "frontend/src/App.css"
check_file "frontend/src/components/Navigation.js"
check_file "frontend/src/components/Dashboard.js"
check_file "frontend/src/components/UserManagement.js"
check_file "frontend/src/components/BlockchainExplorer.js"
check_file "frontend/src/components/TransactionHistory.js"
check_file "frontend/public/index.html"

echo ""
echo -e "${YELLOW}Blockchain Files:${NC}"
check_file "blockchain/chaincode/brick.go"
check_file "blockchain/chaincode/go.mod"
check_file "blockchain/network/docker-compose.yml"
check_file "blockchain/network/setup.sh"
check_file "blockchain/network/install-chaincode.sh"

echo ""
echo -e "${YELLOW}Configuration Files:${NC}"
check_file "go.mod"
check_file ".env"
check_file "docker-compose.yml"
check_file "Dockerfile.backend"
check_file "Dockerfile.frontend"
check_file "Makefile"

echo ""
echo -e "${YELLOW}Documentation Files:${NC}"
check_file "README.md"
check_file "QUICKSTART.md"
check_file "BUILD.md"
check_file "IMPLEMENTATION.md"
check_file "ARCHITECTURE.md"
check_file "CONTRIBUTING.md"
check_file "LICENSE"

echo ""
echo "================================================"
echo "Directory Structure:"
echo "================================================"
check_dir "backend"
check_dir "backend/config"
check_dir "backend/handlers"
check_dir "backend/models"
check_dir "backend/middleware"
check_dir "blockchain"
check_dir "blockchain/chaincode"
check_dir "blockchain/network"
check_dir "frontend"
check_dir "frontend/src"
check_dir "frontend/src/components"
check_dir "frontend/public"

echo ""
echo "================================================"
echo "Next Steps:"
echo "================================================"
echo "1. Install Backend Dependencies:"
echo "   cd backend && go mod download"
echo ""
echo "2. Install Frontend Dependencies:"
echo "   cd frontend && npm install"
echo ""
echo "3. Start Blockchain Network:"
echo "   cd blockchain/network && docker-compose up -d"
echo ""
echo "4. Start Backend Server:"
echo "   cd backend && go run main.go"
echo ""
echo "5. Start Frontend Application:"
echo "   cd frontend && npm start"
echo ""
echo "For more details, see QUICKSTART.md"
echo ""
echo "================================================"
