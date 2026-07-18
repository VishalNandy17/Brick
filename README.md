# BRICK — Blockchain Identity & Access Management

Decentralized IAM engine with Hyperledger Fabric chaincode and a **cloud ledger mode** that runs without Docker on any laptop.

## Quick Start (No Docker)

**Requirements:** Go 1.21+, Node.js 18+

```powershell
# Terminal 1 — Backend
cd backend
go run -buildvcs=false .

# Terminal 2 — Frontend
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 → **Connect Identity** → Sign in as `admin` / `Org1MSP`.

Or use the one-click script:

```powershell
.\start.ps1
```

## What's Included

| Layer | Location | Status |
|-------|----------|--------|
| Fabric chaincode | `blockchain/chaincode/` | Production-ready |
| Go API gateway | `backend/` | Cloud + Fabric modes |
| Next.js frontend | `frontend/` | Auth context + dashboard |
| Connection profiles | `connection-cloud.json`, `connection.json` | Cloud + Fabric |
| Security middleware | `backend/middleware/` | CORS, JWT, ABAC, panic recovery |
| Documentation | `SETUP-NO-DOCKER.md`, `CLOUD-DEPLOYMENT.md` | Full guides |

## Cloud Deployment

Deploy without running Fabric locally:

- **Backend:** Render, Railway, or Fly.io — see `render.yaml`
- **Frontend:** Vercel with `NEXT_PUBLIC_API_URL` pointing to your backend
- **Upgrade to real Fabric:** IBM Blockchain, Kaleido, or Play-with-Docker

See [CLOUD-DEPLOYMENT.md](./CLOUD-DEPLOYMENT.md) for step-by-step instructions.

## Architecture

```
Next.js UI  →  Go API Gateway  →  Cloud Ledger (JSON)  or  Hyperledger Fabric
```

Set `BRICK_LEDGER_MODE=cloud` (default) for no-Docker development. Set `BRICK_LEDGER_MODE=fabric` when connecting to a remote Fabric network.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/v1/brick/enroll` | Register identity |
| GET | `/api/v1/brick/session/:userId` | Get session |
| GET | `/api/v1/brick/identities` | List org identities |
| GET | `/api/blockchain/query?key=` | Query ledger |
| POST | `/api/blockchain/invoke` | Invoke ledger function |

## License

MIT — see [README-ENTERPRISE.md](./README-ENTERPRISE.md) for full enterprise documentation.
