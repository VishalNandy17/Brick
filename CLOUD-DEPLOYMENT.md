# BRICK Cloud Deployment Guide

Run BRICK end-to-end **without Docker** on a low-spec laptop. The cloud ledger implements the same identity logic as the Hyperledger Fabric chaincode, with an upgrade path to real Fabric in the cloud.

---

## Architecture

```
┌─────────────────┐     REST API      ┌──────────────────────┐
│  Next.js UI     │ ────────────────► │  Go API Gateway      │
│  (localhost:3000)│                   │  (localhost:8080)    │
└─────────────────┘                   └──────────┬───────────┘
                                                 │
                                    ┌────────────▼────────────┐
                                    │  Cloud Ledger (JSON)    │
                                    │  data/cloud-ledger.json │
                                    └─────────────────────────┘
```

When you later connect to IBM Blockchain, Kaleido, or Play-with-Docker Fabric, set `BRICK_LEDGER_MODE=fabric` and provide certs in `connection.json`.

---

## Quick Start (Local, No Docker)

### 1. Start the backend

```powershell
cd D:\brick\backend
go mod tidy
go run .
```

Expected output:
```
Ledger initialized in cloud mode
Server running on port 8080 (ledger: cloud)
```

### 2. Start the frontend

```powershell
cd D:\brick\frontend
npm install
npm run dev
```

Open http://localhost:3000

### 3. Sign in with the seeded demo identity

| Field | Value |
|-------|-------|
| User ID | `admin` |
| Org (MSP ID) | `Org1MSP` |

Go to **Connect Identity → Sign In**, then open the dashboard.

### 4. Enroll a new identity

Switch to **Enroll New**, enable **brick-admin**, and register a new user ID (e.g. `alice`).

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BRICK_LEDGER_MODE` | `cloud` | `cloud` = no Docker; `fabric` = remote Fabric |
| `BRICK_LEDGER_DATA` | `../data/cloud-ledger.json` | Persistent ledger file |
| `CONNECTION_PROFILE` | `../connection-cloud.json` | Connection profile path |
| `SERVER_PORT` | `8080` | API port |
| `JWT_SECRET` | `dev-secret` | JWT signing key (change in production) |

Frontend (`.env.local`):

```
NEXT_PUBLIC_API_URL=http://localhost:8080
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health + ledger mode |
| POST | `/api/v1/brick/enroll` | Register identity |
| GET | `/api/v1/brick/session/:userId` | Get identity session |
| GET | `/api/v1/brick/identities` | List org identities |
| GET | `/api/blockchain/query?key=` | Query ledger state |
| POST | `/api/blockchain/invoke` | Invoke ledger function |
| GET | `/api/blockchain/history/:key` | Get key history |

Required headers for IAM routes:
- `X-User-Identity` — caller user ID
- `X-Org-ID` — organization MSP ID (e.g. `Org1MSP`)
- `X-Brick-Admin: true` — required for enrollment

---

## Cloud Hosting Options

### Option A: Render / Railway / Fly.io (Recommended)

Deploy the Go backend as a web service:

1. Push repo to GitHub
2. Create a new web service pointing to `backend/`
3. Set build command: `go build -o brick .`
4. Set start command: `./brick`
5. Set env vars: `BRICK_LEDGER_MODE=cloud`, `SERVER_PORT=8080`
6. Attach a persistent volume at `/data` and set `BRICK_LEDGER_DATA=/data/cloud-ledger.json`

Deploy frontend to Vercel:

1. Root directory: `frontend/`
2. Set `NEXT_PUBLIC_API_URL=https://your-backend.onrender.com`

### Option B: Play with Docker (Free Fabric Network)

When you want **real** Hyperledger Fabric without installing Docker locally:

1. Go to https://labs.play-with-docker.com/
2. Start a session and run the Fabric test network
3. Copy peer TLS certs and admin credentials to your machine or cloud backend
4. Update `connection.json` with the public peer address
5. Set `BRICK_LEDGER_MODE=fabric`

### Option C: IBM Blockchain Platform / Kaleido

Managed Fabric services provide connection profiles and enrolled identities:

1. Create a Fabric network in the cloud console
2. Deploy `blockchain/chaincode/` as `brick-identity`
3. Download connection profile + wallet certs
4. Place certs in `./certs/` and update `connection.json`
5. Set `BRICK_LEDGER_MODE=fabric`

---

## Chaincode Deployment (When Fabric Is Available)

The chaincode in `blockchain/chaincode/` is production-ready:

```bash
# On a cloud shell with Fabric test network running:
cd blockchain/chaincode
go mod vendor
peer lifecycle chaincode package brick-identity.tar.gz \
  --path . --lang golang --label brick-identity_1.0
```

Deploy using your network's lifecycle commands. Chaincode name must match `CHAINCODE_NAME=brick-identity`.

---

## Security Notes

- Cloud mode uses file-based persistence — protect `data/cloud-ledger.json` in production
- Change `JWT_SECRET` before deploying publicly
- Enrollment requires `X-Brick-Admin: true` (mirrors chaincode ABAC)
- Org isolation enforced: callers can only access their own MSP org

---

## Troubleshooting

**Backend won't start**
```powershell
cd D:\brick\backend
go mod tidy
go run .
```

**Frontend build errors**
```powershell
cd D:\brick\frontend
npm install
npm run dev
```

**Enrollment fails with "identity already exists"**
Use **Sign In** instead of **Enroll New** for existing users.

**GATEWAY_ERROR / Ledger not initialized**
Check that `BRICK_LEDGER_MODE=cloud` is set and `data/` directory is writable.

---

## Upgrade Path Summary

| Stage | Mode | Requirements |
|-------|------|--------------|
| Development | `cloud` | Go + Node.js only |
| Staging | `cloud` + hosted backend | Render/Railway + Vercel |
| Production | `fabric` | IBM/Kaleido/PWD + chaincode deployed |

The same API and frontend work across all stages — only the ledger backend changes.
