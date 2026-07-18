# BRICK Setup — No Docker Required

This guide is for running BRICK on a low-spec laptop without Docker.

## What Works Out of the Box

- Go backend with cloud ledger (chaincode-equivalent identity logic)
- Next.js frontend with auth context and dashboard
- Identity enrollment, session validation, blockchain query/history
- Persistent JSON ledger at `data/cloud-ledger.json`

## Start in 2 Terminals

**Terminal 1 — Backend**
```powershell
cd D:\brick\backend
go run .
```

**Terminal 2 — Frontend**
```powershell
cd D:\brick\frontend
npm install
npm run dev
```

## First Login

1. Open http://localhost:3000
2. Click **Connect Identity**
3. Use **Sign In** tab with:
   - User ID: `admin`
   - Org: `Org1MSP`

## Full Documentation

See [CLOUD-DEPLOYMENT.md](./CLOUD-DEPLOYMENT.md) for API reference, cloud hosting, and Fabric upgrade paths.
