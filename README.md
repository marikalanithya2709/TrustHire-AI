# TrustHire AI — Verify Before You Apply

**Preview (claude.ai, may require sign-in):** https://claude.ai/artifact/Prrm11pwjgv7mJf4jnkz2c
React + Vite frontend, Express backend, Supabase (Postgres + Auth). Rule-based explainable engine (always works) + optional Claude AI second opinion/assistant.

## Setup
1. Create a free project at supabase.com. SQL Editor → paste `database/schema.sql` → Run.
2. Auth → URL Configuration: add `http://localhost:5173` as Site URL / redirect.
3. Copy `.env.example` values into `backend/.env` and `frontend/.env` (keys from Project Settings → API; use the **anon** key only).
4. Backend: `cd backend && npm install && npm run dev`
5. Frontend (new terminal): `cd frontend && npm install && npm run dev` → open http://localhost:5173
6. Tests: `cd backend && npm test`

## Architecture
Frontend → Express API (verifies the user's JWT) → Supabase using the user's own token, so Postgres Row Level Security enforces per-user isolation. The server never fetches user URLs (no SSRF). Rate limits and 50 KB body limit are on.

## API
GET /api/health · POST /api/demo/analyze · POST /api/analyze · GET /api/analyses · GET/DELETE /api/analyses/:id · GET/POST /api/saved · DELETE /api/saved/:id · GET/PUT /api/profile · GET/POST /api/reports · POST /api/assistant

## Scoring
Weights live in `backend/src/engine.js` (`WEIGHTS`, `LEVELS`). Each rule counts once; max 100. 0–29 low, 30–59 moderate, 60–79 high, 80–100 critical.

## Known limitations
Not run end-to-end yet. Only the engine unit tests were executed. No company-registry verification; Google login, notifications UI, tailwind styling (plain CSS used), saved-list page and file upload are not implemented. Community reports need manual approval in Supabase (status='approved').

## Deploy
Backend: Render/Railway (set env vars, start `npm start`). Frontend: Vercel/Netlify (root `frontend`, build `npm run build`, set VITE_ vars incl. VITE_API_URL). Set FRONTEND_ORIGIN to the deployed frontend URL and add it in Supabase Auth URLs.

## GitHub
git init && git add . && git commit -m "TrustHire AI" && git branch -M main && git remote add origin https://github.com/USER/trusthire-ai.git && git push -u origin main
