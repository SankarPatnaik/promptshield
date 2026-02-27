# PromptShield 🛡️
A production-ready starter repo for validating prompts (prompt injection detection + mitigation) and **gating** all prompts through **Lakera Guard** before sending them to an LLM.

## What you get
- **Backend**: FastAPI service with:
  - `/validate` endpoint for prompt validation + mitigation
  - Built-in injection heuristics + safe rewrite template
  - **Lakera Guard** integration using `/v2/guard`
- **Frontend**: Next.js UI to paste prompts, run validation, and copy the safe prompt
- **Docker Compose** for local one-command run

> Note: You need a Lakera API key + project id. Set them in `backend/.env` and `frontend/.env.local`.

---

## Quickstart (Docker)
1. Copy env templates:
   - `cp backend/.env.example backend/.env`
   - `cp frontend/.env.local.example frontend/.env.local`
2. Fill in Lakera variables.
3. Run:
```bash
docker compose up --build
```

Open:
- Frontend: http://localhost:3000
- Backend docs: http://localhost:8000/docs

---

## License
MIT
