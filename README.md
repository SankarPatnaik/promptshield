# PromptShield 🛡️
A production-ready starter repo for validating prompts (prompt injection detection + mitigation) and gating all prompts through a **local security shield engine** before sending them to an LLM.

## What you get
- **Backend**: FastAPI service with:
  - `/validate` endpoint for prompt validation + mitigation
  - Built-in prompt-injection heuristics and safe rewrite template
  - Local scoring model with risk breakdown and confidence (no external API key required)
- **Frontend**: Next.js UI to paste prompts, run validation, and copy the safe prompt
- **Docker Compose** for local one-command run

---

## Quickstart (Docker)
1. Copy env templates:
   - `cp backend/.env.example backend/.env`
   - `cp frontend/.env.local.example frontend/.env.local`
2. Run:
```bash
docker compose up --build
```

Open:
- Frontend: http://localhost:3000
- Backend docs: http://localhost:8000/docs

---

## License
MIT
