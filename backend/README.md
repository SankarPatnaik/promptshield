# Backend (FastAPI)

Run locally (without Docker):
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -e .
cp .env.example .env   # then edit
uvicorn app.main:app --reload --port 8000
```

Docs: http://localhost:8000/docs
