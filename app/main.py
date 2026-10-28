from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.webhook import router

app = FastAPI(title="Phishing Monitor", version="0.1.0")
app.include_router(router)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


app.mount("/", StaticFiles(directory=Path(__file__).resolve().parent.parent / "public", html=True), name="public")