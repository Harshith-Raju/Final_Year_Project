"""
Vercel Serverless Entrypoint for Privacy-Preserving AI Code Review Framework.
Handles both the web dashboard UI and /api/review endpoint on Vercel.
"""

import sys
import os

# Set sys.path so src imports work in Vercel serverless environment
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from src.pipeline import PrivacyPreservingReviewPipeline
from server import HTML_PAGE

app = FastAPI(title="Privacy-Preserving Code Reviewer")
pipeline = PrivacyPreservingReviewPipeline(llm_backend="mock")

@app.get("/")
def serve_ui():
    return HTMLResponse(content=HTML_PAGE, status_code=200)

@app.get("/health")
def health():
    return {"status": "running", "platform": "Vercel Serverless"}

@app.post("/api/review")
async def review_code(request: Request):
    payload = await request.json()
    code = payload.get("code", "")
    result = pipeline.process_code_review(raw_code=code)
    return JSONResponse(content=result)
