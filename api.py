import os
import sys

# Add src folder to Python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")

if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from fastapi import FastAPI
from pydantic import BaseModel
from crew import check_message

app = FastAPI(title="CyberGuard AI API")


class MessageRequest(BaseModel):
    message: str


@app.get("/")
def home():
    return {"status": "CyberGuard AI API is running"}


@app.post("/analyze")
def analyze(request: MessageRequest):
    return check_message(message=request.message)
