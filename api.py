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
