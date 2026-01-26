from fastapi import FastAPI, Header, HTTPException, BackgroundTasks
from schemas import IncomingRequest, AgentResponse
import service
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="Honeypot Agent API")

MY_SECRET_KEY = os.getenv("SCAMMER_API_KEY")

@app.get("/")
def health_check():
    """Simple check to see if server is running."""
    return {"status": "alive", "service": "Honeypot Agent"}

@app.post("/webhook", response_model=AgentResponse)
async def handle_incoming_message(
    payload: IncomingRequest, 
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(None)
):
    # 1. Security Check
    if x_api_key != MY_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")

    try:
        # 2. Logic Processing
        agent_response, callback_payload = await service.process_incoming_message(payload)

        # 3. Background Task
        if callback_payload:
            background_tasks.add_task(service.send_callback_background, callback_payload)

        return agent_response

    except Exception as e:
        # PRODUCTION LOGGING
        print(f" CRITICAL SERVER ERROR: {str(e)}")
        
        # Return a 503 (Service Unavailable) or 500 (Internal Error)
        # This tells the caller: "My logic is broken" or "Upstream AI is down"
        raise HTTPException(
            status_code=503, 
            detail=f"AI Service Failure: {str(e)}"
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

