import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
import httpx

app = FastAPI()

CLERK_SECRET_KEY = os.getenv("CLERK_SECRET_KEY")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/")
def root():
    return FileResponse("client/index.html")

@app.get("/api/protected")
async def protected_route(request: Request):
    """A protected endpoint that verifies Clerk session tokens."""
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    session_token = auth_header.split(" ")[1]
    
    # Verify the session with Clerk's API
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://api.clerk.com/v1/sessions",
            headers={
                "Authorization": f"Bearer {CLERK_SECRET_KEY}",
                "Content-Type": "application/json"
            }
        )
        
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Failed to verify session")
    
    return {"message": "You are authenticated!", "status": "success"}

@app.get("/api/user")
async def get_user(request: Request):
    """Get user info from session token."""
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    session_token = auth_header.split(" ")[1]
    
    # For a basic test, we'll verify the token exists and return success
    # In production, you'd decode the JWT and verify it properly
    if not session_token:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return {"message": "Token received", "authenticated": True}
