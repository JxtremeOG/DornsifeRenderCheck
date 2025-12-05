import os
import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()

# Your Clerk instance's JWKS URL (from your publishable key domain)
# Extract the domain from pk_test_aW50ZW50LXdhbGxhYnktMTUuY2xlcmsuYWNjb3VudHMuZGV2JA
# Base64 decodes to: intent-wallaby-15.clerk.accounts.dev
CLERK_JWKS_URL = "https://intent-wallaby-15.clerk.accounts.dev/.well-known/jwks.json"

jwks_client = None

def get_jwks_client():
    global jwks_client
    if jwks_client is None:
        jwks_client = PyJWKClient(CLERK_JWKS_URL)
    return jwks_client

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
    
    token = auth_header.split(" ")[1]
    
    try:
        # Get the signing key from Clerk's JWKS endpoint
        signing_key = get_jwks_client().get_signing_key_from_jwt(token)
        
        # Verify and decode the JWT
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False}  # Clerk tokens don't always have aud
        )
        
        return {
            "message": "You are authenticated!",
            "status": "success",
            "user_id": payload.get("sub"),
            "session_id": payload.get("sid")
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
