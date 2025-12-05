import os
import jwt
from jwt import PyJWKClient
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

app = FastAPI()

SENDGRID_API_KEY = os.getenv("SENDGRID_SECRET_KEY")
SENDGRID_FROM_EMAIL = os.getenv("SENDGRID_FROM_EMAIL")

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


class EmailRequest(BaseModel):
    to_email: EmailStr
    subject: str
    content: str


def verify_clerk_token(request: Request):
    """Verify Clerk JWT token and return payload."""
    auth_header = request.headers.get("Authorization")
    
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = auth_header.split(" ")[1]
    
    try:
        signing_key = get_jwks_client().get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False}
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")


@app.post("/api/send-email")
def send_email(email_request: EmailRequest, request: Request):
    """Send an email using SendGrid. Requires Clerk authentication."""
    payload = verify_clerk_token(request)
    
    if not SENDGRID_API_KEY:
        raise HTTPException(status_code=500, detail="SendGrid API key not configured")
    if not SENDGRID_FROM_EMAIL:
        raise HTTPException(status_code=500, detail="SendGrid from email not configured")
    
    message = Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=email_request.to_email,
        subject=email_request.subject,
        plain_text_content=email_request.content
    )
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        return {
            "status": "success",
            "message": "Email sent",
            "status_code": response.status_code,
            "sent_by_user": payload.get("sub")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")
