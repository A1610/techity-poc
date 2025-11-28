import os
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from supabase import create_client, Client
from jose import jwt as jose_jwt
from fastapi.security import HTTPBearer

# Load .env
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase_public: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# FastAPI app
app = FastAPI()

# JWT verification variables
bearer_scheme = HTTPBearer()
JWKS_URL = SUPABASE_URL.rstrip("/") + "/auth/v1/.well-known/jwks.json"
_jwks = None


# -------------------- JWT JWK Helper --------------------
def get_jwks():
    global _jwks
    if _jwks is None:
        resp = requests.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        _jwks = resp.json()
    return _jwks


# -------------------- Verify JWT ES256 --------------------
def verify_token(credentials=Depends(bearer_scheme)):
    token = credentials.credentials

    try:
        header = jose_jwt.get_unverified_header(token)
        kid = header.get("kid")

        jwks = get_jwks()
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)

        if not key:
            raise HTTPException(401, "JWK key not found")

        claims = jose_jwt.decode(
            token,
            key,
            algorithms=["ES256"],
            options={"verify_aud": False},
        )

        return claims

    except Exception as e:
        raise HTTPException(401, f"Invalid token: {str(e)}")


# -------------------- MODELS --------------------
class SignupBody(BaseModel):
    email: str
    password: str
    full_name: str
    phone: str


class SigninBody(BaseModel):
    email: str
    password: str


class Profile(BaseModel):
    full_name: str
    phone: str


# -------------------- ROUTES --------------------
@app.get("/")
def root():
    return {"message": "FastAPI + Supabase working!"}


# -------------------- SIGNUP --------------------
@app.post("/signup")
def signup_user(body: SignupBody):

    # Create user in Supabase Auth
    resp = requests.post(
        f"{SUPABASE_URL}/auth/v1/signup",
        headers={
            "apikey": SUPABASE_ANON_KEY,
            "Content-Type": "application/json"
        },
        json={"email": body.email, "password": body.password},
        timeout=10
    )

    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)

    data = resp.json()

    # Extract user id
    user_id = None
    if "user" in data and data["user"] and "id" in data["user"]:
        user_id = data["user"]["id"]
    elif "id" in data:
        user_id = data["id"]

    if not user_id:
        raise HTTPException(500, f"Could not extract user ID: {data}")

    # Insert into profiles
    insert_result = supabase_admin.table("profiles").upsert({
        "id": user_id,
        "full_name": body.full_name,
        "phone": body.phone
    }).execute()

    # FIX: Check for error properly
    error = insert_result.__dict__.get("error")
    if error:
        raise HTTPException(500, str(error))

    return {"status": "signup_success", "user_id": user_id}

# -------------------- SIGNIN --------------------
@app.post("/signin")
def signin_user(body: SigninBody):
    resp = requests.post(
        f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
        headers={
            "apikey": SUPABASE_ANON_KEY,
            "Content-Type": "application/json",
        },
        json={"email": body.email, "password": body.password},
        timeout=10,
    )

    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)

    data = resp.json()

    access_token = data.get("access_token") or (
        data.get("session") and data["session"].get("access_token")
    )
    refresh_token = data.get("refresh_token") or (
        data.get("session") and data["session"].get("refresh_token")
    )

    return {
        "status": "signin_success",
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@app.post("/profile")
def update_profile(body: Profile, user=Depends(verify_token)):
    user_id = user["sub"]

    result = (
        supabase_admin.table("profiles")
        .upsert(
            {
                "id": user_id,
                "full_name": body.full_name,
                "phone": body.phone
            },
            on_conflict="id"   # IMPORTANT FIX
        )
        .execute()
    )

    # check for errors
    error = result.__dict__.get("error")
    if error:
        raise HTTPException(500, str(error))

    return {"status": "success", "profile": result.data}




