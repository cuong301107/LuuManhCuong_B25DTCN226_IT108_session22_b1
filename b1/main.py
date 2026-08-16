from datetime import datetime, timedelta, timezone
import os
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError
from dotenv import load_dotenv
import bcrypt

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
ALGORITHM = "HS256"

app = FastAPI()

class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"



fake_users_db = {
    "alice": bcrypt.hashpw("alice123".encode(), bcrypt.gensalt()),
    "bob": bcrypt.hashpw("bob456".encode(), bcrypt.gensalt()),
    "charlie": bcrypt.hashpw("charlie789".encode(), bcrypt.gensalt())
}


def hash_password(p):
    return bcrypt.hashpw(p.encode(), bcrypt.gensalt())

def verify_password(p, h):
    return bcrypt.checkpw(p.encode(), h)

def create_access_token(username):
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": username, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

bearer = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    token = credentials.credentials
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    username = payload.get("sub")
    if username not in fake_users_db:
        raise HTTPException(status_code=401, detail="Invalid token user")
    return username




@app.post("/api/register", status_code=201)
def register(data: RegisterRequest):
    u = data.username.strip()
    p = data.password
    if u in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    fake_users_db[u] = hash_password(p)
    return {"message": "User registered successfully"}

@app.post("/api/login", response_model=TokenResponse)
def login(data: LoginRequest):
    u = data.username.strip()
    p = data.password
    h = fake_users_db.get(u)
    if not h or not verify_password(p, h):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return TokenResponse(access_token=create_access_token(u))

@app.get("/api/profile")
def profile(current_user: str = Depends(get_current_user)):
    return {"message": f"Welcome, {current_user}!"}
