"""
SecureNotes API  —  Week 14 Lab (SECURED + OOP ARCHITECTURE)
Web Systems and Technologies
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError

app = FastAPI(title="SecureNotes API (Week 14 — starter)", version="1.0")

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")
ALGORITHM = "HS256"
TOKEN_MINUTES = 30

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

oauth2 = OAuth2PasswordBearer(tokenUrl="login")

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- OOP Services & Domain Models ------------------------------------------
class PasswordManager:
    """Encapsulates password hashing and verification."""
    @staticmethod
    def hash(raw: str) -> str:
        return pwd.hash(raw)

    @staticmethod
    def verify(raw: str, hashed: str) -> bool:
        return pwd.verify(raw, hashed)


class TokenService:
    """Encapsulates JWT token generation and parsing."""
    @staticmethod
    def create(username: str, expires_delta: Optional[timedelta] = None) -> str:
        delta = expires_delta or timedelta(minutes=TOKEN_MINUTES)
        expire = datetime.now(timezone.utc) + delta
        to_encode = {"sub": username, "exp": expire}
        return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    @staticmethod
    def decode(token: str) -> Optional[str]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username is None:
                return None
            return username
        except JWTError:
            return None


# >>> TASK 1 — Hash passwords with bcrypt (A04 Cryptographic Failures)
# Replace these plaintext stubs so passwords are salted + hashed.
#   hash_password("alicepass")  should return a bcrypt hash
#   verify_password(raw, hashed) should return True/False safely
def hash_password(raw: str) -> str:
    return PasswordManager.hash(raw)

def verify_password(raw: str, hashed: str) -> bool:
    return PasswordManager.verify(raw, hashed)
# <<< END TASK 1


# >>> TASK 2 — Issue & verify a JWT (A07 Authentication Failures)
# The "token" is currently just the username. Make create_token return a signed
# JWT that carries the username in 'sub' and expires in TOKEN_MINUTES. Make
# read_token decode it and return the username, or None if bad/expired.
def create_token(username: str) -> str:
    return TokenService.create(username)

def read_token(token: str):
    return TokenService.decode(token)
# <<< END TASK 2


# --- database (in-memory SQLite, seeded on startup) -----------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.row_factory = sqlite3.Row

def init_db():
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL
        );
        """
    )
    db.execute("INSERT INTO users (username,password,is_admin) VALUES (?,?,1)", ("admin", hash_password("admin123")))
    db.execute("INSERT INTO users (username,password,is_admin) VALUES (?,?,0)", ("alice", hash_password("alicepass")))
    db.execute("INSERT INTO users (username,password,is_admin) VALUES (?,?,0)", ("bob", hash_password("bobpass")))
    db.execute("INSERT INTO notes (owner_id,title,body) VALUES (2,'Alice diary','Alice secret note')")
    db.execute("INSERT INTO notes (owner_id,title,body) VALUES (3,'Bob plans','Bob secret note')")
    db.commit()

def reset_database():
    db.execute("DROP TABLE IF EXISTS users")
    db.execute("DROP TABLE IF EXISTS notes")
    init_db()

init_db()


class Credentials(BaseModel):
    username: str
    password: str

class NewNote(BaseModel):
    title: str
    body: str


# >>> TASK 3 — Validate the token and FAIL CLOSED
# Right now a missing, forged, or expired token is NOT rejected (row can be None,
# and the route then misbehaves). Make this raise HTTPException(401) whenever the
# token is invalid OR the user doesn't exist. Only return a real user row.
def get_current_user(token: str = Depends(oauth2)):
    username = read_token(token)
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return row
# <<< END TASK 3


def require_admin(user=Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


@app.post("/register")
def register(creds: Credentials):
    existing = db.execute("SELECT id FROM users WHERE username = ?", (creds.username,)).fetchone()
    if existing:
        raise HTTPException(status_code=409, detail="Username already taken")
    db.execute(
        "INSERT INTO users (username,password,is_admin) VALUES (?,?,0)",
        (creds.username, hash_password(creds.password)),
    )
    db.commit()
    return {"message": f"user {creds.username} created"}

@app.post("/login")
def login(creds: Credentials):
    row = db.execute(
        "SELECT id, username, password FROM users WHERE username = ?", (creds.username,)
    ).fetchone()
    if row is None or not verify_password(creds.password, row["password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"access_token": create_token(row["username"]), "token_type": "bearer"}

@app.get("/notes")
def list_my_notes(user=Depends(get_current_user)):
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(get_current_user)):
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Note not found")
    # >>> TASK 4 — Ownership check (A01 Broken Access Control)
    # This note must belong to the caller. Add a check: if it isn't theirs,
    # raise HTTPException(403). Right now ANY user can read ANY note.
    if row["owner_id"] != user["id"] and not user["is_admin"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    # <<< END TASK 4
    return dict(row)

@app.post("/notes")
def create_note(note: NewNote, user=Depends(get_current_user)):
    cur = db.execute(
        "INSERT INTO notes (owner_id,title,body) VALUES (?,?,?)",
        (user["id"], note.title, note.body),
    )
    db.commit()
    return {"id": cur.lastrowid, "title": note.title}

@app.get("/admin/users")
def list_all_users(user=Depends(require_admin)):
    # >>> TASK 5 — Role check (A01 Broken Access Control)
    # Only admins may see this. Make it require the admin role (use require_admin),
    # and return ONLY id, username, is_admin — never the password column.
    rows = db.execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]
    # <<< END TASK 5

@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
