"""
SecureNotes API  —  Week 13 Security Lab (SECURED & OOP REFACTORED)
Web Systems and Technologies

A secured notes service implementing OWASP Top 10 (2025) mitigations:
- Parameterized SQL queries (A05 Injection)
- Secure PBKDF2 salt + hash password storage (A04 Cryptographic Failures)
- Proper caller-ownership validation (A01 Broken Access Control)
- Cryptographically signed & expiring session tokens with generic auth errors (A07 Authentication Failures)
- Restrictive CORS configuration & secure generic 500 handler without stack leaks (A02 Security Misconfiguration)
- Fail-closed role checks on authorization exceptions (A10 Exceptional Conditions)
"""

import hmac
import hashlib
import json
import os
import secrets
import sqlite3
import time
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# --- Configuration ---------------------------------------------------------
class AppConfig:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "supersecret123_production_safe_key_98234")
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ]
    TOKEN_EXPIRATION_SECONDS: int = 3600  # 1 hour


config = AppConfig()

# --- app init --------------------------------------------------------------
app = FastAPI(title="SecureNotes API", version="1.0")

# Fix A02: Lock CORS to trusted origins, avoiding open '*' with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# --- Domain Models ---------------------------------------------------------
class User:
    def __init__(self, id: int, username: str, password_hash: str, is_admin: int):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_admin = bool(is_admin)

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "username": self.username,
            "is_admin": int(self.is_admin),
        }
        if include_sensitive:
            data["password"] = self.password_hash
        return data


class Note:
    def __init__(self, id: int, owner_id: int, title: str, body: str):
        self.id = id
        self.owner_id = owner_id
        self.title = title
        self.body = body

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "title": self.title,
            "body": self.body,
        }


# --- Security Service (OOP Auth & Crypto) -----------------------------------
class SecurityService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Fix A04: Hash password with PBKDF2-HMAC-SHA256 and a random salt."""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
        ).hex()
        return f"{salt}${pwd_hash}"

    @staticmethod
    def verify_password(stored_hash: str, provided_password: str) -> bool:
        """Fix A04: Verify password in constant-time using hmac.compare_digest."""
        try:
            salt, original_hash = stored_hash.split("$", 1)
            candidate_hash = hashlib.pbkdf2_hmac(
                "sha256", provided_password.encode("utf-8"), salt.encode("utf-8"), 100000
            ).hex()
            return hmac.compare_digest(original_hash, candidate_hash)
        except Exception:
            return False

    @staticmethod
    def create_token(user_id: int) -> str:
        """Fix A07: Create signed, expiring session token."""
        exp = int(time.time()) + config.TOKEN_EXPIRATION_SECONDS
        payload = f"{user_id}:{exp}"
        signature = hmac.new(
            config.SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return f"{payload}:{signature}"

    @staticmethod
    def verify_token(token: str) -> Optional[int]:
        """Fix A07: Verify signature and expiration, returning user_id or None."""
        try:
            parts = token.split(":")
            if len(parts) != 3:
                return None
            uid_str, exp_str, signature = parts
            payload = f"{uid_str}:{exp_str}"
            expected_sig = hmac.new(
                config.SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                return None
            if int(exp_str) < int(time.time()):
                return None
            return int(uid_str)
        except Exception:
            return None


# --- Database Repository (Data Access Object Pattern) -----------------------
class DatabaseRepository:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema_and_seed()

    def _init_schema_and_seed(self):
        self.conn.executescript(
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
        # Seed users using secure password hashes
        admin_hash = SecurityService.hash_password("admin123")
        alice_hash = SecurityService.hash_password("alicepass")
        bob_hash = SecurityService.hash_password("bobpass")

        self.conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)", ("admin", admin_hash))
        self.conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", ("alice", alice_hash))
        self.conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)", ("bob", bob_hash))

        self.conn.execute("INSERT INTO notes (owner_id, title, body) VALUES (2, 'Alice diary', 'Alice secret note')")
        self.conn.execute("INSERT INTO notes (owner_id, title, body) VALUES (3, 'Bob plans', 'Bob secret note')")
        self.conn.commit()

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        row = self.conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return None
        return User(id=row["id"], username=row["username"], password_hash=row["password"], is_admin=row["is_admin"])

    def get_user_by_username(self, username: str) -> Optional[User]:
        # Fix A05: Parameterized SQL query, preventing injection
        row = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return None
        return User(id=row["id"], username=row["username"], password_hash=row["password"], is_admin=row["is_admin"])

    def create_user(self, username: str, password_hash: str) -> User:
        cur = self.conn.execute(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)",
            (username, password_hash),
        )
        self.conn.commit()
        return User(id=cur.lastrowid, username=username, password_hash=password_hash, is_admin=0)

    def list_users(self) -> List[User]:
        rows = self.conn.execute("SELECT * FROM users").fetchall()
        return [
            User(id=r["id"], username=r["username"], password_hash=r["password"], is_admin=r["is_admin"])
            for r in rows
        ]

    def get_notes_by_owner(self, owner_id: int) -> List[Note]:
        rows = self.conn.execute("SELECT * FROM notes WHERE owner_id = ?", (owner_id,)).fetchall()
        return [Note(id=r["id"], owner_id=r["owner_id"], title=r["title"], body=r["body"]) for r in rows]

    def get_note_by_id(self, note_id: int) -> Optional[Note]:
        row = self.conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        if not row:
            return None
        return Note(id=row["id"], owner_id=row["owner_id"], title=row["title"], body=row["body"])

    def create_note(self, owner_id: int, title: str, body: str) -> Note:
        cur = self.conn.execute(
            "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
            (owner_id, title, body),
        )
        self.conn.commit()
        return Note(id=cur.lastrowid, owner_id=owner_id, title=title, body=body)


# Instantiate repository & service
repo = DatabaseRepository()
db = repo.conn  # Retain backward-compatible db attribute if referenced


# --- Request Models --------------------------------------------------------
class Credentials(BaseModel):
    username: str
    password: str


class NewNote(BaseModel):
    title: str
    body: str


# --- Auth Dependency -------------------------------------------------------
def current_user(authorization: str = Header(default=None)) -> User:
    """Validate token and return current User object. Fails closed with 401."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
        )
    token = authorization.replace("Bearer ", "").strip()
    user_id = SecurityService.verify_token(token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    user = repo.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )
    return user


# --- Global Error Handler (Fix A02: Stop leaking stack traces) -------------
@app.exception_handler(Exception)
async def handle_everything(request, exc):
    if isinstance(exc, HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "An internal server error occurred."},
    )


# --- Routes ----------------------------------------------------------------
@app.post("/register", status_code=status.HTTP_201_CREATED)
def register(creds: Credentials):
    # Fix A04: Hash password before saving
    existing = repo.get_user_by_username(creds.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = SecurityService.hash_password(creds.password)
    repo.create_user(creds.username, password_hash)
    return {"message": f"user {creds.username} created"}


@app.post("/login")
def login(creds: Credentials):
    # Fix A05: Parameterized query via repo.get_user_by_username
    # Fix A07: Generic error prevents account enumeration, timing safe verification
    user = repo.get_user_by_username(creds.username)
    if user is None or not SecurityService.verify_password(user.password_hash, creds.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    token = SecurityService.create_token(user.id)
    return {"token": token}


@app.get("/notes")
def list_my_notes(authorization: str = Header(default=None)):
    user = current_user(authorization)
    notes = repo.get_notes_by_owner(user.id)
    return [n.to_dict() for n in notes]


@app.get("/notes/{note_id}")
def get_note(note_id: int, authorization: str = Header(default=None)):
    user = current_user(authorization)
    note = repo.get_note_by_id(note_id)
    if note is None:
        raise HTTPException(status_code=404, detail="Note not found")
    # Fix A01: Broken Access Control - caller must own the note
    if note.owner_id != user.id and not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return note.to_dict()


@app.post("/notes", status_code=status.HTTP_201_CREATED)
def create_note(note: NewNote, authorization: str = Header(default=None)):
    user = current_user(authorization)
    created = repo.create_note(user.id, note.title, note.body)
    return {"id": created.id, "title": created.title}


@app.get("/admin/users")
def list_all_users(authorization: str = Header(default=None)):
    user = current_user(authorization)
    # Fix A10: Exceptional Conditions - Fail closed! Deny access if condition not met or exception occurs
    try:
        if not user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admins only")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Authorization verification failed")

    users = repo.list_users()
    # Ensure sensitive credentials like passwords are not leaked
    return [u.to_dict(include_sensitive=False) for u in users]


@app.get("/")
def home():
    return {"service": "SecureNotes API", "docs": "/docs"}
