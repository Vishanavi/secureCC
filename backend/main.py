from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from shutil import which
from tempfile import TemporaryDirectory

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import compiler.analyzer as compiler_analyzer

analyze = compiler_analyzer.analyze
DB_PATH = Path(__file__).resolve().parent / "securecc.db"


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                content TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, filename),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )


def get_user_row(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, password FROM users WHERE username = ?",
        (username,),
    ).fetchone()


USERNAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,29}$")


def validate_username(username: str) -> str | None:
    value = username.strip()
    if not value:
        return "Username is required."
    if not value[0].isalpha():
        return "Username must start with a letter (not a number)."
    if not USERNAME_PATTERN.fullmatch(value):
        return "Use 3–30 characters: letters, numbers, and underscore only."
    return None


def validate_password(password: str) -> str | None:
    if len(password) < 6:
        return "Password must be at least 6 characters."
    if not re.search(r"[a-z]", password):
        return "Password must include at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return "Password must include at least one uppercase letter."
    if not re.search(r"\d", password):
        return "Password must include at least one number."
    if not re.search(r"[^a-zA-Z0-9]", password):
        return "Password must include at least one special symbol."
    return None


def format_compile_success_output(program_stdout_stderr: str, exit_code: int) -> str:
    text = (program_stdout_stderr or "").replace("\r\n", "\n").rstrip("\n")
    parts: list[str] = []
    if text:
        parts.append(text)
        parts.append("")
    parts.append("✔ Compilation successful")
    parts.append(f"Exit code: {exit_code}")
    return "\n".join(parts)


def resolve_gcc() -> str | None:
    gcc_on_path = which("gcc")
    if gcc_on_path:
        return gcc_on_path

    candidates = [
        Path("C:/msys64/mingw64/bin/gcc.exe"),
        Path("C:/MinGW/bin/gcc.exe"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None

app = FastAPI(title="SecureCC API")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.options("/{full_path:path}")
async def preflight_handler(full_path: str):
    return Response(status_code=200)

BUILD_DIR = PROJECT_ROOT / "frontend/build"
if (BUILD_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=str(BUILD_DIR / "static")), name="static")

class AnalyzeRequest(BaseModel):
    code: str


class AuthRequest(BaseModel):
    username: str
    password: str


class SaveFileRequest(BaseModel):
    username: str
    filename: str
    content: str = ""


class DeleteFileRequest(BaseModel):
    username: str
    filename: str


@app.on_event("startup")
def startup_event() -> None:
    init_db()


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/backend/ping", response_class=PlainTextResponse)
def backend_ping():
    return "Backend is running"


@app.post("/auth/signup")
def auth_signup(payload: AuthRequest):
    username = payload.username.strip()
    password = payload.password
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required.")

    username_error = validate_username(username)
    if username_error:
        raise HTTPException(status_code=400, detail=username_error)

    password_error = validate_password(password)
    if password_error:
        raise HTTPException(status_code=400, detail=password_error)

    with get_db_connection() as conn:
        existing = get_user_row(conn, username)
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists.")
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, password),
        )
        conn.commit()

    return {"ok": True, "message": "Signup successful."}


@app.post("/auth/login")
def auth_login(payload: AuthRequest):
    username = payload.username.strip()
    password = payload.password
    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required.")

    username_error = validate_username(username)
    if username_error:
        raise HTTPException(status_code=400, detail=username_error)

    with get_db_connection() as conn:
        user = get_user_row(conn, username)
        if not user or user["password"] != password:
            raise HTTPException(status_code=401, detail="Invalid username or password.")

    return {"ok": True, "username": username}


@app.get("/files")
def list_user_files(username: str):
    normalized_username = username.strip()
    if not normalized_username:
        raise HTTPException(status_code=400, detail="Username is required.")

    with get_db_connection() as conn:
        user = get_user_row(conn, normalized_username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        rows = conn.execute(
            """
            SELECT filename, content, updated_at
            FROM files
            WHERE user_id = ?
            ORDER BY filename COLLATE NOCASE ASC
            """,
            (user["id"],),
        ).fetchall()

    return {
        "files": [
            {"filename": row["filename"], "content": row["content"], "updated_at": row["updated_at"]}
            for row in rows
        ]
    }


@app.put("/files")
def save_user_file(payload: SaveFileRequest):
    username = payload.username.strip()
    filename = payload.filename.strip()
    if not username or not filename:
        raise HTTPException(status_code=400, detail="Username and filename are required.")

    with get_db_connection() as conn:
        user = get_user_row(conn, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        conn.execute(
            """
            INSERT INTO files (user_id, filename, content, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, filename) DO UPDATE SET
                content = excluded.content,
                updated_at = CURRENT_TIMESTAMP
            """,
            (user["id"], filename, payload.content),
        )
        conn.commit()

    return {"ok": True, "message": "File saved."}


@app.delete("/files")
def delete_user_file(payload: DeleteFileRequest):
    username = payload.username.strip()
    filename = payload.filename.strip()
    if not username or not filename:
        raise HTTPException(status_code=400, detail="Username and filename are required.")

    with get_db_connection() as conn:
        user = get_user_row(conn, username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        result = conn.execute(
            "DELETE FROM files WHERE user_id = ? AND filename = ?",
            (user["id"], filename),
        )
        conn.commit()

    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="File not found.")

    return {"ok": True, "message": "File deleted."}


@app.post("/compile")
@app.post("/api/compile")
def compile_code(payload: AnalyzeRequest):
    code = payload.code
    findings = analyze(code)


    high_risk = any(f["severity"] == "HIGH" for f in findings)

    if high_risk:
        return {
            "status": "blocked",
            "message": f"{len(findings)} vulnerabilities detected",
            "findings": findings,
        }

    gcc_executable = resolve_gcc()

    if not gcc_executable:
        return {
            "status": "error",
            "output": "GCC not installed. Install MinGW or GCC.",
        }

    with TemporaryDirectory(prefix="securecc_") as tmp_dir:
        tmp_path = Path(tmp_dir)
        src_path = tmp_path / "temp.c"
        binary_name = "temp.exe" if os.name == "nt" else "temp.out"
        binary_path = tmp_path / binary_name
        src_path.write_text(code, encoding="utf-8")

        try:
            result = subprocess.run(
                [gcc_executable, str(src_path), "-o", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError:
            return {
                "status": "error",
                "output": "GCC not installed. Install MinGW or GCC.",
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "output": "Compilation timed out.",
            }

        if result.returncode != 0:
            return {
                "status": "error",
                "output": result.stderr
            }

        try:
            run_result = subprocess.run(
                [str(binary_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "compiled",
                "output": (
                    "✔ Compilation successful\n"
                    "Exit code: (program did not finish - timed out, likely waiting for input or infinite loop)"
                ),
                "exit_code": None,
                "findings": findings,
            }
        except Exception as exc:
            return {
                "status": "compiled",
                "output": (
                    "✔ Compilation successful\n"
                    f"Exit code: (run failed - {exc})"
                ),
                "exit_code": None,
                "findings": findings,
            }

        combined = (run_result.stdout or "") + (run_result.stderr or "")
        exit_code = int(run_result.returncode)
        output = format_compile_success_output(combined, exit_code)

    return {
        "status": "compiled",
        "output": output,
        "exit_code": exit_code,
        "findings": findings,
    }


@app.get("/")
def read_root():
    index_path = BUILD_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"message": "SecureCC API is running. Build frontend to serve UI from here."}


@app.get("/{path:path}")
def serve_spa(path: str):
    file_path = BUILD_DIR / path
    if file_path.exists() and file_path.is_file():
        return FileResponse(str(file_path))
    
    index_path = BUILD_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
        
    return {"error": "Not Found", "detail": f"Path '{path}' not found and build directory is missing."}
