from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
import os
import re
import json
import asyncio
import shutil
import sqlite3
from pathlib import Path

app = FastAPI()
templates = Jinja2Templates(directory="templates")

app.mount("/static", StaticFiles(directory="static"), name="static")

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("SESSION_SECRET", "change-me-please"),
    session_cookie="cpanel_session",
)

STEAMCMD = os.environ.get("STEAMCMD", "C:\\steamcmd\\steamcmd.exe")
WORKSHOP_APPID = "107410"
WORKSHOP_ROOT = Path(os.environ.get("WORKSHOP_ROOT", "C:\\steamcmd\\steamapps\\workshop\\content\\107410"))
MODS_DIR = Path(os.environ.get("MODS_DIR", "C:\\arma3mods"))
DB_PATH = Path(os.environ.get("PANEL_DB", "panel.db"))

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
USERNAME_REGEX = re.compile(r"^[A-Za-z]{1,10}$")
DEFAULT_ADMIN_USER = os.environ.get("DEFAULT_ADMIN_USER", "Comando")
DEFAULT_ADMIN_PASSWORD = os.environ.get("DEFAULT_ADMIN_PASSWORD", "Operativo#2024")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_default_user() -> None:
    """Ensure the panel has at least one operator credential configured."""
    with get_db_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        user = conn.execute(
            "SELECT id FROM users WHERE username = ?",
            (DEFAULT_ADMIN_USER,),
        ).fetchone()
        if user is None:
            password_hash = pwd_context.hash(DEFAULT_ADMIN_PASSWORD)
            conn.execute(
                "INSERT INTO users (username, password_hash, is_active) VALUES (?, ?, 1)",
                (DEFAULT_ADMIN_USER, password_hash),
            )


@app.on_event("startup")
def startup_event() -> None:
    ensure_default_user()


def sanitize_mod_folder(display_name: str) -> str | None:
    if not display_name:
        return None
    name = display_name.strip()
    name = re.sub(r"\s+", "_", name)
    name = re.sub(r"[^A-Za-z0-9_\-]", "", name)
    if not name:
        return None
    if not name.startswith("@"):
        name = "@" + name
    return name


async def steamcmd_download_mod(mod_id: str, display_name: str | None = None):
    cmd = f'"{STEAMCMD}" +login anonymous +workshop_download_item {WORKSHOP_APPID} {mod_id} validate +quit'
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    out, err = await proc.communicate()
    ok = proc.returncode == 0
    result = {"id": mod_id, "ok": ok}
    ws_mod = WORKSHOP_ROOT / mod_id
    if ws_mod.exists():
        target_name = sanitize_mod_folder(display_name) if display_name else f"@mod_{mod_id}"
        target = MODS_DIR / target_name
        try:
            if not target.exists():
                shutil.copytree(ws_mod, target)
            result["installed_path"] = str(target)
        except Exception as e:  # pragma: no cover - filesystem errors logged for diagnostics
            result["copy_error"] = str(e)
    return result


def authenticated_user(request: Request):
    user_id = request.session.get("user_id")
    username = request.session.get("username")
    if not user_id or not username:
        return None
    return {"id": user_id, "username": username}


def redirect_to_login() -> RedirectResponse:
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", include_in_schema=False)
async def root_redirect(request: Request):
    if authenticated_user(request):
        return RedirectResponse(url="/home", status_code=status.HTTP_303_SEE_OTHER)
    return redirect_to_login()


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if authenticated_user(request):
        return RedirectResponse(url="/home", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    if not USERNAME_REGEX.fullmatch(username):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Usuario inválido. Usa solo letras (máx. 10)."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, is_active FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    verified = False
    if row and row["is_active"]:
        try:
            verified = pwd_context.verify(password, row["password_hash"])
        except ValueError:
            verified = False

    if not row or not verified:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Credenciales no válidas."},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    request.session["user_id"] = row["id"]
    request.session["username"] = row["username"]
    return RedirectResponse(url="/home", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout", include_in_schema=False)
async def logout(request: Request):
    request.session.clear()
    return redirect_to_login()


@app.get("/home", response_class=HTMLResponse)
async def home_page(request: Request):
    user = authenticated_user(request)
    if not user:
        return redirect_to_login()
    return templates.TemplateResponse("home.html", {"request": request, "user": user})


@app.get("/mods", response_class=HTMLResponse)
async def mods_page(request: Request):
    user = authenticated_user(request)
    if not user:
        return redirect_to_login()
    return templates.TemplateResponse("mods.html", {"request": request, "user": user})


@app.post("/mods/download")
async def mods_download(
    request: Request,
    ids_text: str = Form(...),
    names_json: str = Form("{}"),
):
    if not authenticated_user(request):
        return redirect_to_login()
    ids = [x.strip() for x in re.split(r"[\n\r,]+", ids_text) if x.strip()]
    try:
        name_map = json.loads(names_json)
    except Exception:  # pragma: no cover - fallback for malformed payloads
        name_map = {}
    results = []
    for mid in ids:
        disp = name_map.get(mid)
        res = await steamcmd_download_mod(mid, disp)
        results.append(res)
    return {"results": results}
