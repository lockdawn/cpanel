from fastapi import FastAPI, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext
from datetime import datetime, timezone
from contextlib import suppress
import os
import re
import json
import asyncio
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Iterable

try:  # pragma: no cover - psutil is optional at runtime
    import psutil  # type: ignore
except ModuleNotFoundError:  # pragma: no cover - provide graceful fallback when psutil is missing
    psutil = None  # type: ignore

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


def format_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    number = float(value)
    for unit in units:
        if abs(number) < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(number)} {unit}"
            return f"{number:.2f} {unit}"
        number /= 1024


def format_duration(seconds: float | None) -> str | None:
    if seconds is None:
        return None
    total_seconds = int(seconds)
    if total_seconds <= 0:
        return "0s"
    minutes, sec = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if sec and len(parts) < 3:
        parts.append(f"{sec}s")
    return " ".join(parts) if parts else "0s"


def _matches_process(info: dict, candidates: Iterable[str]) -> bool:
    name = (info.get("name") or "").lower()
    cmdline = " ".join(info.get("cmdline") or ()).lower()
    for candidate in candidates:
        normalized = candidate.lower()
        if name == normalized:
            return True
        if normalized in cmdline:
            return True
        if normalized in name:
            return True
    return False


def _parse_ps_etime(etime: str) -> float:
    days = 0
    if "-" in etime:
        day_part, time_part = etime.split("-", 1)
        with suppress(ValueError):
            days = int(day_part)
    else:
        time_part = etime
    parts = time_part.split(":")
    parts = [int(p) for p in parts]
    while len(parts) < 3:
        parts.insert(0, 0)
    hours, minutes, seconds = parts[-3:]
    total_seconds = seconds + minutes * 60 + hours * 3600 + days * 86400
    return float(total_seconds)


def _collect_service_metrics_ps(candidates: Iterable[str]) -> dict:
    try:
        result = subprocess.run(
            ["ps", "-eo", "pid,comm,pcpu,rss,etime,args"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return {
            "online": False,
            "process_count": 0,
            "total_cpu_percent": 0.0,
            "total_memory_human": "N/D",
            "uptime_human": None,
            "processes": [],
        }

    processes: list[dict] = []
    total_cpu = 0.0
    total_memory = 0
    longest_uptime = 0.0
    for line in result.stdout.strip().splitlines()[1:]:
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        pid_str, comm, pcpu_str, rss_str, etime_str, args = parts
        merged_name = f"{comm} {args}".lower()
        if not any(candidate.lower() in merged_name for candidate in candidates):
            continue
        try:
            pid = int(pid_str)
            cpu_percent = float(pcpu_str)
            memory_kb = int(rss_str)
            uptime_seconds = _parse_ps_etime(etime_str)
        except ValueError:
            continue
        total_cpu += cpu_percent
        total_memory += memory_kb * 1024
        if uptime_seconds > longest_uptime:
            longest_uptime = uptime_seconds
        processes.append(
            {
                "pid": pid,
                "name": comm,
                "status": "",
                "cpu_percent": round(cpu_percent, 2),
                "memory_human": format_bytes(memory_kb * 1024),
                "uptime_human": format_duration(uptime_seconds),
            }
        )

    return {
        "online": bool(processes),
        "process_count": len(processes),
        "total_cpu_percent": round(total_cpu, 2),
        "total_memory_human": format_bytes(total_memory) if processes else "N/D",
        "uptime_human": format_duration(longest_uptime) if processes else None,
        "processes": sorted(processes, key=lambda p: p.get("pid") or 0),
    }


def collect_service_metrics(candidates: Iterable[str]) -> dict:
    if psutil is None:
        return _collect_service_metrics_ps(candidates)
    now = datetime.now(timezone.utc)
    processes: list[dict] = []
    total_cpu = 0.0
    total_memory = 0
    earliest_start: float | None = None
    for proc in psutil.process_iter(["pid", "name", "cmdline", "status", "create_time"]):
        try:
            if not _matches_process(proc.info, candidates):
                continue
            cpu_percent = proc.cpu_percent(interval=0.0)
            memory_info = proc.memory_info()
            create_time = proc.info.get("create_time") or proc.create_time()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        uptime_seconds = max(0.0, now.timestamp() - create_time)
        total_cpu += cpu_percent
        total_memory += memory_info.rss
        if earliest_start is None or create_time < earliest_start:
            earliest_start = create_time
        processes.append(
            {
                "pid": proc.info.get("pid"),
                "name": proc.info.get("name") or "",
                "status": proc.info.get("status") or "",
                "cpu_percent": round(cpu_percent, 2),
                "memory_human": format_bytes(memory_info.rss),
                "uptime_human": format_duration(uptime_seconds),
            }
        )
    return {
        "online": bool(processes),
        "process_count": len(processes),
        "total_cpu_percent": round(total_cpu, 2),
        "total_memory_human": format_bytes(total_memory) if processes else "0 B",
        "uptime_human": format_duration(now.timestamp() - earliest_start) if earliest_start else None,
        "processes": sorted(processes, key=lambda p: p.get("pid") or 0),
    }


def _drive_letter(part) -> str | None:
    device = part.device or ""
    if os.name == "nt" and len(device) >= 2 and device[1] == ":":
        return device[0].upper()
    return None


def _fallback_cpu_percent() -> float | None:
    try:
        load1, _, _ = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        percent = (load1 / cpu_count) * 100
        return round(max(0.0, percent), 2)
    except (AttributeError, OSError):
        return None


def _fallback_memory_stats() -> dict[str, float | str]:
    meminfo: dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                parts = value.strip().split()
                if not parts:
                    continue
                with suppress(ValueError):
                    meminfo[key.strip()] = int(parts[0])
    except FileNotFoundError:
        return {}

    total_kb = meminfo.get("MemTotal")
    available_kb = meminfo.get("MemAvailable")
    if not total_kb or available_kb is None:
        return {}
    used_kb = total_kb - available_kb
    percent = (used_kb / total_kb) * 100
    return {
        "memory_percent": round(percent, 2),
        "memory_used_human": format_bytes(used_kb * 1024),
        "memory_total_human": format_bytes(total_kb * 1024),
    }


def _fallback_disks() -> list[dict]:
    disks: list[dict] = [
        {"label": "Unidad C", "missing": True},
        {"label": "Unidad D", "missing": True},
    ]
    root_path = os.path.abspath(os.sep)
    with suppress(OSError):
        usage = shutil.disk_usage(root_path)
        disks.append(
            {
                "label": root_path,
                "free_human": format_bytes(usage.free),
                "total_human": format_bytes(usage.total),
                "percent": round((usage.used / usage.total) * 100, 1) if usage.total else 0.0,
            }
        )
    return disks


def collect_instance_metrics() -> dict:
    if psutil is None:
        cpu_percent = _fallback_cpu_percent()
        memory_stats = _fallback_memory_stats()
        disks = _fallback_disks()
        return {
            "cpu_percent": cpu_percent if cpu_percent is not None else 0.0,
            "memory_percent": memory_stats.get("memory_percent", 0.0),
            "memory_used_human": memory_stats.get("memory_used_human", "N/D"),
            "memory_total_human": memory_stats.get("memory_total_human", "N/D"),
            "disks": disks,
        }

    cpu_percent = psutil.cpu_percent(interval=0.1)
    virtual_memory = psutil.virtual_memory()
    disks: list[dict] = []
    partitions = psutil.disk_partitions(all=False)
    letter_map = {}
    for part in partitions:
        letter = _drive_letter(part)
        if letter and letter not in letter_map:
            letter_map[letter] = part

    def add_disk(part, label: str) -> None:
        with suppress(OSError):
            usage = psutil.disk_usage(part.mountpoint)
            disks.append(
                {
                    "label": label,
                    "free_human": format_bytes(usage.free),
                    "total_human": format_bytes(usage.total),
                    "percent": round(usage.percent, 1),
                }
            )

    for letter in ("C", "D"):
        part = letter_map.get(letter)
        if part:
            add_disk(part, f"Unidad {letter}")
        else:
            disks.append({"label": f"Unidad {letter}", "missing": True})

    for part in partitions:
        letter = _drive_letter(part)
        if letter in {"C", "D"}:
            continue
        label = part.device or part.mountpoint
        if any(d.get("label") == label for d in disks):
            continue
        add_disk(part, label)

    return {
        "cpu_percent": round(cpu_percent, 2),
        "memory_percent": round(virtual_memory.percent, 2),
        "memory_used_human": format_bytes(virtual_memory.used),
        "memory_total_human": format_bytes(virtual_memory.total),
        "disks": disks,
    }


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
    teamspeak_metrics = collect_service_metrics(["ts3server", "ts3server.exe"])
    arma3_metrics = collect_service_metrics(["arma3server", "arma3server_x64", "arma3server.exe"])
    instance_metrics = collect_instance_metrics()
    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "user": user,
            "teamspeak": teamspeak_metrics,
            "arma3": arma3_metrics,
            "instance": instance_metrics,
        },
    )


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
