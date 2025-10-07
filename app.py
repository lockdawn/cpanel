from fastapi import FastAPI, Request, Form, BackgroundTasks, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import os, re, json, asyncio, shutil
from pathlib import Path

app = FastAPI()
templates = Jinja2Templates(directory="templates")

STEAMCMD = os.environ.get("STEAMCMD", "C:\\steamcmd\\steamcmd.exe")
WORKSHOP_APPID = "107410"
WORKSHOP_ROOT = Path(os.environ.get("WORKSHOP_ROOT", "C:\\steamcmd\\steamapps\\workshop\\content\\107410"))
MODS_DIR = Path(os.environ.get("MODS_DIR", "C:\\arma3mods"))

def sanitize_mod_folder(display_name: str) -> str:
    import re
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

async def steamcmd_download_mod(mod_id: str, display_name: str|None=None):
    cmd = f'"{STEAMCMD}" +login anonymous +workshop_download_item {WORKSHOP_APPID} {mod_id} validate +quit'
    proc = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    out, err = await proc.communicate()
    ok = (proc.returncode == 0)
    result = {"id": mod_id, "ok": ok}
    ws_mod = WORKSHOP_ROOT/mod_id
    if ws_mod.exists():
        target_name = sanitize_mod_folder(display_name) if display_name else f"@mod_{mod_id}"
        target = MODS_DIR/target_name
        try:
            if not target.exists():
                shutil.copytree(ws_mod, target)
            result["installed_path"] = str(target)
        except Exception as e:
            result["copy_error"] = str(e)
    return result

@app.get("/mods", response_class=HTMLResponse)
async def mods_page(request: Request):
    return templates.TemplateResponse("mods.html", {"request": request})

@app.post("/mods/download")
async def mods_download(request: Request, background_tasks: BackgroundTasks, ids_text: str = Form(...), names_json: str = Form("{}")):
    ids = [x.strip() for x in re.split(r"[\n\r,]+", ids_text) if x.strip()]
    try:
        name_map = json.loads(names_json)
    except:
        name_map = {}
    results = []
    for mid in ids:
        disp = name_map.get(mid)
        res = await steamcmd_download_mod(mid, disp)
        results.append(res)
    return {"results": results}
