#!/usr/bin/env python3
"""Kleine Firewall fuer Windows - fragt nach, bevor ein Programm ins Netz darf.

Nutzt nur Bordmittel von Windows (Windows-Firewall + deren Protokoll) und die
Python-Standardbibliothek. Die Oberflaeche ist eine Seite im Browser, die nur
auf diesem Rechner erreichbar ist.

Start:        Doppelklick oder  python kleinefirewall_windows.py
Ansehen:      python kleinefirewall_windows.py --demo      (veraendert nichts)
Rueckgaengig: python kleinefirewall_windows.py --zuruecksetzen
"""
import argparse
import ctypes
import hashlib
import json
import ntpath
import os
import platform
import secrets
import string
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP = "KleineFirewall"
PORT = 47615
TASK = "KleineFirewall"
# Windows-Protokollkategorie "Filterplattformverbindung" (sprachunabhaengige Kennung)
AUDIT_GUID = "{0CCE9226-69AE-11D9-BED3-505054503030}"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
MODES = ("ask", "quiet", "allow")


class SysError(Exception):
    pass


def rule_name(path):
    return f"{APP} {hashlib.sha1(path.lower().encode('utf-8')).hexdigest()[:10]}"


def nice_name(path):
    base = ntpath.basename(path) or path
    return base[:-4] if base.lower().endswith(".exe") else base


def parse_events(text):
    """Text von 'wevtutil ... /f:xml' -> (hoechste Datensatznummer, Ereignisse)."""
    try:
        root = ET.fromstring("<r>" + text + "</r>")
    except ET.ParseError:
        return 0, []
    top, events = 0, []
    for ev in root.iter(NS + "Event"):
        try:
            top = max(top, int(ev.findtext(f"{NS}System/{NS}EventRecordID") or 0))
        except ValueError:
            pass
        d = {x.get("Name"): (x.text or "").strip() for x in ev.iter(NS + "Data")}
        if not d.get("Application"):
            continue
        inbound = d.get("Direction") == "%%14592"
        events.append({
            "app": d["Application"],
            "dir": "in" if inbound else "out",
            "addr": d.get("SourceAddress" if inbound else "DestAddress", ""),
            "port": d.get("DestPort", ""),
            "proto": {"6": "TCP", "17": "UDP"}.get(d.get("Protocol", ""), ""),
        })
    return top, events


# ---------------------------------------------------------------- Windows

class WinSystem:
    demo = False

    def __init__(self, state_dir):
        self.state_dir = state_dir
        self.last_record = None
        self.devices = {}

    def cmd(self, args, check=True):
        try:
            p = subprocess.run(args, capture_output=True, creationflags=NOWIN, timeout=60)
        except (OSError, subprocess.SubprocessError) as e:
            raise SysError(f"{args[0]} konnte nicht ausgefuehrt werden: {e}")
        if check and p.returncode != 0:
            out = (p.stdout or p.stderr).decode("oem", "replace").strip()
            raise SysError(f"Windows meldet einen Fehler bei '{' '.join(args[:4])} ...':\n{out}")
        return p.returncode, p.stdout

    # -- Einrichtung
    def protect_folder(self):
        # Ordner nur fuer Administratoren und System lesbar (enthaelt den Zugangsschluessel)
        self.cmd(["icacls", str(self.state_dir), "/inheritance:r", "/grant:r",
                  "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], check=False)

    def setup(self):
        backup = self.state_dir / "windows-firewall-vorher.wfw"
        if not backup.exists():
            self.cmd(["netsh", "advfirewall", "export", str(backup)], check=False)
        self.cmd(["netsh", "advfirewall", "set", "allprofiles", "state", "on"])
        self.enable_log()

    def enable_log(self):
        self.cmd(["auditpol", "/set", f"/subcategory:{AUDIT_GUID}", "/failure:enable"])

    def set_policy(self, block_out):
        policy = "blockinbound,blockoutbound" if block_out else "blockinbound,allowoutbound"
        self.cmd(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", policy])

    # -- Regeln
    def add_rule(self, path, action, dirs):
        self.delete_rule(path)
        for d in dirs:
            self.cmd(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name(path)}",
                      f"dir={d}", f"action={action}", f"program={path}", "enable=yes", "profile=any"])

    def delete_rule(self, path):
        self.cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name(path)}"], check=False)

    def svchost(self):
        return ntpath.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "svchost.exe")

    # -- Protokoll der blockierten Verbindungen
    def _load_devices(self):
        self.devices = {}
        buf = ctypes.create_unicode_buffer(1024)
        for letter in string.ascii_uppercase:
            if ctypes.windll.kernel32.QueryDosDeviceW(letter + ":", buf, 1024):
                self.devices[buf.value.lower()] = letter + ":"

    def _to_path(self, dev):
        low = dev.lower()
        for attempt in (0, 1):
            for device, letter in self.devices.items():
                if low.startswith(device + "\\"):
                    path = letter + dev[len(device):]
                    try:
                        return os.path.realpath(path) if os.path.exists(path) else path
                    except OSError:
                        return path
            if attempt == 0 and low.startswith("\\device\\"):
                self._load_devices()  # z. B. neu eingesteckter Datentraeger
        return dev

    def _query(self, query, count, newest_first=True):
        args = ["wevtutil", "qe", "Security", f"/q:{query}", "/f:xml", f"/c:{count}"]
        if newest_first:
            args.append("/rd:true")
        return self.cmd(args, check=False)[1]

    def read_events(self):
        if self.last_record is None:  # nur Neues ab jetzt beachten
            raw = self._query("*[System[(EventID=5157)]]", 1)
            self.last_record = parse_events(raw.decode("utf-8", "replace"))[0]
            return []
        raw = self._query(f"*[System[(EventID=5157) and (EventRecordID>{self.last_record})]]", 400)
        if not raw.strip():
            return []
        best = None
        for enc in ("utf-8", "oem", "mbcs"):  # Zeichensatz mit den meisten auffindbaren Pfaden gewinnt
            try:
                top, events = parse_events(raw.decode(enc))
            except (UnicodeDecodeError, LookupError):
                continue
            for e in events:
                e["path"] = self._to_path(e.pop("app"))
            missing = sum(1 for e in events if ":" in e["path"] and not os.path.exists(e["path"]))
            if best is None or missing < best[0]:
                best = (missing, top, events)
            if missing == 0:
                break
        if best is None:
            return []
        self.last_record = max(self.last_record, best[1])
        return list(reversed(best[2]))  # aelteste zuerst

    # -- Autostart
    def autostart(self):
        return self.cmd(["schtasks", "/query", "/tn", TASK], check=False)[0] == 0

    def set_autostart(self, on):
        if not on:
            self.cmd(["schtasks", "/delete", "/tn", TASK, "/f"], check=False)
            return
        exe = Path(sys.executable)
        quiet = exe.with_name("pythonw.exe")
        runner = quiet if quiet.exists() else exe
        target = f'"{runner}" "{os.path.abspath(__file__)}" --hintergrund'
        if getattr(sys, "frozen", False):  # als EXE gebaut
            target = f'"{sys.executable}" --hintergrund'
        self.cmd(["schtasks", "/create", "/tn", TASK, "/tr", target, "/sc", "onlogon", "/rl", "highest", "/f"])

    def reset(self, paths):
        for path in paths:
            self.delete_rule(path)
        self.cmd(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy",
                  "blockinbound,allowoutbound"], check=False)
        self.cmd(["auditpol", "/set", f"/subcategory:{AUDIT_GUID}", "/failure:disable"], check=False)
        self.set_autostart(False)


class DemoSystem:
    """Tut nur so - zum gefahrlosen Ansehen der Oberflaeche auf jedem Rechner."""
    demo = True
    SCRIPT = [
        (2, r"C:\Program Files\Mozilla Firefox\firefox.exe", "out", "34.107.221.82", "443", "TCP"),
        (4, r"C:\Users\Du\AppData\Roaming\Spotify\Spotify.exe", "out", "35.186.224.25", "443", "TCP"),
        (9, r"C:\Program Files\Notizen Plus\updater.exe", "out", "185.199.108.153", "80", "TCP"),
        (15, r"C:\Program Files\Medienserver\medienserver.exe", "in", "192.168.1.23", "32400", "TCP"),
    ]

    def __init__(self, state_dir):
        self.start = time.time()
        self.sent = 0
        self._auto = False

    def protect_folder(self): pass
    def setup(self): pass
    def enable_log(self): pass
    def set_policy(self, block_out): pass
    def add_rule(self, path, action, dirs): pass
    def delete_rule(self, path): pass
    def svchost(self): return r"C:\Windows\System32\svchost.exe"
    def autostart(self): return self._auto
    def set_autostart(self, on): self._auto = on
    def reset(self, paths): pass

    def read_events(self):
        out = []
        while self.sent < len(self.SCRIPT) and time.time() - self.start >= self.SCRIPT[self.sent][0]:
            _, path, d, addr, port, proto = self.SCRIPT[self.sent]
            out.append({"path": path, "dir": d, "addr": addr, "port": port, "proto": proto})
            self.sent += 1
        return out


# ---------------------------------------------------------------- Logik

class Guard:
    def __init__(self, system, state_dir, url):
        self.sys = system
        self.file = state_dir / "state.json"
        self.url = url
        self.lock = threading.RLock()
        self.pending = {}        # key -> Anfrage
        self.error = ""
        self.tray_error = ""
        self.net = None          # aktueller Datenverkehr fuer die Anzeige
        self.balloon = None      # Text fuer die naechste Sprechblase in der Taskleiste
        self.last_poll = 0.0     # wann die Oberflaeche zuletzt nachgefragt hat
        self.last_open = time.time()
        self.stop = threading.Event()
        try:
            self.state = json.loads(self.file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.state = {}
        self.state.setdefault("mode", None)
        self.state.setdefault("programs", {})

    def save(self):
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.state, indent=1), encoding="utf-8")
        os.replace(tmp, self.file)

    def set_mode(self, mode):
        if mode not in MODES:
            raise SysError("Unbekannter Modus.")
        with self.lock:
            if self.state["mode"] is None:
                self.sys.setup()
                svchost = self.sys.svchost()  # Windows-Dienste (Updates, Uhrzeit) vorab erlauben
                if svchost.lower() not in self.state["programs"]:
                    self.sys.add_rule(svchost, "allow", ["out"])
                    self.state["programs"][svchost.lower()] = {"path": svchost, "action": "allow", "dirs": ["out"]}
            self.sys.set_policy(block_out=(mode != "allow"))
            if mode == "allow":
                self.pending.clear()
            self.state["mode"] = mode
            self.save()

    def decide(self, path, action):
        if action not in ("allow", "block") or not path:
            raise SysError("Ungueltige Eingabe.")
        with self.lock:
            key = path.lower()
            old = self.state["programs"].get(key, {})
            want = self.pending.get(key, {}).get("dirs", [])
            keep = old.get("dirs", []) if old.get("action") == "allow" else []
            dirs = ["in", "out"] if action == "block" else sorted({"out", *keep, *want})
            self.sys.add_rule(path, action, dirs)
            self.state["programs"][key] = {"path": path, "action": action, "dirs": dirs}
            self.pending.pop(key, None)
            self.save()

    def forget(self, path):
        with self.lock:
            if self.state["programs"].pop(path.lower(), None):
                self.sys.delete_rule(path)
                self.save()

    def reset(self):
        with self.lock:
            self.sys.reset([p["path"] for p in self.state["programs"].values()])
            self.state = {"mode": None, "programs": {}}
            self.pending.clear()
            self.save()

    def snapshot(self):
        with self.lock:
            progs = sorted(self.state["programs"].values(), key=lambda p: nice_name(p["path"]).lower())
            view = lambda p: {"path": p["path"], "name": nice_name(p["path"]), "dirs": p.get("dirs", [])}
            return {
                "mode": self.state["mode"], "demo": self.sys.demo, "error": self.error or self.tray_error, "net": self.net,
                "pending": sorted(self.pending.values(), key=lambda p: p["first"]),
                "allowed": [view(p) for p in progs if p["action"] == "allow"],
                "blocked": [view(p) for p in progs if p["action"] == "block"],
            }

    def _handle(self, events):
        fresh = ""
        for e in events:
            key = e["path"].lower()
            known = self.state["programs"].get(key)
            if known and (known["action"] == "block" or e["dir"] in known.get("dirs", [])):
                continue
            item = self.pending.get(key)
            if item is None:
                item = self.pending[key] = {"path": e["path"], "name": nice_name(e["path"]), "dirs": [],
                                            "count": 0, "first": time.time()}
                fresh = item["name"]
            if e["dir"] not in item["dirs"]:
                item["dirs"].append(e["dir"])
                fresh = item["name"]
            item.update(count=item["count"] + 1, addr=e["addr"], port=e["port"], proto=e["proto"], dir=e["dir"])
        return fresh

    def watch(self):
        while not self.stop.wait(2):
            try:
                with self.lock:
                    mode = self.state["mode"]
                if mode not in ("ask", "quiet"):
                    continue
                events = self.sys.read_events()
                with self.lock:
                    fresh = self._handle(events)
                self.error = ""
                now = time.time()
                if self.sys.demo:
                    self.net = {"in": fmt_rate(2.3 * 1024 ** 2 + now % 7 * 90000), "out": fmt_rate(41000 + now % 5 * 3000)}
                if fresh and mode == "ask":
                    self.balloon = f"{fresh} will ins Netz. Klicken, um zu entscheiden."
                # Oberflaeche nicht offen? Dann im Fragen-Modus von selbst in den Vordergrund holen.
                if fresh and mode == "ask" and now - self.last_poll > 6 and now - self.last_open > 45:
                    self.last_open = now
                    open_ui(self.url)
            except SysError as e:
                self.error = str(e)
            except Exception as e:  # der Waechter darf nie stehen bleiben
                self.error = f"Unerwarteter Fehler: {e}"


# ---------------------------------------------------------------- Oberflaeche

PAGE = r"""<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kleine Firewall</title>
<style>
:root{--bg:#b9bdc4;--card:#d3d6db;--text:#14181e;--muted:#454b55;--line:#a3a8b1;--accent:#1d4ed8;--accentbg:#c3cff0;
--ok:#146c35;--okbg:#bfdcc9;--bad:#a11f15;--badbg:#e6c4c0;--warnbg:#e3d5a4;--warn:#553a00;--shadow:0 1px 2px rgba(16,24,40,.12)}
@media (prefers-color-scheme:dark){:root{--bg:#11141a;--card:#1a1f28;--text:#e9ecf2;--muted:#98a2b3;--line:#2b3240;
--accent:#6ea0ff;--accentbg:#1c2a4a;--ok:#62d394;--okbg:#153324;--bad:#ff8f85;--badbg:#3a1b19;--warnbg:#3a2f12;--warn:#f2c661;--shadow:none}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.35 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:420px;margin:0 auto;padding:12px 12px 16px}
header{display:flex;align-items:center;gap:9px;margin-bottom:10px}
header svg{flex:none}
h1{font-size:15px;margin:0}
#sub{color:var(--muted);font-size:12px}
h2{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:14px 2px 5px;font-weight:700}
#net{font-size:11.5px;color:var(--muted);text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
#net i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:5px}
#net .o{background:#c44fd6}#net .i{background:#3b82f6}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;box-shadow:var(--shadow)}
button{font:inherit;cursor:pointer;border-radius:7px;border:1px solid var(--line);background:var(--card);color:var(--text);padding:4px 9px}
button:hover{border-color:var(--accent)}
button:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.btn-ok{background:var(--ok);border-color:var(--ok);color:#fff;font-weight:600}
.btn-bad{background:var(--bad);border-color:var(--bad);color:#fff;font-weight:600}
@media (prefers-color-scheme:dark){.btn-ok,.btn-bad{color:#10141a}}
.btn-big{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600;padding:8px 16px}
.link{border:0;background:none;color:var(--muted);padding:3px 6px;font-size:12px}
.link:hover{color:var(--text)}
.modes{margin-top:8px;display:flex;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:3px;gap:3px}
.mode{flex:1;border:0;background:none;padding:6px 4px;font-weight:600;font-size:13px;color:var(--muted);white-space:nowrap}
.mode.sel{background:var(--accent);color:#fff}
@media (prefers-color-scheme:dark){.mode.sel{color:#10141a}}
.req{display:flex;gap:9px;align-items:center;padding:8px 9px;margin-bottom:5px}
.av{flex:none;width:30px;height:30px;border-radius:8px;color:#fff;font-weight:700;font-size:14px;display:grid;place-items:center}
.info{flex:1;min-width:0}
.info>*{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.info b{font-size:14px}
.info .path{font-size:11.5px;color:var(--muted)}
.acts{display:flex;gap:5px;flex:none}
.acts button{padding:5px 10px;font-size:13px}
.empty{padding:10px;color:var(--muted);text-align:center;font-size:13px}
.tabs{display:flex;gap:2px;padding:4px 6px 0}
.tab{border:0;background:none;border-radius:0;padding:5px 9px;color:var(--muted);font-weight:600;font-size:13px}
.tab.sel{color:var(--text);box-shadow:0 -2px 0 var(--accent) inset}
#list{max-height:176px;overflow-y:auto}
.row{display:flex;gap:8px;align-items:center;padding:5px 9px;border-top:1px solid var(--line)}
.row .av{width:22px;height:22px;border-radius:6px;font-size:11px}
.row button{font-size:12px;padding:3px 8px;flex:none}
.banner{border-radius:8px;padding:6px 9px;margin-top:8px;font-size:12px;white-space:pre-wrap}
.banner.warn{background:var(--warnbg);color:var(--warn)}
.banner.err{background:var(--badbg);color:var(--bad)}
.welcome{padding:16px;text-align:center}
.welcome p{color:var(--muted);margin:8px 0 12px;font-size:13px}
.foot{display:flex;gap:2px;align-items:center;margin-top:10px;color:var(--muted);font-size:12px}
.foot label{display:flex;gap:5px;align-items:center;cursor:pointer;margin-right:auto}
#toast{position:fixed;left:50%;bottom:12px;transform:translateX(-50%);width:max-content;max-width:92vw;padding:8px 12px;border-radius:8px;
background:var(--bad);color:#fff;display:none;white-space:pre-wrap;font-size:13px}
</style></head><body><main>
<header>
  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linejoin="round">
    <path d="M12 3l7 3v5.5c0 4.3-2.9 8-7 9.5-4.1-1.500-7-5.200-7-9.500V6l7-3z"/><path d="M9 12l2.200 2.200L15.200 10" stroke-linecap="round"/></svg>
  <div style="flex:1;min-width:0"><h1>Kleine Firewall</h1><div id="sub">…</div></div>
  <div id="net" title="Datenverkehr gerade: Out = hinaus, In = herein" hidden><div><i class="o"></i><span id="nout"></span></div><div><i class="i"></i><span id="nin"></span></div></div>
</header>
<div id="demo" class="banner warn" hidden>Vorschau: Es wird nichts an diesem Rechner verändert, die Anfragen sind erfunden.</div>
<div id="error" class="banner err" hidden></div>

<div id="welcome" class="card welcome" hidden>
  <b style="font-size:15px">Schutz einschalten?</b>
  <p>Ab dann darf kein Programm mehr von selbst ins Internet. Sobald eines es versucht, wirst du hier gefragt
     und entscheidest mit einem Klick. Windows-Dienste für Updates und Uhrzeit sind vorab erlaubt.</p>
  <button class="btn-big" id="start">Schutz einschalten</button>
</div>

<div id="app" hidden>
  <div class="modes" id="modes">
    <button class="mode" data-m="ask" title="Bei jedem neuen Programm entscheidest du.">Fragen</button>
    <button class="mode" data-m="quiet" title="Neues bleibt still gesperrt und wartet hier auf dich.">Nicht stören</button>
    <button class="mode" data-m="allow" title="Alles darf raus – außer was du gesperrt hast.">Alles erlauben</button>
  </div>
  <div id="notify" class="banner warn" hidden>Auch im Hintergrund Bescheid bekommen?
    <button id="notifybtn" style="margin-left:6px">Hinweise einschalten</button></div>

  <h2 id="reqtitle">Anfragen</h2>
  <div id="reqs"></div>

  <h2>Listen</h2>
  <div class="card">
    <div class="tabs"><button class="tab" data-t="allowed"></button><button class="tab" data-t="blocked"></button></div>
    <div id="list"></div>
  </div>

  <div class="foot">
    <label><input type="checkbox" id="auto"> Mit Windows starten</label>
    <button class="link" id="reset">Alles zurücksetzen</button>
    <button class="link" id="quit">Beenden</button>
  </div>
</div>
</main><div id="toast"></div>

<script>
const TOKEN = "__TOKEN__", $ = id => document.getElementById(id);
let S = null, tab = "allowed", lastJson = "", known = new Set(), first = true;

async function api(path, body){
  const r = await fetch("/api/" + path, {method: body ? "POST" : "GET",
    headers: {"X-Token": TOKEN, "Content-Type": "application/json"}, body: body ? JSON.stringify(body) : undefined});
  const j = await r.json();
  if(!r.ok) throw new Error(j.error || "Fehler");
  return j;
}
function toast(t){ const e = $("toast"); e.textContent = t; e.style.display = "block";
  clearTimeout(toast.t); toast.t = setTimeout(() => e.style.display = "none", 8000); }
async function act(path, body){ try{ show(await api(path, body)); }catch(e){ toast(e.message); } }

function el(tag, cls, text){ const e = document.createElement(tag); if(cls) e.className = cls;
  if(text != null) e.textContent = text; return e; }
function avatar(name){ let h = 0; for(const c of name) h = (h * 31 + c.charCodeAt(0)) % 360;
  const a = el("div", "av", (name[0] || "?").toUpperCase()); a.style.background = `hsl(${h} 50% 42%)`; return a; }
function btn(text, cls, fn, title){ const b = el("button", cls, text); b.onclick = fn; if(title) b.title = title; return b; }
function wants(p){
  const out = p.dirs.includes("out"), inn = p.dirs.includes("in");
  return out && inn ? "will raus und Verbindungen annehmen"
       : inn ? "will Verbindungen von außen annehmen" : "will ins Internet";
}
function detail(p){
  const bits = [];
  if(p.addr) bits.push((p.dir == "in" ? "von " : "nach ") + p.addr);
  if(p.count > 1) bits.push(p.count + "×");
  return bits.join(" · ");
}

function show(s){
  S = s;
  const json = JSON.stringify(Object.assign({}, s, {net: null})) + tab;
  for(const p of s.pending){
    const id = p.path + p.dirs.join();
    if(!known.has(id)){ known.add(id);
      if(!first && s.mode == "ask" && document.hidden && window.Notification && Notification.permission == "granted"){
        const n = new Notification(p.name + " " + wants(p), {body: "Klicken, um zu entscheiden.", tag: p.path});
        n.onclick = () => { window.focus(); n.close(); };
      }}
  }
  first = false;
  document.title = (s.pending.length ? "(" + s.pending.length + ") " : "") + "Kleine Firewall";
  $("net").hidden = !s.net; if(s.net){ $("nout").textContent = "Out " + s.net.out; $("nin").textContent = "In " + s.net.in; }
  if(json == lastJson) return; lastJson = json;

  $("demo").hidden = !s.demo;
  $("error").hidden = !s.error; $("error").textContent = s.error;
  $("welcome").hidden = s.mode != null; $("app").hidden = s.mode == null;
  $("sub").textContent = {null: "Schutz ist noch aus", ask: "Schutz aktiv – du wirst gefragt",
    quiet: "Schutz aktiv – Neues bleibt still gesperrt", allow: "Alles darf raus, außer deiner Sperrliste"}[s.mode];
  for(const b of $("modes").children) b.classList.toggle("sel", b.dataset.m == s.mode);
  $("notify").hidden = !(s.mode == "ask" && window.Notification && Notification.permission == "default");
  $("auto").checked = !!s.autostart;

  $("reqtitle").textContent = s.pending.length ? "Anfragen (" + s.pending.length + ")" : "Anfragen";
  const reqs = $("reqs"); reqs.replaceChildren();
  if(!s.pending.length) reqs.append(el("div", "card empty",
    s.mode == "allow" ? "In diesem Modus wird nicht gefragt." : "Alles ruhig."));
  for(const p of s.pending){
    const c = el("div", "card req"), info = el("div", "info");
    info.append(el("b", "", p.name), el("div", "path", [wants(p), detail(p)].filter(Boolean).join(" · ")));
    c.title = p.path;
    const acts = el("div", "acts");
    acts.append(btn("Erlauben", "btn-ok", () => act("decide", {path: p.path, action: "allow"})),
                btn("Sperren", "btn-bad", () => act("decide", {path: p.path, action: "block"})));
    c.append(avatar(p.name), info, acts); reqs.append(c);
  }

  for(const t of document.querySelectorAll(".tab")){
    t.classList.toggle("sel", t.dataset.t == tab);
    t.textContent = (t.dataset.t == "allowed" ? "Erlaubt" : "Gesperrt") + " (" + s[t.dataset.t].length + ")";
  }
  const list = $("list"); list.replaceChildren();
  if(!s[tab].length) list.append(el("div", "empty", tab == "allowed" ? "Noch nichts erlaubt." : "Noch nichts gesperrt."));
  for(const p of s[tab]){
    const r = el("div", "row"), info = el("div", "info");
    info.append(el("div", "", p.name)); r.title = p.path;
    r.append(avatar(p.name), info,
      tab == "allowed" ? btn("Sperren", "", () => act("decide", {path: p.path, action: "block"}))
                       : btn("Erlauben", "", () => act("decide", {path: p.path, action: "allow"})),
      btn("✕", "link", () => act("forget", {path: p.path}), "Vergessen – beim nächsten Mal wird wieder gefragt"));
    list.append(r);
  }
}

$("start").onclick = () => act("mode", {mode: "ask"});
$("modes").onclick = e => { const b = e.target.closest("button"); if(b && b.dataset.m != S.mode) act("mode", {mode: b.dataset.m}); };
for(const t of document.querySelectorAll(".tab")) t.onclick = () => { tab = t.dataset.t; lastJson = ""; show(S); };
$("auto").onchange = e => act("autostart", {on: e.target.checked});
$("notifybtn").onclick = async () => { await Notification.requestPermission(); lastJson = ""; show(S); };
$("reset").onclick = async () => {
  if(!confirm("Alle Regeln dieser Firewall löschen und Windows wieder so einstellen, dass alles ins Internet darf?")) return;
  try{ await api("reset", {}); bye("Alles zurückgesetzt."); }catch(e){ toast(e.message); } };
$("quit").onclick = async () => {
  if(!confirm("Beenden? Deine Regeln bleiben aktiv, aber du wirst nicht mehr gefragt – Neues bleibt gesperrt.")) return;
  try{ await api("quit", {}); }catch(e){} bye("Kleine Firewall wurde beendet. Deine Regeln bleiben aktiv."); };
function bye(text){ clearInterval(timer); document.querySelector("main").replaceChildren(el("div", "card empty", text)); }
const tick = () => api("state").then(show).catch(() => {});
const timer = setInterval(tick, 1500); tick();
</script></body></html>
"""


def make_server(guard, token, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _allowed(self, value):
            # nur von diesem Rechner und nur mit dem geheimen Schluessel
            host_ok = self.headers.get("Host", "") == f"127.0.0.1:{self.server.server_port}"
            return host_ok and secrets.compare_digest(value or "", token)

        def _state(self):
            guard.last_poll = time.time()
            data = guard.snapshot()
            try:
                data["autostart"] = guard.sys.autostart() if data["mode"] else False
            except SysError:
                data["autostart"] = False
            return data

        def do_GET(self):
            path, _, query = self.path.partition("?")
            if path == "/" and self._allowed(query.removeprefix("t=")):
                self._send(200, PAGE.replace("__TOKEN__", token).encode("utf-8"), "text/html")
            elif path == "/api/state" and self._allowed(self.headers.get("X-Token")):
                self._send(200, self._state())
            else:
                self._send(403, {"error": "Kein Zugriff."})

        def do_POST(self):
            if not self._allowed(self.headers.get("X-Token")):
                return self._send(403, {"error": "Kein Zugriff."})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(min(length, 65536)) or b"{}")
                if self.path == "/api/decide":
                    guard.decide(str(body.get("path", "")), body.get("action"))
                elif self.path == "/api/forget":
                    guard.forget(str(body.get("path", "")))
                elif self.path == "/api/mode":
                    guard.set_mode(body.get("mode"))
                elif self.path == "/api/autostart":
                    guard.sys.set_autostart(bool(body.get("on")))
                elif self.path in ("/api/reset", "/api/quit"):
                    if self.path == "/api/reset":
                        guard.reset()
                    self._send(200, {})
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                    return
                else:
                    return self._send(404, {"error": "Unbekannt."})
                self._send(200, self._state())
            except SysError as e:
                self._send(400, {"error": str(e)})
            except (ValueError, TypeError, AttributeError):
                self._send(400, {"error": "Ungueltige Eingabe."})

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


# ---------------------------------------------------------------- Taskleisten-Anzeige

LEVELS = (1024, 10 * 1024, 100 * 1024, 1024 ** 2, 10 * 1024 ** 2)  # Bytes/s je Balken-Stufe
C_OUT, C_IN, C_DIM = b"\xf0\x8c\xe5\xff", b"\xff\xa8\x6a\xff", b"\x80\x80\x80\xff"  # Blau-Gruen-Rot-Deckkraft


def level(rate):
    return sum(1 for limit in LEVELS if rate >= limit)


def fmt_rate(rate):
    if rate >= 1024 ** 2:
        return f"{rate / 1024 ** 2:.1f} MB/s".replace(".", ",")
    return f"{int(rate / 1024)} KB/s"


def icon_pixels(size, lvl_in, lvl_out):
    """Zwei Balkenreihen: oben Out (rosa), unten In (blau). Liefert Bildpunkte von oben nach unten."""
    px = bytearray(size * size * 4)
    n = len(LEVELS)
    gap = max(1, round(size / 16))
    seg = (size - gap * (n - 1)) // n
    x0 = (size - (seg * n + gap * (n - 1))) // 2
    margin = max(1, size // 8)
    row_h = (size - 2 * margin - gap) // 2
    for row, (lvl, color) in enumerate(((lvl_out, C_OUT), (lvl_in, C_IN))):
        y0 = margin + row * (row_h + gap)
        for i in range(n):
            c = color if i < lvl else C_DIM
            for y in range(y0, y0 + row_h):
                start = (y * size + x0 + i * (seg + gap)) * 4
                px[start:start + seg * 4] = c * seg
    return bytes(px)


class WinNet:
    """Gesamter Datenverkehr aller Netzwerkkarten in Bytes pro Sekunde (ein, aus)."""

    def __init__(self):
        from ctypes import wintypes as w

        class Row(ctypes.Structure):
            _fields_ = ([("wszName", w.WCHAR * 256)] +
                        [(n, w.DWORD) for n in ("dwIndex", "dwType", "dwMtu", "dwSpeed", "dwPhysAddrLen")] +
                        [("bPhysAddr", ctypes.c_ubyte * 8)] +
                        [(n, w.DWORD) for n in (
                            "dwAdminStatus", "dwOperStatus", "dwLastChange", "dwInOctets", "dwInUcastPkts",
                            "dwInNUcastPkts", "dwInDiscards", "dwInErrors", "dwInUnknownProtos", "dwOutOctets",
                            "dwOutUcastPkts", "dwOutNUcastPkts", "dwOutDiscards", "dwOutErrors", "dwOutQLen",
                            "dwDescrLen")] +
                        [("bDescr", ctypes.c_ubyte * 256)])
        self.Row = Row
        self.prev = {}
        self.when = time.time()

    def _counters(self):
        from ctypes import wintypes as w
        api = ctypes.windll.iphlpapi
        size = w.ULONG(0)
        api.GetIfTable(None, ctypes.byref(size), False)
        buf = ctypes.create_string_buffer(max(size.value, 4))
        if api.GetIfTable(buf, ctypes.byref(size), False) != 0:
            return {}
        count = w.DWORD.from_buffer(buf).value
        rows = (self.Row * count).from_buffer(buf, 4)
        totals = {}
        for r in rows:
            if r.dwType == 24 or not r.dwPhysAddrLen:  # Loopback und Pseudo-Schnittstellen
                continue
            mac = bytes(r.bPhysAddr[:r.dwPhysAddrLen])
            # Filter-Schichten melden dieselbe Karte mehrfach -> je Karte nur einmal zaehlen
            old = totals.get(mac, (0, 0))
            totals[mac] = (max(old[0], r.dwInOctets), max(old[1], r.dwOutOctets))
        return totals

    def sample(self):
        now, cur = time.time(), self._counters()
        dt = max(now - self.when, 0.2)
        rate = [0.0, 0.0]
        for mac, vals in cur.items():
            old = self.prev.get(mac)
            for i in (0, 1):
                diff = (vals[i] - old[i]) % 2 ** 32 if old else 0  # 32-Bit-Zaehler laufen ueber
                if diff < 2 ** 31:
                    rate[i] += diff / dt
        self.prev, self.when = cur, now
        return rate[0], rate[1]


class Tray:
    """Kleines Symbol im Infobereich der Taskleiste mit In/Out-Balken."""
    ICON_MSG = 0x8001

    def __init__(self, guard):
        self.guard = guard
        self.hwnd = None
        self.added = False
        self.icons = {}
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    def close(self):
        if self.hwnd:
            ctypes.windll.user32.PostMessageW(self.hwnd, 0x0010, 0, 0)  # WM_CLOSE
            self.thread.join(2)

    def _run(self):
        try:
            self._loop()
        except Exception as e:
            self.guard.tray_error = f"Anzeige in der Taskleiste nicht verfuegbar: {e}"

    def _loop(self):
        from ctypes import wintypes as w
        H, P = ctypes.c_void_p, ctypes.POINTER
        u, g, sh, k = ctypes.windll.user32, ctypes.windll.gdi32, ctypes.windll.shell32, ctypes.windll.kernel32
        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, H, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t)

        class WNDCLASS(ctypes.Structure):
            _fields_ = [("style", ctypes.c_uint), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int),
                        ("cbWndExtra", ctypes.c_int), ("hInstance", H), ("hIcon", H), ("hCursor", H),
                        ("hbrBackground", H), ("lpszMenuName", w.LPCWSTR), ("lpszClassName", w.LPCWSTR)]

        class ICONINFO(ctypes.Structure):
            _fields_ = [("fIcon", w.BOOL), ("xHotspot", w.DWORD), ("yHotspot", w.DWORD),
                        ("hbmMask", H), ("hbmColor", H)]

        class NID(ctypes.Structure):
            _fields_ = [("cbSize", w.DWORD), ("hWnd", H), ("uID", ctypes.c_uint), ("uFlags", ctypes.c_uint),
                        ("uCallbackMessage", ctypes.c_uint), ("hIcon", H), ("szTip", w.WCHAR * 128),
                        ("dwState", w.DWORD), ("dwStateMask", w.DWORD), ("szInfo", w.WCHAR * 256),
                        ("uVersion", ctypes.c_uint), ("szInfoTitle", w.WCHAR * 64), ("dwInfoFlags", w.DWORD),
                        ("guidItem", ctypes.c_ubyte * 16), ("hBalloonIcon", H)]

        u.DefWindowProcW.argtypes = [H, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
        u.DefWindowProcW.restype = ctypes.c_ssize_t
        u.CreateWindowExW.argtypes = [w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD] + [ctypes.c_int] * 4 + [H, H, H, H]
        u.CreateWindowExW.restype = H
        u.RegisterClassW.argtypes = [P(WNDCLASS)]
        u.DestroyWindow.argtypes = [H]
        u.SetTimer.argtypes = [H, ctypes.c_size_t, ctypes.c_uint, H]
        u.PostMessageW.argtypes = [H, ctypes.c_uint, ctypes.c_size_t, ctypes.c_ssize_t]
        u.GetMessageW.argtypes = [P(w.MSG), H, ctypes.c_uint, ctypes.c_uint]
        u.TranslateMessage.argtypes = u.DispatchMessageW.argtypes = [P(w.MSG)]
        u.CreateIconIndirect.argtypes = [P(ICONINFO)]
        u.CreateIconIndirect.restype = H
        g.CreateBitmap.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_char_p]
        g.CreateBitmap.restype = H
        g.DeleteObject.argtypes = [H]
        k.GetModuleHandleW.argtypes = [w.LPCWSTR]
        k.GetModuleHandleW.restype = H
        sh.Shell_NotifyIconW.argtypes = [w.DWORD, P(NID)]

        size = u.GetSystemMetrics(49) or 16  # Groesse kleiner Symbole, passt sich der Bildschirm-Skalierung an
        net = WinNet()
        taskbar_created = u.RegisterWindowMessageW("TaskbarCreated")

        def icon(lvl_in, lvl_out):
            if (lvl_in, lvl_out) not in self.icons:
                pixels = icon_pixels(size, lvl_in, lvl_out)
                mask_row = ((size + 15) // 16) * 2
                color = g.CreateBitmap(size, size, 1, 32, pixels)
                mask = g.CreateBitmap(size, size, 1, 1, b"\x00" * (mask_row * size))
                info = ICONINFO(True, 0, 0, mask, color)
                self.icons[(lvl_in, lvl_out)] = u.CreateIconIndirect(ctypes.byref(info))
                g.DeleteObject(color)
                g.DeleteObject(mask)
            return self.icons[(lvl_in, lvl_out)]

        def nid(flags=0):
            n = NID()
            n.cbSize, n.hWnd, n.uID, n.uFlags, n.uCallbackMessage = ctypes.sizeof(NID), self.hwnd, 1, flags, self.ICON_MSG
            return n

        def tick():
            rate_in, rate_out = net.sample()
            self.guard.net = {"in": fmt_rate(rate_in), "out": fmt_rate(rate_out)}
            n = nid(1 | 2 | 4)  # Nachricht, Symbol, Text
            n.hIcon = icon(level(rate_in), level(rate_out))
            n.szTip = f"Kleine Firewall\nIn {fmt_rate(rate_in)} - Out {fmt_rate(rate_out)}"[:127]
            note, self.guard.balloon = self.guard.balloon, None
            if note and self.added:
                n.uFlags |= 0x10  # Sprechblase
                n.szInfoTitle, n.szInfo, n.dwInfoFlags = "Kleine Firewall", note[:255], 1
            if self.added:
                sh.Shell_NotifyIconW(1, ctypes.byref(n))
            else:
                self.added = bool(sh.Shell_NotifyIconW(0, ctypes.byref(n)))

        def wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == 0x0113:  # Zeitgeber
                    tick()
                elif msg == self.ICON_MSG and (lparam & 0xFFFF) in (0x0202, 0x0203, 0x0205, 0x0405):
                    open_ui(self.guard.url)  # Klick auf Symbol oder Sprechblase
                elif msg == taskbar_created:
                    self.added = False
                elif msg == 0x0010:  # schliessen
                    sh.Shell_NotifyIconW(2, ctypes.byref(nid()))
                    u.DestroyWindow(hwnd)
                    return 0
                elif msg == 0x0002:
                    u.PostQuitMessage(0)
                    return 0
            except Exception as e:
                self.guard.tray_error = f"Anzeige in der Taskleiste: {e}"
            return u.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._proc = WNDPROC(wndproc)  # Verweis halten, sonst raeumt Python die Funktion weg
        wc = WNDCLASS()
        wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = self._proc, k.GetModuleHandleW(None), "KleineFirewallTray"
        u.RegisterClassW(ctypes.byref(wc))
        self.hwnd = u.CreateWindowExW(0, wc.lpszClassName, "Kleine Firewall", 0, 0, 0, 0, 0, None, None, wc.hInstance, None)
        if not self.hwnd:
            raise OSError("Fenster konnte nicht angelegt werden")
        tick()
        u.SetTimer(self.hwnd, 1, 1000, None)
        msg = w.MSG()
        while u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            u.TranslateMessage(ctypes.byref(msg))
            u.DispatchMessageW(ctypes.byref(msg))


# ---------------------------------------------------------------- Start

def open_ui(url):
    """Als kleines App-Fenster oeffnen (Edge ist bei Windows dabei), sonst im Standardbrowser."""
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        edge = os.path.join(base or "", "Microsoft", "Edge", "Application", "msedge.exe")
        if base and os.path.exists(edge):
            try:
                subprocess.Popen([edge, f"--app={url}", "--window-size=440,620"])
                return
            except OSError:
                break
    webbrowser.open(url)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def say(text):
    if sys.stdout:
        print(text, flush=True)


def main():
    ap = argparse.ArgumentParser(description="Kleine Firewall fuer Windows")
    ap.add_argument("--demo", action="store_true", help="nur ansehen, nichts veraendern")
    ap.add_argument("--hintergrund", action="store_true", help="starten, ohne die Oberflaeche zu oeffnen")
    ap.add_argument("--zuruecksetzen", action="store_true", help="alle Regeln entfernen, Windows-Standard herstellen")
    ap.add_argument("--port", type=int, default=PORT, help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.demo:
        state_dir = Path(tempfile.mkdtemp(prefix="kleinefirewall-demo-"))
        system = DemoSystem(state_dir)
    else:
        if platform.system() != "Windows":
            say("Dieses Programm laeuft nur unter Windows. Zum Ansehen: --demo")
            return 1
        if not is_admin():  # mit Administratorrechten neu starten (Windows fragt nach)
            own = [] if getattr(sys, "frozen", False) else [os.path.abspath(__file__)]  # als EXE: kein Skript
            params = subprocess.list2cmdline(own + sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            return 0
        state_dir = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP
        state_dir.mkdir(parents=True, exist_ok=True)
        system = WinSystem(state_dir)
        system.protect_folder()

    ui_file = state_dir / "ui.json"
    if args.zuruecksetzen:
        Guard(system, state_dir, "").reset()
        say("Zurueckgesetzt: Regeln entfernt, ausgehende Verbindungen wieder erlaubt.")
        return 0

    token = secrets.token_urlsafe(24)
    guard = Guard(system, state_dir, "")
    try:
        server = make_server(guard, token, args.port)
    except OSError:  # laeuft schon -> einfach dessen Oberflaeche zeigen
        try:
            open_ui(json.loads(ui_file.read_text(encoding="utf-8"))["url"])
        except (OSError, ValueError, KeyError):
            say(f"Port {args.port} ist belegt.")
        return 0
    url = f"http://127.0.0.1:{server.server_port}/?t={token}"
    ui_file.write_text(json.dumps({"url": url}), encoding="utf-8")

    guard.url = url
    if guard.state["mode"] in ("ask", "quiet") and not system.demo:
        try:
            system.enable_log()
        except SysError as e:
            guard.error = str(e)
    threading.Thread(target=guard.watch, daemon=True).start()
    tray = None if system.demo else Tray(guard)
    if tray:
        tray.start()
    say("Kleine Firewall laeuft. Oberflaeche:\n  " + url)
    if not args.hintergrund:
        open_ui(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        guard.stop.set()
        if tray:
            tray.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
