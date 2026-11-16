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
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

APP = "KleineFirewall"
VERSION = "2.2"
PORT = 47615
TASK = "KleineFirewall"
# Windows-Protokollkategorie "Filterplattformverbindung" (sprachunabhaengige Kennung)
AUDIT_GUID = "{0CCE9226-69AE-11D9-BED3-505054503030}"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
NOWIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)
MODES = ("ask", "quiet", "allow")
NATIVE = {"window": None, "quitting": False}  # eigenes Programmfenster, falls verfuegbar


LOG = {"file": None}


def log(text):
    """Kurzes Protokoll zum Nachsehen, wenn etwas nicht klappt (ProgramData\\KleineFirewall\\log.txt)."""
    try:
        if LOG["file"]:
            if LOG["file"].exists() and LOG["file"].stat().st_size > 200000:
                LOG["file"].unlink()
            with open(LOG["file"], "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + str(text) + "\n")
    except OSError:
        pass


def message(text):
    """Sichtbare Meldung - damit nie einfach 'nichts passiert'."""
    log("Meldung: " + text)
    try:
        ctypes.windll.user32.MessageBoxW(None, text, "Kleine Firewall", 0x30)
    except Exception:
        if sys.stdout:
            print(text, flush=True)


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

    def file_info(self, path):
        """Hersteller und Beschreibung, wie sie in der Programmdatei hinterlegt sind."""
        try:
            v = ctypes.windll.version
            size = v.GetFileVersionInfoSizeW(path, None)
            if not size:
                return {}
            buf = ctypes.create_string_buffer(size)
            if not v.GetFileVersionInfoW(path, 0, size, buf):
                return {}
            ptr, length = ctypes.c_void_p(), ctypes.c_uint()

            def query(key):
                ok = v.VerQueryValueW(buf, key, ctypes.byref(ptr), ctypes.byref(length))
                return (ptr.value, length.value) if ok and ptr.value and length.value else (None, 0)

            langs = []
            addr, _ = query("\\VarFileInfo\\Translation")
            if addr:
                pair = (ctypes.c_ushort * 2).from_address(addr)
                langs.append("%04x%04x" % (pair[0], pair[1]))
            langs += ["040904b0", "040904e4", "040704b0", "000004b0"]
            out = {}
            for field, name in (("company", "CompanyName"), ("desc", "FileDescription")):
                for lang in langs:
                    addr, n = query(f"\\StringFileInfo\\{lang}\\{name}")
                    if addr:
                        text = ctypes.wstring_at(addr, n).split("\0")[0].strip()
                        if text:
                            out[field] = text[:80]
                            break
            return out
        except Exception:
            return {}

    def host_name(self, addr):
        try:
            return socket.gethostbyaddr(addr)[0]
        except (OSError, UnicodeError):
            return ""

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

    def file_info(self, path):
        return {"firefox.exe": {"company": "Mozilla Corporation", "desc": "Firefox"},
                "spotify.exe": {"company": "Spotify Ltd", "desc": "Spotify"},
                "medienserver.exe": {"company": "Beispiel GmbH", "desc": "Medienserver"}}.get(ntpath.basename(path).lower(), {})

    def host_name(self, addr):
        return {"34.107.221.82": "detectportal.firefox.com", "35.186.224.25": "ap.spotify.com"}.get(addr, "")

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
        self.hosts = {}          # IP-Adresse -> Name der Gegenstelle
        self.error = ""
        self.tray_error = ""
        self.net = None          # aktueller Datenverkehr fuer die Anzeige
        self.on_quit = None      # wird beim Start gesetzt: beendet das ganze Programm
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
            self.state = {"mode": None, "programs": {}, "scale": self.state.get("scale")}
            self.pending.clear()
            self.save()

    def snapshot(self):
        with self.lock:
            progs = sorted(self.state["programs"].values(), key=lambda p: nice_name(p["path"]).lower())
            view = lambda p: {"path": p["path"], "name": nice_name(p["path"]), "dirs": p.get("dirs", [])}
            return {
                "mode": self.state["mode"], "demo": self.sys.demo, "native": NATIVE["window"] is not None, "scale": self.state.get("scale"), "error": self.error or self.tray_error, "net": self.net,
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
                                            "count": 0, "first": time.time(), **self.sys.file_info(e["path"])}
                fresh = item["name"]
            if e["dir"] not in item["dirs"]:
                item["dirs"].append(e["dir"])
                fresh = item["name"]
            item.update(count=item["count"] + 1, addr=e["addr"], port=e["port"], proto=e["proto"], dir=e["dir"],
                        host=self.hosts.get(e["addr"], ""))
            if e["addr"] and e["addr"] not in self.hosts:
                self.hosts[e["addr"]] = ""
                threading.Thread(target=self._lookup, args=(e["addr"],), daemon=True).start()
        return fresh

    def _lookup(self, addr):
        name = self.sys.host_name(addr)
        with self.lock:
            self.hosts[addr] = name
            for item in self.pending.values():
                if item.get("addr") == addr:
                    item["host"] = name

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
:root{--bg:#c2c5ca;--card:#d2d4d8;--text:#1b1e23;--muted:#565c65;--line:#a8acb3;--accent:#3c4450;
--ok:#437a57;--bad:#9a4f48}
@media (prefers-color-scheme:dark){:root{--bg:#1c1e22;--card:#26292e;--text:#e4e6ea;--muted:#9aa0a9;--line:#3a3e45;
--accent:#aeb4be;--ok:#3f7352;--bad:#8f4741}}
*{box-sizing:border-box}
html{overflow-x:hidden;scrollbar-width:thin}
body{margin:0;background:var(--bg);color:var(--text);font:11.5px/1.3 system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:300px;margin:0 auto;padding:7px}
header{display:flex;align-items:center;gap:6px;margin-bottom:5px}
header svg{flex:none}
h1{font-size:12px;margin:0}
h1 small{font-weight:400;color:var(--muted);font-size:10px;margin-left:4px}
#sub{color:var(--muted);font-size:10.5px}
h2{font-size:9.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:8px 2px 3px;font-weight:700}
#net{white-space:pre;font-size:10px;color:var(--muted);text-align:right;font-variant-numeric:tabular-nums}
.card{background:var(--card);border:1px solid var(--line);border-radius:6px}
button{font:inherit;cursor:pointer;border-radius:5px;border:1px solid var(--line);background:none;color:var(--text);padding:2px 7px}
button:hover{border-color:var(--text)}
button:focus-visible{outline:2px solid var(--text);outline-offset:1px}
.btn-ok{background:var(--ok);border-color:var(--ok);color:#fff;font-weight:600}
.btn-bad{background:var(--bad);border-color:var(--bad);color:#fff;font-weight:600}
.btn-big{background:var(--accent);border-color:var(--accent);color:var(--card);font-weight:600;padding:5px 12px}
.link{border:0;color:var(--muted);padding:2px 4px;font-size:10.5px}
.link:hover{color:var(--text)}
.modes{display:flex;border:1px solid var(--line);border-radius:6px;padding:2px;gap:2px}
.mode{flex:1;border:0;padding:3px 2px;font-size:11px;color:var(--muted);white-space:nowrap}
.mode.sel{background:var(--accent);color:var(--card);font-weight:600}
.req{padding:6px 7px;margin-bottom:4px}
.info{flex:1;min-width:0}
.info>*{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.info b{font-size:12px;display:block}
.info .path{font-size:10px;color:var(--muted)}
.facts{margin:4px 0 6px;font-size:10.5px;display:grid;grid-template-columns:auto 1fr;gap:1px 6px}
.facts dt{color:var(--muted)}.facts dd{margin:0;overflow-wrap:anywhere}
.acts{display:flex;gap:5px}
.acts button{flex:1;padding:3px 8px}
.empty{padding:6px;color:var(--muted);text-align:center;font-size:10.5px}
.tabs{display:flex;gap:2px;padding:1px 4px 0}
.tab{border:0;border-radius:0;padding:3px 6px;color:var(--muted);font-size:11px}
.tab.sel{color:var(--text);font-weight:600;box-shadow:0 -2px 0 var(--accent) inset}
#list,#reqs{overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--line) transparent}
#list{max-height:124px}#reqs{max-height:330px}
.row{display:flex;gap:6px;align-items:center;padding:2px 7px;border-top:1px solid var(--line)}
.row button{font-size:10.5px;padding:1px 6px;flex:none}
.banner{border:1px solid var(--line);border-radius:6px;padding:3px 7px;margin:5px 0;font-size:10.5px;color:var(--muted);white-space:pre-wrap}
.banner.err{border-color:var(--bad);color:var(--text)}
.welcome{padding:10px;text-align:center}
.welcome p{color:var(--muted);margin:5px 0 9px;font-size:10.5px}
.foot{display:flex;gap:1px;align-items:center;margin-top:6px;color:var(--muted);font-size:10.5px}
.foot label{display:flex;gap:4px;align-items:center;cursor:pointer;margin-right:auto}
.foot input{margin:0;width:11px;height:11px}
#toast{position:fixed;left:50%;bottom:8px;transform:translateX(-50%);width:max-content;max-width:94vw;padding:5px 9px;border-radius:6px;
background:var(--bad);color:#fff;display:none;white-space:pre-wrap;font-size:10.5px}
</style></head><body><main>
<header>
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" stroke-width="2" stroke-linejoin="round">
    <path d="M12 3l7 3v5.5c0 4.3-2.9 8-7 9.5-4.1-1.5-7-5.2-7-9.5V6l7-3z"/></svg>
  <div style="flex:1;min-width:0"><h1>Kleine Firewall<small>v__VERSION__</small></h1><div id="sub">…</div></div>
  <div id="net" title="Datenverkehr gerade: Out = hinaus, In = herein" hidden></div>
</header>
<div id="demo" class="banner warn" hidden>Vorschau – nichts wird verändert, Anfragen sind erfunden.</div>
<div id="error" class="banner err" hidden></div>

<div id="welcome" class="card welcome" hidden>
  <b style="font-size:12px">Schutz einschalten?</b>
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
    <button class="link" id="smaller" title="Anzeige kleiner">A−</button>
    <button class="link" id="bigger" title="Anzeige größer">A+</button>
  </div>
  <div class="foot" style="margin-top:0">
    <span style="margin-right:auto"></span>
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
function btn(text, cls, fn, title){ const b = el("button", cls, text); b.onclick = fn; if(title) b.title = title; return b; }
function wants(p){
  const out = p.dirs.includes("out"), inn = p.dirs.includes("in");
  return out && inn ? "ins Internet und Verbindungen annehmen"
       : inn ? "Verbindungen von außen annehmen" : "ins Internet";
}
const PORTS = {"80": "Webseite", "443": "Webseite (verschlüsselt)", "53": "Namensauflösung", "123": "Uhrzeit",
  "25": "E-Mail-Versand", "465": "E-Mail-Versand", "587": "E-Mail-Versand", "993": "E-Mail-Abruf", "995": "E-Mail-Abruf",
  "143": "E-Mail-Abruf", "22": "Fernzugriff (SSH)", "3389": "Fernsteuerung", "445": "Dateifreigabe", "21": "Dateiübertragung"};
function fileOf(path){ return path.split(/[\\/]/).pop(); }
function where(p){
  if(!p.addr) return "";
  const home = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|f[cde])/i.test(p.addr);
  return p.host ? p.host + " (" + p.addr + ")" : p.addr + (home ? " – Gerät im eigenen Netz" : "");
}

let scale = 0;
function setScale(v){ if(v != scale){ scale = v; document.querySelector("main").style.zoom = v; fit(); } }
let fitGoal = "", fitTries = 0, fitBusy = false;
function fit(){  // dem Programm melden, um wie viel das Fenster vom Inhalt abweicht - es stellt die Groesse dann ein
  if(document.hidden || fitBusy || !scale) return;
  const box = document.querySelector("main").getBoundingClientRect();
  const w = Math.ceil(300 * scale), h = Math.ceil(box.height) + 1, goal = w + "x" + h;
  if(goal != fitGoal){ fitGoal = goal; fitTries = 0; }
  const dw = w - innerWidth, dh = h - innerHeight;
  if((Math.abs(dw) <= 2 && Math.abs(dh) <= 2) || fitTries >= 4) return;
  fitTries++; fitBusy = true;
  api("size", {dw, dh, dpr: devicePixelRatio}).catch(() => {}).finally(() => setTimeout(() => { fitBusy = false; fit(); }, 400));
}
function step(d){ const v = Math.min(1.5, Math.max(0.5, Math.round((scale + d) * 10) / 10)); act("scale", {scale: v}); }

function show(s){
  S = s;
  const json = JSON.stringify(Object.assign({}, s, {net: null})) + tab;
  for(const p of s.pending){
    const id = p.path + p.dirs.join();
    if(!known.has(id)){ known.add(id);
      if(!first && s.mode == "ask" && document.hidden && window.Notification && Notification.permission == "granted"){
        const n = new Notification(p.name + " will " + wants(p), {body: "Klicken, um zu entscheiden.", tag: p.path});
        n.onclick = () => { window.focus(); n.close(); };
      }}
  }
  first = false;
  document.title = (s.pending.length ? "(" + s.pending.length + ") " : "") + "Kleine Firewall";
  $("net").hidden = !s.net; if(s.net) $("net").textContent = "Out " + s.net.out + "\nIn " + s.net.in;
  setScale(s.scale || (devicePixelRatio >= 1.4 ? 0.8 : 1));
  if(json == lastJson) return; lastJson = json;

  $("demo").hidden = !s.demo;
  $("error").hidden = !s.error; $("error").textContent = s.error;
  $("welcome").hidden = s.mode != null; $("app").hidden = s.mode == null;
  $("sub").textContent = {null: "Schutz ist noch aus", ask: "Schutz aktiv – du wirst gefragt",
    quiet: "Schutz aktiv – Neues bleibt still gesperrt", allow: "Alles darf raus, außer deiner Sperrliste"}[s.mode];
  for(const b of $("modes").children) b.classList.toggle("sel", b.dataset.m == s.mode);
  $("notify").hidden = !(s.mode == "ask" && !s.native && window.Notification && Notification.permission == "default");
  $("auto").checked = !!s.autostart;

  $("reqtitle").textContent = s.pending.length ? "Anfragen (" + s.pending.length + ")" : "Anfragen";
  const reqs = $("reqs"); reqs.replaceChildren();
  if(!s.pending.length) reqs.append(el("div", "card empty",
    s.mode == "allow" ? "In diesem Modus wird nicht gefragt." : "Alles ruhig."));
  for(const p of s.pending){
    const c = el("div", "card req"), top = el("div", "top"), info = el("div", "info");
    info.append(el("b", "", p.desc || p.name), el("div", "path", [fileOf(p.path), p.company].filter(Boolean).join(" · ")));
    top.append(info);
    const facts = el("dl", "facts");
    const fact = (k, v) => { if(v) facts.append(el("dt", "", k), el("dd", "", v)); };
    fact("Will", wants(p) + (p.count > 1 ? " (" + p.count + " Versuche)" : ""));
    fact(p.dir == "in" ? "Von" : "Nach", where(p));
    fact("Port", p.port ? p.port + (p.proto ? " " + p.proto : "") + (PORTS[p.port] ? " – " + PORTS[p.port] : "") : "");
    fact("Datei", p.path);
    const acts = el("div", "acts");
    acts.append(btn("Erlauben", "btn-ok", () => act("decide", {path: p.path, action: "allow"})),
                btn("Sperren", "btn-bad", () => act("decide", {path: p.path, action: "block"})));
    c.append(top, facts, acts); reqs.append(c);
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
    r.append(info,
      tab == "allowed" ? btn("Sperren", "", () => act("decide", {path: p.path, action: "block"}))
                       : btn("Erlauben", "", () => act("decide", {path: p.path, action: "allow"})),
      btn("✕", "link", () => act("forget", {path: p.path}), "Vergessen – beim nächsten Mal wird wieder gefragt"));
    list.append(r);
  }
  fit();
}

$("smaller").onclick = () => step(-0.1);
$("bigger").onclick = () => step(0.1);
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
const tick = () => api("state").then(s => { show(s); fit(); }).catch(() => {});
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
                self._send(200, PAGE.replace("__TOKEN__", token).replace("__VERSION__", VERSION).encode("utf-8"), "text/html")
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
                elif self.path == "/api/scale":
                    with guard.lock:
                        guard.state["scale"] = min(1.5, max(0.5, round(float(body.get("scale")), 1)))
                        guard.save()
                elif self.path == "/api/size":
                    resize_window(float(body.get("dw", 0)), float(body.get("dh", 0)),
                                            min(4.0, max(0.5, float(body.get("dpr", 1)))))
                    return self._send(200, {})
                elif self.path == "/api/autostart":
                    guard.sys.set_autostart(bool(body.get("on")))
                elif self.path in ("/api/reset", "/api/quit"):
                    if self.path == "/api/reset":
                        guard.reset()
                    self._send(200, {})
                    guard.on_quit()
                    return
                else:
                    return self._send(404, {"error": "Unbekannt."})
                self._send(200, self._state())
            except SysError as e:
                self._send(400, {"error": str(e)})
            except (ValueError, TypeError, AttributeError):
                self._send(400, {"error": "Ungueltige Eingabe."})

    class Server(ThreadingHTTPServer):
        allow_reuse_address = platform.system() != "Windows"  # sonst liessen sich zwei Programme gleichzeitig starten
        daemon_threads = True

    return Server(("127.0.0.1", port), Handler)


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
        u.CreatePopupMenu.restype = H
        u.AppendMenuW.argtypes = [H, ctypes.c_uint, ctypes.c_size_t, w.LPCWSTR]
        u.TrackPopupMenu.argtypes = [H, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, H, H]
        u.DestroyMenu.argtypes = [H]
        u.SetForegroundWindow.argtypes = [H]

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
            n.szTip = f"Kleine Firewall {VERSION}\nIn {fmt_rate(rate_in)} - Out {fmt_rate(rate_out)}"[:127]
            note, self.guard.balloon = self.guard.balloon, None
            if note and self.added:
                n.uFlags |= 0x10  # Sprechblase
                n.szInfoTitle, n.szInfo, n.dwInfoFlags = "Kleine Firewall", note[:255], 1
            if self.added:
                sh.Shell_NotifyIconW(1, ctypes.byref(n))
            else:
                self.added = bool(sh.Shell_NotifyIconW(0, ctypes.byref(n)))

        def menu():
            point = w.POINT()
            u.GetCursorPos(ctypes.byref(point))
            popup = u.CreatePopupMenu()
            u.AppendMenuW(popup, 0, 1, "Öffnen")
            u.AppendMenuW(popup, 0x0800, 0, None)  # Trennlinie
            u.AppendMenuW(popup, 0, 2, "Beenden")
            u.SetForegroundWindow(self.hwnd)  # sonst schliesst sich das Menue nicht beim Wegklicken
            choice = u.TrackPopupMenu(popup, 0x0100 | 0x0002 | 0x0080, point.x, point.y, 0, self.hwnd, None)
            u.DestroyMenu(popup)
            if choice == 1:
                open_ui(self.guard.url)
            elif choice == 2 and self.guard.on_quit:
                self.guard.on_quit()

        def wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == 0x0113:  # Zeitgeber
                    tick()
                elif msg == self.ICON_MSG and (lparam & 0xFFFF) in (0x0202, 0x0203, 0x0405):
                    open_ui(self.guard.url)  # Klick auf Symbol oder Sprechblase
                elif msg == self.ICON_MSG and (lparam & 0xFFFF) == 0x0205:  # rechte Maustaste
                    menu()
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

def app_browsers():
    """Browser, die ein eigenes kleines App-Fenster oeffnen koennen: Edge, sonst Chrome."""
    found = []
    for exe, folder in (("msedge.exe", ("Microsoft", "Edge", "Application")),
                        ("chrome.exe", ("Google", "Chrome", "Application"))):
        paths = []
        try:  # wo Windows das Programm eingetragen hat
            import winreg
            for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                try:
                    key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" + "\\" + exe
                    paths.append(winreg.QueryValue(root, key))
                except OSError:
                    pass
        except ImportError:
            pass
        for var in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):  # uebliche Orte
            if os.environ.get(var):
                paths.append(os.path.join(os.environ[var], *folder, exe))
        for path in paths:
            path = (path or "").strip('"')
            if path and os.path.exists(path) and path not in found:
                found.append(path)
    return found


def app_windows(detail=None):
    """Bereits offene Fenster dieser Oberflaeche (nur das eigene App-Fenster, kein Browser-Tab)."""
    if platform.system() != "Windows":
        return []
    from ctypes import wintypes as w
    u = ctypes.windll.user32
    found = []

    def each(hwnd, _):
        title, cls, pid = ctypes.create_unicode_buffer(200), ctypes.create_unicode_buffer(80), w.DWORD(0)
        u.GetWindowTextW(w.HWND(hwnd), title, 200)
        u.GetClassNameW(w.HWND(hwnd), cls, 80)
        u.GetWindowThreadProcessId(w.HWND(hwnd), ctypes.byref(pid))
        own = pid.value == os.getpid() and title.value.endswith("Kleine Firewall")  # eigenes Programmfenster
        browser = cls.value.startswith("Chrome_WidgetWin") and title.value.endswith("Kleine Firewall")
        if (own or browser) and u.IsWindowVisible(w.HWND(hwnd)):
            found.append(hwnd)
            if detail is not None:
                detail.append(f"{cls.value} '{title.value}' eigen={own}")
        return True

    try:
        u.EnumWindows(ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)(each), 0)
    except Exception:
        pass
    return found


def resize_window(dw, dh, dpr):
    """Eigenes App-Fenster um (dw, dh) Seiten-Pixel groesser oder kleiner machen."""
    if platform.system() != "Windows":
        return
    from ctypes import wintypes as w
    u = ctypes.windll.user32
    found = app_windows()
    max_h = int((u.GetSystemMetrics(1) or 2000) * 0.92)
    for hwnd in found:
        hwnd = w.HWND(hwnd)
        if u.IsIconic(hwnd):
            continue
        if u.IsZoomed(hwnd):
            u.ShowWindow(hwnd, 9)  # aus dem Vollbild zurueckholen
        rect = w.RECT()
        if not u.GetWindowRect(hwnd, ctypes.byref(rect)):
            continue
        width = max(120, rect.right - rect.left + round(dw * dpr))
        height = min(max_h, max(100, rect.bottom - rect.top + round(dh * dpr)))
        u.SetWindowPos(hwnd, None, 0, 0, width, height, 0x0002 | 0x0004 | 0x0010)  # nicht verschieben


def open_ui(url):
    """Als kleines App-Fenster oeffnen (Edge ist bei Windows dabei), sonst im Standardbrowser.
    Ist das Fenster schon offen, wird es nur nach vorn geholt - es gibt immer nur eins."""
    if NATIVE["window"] is not None:  # eigenes Programmfenster: einblenden
        try:
            NATIVE["window"].show()
            NATIVE["window"].restore()
        except Exception:
            pass
        for hwnd in app_windows()[:1]:
            ctypes.windll.user32.SetForegroundWindow(ctypes.c_void_p(hwnd))
        return
    for hwnd in app_windows()[:1]:
        from ctypes import wintypes as w
        u = ctypes.windll.user32
        if u.IsIconic(w.HWND(hwnd)):
            u.ShowWindow(w.HWND(hwnd), 9)
        u.SetForegroundWindow(w.HWND(hwnd))
        return
    for browser in app_browsers():
        try:
            subprocess.Popen([browser, f"--app={url}", "--window-size=300,420"])
            return
        except OSError:
            continue
    webbrowser.open(url)


def webview2_version():
    """Version der Anzeige-Komponente von Windows (WebView2), leer wenn sie fehlt."""
    try:
        import winreg
    except ImportError:
        return ""
    guid = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    for root, key in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients"),
                      (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\EdgeUpdate\Clients"),
                      (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\EdgeUpdate\Clients")):
        try:
            with winreg.OpenKey(root, key + "\\" + guid) as k:
                version = winreg.QueryValueEx(k, "pv")[0]
                if version and version != "0.0.0.0":
                    return version
        except OSError:
            pass
    return ""


def selftest(path, guard, tray):
    """Prueft die Windows-Teile, ohne etwas am Rechner zu veraendern, und schreibt das Ergebnis in eine Datei."""
    lines = [f"Kleine Firewall {VERSION} Selbsttest"]

    def check(name, fn, level="FEHLER"):
        try:
            lines.append(f"OK     {name}: {fn()}")
        except Exception as e:
            lines.append(f"{level} {name}: {type(e).__name__}: {e}")

    def window():
        win = NATIVE["window"]
        if win is None:
            raise RuntimeError("kein eigenes Fenster")
        info = win.evaluate_js("document.title + ' | innen ' + innerWidth + 'x' + innerHeight + ' | dpr ' + "
                               "devicePixelRatio + ' | ziel ' + fitGoal + ' | anfragen ' + "
                               "document.querySelectorAll('.req').length + ' | ' + document.querySelector('h1').innerText")
        want = [int(v) for v in str(info).split("ziel ")[1].split(" |")[0].split("x")]
        have = [int(v) for v in str(info).split("innen ")[1].split(" |")[0].split("x")]
        if abs(want[0] - have[0]) > 3 or abs(want[1] - have[1]) > 3:
            raise RuntimeError(f"Groesse passt nicht: {info}")
        return info

    def network():
        net = WinNet()
        net.sample()
        time.sleep(1)
        return f"{net.sample()} Karten: {len(net.prev)}"

    def events():
        ws = WinSystem(Path("."))
        ws.read_events()
        return f"letzter Datensatz {ws.last_record}, neue: {len(ws.read_events())}"

    def devices():
        ws = WinSystem(Path("."))
        ws._load_devices()
        first = next(iter(ws.devices))
        return f"{len(ws.devices)} Laufwerke, {first}\\x.exe -> {ws._to_path(first + chr(92) + 'x.exe')}"

    def tray_state():
        if not tray.added:
            raise RuntimeError(guard.tray_error or "Symbol nicht angelegt")
        return f"Symbol angelegt, {len(tray.icons)} Bilder, Verkehr {guard.net}"

    time.sleep(12)
    notepad = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "notepad.exe")
    check("Anzeige-Komponente", webview2_version)
    found = []
    check("Fensterliste", lambda: (app_windows(found), found)[1], "INFO  ")
    check("Fenster", window)
    check("Datenverkehr", network)
    check("Datei-Angaben", lambda: WinSystem(Path(".")).file_info(notepad) or (_ for _ in ()).throw(RuntimeError("leer")))
    check("Laufwerke", devices)
    check("Ereignisprotokoll", events)
    check("Gegenstelle", lambda: WinSystem(Path(".")).host_name("1.1.1.1"), "INFO  ")
    check("Autostart-Abfrage", lambda: WinSystem(Path(".")).autostart())
    check("Browser-Ersatz", app_browsers, "INFO  ")
    check("Taskleiste", tray_state, "INFO  ")
    check("Fehlermeldung", lambda: guard.error or guard.tray_error or "keine")
    try:
        Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    finally:
        guard.on_quit()


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def say(text):
    if sys.stdout:
        print(text, flush=True)


def run():
    ap = argparse.ArgumentParser(description=f"Kleine Firewall fuer Windows, Version {VERSION}")
    ap.add_argument("--demo", action="store_true", help="nur ansehen, nichts veraendern")
    ap.add_argument("--hintergrund", action="store_true", help="starten, ohne die Oberflaeche zu oeffnen")
    ap.add_argument("--zuruecksetzen", action="store_true", help="alle Regeln entfernen, Windows-Standard herstellen")
    ap.add_argument("--port", type=int, default=PORT, help=argparse.SUPPRESS)
    ap.add_argument("--browser", action="store_true", help="Oberflaeche im Browser statt im eigenen Fenster")
    ap.add_argument("--selbsttest", metavar="DATEI", help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.selbsttest:
        args.demo = True
        threading.Timer(120, lambda: os._exit(3)).start()  # haengt nie fest

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
        try:  # mit echten Bildschirm-Pixeln arbeiten, egal welche Skalierung Windows nutzt
            ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
        except Exception:
            pass
        state_dir = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / APP
        state_dir.mkdir(parents=True, exist_ok=True)
        system = WinSystem(state_dir)
        system.protect_folder()

    ui_file = state_dir / "ui.json"
    LOG["file"] = state_dir / "log.txt"
    log(f"Start Version {VERSION} {sys.argv[1:]} aus {sys.executable}")
    threading.excepthook = lambda a: log("Fehler in Nebenaufgabe: " + "".join(
        traceback.format_exception(a.exc_type, a.exc_value, a.exc_traceback))[-1500:])
    if args.zuruecksetzen:
        Guard(system, state_dir, "").reset()
        say("Zurueckgesetzt: Regeln entfernt, ausgehende Verbindungen wieder erlaubt.")
        return 0

    token = secrets.token_urlsafe(24)
    guard = Guard(system, state_dir, "")
    server = None
    for attempt in range(30):
        try:
            server = make_server(guard, token, args.port)
            break
        except OSError:
            if attempt == 0:  # laeuft schon (evtl. aeltere Version) -> diese beenden und uebernehmen
                log("Programm laeuft bereits - bitte es, sich zu beenden")
                try:
                    old = json.loads(ui_file.read_text(encoding="utf-8"))["url"].split("?t=")[1]
                    req = urllib.request.Request(f"http://127.0.0.1:{args.port}/api/quit", data=b"{}", method="POST",
                                                 headers={"X-Token": old, "Content-Type": "application/json"})
                    urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5).read()
                except Exception as e:
                    log(f"Beenden der laufenden Version nicht moeglich: {e}")
            time.sleep(0.5)
    if server is None:
        message("Kleine Firewall läuft bereits und ließ sich nicht ablösen.\n\n"
                "Bitte im Task-Manager alle Einträge 'KleineFirewall' beenden und neu starten.")
        return 1
    log("Bereit, Anschluss belegt")
    url = f"http://127.0.0.1:{server.server_port}/?t={token}"
    ui_file.write_text(json.dumps({"url": url}), encoding="utf-8")

    guard.url = url

    done = threading.Event()
    tray = None

    def quit_all():  # Knopf "Beenden", Zuruecksetzen oder Menue in der Taskleiste
        NATIVE["quitting"] = True
        for hwnd in app_windows():
            ctypes.windll.user32.PostMessageW(ctypes.c_void_p(hwnd), 0x0010, 0, 0)
        done.set()

        def force():  # falls das Fenster das Beenden blockiert
            if tray:
                tray.close()
            os._exit(0)
        timer = threading.Timer(6, force)
        timer.daemon = True
        timer.start()
        if NATIVE["window"] is not None:
            try:
                NATIVE["window"].destroy()
            except Exception:
                pass
    guard.on_quit = quit_all
    if guard.state["mode"] in ("ask", "quiet") and not system.demo:
        try:
            system.enable_log()
        except SysError as e:
            guard.error = str(e)
    if not system.demo:
        try:  # Dateiname enthaelt die Versionsnummer -> Autostart auf diese Datei umstellen
            if system.autostart():
                system.set_autostart(True)
        except SysError:
            pass
    threading.Thread(target=guard.watch, daemon=True).start()
    on_windows = platform.system() == "Windows"
    tray = Tray(guard) if on_windows and (not system.demo or args.selbsttest) else None
    if tray:
        tray.start()
    say("Kleine Firewall laeuft. Oberflaeche:\n  " + url)
    for hwnd in app_windows():  # Fenster eines frueheren Laufs schliessen - sie sind nicht mehr verbunden
        ctypes.windll.user32.PostMessageW(ctypes.c_void_p(hwnd), 0x0010, 0, 0)
        time.sleep(0.3)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if args.selbsttest:
        guard.set_mode("ask")
        threading.Thread(target=selftest, args=(args.selbsttest, guard, tray), daemon=True).start()

    started = False
    if on_windows and not args.browser and webview2_version():
        try:  # eigenes Programmfenster
            import webview
            win = webview.create_window("Kleine Firewall", url, width=330, height=480,
                                        hidden=args.hintergrund, min_size=(150, 100))

            def closing():  # Schliessen-Kreuz blendet nur aus; das Programm laeuft in der Taskleiste weiter
                if NATIVE["quitting"]:
                    return True
                win.hide()
                return False
            win.events.closing += closing
            NATIVE["window"] = win
            started = True
            log("Eigenes Fenster wird geoeffnet")
            webview.start()  # kehrt zurueck, wenn das Fenster endgueltig geschlossen wird
        except Exception as e:
            log("Eigenes Fenster: " + traceback.format_exc()[-1500:])
            NATIVE["window"] = None
            if started:
                done.set()
            else:
                guard.tray_error = f"Eigenes Fenster nicht verfuegbar ({e}) - Anzeige im Browser."
    if not started:
        log("Anzeige ueber Browser")
        if not args.hintergrund:
            open_ui(url)
        try:
            while not done.wait(1):
                pass
        except KeyboardInterrupt:
            pass
    log("Ende")
    guard.stop.set()
    if tray:
        tray.close()
    server.shutdown()
    server.server_close()
    return 0


def main():
    try:
        return run()
    except Exception:
        log(traceback.format_exc())
        message("Kleine Firewall konnte nicht starten:\n\n" + traceback.format_exc()[-900:])
        return 1


if __name__ == "__main__":
    sys.exit(main())
