import os
import re
import io
import json
import time
import math
import pytz
import zipfile
import tempfile
import logging
import datetime
import sqlite3
import requests
import rarfile
import py7zr
import asyncio

import discord
from discord.ext import commands, tasks
from discord import Embed
from discord.ui import View, Button

from dotenv import load_dotenv

# Optional AI libs (if keys present)
try:
    from openai import OpenAI
except Exception:
    OpenAI = None
try:
    import google.generativeai as genai
except Exception:
    genai = None

# ---------------- logging ----------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("harmony-guardian")

# ---------------- load env ----------------
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
# ALLOWED_CHANNELS: comma separated channel IDs (integers)
ALLOWED_CHANNELS = [int(x.strip()) for x in os.getenv("ALLOWED_CHANNELS", "").split(",") if x.strip().isdigit()]

# Timezone
TZ = pytz.timezone("Asia/Jakarta")

if not DISCORD_TOKEN:
    raise ValueError("DISCORD_TOKEN missing in .env")

# ---------------- constants ----------------
SUPPORTED_EXTS = {".lua", ".luac", ".txt", ".zip", ".7z", ".rar", ".py", ".js", ".php", ".asi", ".cs", ".csa", ".cleo", ".dll", ".exe"}
MAX_SIZE = 20 * 1024 * 1024  # 20MB
MAX_ARCHIVE_FILES = 20
DANGER_LEVELS = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "VERY SUSPICIOUS": "🟠", "DANGEROUS": "🔴"}
LEVEL_ORDER = ["SAFE", "SUSPICIOUS", "VERY SUSPICIOUS", "DANGEROUS"]

# ---------------- DB ----------------
conn = sqlite3.connect('scans.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS scans 
                  (user_id INTEGER, file_name TEXT, analyst TEXT, result TEXT, level TEXT, timestamp TEXT, confidence INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS stats 
                  (user_id INTEGER PRIMARY KEY, scans_today INTEGER DEFAULT 0, last_reset TEXT)''')
conn.commit()

# ---------------- concurrency & cache ----------------
ongoing_scans = set()
scan_cache = {}  # {user_id: {"json":..., "txt":..., "timestamp":...}}

# ---------------- heuristics ----------------
SUSPICIOUS_KEYWORDS = [
    "os.execute", "io.popen", "token", "keylog", "base64", "discord.com/api/webhooks",
    "SetWindowsHookEx", "keybd_event", "sampGetCurrentServerAddress", "GetAsyncKeyState",
    "CreateFile", "WriteFile", "InternetOpenUrlA", "HttpSendRequest", "MapVirtualKey",
    "clipboard", "getclipboard", "getpass", "authorization", "bearer"
]
EXPLANATION_MAP = {
    "SetWindowsHookEx": "Memantau input keyboard/mouse, sering digunakan untuk keylogger.",
    "keybd_event": "Menyimulasikan input keyboard, berpotensi untuk keylogger.",
    "sampGetCurrentServerAddress": "Mengambil alamat server game, bisa untuk mencuri data peta.",
    "keylog": "Kode untuk mencatat input keyboard, berisiko mencuri data sensitif.",
    "token": "Mencuri token login, sering digunakan untuk hack akun.",
    "base64": "Menyembunyikan kode, sering dipakai malware untuk sembunyi.",
    "discord.com/api/webhooks": "Mengirim data ke Discord, bisa untuk curi info akun.",
    "GetAsyncKeyState": "Memantau status tombol keyboard — indikasi keylogger.",
    "CreateFile": "Fungsi buat buka/tulis file — bisa dipakai stealer/dropper.",
    "WriteFile": "Menulis ke file — bisa membuat file log/data curian.",
    "InternetOpenUrlA": "Memungkinkan program mengirim/mengambil data lewat HTTP.",
    "HttpSendRequest": "Mengirim data ke server eksternal — kemungkinan exfiltration.",
    "clipboard": "Akses clipboard dapat mencuri teks sensitif yang disalin pengguna."
}
PURPOSE_MAP = {
    "keylogger": ["GetAsyncKeyState", "SetWindowsHookEx", "keylog", "keybd_event", "keyboard.read_key"],
    "stealer": ["CreateFile", "WriteFile", "sampGetCurrentServerAddress", "discord.com/api/webhooks", "token", "clipboard", "getclipboard"],
    "exfiltration": ["InternetOpenUrlA", "HttpSendRequest", "socket.connect", "fetch", "send"],
    "obfuscation": ["base64", "eval", "loadstring", "decode", "xor", "rot13"],
    "rce": ["os.execute", "io.popen", "system", "exec", "subprocess"],
    "rat": ["socket.connect", "bind", "listen", "accept"]
}

# ---------------- helpers: entropy & obfuscation ----------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return - sum(p * math.log2(p) for p in prob)

def detect_obfuscation_in_text(text: str):
    """Detect suspicious encoded/obfuscated patterns and return list of findings."""
    findings = []
    # long base64-like runs
    for m in re.finditer(r'([A-Za-z0-9+/=]{50,})', text):
        chunk = m.group(1)
        ent = shannon_entropy(chunk)
        findings.append({"type":"base64_string","sample": chunk[:120] + ("..." if len(chunk)>120 else ""), "entropy": ent})
    # hex blobs
    hex_chunks = re.findall(r'(?:\\x[0-9A-Fa-f]{2}){8,}', text)
    for hx in hex_chunks:
        findings.append({"type":"hex_blob","sample": hx[:120] + ("..." if len(hx)>120 else ""), "entropy": shannon_entropy(hx)})
    # loadstring + decode pattern
    if re.search(r'loadstring\s*\(|load\(|assert\(', text, re.IGNORECASE) and re.search(r'base64|decode|unpack|string\.char', text, re.IGNORECASE):
        findings.append({"type":"loadstring_obf","sample":"loadstring/decode pattern", "entropy": 7.0})
    # high entropy long chunk
    for chunk in re.findall(r'([A-Za-z0-9+/=~\-_]{100,})', text):
        ent = shannon_entropy(chunk)
        if ent > 4.5:
            findings.append({"type":"high_entropy_blob","sample": chunk[:120]+"...", "entropy": ent})
    return findings

# ---------------- static scan ----------------
def static_scan_file(filepath):
    suspicious_found = []
    content_text = ""
    try:
        ext = os.path.splitext(filepath)[1].lower()
        if ext in {".lua", ".luac", ".cleo", ".csa", ".cs", ".txt", ".py", ".js", ".php", ".asi"}:
            with open(filepath, "r", errors="ignore") as f:
                lines = f.readlines()
            content_text = "".join(lines)
            for i, line in enumerate(lines, start=1):
                lower = line.lower()
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw.lower() in lower:
                        suspicious_found.append((i, kw, line.strip(), EXPLANATION_MAP.get(kw, "Pola mencurigakan")))
                for purpose, patterns in PURPOSE_MAP.items():
                    for p in patterns:
                        if p.lower() in lower:
                            suspicious_found.append((i, p, line.strip(), EXPLANATION_MAP.get(p, f"Indikasi {purpose}.")))
            # obfuscation on whole
            obfs = detect_obfuscation_in_text(content_text)
            for ob in obfs:
                suspicious_found.append((0, ob["type"], ob["sample"], f"Terindikasi obfuscation (entropy={ob['entropy']:.2f})"))
        else:
            with open(filepath, "rb") as f:
                raw = f.read()
            chunks = re.findall(b'[ -~]{4,}', raw)
            text = "\n".join([c.decode(errors="ignore") for c in chunks])
            content_text = text
            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in text.lower():
                    suspicious_found.append((0, kw, "<binary>", EXPLANATION_MAP.get(kw, "API mencurigakan.")))
            # obfuscation
            obfs = detect_obfuscation_in_text(text)
            for ob in obfs:
                suspicious_found.append((0, ob["type"], ob["sample"], f"Terindikasi obfuscation (entropy={ob['entropy']:.2f})"))
    except Exception as e:
        logger.error("Static read error: %s", e)
        suspicious_found.append((-1, "Error", str(e), "Gagal membaca file untuk analisis."))
    return suspicious_found, content_text

def static_scan_text(content: str):
    suspicious_found = []
    content_text = content
    try:
        lines = content.splitlines()
        for i, line in enumerate(lines, start=1):
            lower = line.lower()
            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in lower:
                    suspicious_found.append((i, kw, line.strip(), EXPLANATION_MAP.get(kw, "Pola mencurigakan")))
            for purpose, patterns in PURPOSE_MAP.items():
                for p in patterns:
                    if p.lower() in lower:
                        suspicious_found.append((i, p, line.strip(), EXPLANATION_MAP.get(p, f"Indikasi {purpose}.")))
        obfs = detect_obfuscation_in_text(content_text)
        for ob in obfs:
            suspicious_found.append((0, ob["type"], ob["sample"], f"Terindikasi obfuscation (entropy={ob['entropy']:.2f})"))
    except Exception as e:
        logger.error("Static text error: %s", e)
        suspicious_found.append((-1, "Error", str(e), "Gagal menganalisis teks."))
    return suspicious_found, content_text

# ---------------- VirusTotal ----------------
def scan_with_virustotal(filepath):
    if not VT_API_KEY:
        return None
    try:
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": VT_API_KEY}
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            response = requests.post(url, headers=headers, files=files, timeout=30)
        if response.status_code == 200:
            return response.json()["data"]["id"]
        logger.warning("VT upload failed: %s %s", response.status_code, response.text[:200])
    except Exception as e:
        logger.error("VT upload exception: %s", e)
    return None

def get_scan_result(analysis_id):
    if not analysis_id or not VT_API_KEY:
        return None
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    for _ in range(6):
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                rj = response.json()
                status = rj.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return rj
            time.sleep(5)
        except Exception as e:
            logger.error("VT get result error: %s", e)
            time.sleep(3)
    return None

# ---------------- AI integration ----------------
deepseek_client = None
if DEEPSEEK_API_KEY and OpenAI:
    try:
        deepseek_client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1")
    except Exception as e:
        logger.error("DeepSeek init error: %s", e)

if GEMINI_API_KEY and genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception as e:
        logger.error("Gemini init error: %s", e)

# parse AI outputs robustly
def parse_ai_response(text):
    level_match = re.search(r'(SAFE|SUSPICIOUS|VERY SUSPICIOUS|DANGEROUS)', text, re.IGNORECASE)
    conf_match = re.search(r'confidence[:\s]*(\d+)', text, re.IGNORECASE)
    level = level_match.group(1).upper() if level_match else "SUSPICIOUS"
    conf = int(conf_match.group(1)) if conf_match else 50
    if any(kw in text.lower() for kw in ["keylog", "setwindowshookex", "keybd_event", "sampgetcurrentserveraddress"]):
        conf = max(conf, 80)
    explanation = text.strip()[:1200]
    return level, conf, explanation

async def analyze_with_ai(content):
    prompt = f"""Analyze this code for security issues, malware, or exploits in Lua/game mods.
Rate danger level exactly as: SAFE, SUSPICIOUS, VERY SUSPICIOUS, or DANGEROUS.
Provide a confidence score (0-100%) and brief explanation in Indonesian if possible.
Code: {content[:4000]}"""

    results = []
    # DeepSeek
    if deepseek_client:
        try:
            response = deepseek_client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role":"user","content":prompt}],
                max_tokens=500
            )
            text = response.choices[0].message.content
            results.append(parse_ai_response(text))
        except Exception as e:
            logger.error("DeepSeek error: %s", e)
    # Gemini
    if GEMINI_API_KEY and genai:
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = await model.generate_content_async(prompt)
            txt = response.text if hasattr(response, 'text') else str(response)
            results.append(parse_ai_response(txt))
        except Exception as e:
            logger.error("Gemini error: %s", e)
    # OpenAI
    if OPENAI_API_KEY and OpenAI:
        try:
            client = OpenAI(api_key=OPENAI_API_KEY)
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role":"user","content":prompt}],
                max_tokens=700
            )
            text = resp.choices[0].message.content
            results.append(parse_ai_response(text))
        except Exception as e:
            logger.error("OpenAI error: %s", e)

    # Fallback
    if not results:
        sf, _ = static_scan_text(content)
        score = len(sf)
        if score == 0:
            return "SAFE", 60, "Static heuristic: tidak ditemukan pola mencurigakan."
        if score <= 2:
            return "SUSPICIOUS", 75, f"Static heuristic: {score} pola mencurigakan."
        if score <= 6:
            return "VERY SUSPICIOUS", 85, f"Static heuristic: {score} pola mencurigakan."
        return "DANGEROUS", 95, f"Static heuristic: {score} pola berbahaya terdeteksi."

    # Aggregate results
    level_votes = {}
    for level, conf, exp in results:
        level_votes[level] = level_votes.get(level, 0) + 1
    majority_level = max(level_votes, key=lambda k: (level_votes[k], LEVEL_ORDER.index(k)))
    confs = [c for l, c, _ in results if l == majority_level]
    conf = sum(confs) / len(confs) if confs else 50
    exps = [e for l, _, e in results if l == majority_level]
    explanation = " | ".join(exps[:2])
    return majority_level, conf, explanation

# ---------------- archive extraction ----------------
def extract_archive(filepath):
    files = []
    ext = os.path.splitext(filepath)[1].lower()
    temp_dir = tempfile.mkdtemp()
    try:
        if ext == ".zip":
            with zipfile.ZipFile(filepath) as z:
                z.extractall(temp_dir)
        elif ext == ".rar":
            with rarfile.RarFile(filepath) as r:
                r.extractall(temp_dir)
        elif ext == ".7z":
            with py7zr.SevenZipFile(filepath, mode='r') as s:
                s.extractall(temp_dir)
        for root, _, fs in os.walk(temp_dir):
            for f in fs:
                full = os.path.join(root, f)
                if (os.path.splitext(f)[1].lower() in SUPPORTED_EXTS - {".zip", ".rar", ".7z"}
                    and os.path.getsize(full) <= MAX_SIZE):
                    files.append(full)
        files = files[:MAX_ARCHIVE_FILES]
    except Exception as e:
        logger.error("Extract error: %s", e)
    return files

# ---------------- purpose detection ----------------
def detect_purpose(static_findings_text, ai_explanation_text, vt_stats):
    text = (static_findings_text or "") + " " + (ai_explanation_text or "")
    text_l = text.lower()
    counts = {}
    for purpose, keys in PURPOSE_MAP.items():
        for k in keys:
            if k.lower() in text_l:
                counts[purpose] = counts.get(purpose, 0) + 1
    vt_score = 0
    try:
        vt_mal = vt_stats.get("malicious", 0)
        vt_susp = vt_stats.get("suspicious", 0)
        vt_score = vt_mal * 3 + vt_susp * 1
    except:
        vt_score = 0
    if counts:
        chosen = max(counts.items(), key=lambda kv: kv[1])[0]
        base_conf = min(95, 40 + counts[chosen]*20 + vt_score*5)
        friendly = {
            "keylogger": "Keylogger / Merekam penekanan tombol",
            "stealer": "Pengambil data (stealer) — mencoba akses/ambil file atau token",
            "exfiltration": "Pengiriman/Exfiltrasi data ke server eksternal",
            "obfuscation": "Kode terobfuskasi/encoded (mencurigakan)",
            "rce": "Remote command execution (jalankan perintah sistem)",
            "rat": "Remote Access Trojan (kontrol jarak jauh)"
        }
        return friendly.get(chosen, chosen), int(base_conf)
    else:
        if vt_score > 0:
            conf = min(95, 30 + vt_score*10)
            return "Malware / Berbahaya (deteksi VT)", int(conf)
        return "Tidak jelas / kemungkinan fungsi normal", 30

# ---------------- core scan ----------------
async def do_scan(filepath, progress_msg, user_id, original_name=None):
    ext = os.path.splitext(filepath)[1].lower()
    is_archive = ext in {".zip", ".7z", ".rar"}
    sub_results = []
    static_findings = []
    static_text = ""
    ai_exp = ""
    vt_stats = {"malicious":0,"suspicious":0,"undetected":0}
    vt_text = "VirusTotal tidak tersedia."

    if is_archive:
        subfiles = extract_archive(filepath)
        if not subfiles:
            raise ValueError("Gagal mengekstrak arsip.")
        for i, sub in enumerate(subfiles):
            try:
                with open(sub, "r", errors="ignore") as f:
                    content = f.read()[:4000]
                lvl, conf, exp = await analyze_with_ai(content)
                sub_results.append((os.path.basename(sub), lvl, conf, exp))
                os.unlink(sub)
            except Exception as e:
                logger.error("Subfile scan error: %s", e)
            await progress_msg.edit(content=f"📦 Memindai arsip {i+1}/{len(subfiles)}")
        overall_level = max([r[1] for r in sub_results], key=lambda x: LEVEL_ORDER.index(x)) if sub_results else "SAFE"
        conf = sum([r[2] for r in sub_results]) / len(sub_results) if sub_results else 50
        explanation = f"Arsip: {len(sub_results)} file. Tingkat tertinggi: {overall_level}."
        static_agg_text = " ".join([r[3] for r in sub_results])
        purpose, pconf = detect_purpose(static_agg_text, explanation, {})
    else:
        # read content for analysis
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()[:40000]
        await progress_msg.edit(content="🤖 Memindai dengan AI...")
        level, conf_ai, ai_exp = await analyze_with_ai(content)
        await progress_msg.edit(content="🧪 Memindai pola & VirusTotal...")
        static_findings, static_text = static_scan_file(filepath)
        # VT
        analysis_id = None
        if os.path.getsize(filepath) <= MAX_SIZE and VT_API_KEY:
            analysis_id = scan_with_virustotal(filepath)
        if analysis_id:
            time.sleep(5)
            res = get_scan_result(analysis_id)
            if res:
                stats = res["data"]["attributes"]["stats"]
                vt_stats = {"malicious": stats.get("malicious",0), "suspicious": stats.get("suspicious",0), "undetected": stats.get("undetected",0)}
                vt_text = f"Malicious: {vt_stats['malicious']}, Suspicious: {vt_stats['suspicious']}, Clean: {vt_stats['undetected']}"
        else:
            if VT_API_KEY:
                vt_text = "Gagal upload ke VirusTotal (rate limit / error) atau file > MAX_SIZE."
            else:
                vt_text = "VirusTotal API key tidak tersedia."

        # determine overall
        levels = [level]
        if static_findings:
            levels.append("SUSPICIOUS")
        if vt_stats.get("malicious",0) > 0:
            levels.append("DANGEROUS")
        if any("obfusc" in (str(f[1]).lower()) for f in static_findings):
            levels.append("VERY SUSPICIOUS")
        overall_level = max(levels, key=lambda x: LEVEL_ORDER.index(x))
        conf = max(conf_ai if isinstance(conf_ai,(int,float)) else 50, 80 if vt_stats.get("malicious",0)>0 else 0)
        explanation = f"AI: {ai_exp}\nStatic Count: {len(static_findings)} issues.\nVT: {vt_text}"
        static_concat = " ".join([str(f[3]) for f in static_findings]) if static_findings else static_text
        purpose, pconf = detect_purpose(static_concat, ai_exp, vt_stats)

    # bump if keylogger
    if any("keylog" in (str(s[1]).lower()) for s in (static_findings if not is_archive else [])):
        overall_level = max(overall_level, "DANGEROUS", key=lambda x: LEVEL_ORDER.index(x))
        conf = max(conf, 85)

    # build report
    report_file_name = original_name or os.path.basename(filepath)
    result_json = {"level":overall_level, "confidence":int(conf), "explanation":explanation, "purpose":purpose}
    cursor.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (user_id, report_file_name, "auto", json.dumps(result_json, ensure_ascii=False), overall_level, datetime.datetime.now().isoformat(), int(conf)))
    conn.commit()

    report = {
        "file": report_file_name,
        "level": overall_level,
        "confidence": conf,
        "purpose": purpose,
        "explanation": explanation,
        "vt": vt_stats,
        "static_count": len(static_findings),
        "subfiles": [{"name": r[0], "level": r[1], "conf": r[2]} for r in sub_results] if is_archive else [],
    }

    # add obfuscation summary
    obf_list = []
    if static_findings:
        for s in static_findings:
            if isinstance(s[1], str) and "obfusc" in s[1].lower() or (isinstance(s[0], int) and s[0]==0 and ("base64" in str(s[1]).lower() or "high_entropy" in str(s[1]).lower())):
                obf_list.append({"line": s[0], "type": s[1], "sample": s[2], "note": s[3]})
    if obf_list:
        report["obfuscation"] = obf_list

    json_report = json.dumps(report, indent=2, ensure_ascii=False)
    txt_report_lines = [
        "┌───────────────── Raxt Community Scanner ─────────────────┐",
        f"│ Status: {DANGER_LEVELS.get(overall_level,'🟡')} {overall_level}",
        f"│ File: {report_file_name}",
        f"│ Skor: {conf:.1f}%",
        f"│ Tujuan: {purpose}",
        f"│ Penjelasan: {explanation[:400]}...",
        f"│ Static Findings: {len(static_findings)}",
        f"│ VT: {vt_text}",
    ]
    if obf_list:
        txt_report_lines.append("│ Deteksi Obfuscation:")
        for ob in obf_list[:8]:
            txt_report_lines.append(f"│ - {ob.get('type')}: {ob.get('note')}")
    txt_report_lines.append("└───────────────── Powered by Raxt Community ─────────────┘")
    txt_report = "\n".join(txt_report_lines)

    # write temp files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as jf:
        jf.write(json_report)
        json_path = jf.name
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as tf:
        tf.write(txt_report)
        txt_path = tf.name

    return overall_level, conf, purpose, explanation, [json_path, txt_path], sub_results, report

# ---------------- UI: Export View ----------------
class ExportView(View):
    def __init__(self, user_id, report_json, report_txt):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.report_json = report_json
        self.report_txt = report_txt

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.user_id

    @discord.ui.button(label="📁 Export JSON", style=discord.ButtonStyle.secondary)
    async def export_json(self, interaction: discord.Interaction, button: discord.ui.Button):
        buf = io.BytesIO(self.report_json.encode("utf-8"))
        filename = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        await interaction.response.send_message(file=discord.File(buf, filename), ephemeral=True)

    @discord.ui.button(label="📄 Export TXT", style=discord.ButtonStyle.secondary)
    async def export_txt(self, interaction: discord.Interaction, button: discord.ui.Button):
        buf = io.BytesIO(self.report_txt.encode("utf-8"))
        filename = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        await interaction.response.send_message(file=discord.File(buf, filename), ephemeral=True)

    @discord.ui.button(label="🗑️ Hapus Laporan", style=discord.ButtonStyle.danger)
    async def delete_cache(self, interaction: discord.Interaction, button: discord.ui.Button):
        if scan_cache.get(self.user_id):
            del scan_cache[self.user_id]
        await interaction.response.send_message("🧹 Laporan dihapus dari cache.", ephemeral=True)

# ---------------- ScanButtons (kept for backward) ----------------
class ScanButtons(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Scan File", style=discord.ButtonStyle.green, emoji="🔍")
    async def scan_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("📤 Silakan unggah file untuk di-scan!", ephemeral=True)

    @discord.ui.button(label="Bantuan", style=discord.ButtonStyle.blurple, emoji="❓")
    async def help_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = Embed(title="🛡️ Raxt Community Scanner - Bantuan",
                      description="🔒 Bot keamanan untuk memindai file Lua/mod, dibuat oleh Raxt Community.",
                      color=0x00b7eb)
        embed.add_field(name="🔍 Cara Pakai", value="• Upload File: Ketik `!scan` lalu unggah file.\n• URL: `!scan <URL>`\n• Otomatis: Unggah file di channel yang diizinkan.", inline=False)
        embed.add_field(name="⚙️ Perintah", value="`!scan` - Scan file/URL\n`!history [n]` - Lihat riwayat scan\n`!help` - Bantuan", inline=False)
        embed.add_field(name="📁 File Didukung", value="Supported: .lua, .luac, .asi, .csa, .cs, .cleo, .txt, .zip, .7z, .rar, .dll, .exe (max 20MB)", inline=False)
        embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
        await interaction.response.send_message(embed=embed, ephemeral=True)

# ---------------- greeting & prayer config ----------------
MORNING_QUOTES = [
    "Selamat pagi! 🌞 Hari baru, semangat baru. Kamu pasti bisa!",
    "Bangun, bersyukur, dan lakukan satu hal produktif hari ini 💪",
    "Selamat pagi — jangan lupa senyum dan mulai hari dengan niat baik."
]
DAKWAH_MESSAGES = [
    "Jumat berkah! Yuk sholat Jumat dan sebarkan kebaikan.",
    "Ingat untuk selalu peduli dan berbagi rezeki kepada sesama."
]
UNIVERSAL_REMINDERS = [
    {"name":"Doa Harian","time":"20:00","msg":"🕊️ Luangkan waktu untuk doa/refleksi malam ini."},
    {"name":"Kebaktian Minggu","time":"08:00","msg":"⛪ Waktunya kebaktian minggu. Semoga damai menyertai."}
]
PRAYER_SCHEDULE = {
    "04:30":"Subuh",
    "12:00":"Dzuhur",
    "15:15":"Ashar",
    "18:00":"Maghrib",
    "19:30":"Isya"
}

# ---------------- Helper time funcs ----------------
def now_jakarta():
    return datetime.datetime.now(TZ)

def fmt_now_jakarta():
    return now_jakarta().strftime("%A, %d %B %Y • %H:%M:%S WIB")

# ---------------- Bot init ----------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# ---------------- tasks: greetings & reminders ----------------
@tasks.loop(minutes=1)
async def scheduled_tasks():
    now = now_jakarta()
    hhmm = now.strftime("%H:%M")
    # greeting times (06:00,12:00,17:30,21:00)
    if hhmm == "06:00":
        await broadcast_message_random("morning")
    if hhmm == "12:00":
        await broadcast_message_random("noon")
    if hhmm == "17:30":
        await broadcast_message_random("afternoon")
    if hhmm == "21:00":
        await broadcast_message_random("night")
    # prayer times
    for t, name in PRAYER_SCHEDULE.items():
        if hhmm == t:
            await broadcast_prayer(name)
    # universal reminders
    for rem in UNIVERSAL_REMINDERS:
        if hhmm == rem["time"]:
            await broadcast_custom(rem["msg"])
    # friday dakwah at 11:30
    if now.weekday() == 4 and hhmm == "11:30":  # Friday
        await broadcast_dakwah()

async def broadcast_message_random(when):
    msg = random.choice(MORNING_QUOTES)
    for guild in bot.guilds:
        for ch in guild.text_channels:
            if ch.id in ALLOWED_CHANNELS:
                try:
                    embed = Embed(title="🌅 Salam", description=f"{msg}\n\n🕓 {fmt_now_jakarta()}", color=0x00BFFF)
                    await ch.send(embed=embed)
                except Exception as e:
                    logger.debug("Broadcast error: %s", e)

async def broadcast_prayer(name):
    text = PRAYER_SCHEDULE_INV = None
    # find message
    msg = None
    for k,v in PRAYER_SCHEDULE.items():
        if v == name:
            msg = PRAYER_SCHEDULE.get(f) if False else None
    # fallback
    short_map = {
        "Subuh":"🕌 Waktunya Sholat Subuh!",
        "Dzuhur":"🕌 Waktunya Sholat Dzuhur!",
        "Ashar":"🕌 Waktunya Sholat Ashar!",
        "Maghrib":"🕌 Waktunya Sholat Maghrib!",
        "Isya":"🕌 Waktunya Sholat Isya!"
    }
    text = short_map.get(name, f"🕌 Waktunya {name}!")
    for guild in bot.guilds:
        for ch in guild.text_channels:
            if ch.id in ALLOWED_CHANNELS:
                try:
                    embed = Embed(title=f"🕋 Pengingat Ibadah - {name}", description=f"{text}\n\n🕓 {fmt_now_jakarta()}", color=0xFFD700)
                    await ch.send(embed=embed)
                except Exception as e:
                    logger.debug("Prayer broadcast error: %s", e)

async def broadcast_custom(msg):
    for guild in bot.guilds:
        for ch in guild.text_channels:
            if ch.id in ALLOWED_CHANNELS:
                try:
                    embed = Embed(title="📣 Pengingat", description=f"{msg}\n\n🕓 {fmt_now_jakarta()}", color=0x00b7eb)
                    await ch.send(embed=embed)
                except Exception as e:
                    logger.debug("Custom broadcast error: %s", e)

async def broadcast_dakwah():
    msg = random.choice(DAKWAH_MESSAGES)
    for guild in bot.guilds:
        for ch in guild.text_channels:
            if ch.id in ALLOWED_CHANNELS:
                try:
                    embed = Embed(title="📖 Dakwah Jumat", description=f"{msg}\n\n🕓 {fmt_now_jakarta()}", color=0x8A2BE2)
                    await ch.send(embed=embed)
                except Exception as e:
                    logger.debug("Dakwah broadcast error: %s", e)

@scheduled_tasks.before_loop
async def before_scheduled_tasks():
    await bot.wait_until_ready()

# ---------------- COMMANDS ----------------
@bot.command()
@commands.cooldown(1, 40, commands.BucketType.user)
async def scan(ctx, url: str = None):
    # restrict to allowed channels
    if ALLOWED_CHANNELS and ctx.channel.id not in ALLOWED_CHANNELS:
        await ctx.reply("⚠️ Perintah hanya diizinkan di channel khusus.")
        return

    user_id = ctx.author.id
    today = datetime.date.today().isoformat()
    cursor.execute("SELECT scans_today FROM stats WHERE user_id=? AND last_reset=?", (user_id, today))
    row = cursor.fetchone()
    scans_today = row[0] if row else 0
    if scans_today >= 50:
        await ctx.send("❌ Batas harian tercapai! Coba besok.")
        return
    cursor.execute("INSERT OR REPLACE INTO stats (user_id, scans_today, last_reset) VALUES (?, ?, ?)",
                   (user_id, scans_today + 1, today))
    conn.commit()

    if len(ongoing_scans) >= 3:
        await ctx.send("⏳ Antrian penuh (maks 3). Coba lagi sebentar.")
        return
    ongoing_scans.add(user_id)

    progress_msg = await ctx.send("⏳ Memulai scan...")
    filepath = None
    filename_for_report = None
    try:
        # handle URL
        if url:
            filename = url.split("/")[-1] or "file"
            downloaded = await download_from_url(url, filename)
            if not downloaded:
                await progress_msg.edit(content="❌ Gagal mengunduh dari URL.")
                ongoing_scans.discard(user_id)
                return
            filepath = downloaded
            filename_for_report = filename
            await progress_msg.edit(content=f"📥 Berhasil mengunduh {filename_for_report}")
        else:
            if not ctx.message.attachments:
                await progress_msg.edit(content="❌ Unggah file atau beri URL.")
                ongoing_scans.discard(user_id)
                return
            attachment = ctx.message.attachments[0]
            if attachment.size > MAX_SIZE:
                await progress_msg.edit(content=f"⚠️ File > {MAX_SIZE//1024//1024}MB, hanya static scan akan dilakukan.")
            ext = os.path.splitext(attachment.filename)[1].lower()
            if ext not in SUPPORTED_EXTS:
                await progress_msg.edit(content="❌ Ekstensi file tidak didukung.")
                ongoing_scans.discard(user_id)
                return
            with tempfile.NamedTemporaryFile(delete=False, suffix=ext, prefix="raxt_") as tmp:
                temp_path = tmp.name
            await attachment.save(temp_path)
            filepath = temp_path
            filename_for_report = attachment.filename
            await progress_msg.edit(content=f"📂 Memuat {filename_for_report}")

        # run core scan
        overall_level, conf, purpose, explanation, report_paths, sub_results, report_dict = await do_scan(filepath, progress_msg, user_id, original_name=filename_for_report)
        await progress_msg.edit(content="✅ Scan selesai! 100%")

        color_map = {"SAFE":0x00ff00,"SUSPICIOUS":0xffff00,"VERY SUSPICIOUS":0xffa500,"DANGEROUS":0xff0000}
        embed = Embed(title="🔍 Raxt Community - Hasil Scan",
                      description=(f"**File**: `{filename_for_report}`\n**Status**: {DANGER_LEVELS.get(overall_level,'🟡')} **{overall_level}**\n**Confidence**: {conf:.1f}%\n**Purpose**: {purpose}\n\n**Ringkasan**: {explanation[:600]}"),
                      color=color_map.get(overall_level,0x00b7eb),
                      timestamp=now_jakarta())
        # add static preview
        if not sub_results:
            static_findings, _ = static_scan_file(filepath)
            if static_findings:
                preview = []
                for s in static_findings[:6]:
                    ln, kw, code, reason = s
                    if ln > 0:
                        preview.append(f"Line {ln}: `{kw}` → {reason}")
                    else:
                        preview.append(f"{kw}: {reason}")
                embed.add_field(name="🧠 Static Analysis (contoh)", value="```" + "\n".join(preview) + "```", inline=False)
        # obfuscation
        if report_dict.get("obfuscation"):
            ob_lines = []
            for ob in report_dict["obfuscation"][:6]:
                ob_lines.append(f"{ob.get('type')}: {ob.get('note')}")
            embed.add_field(name="🔐 Deteksi Obfuscation", value="\n".join(ob_lines), inline=False)

        # VirusTotal summary
        vt = report_dict.get("vt", {})
        if vt:
            embed.add_field(name="🧠 VirusTotal", value=f"Malicious: {vt.get('malicious',0)} | Suspicious: {vt.get('suspicious',0)} | Clean: {vt.get('undetected',0)}", inline=False)
        else:
            embed.add_field(name="🧠 VirusTotal", value="Tidak ada data VirusTotal atau gagal upload.", inline=False)

        # footer with server stats
        guild = ctx.guild
        if guild:
            total_members = guild.member_count
            online_members = sum(1 for m in guild.members if m.status != discord.Status.offline)
            embed.set_footer(text=f"Dipindai pada {now_jakarta().strftime('%A, %d %B %Y • %H:%M:%S')} | Members: {total_members} | Online: {online_members}")
        else:
            embed.set_footer(text=f"Dipindai pada {now_jakarta().strftime('%A, %d %B %Y • %H:%M:%S')}")

        # create export view
        with open(report_paths[0], "r", encoding="utf-8") as jf:
            report_json_txt = jf.read()
        with open(report_paths[1], "r", encoding="utf-8") as tf:
            report_txt = tf.read()
        view = ExportView(user_id, report_json_txt, report_txt)

        # cache (TTL 10 min)
        scan_cache[user_id] = {"json":report_json_txt, "txt":report_txt, "ts":time.time()}
        await progress_msg.edit(content=None, embed=embed, view=view)

        # cleanup temp files (keep reports until view used)
        for p in report_paths:
            try:
                if os.path.exists(p):
                    os.unlink(p)
            except:
                pass
        if filepath and os.path.exists(filepath):
            try:
                os.unlink(filepath)
            except:
                pass

    except Exception as e:
        logger.error("Scan error: %s", e, exc_info=True)
        await progress_msg.edit(content=f"❌ Gagal scan: {e}")
    finally:
        ongoing_scans.discard(user_id)

@bot.command()
async def history(ctx, limit: int = 5):
    user_id = ctx.author.id
    cursor.execute("SELECT file_name, level, confidence, timestamp FROM scans WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
                   (user_id, min(limit, 50)))
    rows = cursor.fetchall()
    if not rows:
        await ctx.send("📋 Tidak ada riwayat scan.")
        return
    embed = Embed(title="📋 Riwayat Scan", color=0x00b7eb)
    for fn,lvl,conf,ts in rows:
        embed.add_field(name=f"{DANGER_LEVELS.get(lvl,'🟡')} {fn[:50]}", value=f"Skor: {conf}% | Tanggal: {ts.split('T')[0]}", inline=False)
    embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
    await ctx.send(embed=embed, view=ScanButtons())

@bot.command()
async def help(ctx):
    guild = ctx.guild
    total_members = guild.member_count if guild else "Unknown"
    online_members = sum(1 for m in guild.members if m.status != discord.Status.offline) if guild else "Unknown"
    embed = Embed(title="🛡️ Raxt Community Scanner: Bantuan",
                  description="🔒 Bot keamanan untuk memindai file Lua/mod, built with AI + heuristics + VirusTotal.",
                  color=0x00b7eb)
    embed.add_field(name="👥 Statistik Server", value=f"Total Member: **{total_members}** | Online: **{online_members}**", inline=False)
    embed.add_field(name="🔍 Cara Pakai", value="• Upload File: Ketik `!scan` lalu unggah file.\n• URL: `!scan <URL>`\n• Otomatis: Unggah di channel yang diizinkan.", inline=False)
    embed.add_field(name="⚙️ Perintah", value="`!scan` - Scan file/URL\n`!history [n]` - Riwayat scan\n`!help` - Bantuan", inline=False)
    embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
    await ctx.send(embed=embed, view=ScanButtons())

# ---------------- auto-scan on upload ----------------
@bot.event
async def on_message(message):
    if message.author.bot:
        return
    # auto greeting when mention or prefix used
    if bot.user and (bot.user.mention in message.content or message.content.startswith("!")):
        msg = None
        hr = now_jakarta().hour
        if 4 <= hr < 11:
            msg = random.choice(MORNING_QUOTES)
        elif 11 <= hr < 15:
            msg = "Selamat siang! Jangan lupa makan dan jaga kesehatan."
        elif 15 <= hr < 18:
            msg = "Selamat sore! Istirahat sejenak bila perlu."
        else:
            msg = "Selamat malam! Semoga istirahatmu berkualitas."
        try:
            await message.channel.send(msg)
        except:
            pass

    # auto-scan attachments if in allowed channel
    if message.channel.id in ALLOWED_CHANNELS and message.attachments:
        await message.reply("🛡️ Memulai scan otomatis...")
        await scan(message, url=None)
    await bot.process_commands(message)

# ---------------- download helper ----------------
async def download_from_url(url, filename):
    try:
        if "github.com" in url and "/blob/" in url:
            url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        elif "drive.google.com" in url:
            file_id = re.search(r'/file/d/([a-zA-Z0-9-_]+)', url)
            if file_id:
                url = f"https://drive.google.com/uc?export=download&id={file_id.group(1)}"
        elif "dropbox.com" in url:
            url = url.replace("?dl=0", "?dl=1").replace("www.dropbox.com", "dl.dropboxusercontent.com")
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200 and len(resp.content) <= MAX_SIZE:
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1], prefix="raxt_") as tmp:
                tmp.write(resp.content)
                return tmp.name
    except Exception as e:
        logger.error("URL download error: %s", e)
    return None

# ---------------- global error handler ----------------
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    logger.error("Command error: %s", error, exc_info=True)
    try:
        await ctx.send(f"❌ Error: {str(error)}")
    except:
        pass

# ---------------- on_ready ----------------
@bot.event
async def on_ready():
    logger.info(f"✅ Bot aktif sebagai {bot.user}")
    await bot.change_presence(activity=discord.Game(name="🔍 Scanning files safely with Raxt Community"), status=discord.Status.online)
    # start scheduled tasks
    if not scheduled_tasks.is_running():
        scheduled_tasks.start()
    # welcome message in allowed channels
    for guild in bot.guilds:
        try:
            online_members = sum(1 for m in guild.members if m.status != discord.Status.offline)
            total_members = guild.member_count
            embed = Embed(title="🛡️ Raxt Community Scanner Aktif!",
                          description=(f"👥 **{total_members} Members** | 🟢 **{online_members} Online**\n\nGunakan tombol di bawah untuk mulai scan file atau melihat bantuan!"),
                          color=0x00b7eb)
            embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
            for ch in guild.text_channels:
                if ch.id in ALLOWED_CHANNELS:
                    try:
                        await ch.send(embed=embed, view=ScanButtons())
                    except Exception as e:
                        logger.debug("Welcome send error: %s", e)
        except Exception as e:
            logger.error("on_ready guild loop error: %s", e)

# ---------------- run ----------------
if __name__ == "__main__":
    try:
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        logger.error("Bot startup error: %s", e)
    finally:
        try:
            conn.close()
            logger.info("DB closed")
        except:
            pass
