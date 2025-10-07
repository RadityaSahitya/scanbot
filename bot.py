# bot.py (final - ditambahkan deteksi tujuan file)
import discord
from discord.ext import commands
import requests
import os
import re
import datetime
import time
import asyncio
import tempfile
import logging
import json
import sqlite3
from dotenv import load_dotenv
import google.generativeai as genai
from openai import OpenAI
import zipfile
import rarfile
import py7zr

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load env
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ALLOWED_CHANNELS = [int(ch.strip()) for ch in os.getenv("ALLOWED_CHANNELS", "").split(",") if ch.strip().isdigit()]

if not DISCORD_TOKEN:
    raise ValueError("Missing DISCORD_TOKEN in .env")

# Intents & Bot
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# Supported
SUPPORTED_EXTS = {".lua", ".txt", ".zip", ".7z", ".rar", ".py", ".js", ".php", ".luac", ".asi"}
MAX_SIZE = 5 * 1024 * 1024  # 5MB
MAX_ARCHIVE_FILES = 10
DANGER_LEVELS = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "VERY SUSPICIOUS": "🟠", "DANGEROUS": "🔴"}
LEVEL_ORDER = ["SAFE", "SUSPICIOUS", "VERY SUSPICIOUS", "DANGEROUS"]

# Cache & DB
conn = sqlite3.connect('scans.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS scans 
                  (user_id INTEGER, file_name TEXT, analyst TEXT, result TEXT, level TEXT, timestamp TEXT, confidence INTEGER)''')
cursor.execute('''CREATE TABLE IF NOT EXISTS stats 
                  (user_id INTEGER PRIMARY KEY, scans_today INTEGER DEFAULT 0, last_reset TEXT)''')
conn.commit()

# Concurrent limit (max 3 scans)
ongoing_scans = set()

# Static patterns
SUSPICIOUS_KEYWORDS = [
    "os.execute", "io.popen", "token", "keylog", "base64", "discord.com/api/webhooks",
    "SetWindowsHookEx", "keybd_event", "sampGetCurrentServerAddress", "GetAsyncKeyState",
    "CreateFile", "WriteFile", "InternetOpenUrlA", "HttpSendRequest", "MapVirtualKey"
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
    "HttpSendRequest": "Dikirim ke server eksternal — kemungkinan exfiltration."
}

# PURPOSE mapping (heuristic)
PURPOSE_MAP = {
    "keylogger": ["GetAsyncKeyState", "SetWindowsHookEx", "keylog", "keybd_event", "keyboard.read_key"],
    "stealer": ["CreateFile", "WriteFile", "sampGetCurrentServerAddress", "discord.com/api/webhooks", "token"],
    "exfiltration": ["InternetOpenUrlA", "HttpSendRequest", "socket.connect", "fetch", "send"],
    "obfuscation": ["base64", "eval", "loadstring", "decode"],
    "rce": ["os.execute", "io.popen", "system", "exec", "subprocess"],
    "rat": ["socket.connect", "bind", "listen", "accept"]
}

def detect_purpose(static_findings_text, ai_explanation_text, vt_stats):
    """
    Heuristic function to decide the likely purpose of a file.
    Uses static findings (text), AI explanation and virus total stats.
    Returns (purpose_text, confidence_score)
    """
    text = (static_findings_text or "") + " " + (ai_explanation_text or "")
    text_l = text.lower()
    counts = {}
    for purpose, keys in PURPOSE_MAP.items():
        for k in keys:
            if k.lower() in text_l:
                counts[purpose] = counts.get(purpose, 0) + 1

    # Weight by VT malicious detection
    vt_score = 0
    try:
        vt_mal = vt_stats.get("malicious", 0)
        vt_susp = vt_stats.get("suspicious", 0)
        vt_score = vt_mal * 3 + vt_susp * 1
    except:
        vt_score = 0

    if counts:
        # choose highest count purpose
        chosen = max(counts.items(), key=lambda kv: kv[1])[0]
        base_conf = min(95, 40 + counts[chosen]*20 + vt_score*5)
        # Friendly verbose purpose
        purpose_map_friendly = {
            "keylogger": "Keylogger / Merekam penekanan tombol",
            "stealer": "Pengambil data (stealer) — mencoba akses/ambil file atau token",
            "exfiltration": "Pengiriman/Exfiltrasi data ke server eksternal",
            "obfuscation": "Kode terobfuskasi/encoded (mencurigakan)",
            "rce": "Remote command execution (jalankan perintah sistem)",
            "rat": "Remote Access Trojan (kontrol jarak jauh)"
        }
        return purpose_map_friendly.get(chosen, chosen), int(base_conf)
    else:
        # fallback: if VT shows malicious, say generic data theft / malware
        if vt_score > 0:
            conf = min(95, 30 + vt_score*10)
            return "Malware / Berbahaya (menunjukkan deteksi VT)", int(conf)
        return "Tidak jelas / fungsi normal kemungkinan besar", 30

# ========== STATIC FILE SCAN ==========
def static_scan(filepath):
    suspicious_found = []
    ext = os.path.splitext(filepath)[1].lower()
    content_text = ""
    try:
        if ext in [".lua", ".cleo", ".moonloader", ".cs", ".txt", ".asi", ".py", ".js"]:
            with open(filepath, "r", errors="ignore") as f:
                lines = f.readlines()
                for i, line in enumerate(lines, start=1):
                    content = line.strip()
                    content_lower = content.lower()

                    # Basic keywords
                    for kw in SUSPICIOUS_KEYWORDS:
                        if kw.lower() in content_lower:
                            reason = EXPLANATION_MAP.get(kw, "Pola ini sering dipakai dalam malware.")
                            suspicious_found.append((i, kw, content.strip(), reason))

                    # Advanced patterns (categories)
                    for category, patterns in PURPOSE_MAP.items():
                        for p in patterns:
                            if p.lower() in content_lower:
                                reason = EXPLANATION_MAP.get(p, f"Indikasi {category}.")
                                suspicious_found.append((i, p, content.strip(), reason))
                content_text = "".join(lines)
        else:
            # Binary scan (extract readable ascii)
            with open(filepath, "rb") as f:
                raw = f.read()
            content_chunks = re.findall(b"[ -~]{4,}", raw)
            text = "\n".join([c.decode(errors="ignore") for c in content_chunks])
            content_text = text
            for category, patterns in PURPOSE_MAP.items():
                for p in patterns:
                    if p.lower() in text.lower():
                        suspicious_found.append((0, p, "<binary>", EXPLANATION_MAP.get(p, f"Indikasi {category}.")))
            for kw in SUSPICIOUS_KEYWORDS:
                if kw.lower() in text.lower():
                    suspicious_found.append((0, kw, "<binary>", EXPLANATION_MAP.get(kw, "API mencurigakan.")))
    except Exception as e:
        logger.error(f"Static scan read error: {e}")
        suspicious_found.append((-1, "Error", str(e), "Gagal membaca file untuk analisis."))

    return suspicious_found, content_text

# ========== VIRUSTOTAL ==========
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
        logger.warning(f"VT upload failed: {response.status_code} {response.text[:200]}")
    except Exception as e:
        logger.error(f"VT upload exception: {e}")
    return None

def get_scan_result(analysis_id):
    if not analysis_id or not VT_API_KEY:
        return None
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    for _ in range(6):  # up to ~30s
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                rj = response.json()
                status = rj.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    return rj
            time.sleep(5)
        except Exception as e:
            logger.error(f"VT get result error: {e}")
            time.sleep(3)
    return None

# ========== AI Analysts (keadaan tidak diubah) ==========
deepseek_client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com/v1") if DEEPSEEK_API_KEY else None
genai.configure(api_key=GEMINI_API_KEY)

async def analyze_with_ai(content):
    prompt = f"""Analyze this code for security issues, malware, or exploits in Lua/game mods.
    Rate danger level exactly as: SAFE, SUSPICIOUS, VERY SUSPICIOUS, or DANGEROUS.
    Provide a confidence score (0-100%) and brief explanation.
    Code: {content[:4000]}"""
    
    results = []
    if deepseek_client:
        try:
            response = deepseek_client.chat.completions.create(
                model="deepseek-chat",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=500
            )
            results.append(parse_ai_response(response.choices[0].message.content))
        except Exception as e:
            logger.error(f"DeepSeek error: {e}")
    if GEMINI_API_KEY:
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = await model.generate_content_async(prompt)
            results.append(parse_ai_response(response.text))
        except Exception as e:
            logger.error(f"Gemini error: {e}")
    
    if not results:
        return static_scan(content)[0]  # fallback (note: returns list)
    level_votes = {}
    for level, conf, exp in results:
        level_votes[level] = level_votes.get(level, 0) + 1
    majority_level = max(level_votes, key=lambda k: (level_votes[k], LEVEL_ORDER.index(k)))
    confs = [c for l, c, _ in results if l == majority_level]
    conf = sum(confs) / len(confs) if confs else 50
    exps = [e for l, _, e in results if l == majority_level]
    explanation = f"AI Consensus: {majority_level}. {' | '.join(exps[:2])}"
    return majority_level, conf, explanation

def parse_ai_response(text):
    level_match = re.search(r'(SAFE|SUSPICIOUS|VERY SUSPICIOUS|DANGEROUS)', text, re.IGNORECASE)
    conf_match = re.search(r'confidence[:\s]*(\d+)', text, re.IGNORECASE)
    level = level_match.group(1).upper() if level_match else "SUSPICIOUS"
    conf = int(conf_match.group(1)) if conf_match else 50
    if any(kw in text.lower() for kw in ["keylog", "setwindowshookex", "keybd_event", "sampgetcurrentserveraddress"]):
        conf = max(conf, 80)
    explanation = text[:1000].strip()
    return level, conf, explanation

# ========== Extract archive ==========
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
                full_path = os.path.join(root, f)
                if (os.path.splitext(f)[1].lower() in SUPPORTED_EXTS - {".zip", ".rar", ".7z"}
                    and os.path.getsize(full_path) <= MAX_SIZE):
                    files.append(full_path)
        files = files[:MAX_ARCHIVE_FILES]
    except Exception as e:
        logger.error(f"Extract error: {e}")
    return files

# ========== CORE SCAN ==========
async def do_scan(filepath, progress_msg, user_id):
    ext = os.path.splitext(filepath)[1].lower()
    is_archive = ext in {".zip", ".7z", ".rar"}
    progress = 0
    sub_results = []

    if is_archive:
        subfiles = extract_archive(filepath)
        if not subfiles:
            raise ValueError("Gagal mengekstrak arsip.")
        for i, sub in enumerate(subfiles):
            try:
                with open(sub, "r", errors="ignore") as f:
                    content = f.read()[:4000]
                level, conf, exp = await analyze_with_ai(content)
                sub_results.append((os.path.basename(sub), level, conf, exp))
                os.unlink(sub)
            except Exception as e:
                logger.error(f"Subfile scan error: {e}")
            progress += (100 // len(subfiles))
            bar = "▓" * (progress // 10) + "░" * (10 - progress // 10)
            await progress_msg.edit(content=f"📦 Memindai arsip {i+1}/{len(subfiles)} [{bar}] {progress}%")
        overall_level = max([r[1] for r in sub_results], key=lambda x: LEVEL_ORDER.index(x)) if sub_results else "SAFE"
        conf = sum([r[2] for r in sub_results]) / len(sub_results) if sub_results else 50
        explanation = f"Arsip: {len(sub_results)} file. Tingkat tertinggi: {overall_level}."
        # Determine purpose from aggregated subresults and explanations
        static_agg_text = " ".join([r[3] for r in sub_results])
        purpose, pconf = detect_purpose(static_agg_text, explanation, {})
    else:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()[:4000]
        await progress_msg.edit(content="🤖 Memindai dengan AI... [▓▓▓░░░] 60%")
        level, conf, ai_exp = await analyze_with_ai(content)
        await progress_msg.edit(content="🧪 Memindai pola & VT... [▓▓▓▓▓░] 80%")
        static_findings, static_text = static_scan(filepath)
        # vt
        analysis_id = scan_with_virustotal(filepath)
        vt_stats = {"malicious": 0, "suspicious": 0, "undetected": 0}
        vt_text = "VirusTotal tidak tersedia."
        if analysis_id:
            # blocking wait: acceptable for now (existing pattern)
            time.sleep(5)
            res = get_scan_result(analysis_id)
            if res:
                stats = res["data"]["attributes"]["stats"]
                vt_stats = {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0), "undetected": stats.get("undetected", 0)}
                vt_text = f"Malicious: {vt_stats['malicious']}, Suspicious: {vt_stats['suspicious']}, Clean: {vt_stats['undetected']}"
        else:
            vt_text = "Gagal upload ke VirusTotal atau API key tidak tersedia."
        # Determine overall level
        levels = [level]
        if static_findings:
            # map static findings to at least SUSPICIOUS
            levels.append("SUSPICIOUS")
        if vt_stats.get("malicious", 0) > 0:
            levels.append("DANGEROUS")
        overall_level = max(levels, key=lambda x: LEVEL_ORDER.index(x))
        # Confidence heuristics
        conf = max(conf if isinstance(conf, (int, float)) else 50, 80 if vt_stats.get("malicious", 0) > 0 else 0)
        # explanation
        explanation = f"AI: {ai_exp}\nStatic: {static_findings[:3]}\nVT: {vt_text}"
        purpose, pconf = detect_purpose(" ".join([f[3] for f in static_findings]) if static_findings else static_text, ai_exp, vt_stats)

    # bump danger if certain keywords present
    if any("keylog" in (s[1].lower() if isinstance(s, tuple) else str(s).lower()) for s in static_findings):
        overall_level = max(overall_level, "DANGEROUS", key=lambda x: LEVEL_ORDER.index(x))
        conf = max(conf, 85)

    # Save to DB
    result_json = json.dumps({"level": overall_level, "confidence": conf, "explanation": explanation, "purpose": purpose})
    cursor.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (user_id, os.path.basename(filepath), "auto", result_json, overall_level, datetime.datetime.now().isoformat(), int(conf)))
    conn.commit()

    # Build output report files
    report = {
        "file": os.path.basename(filepath),
        "level": overall_level,
        "confidence": conf,
        "purpose": purpose,
        "explanation": explanation,
        "subfiles": [{"name": r[0], "level": r[1], "conf": r[2]} for r in sub_results] if is_archive else []
    }
    json_report = json.dumps(report, indent=2)
    txt_report = (
        f"┌───────────────── Raxt Community Scanner ─────────────────┐\n"
        f"│ {DANGER_LEVELS.get(overall_level, '🟡')} **Status**: {overall_level}                        │\n"
        f"│ 💾 **File**: {os.path.basename(filepath)}                         │\n"
        f"│ 📊 **Skor**: {conf:.1f}%                                  │\n"
        f"│ 🎯 **Tujuan (Purpose)**: {purpose}                          │\n"
        f"│ 📝 **Penjelasan**: {explanation[:400]}...                │\n"
    )
    if sub_results:
        txt_report += "│ 📂 **File dalam Arsip**: " + ', '.join([r[0] + f' ({r[1]})' for r in sub_results]) + "\n"
    txt_report += "└───────────────── Powered by Raxt Community ─────────────┘"

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as jf:
        jf.write(json_report)
        json_path = jf.name
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False, encoding='utf-8') as tf:
        tf.write(txt_report)
        txt_path = tf.name

    return overall_level, conf, purpose, explanation, [json_path, txt_path], sub_results

# Button interaction (unchanged)
class ScanButtons(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="Scan File", style=discord.ButtonStyle.green, emoji="🔍")
    async def scan_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("📤 Silakan unggah file untuk di-scan!", ephemeral=True)

    @discord.ui.button(label="Bantuan", style=discord.ButtonStyle.blurple, emoji="❓")
    async def help_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        embed = discord.Embed(
            title="🛡️ Raxt Community Scanner - Bantuan",
            description="🔒 Bot keamanan untuk memindai file Lua/mod, dibuat oleh **Raxt Community**.",
            color=0x00b7eb
        )
        embed.add_field(
            name="🔍 Cara Pakai",
            value="┌────────────────────────────┐\n"
                  "│ **Upload File**: Ketik !scan lalu unggah file. │\n"
                  "│ **URL**: !scan <URL>                     │\n"
                  "│ **Otomatis**: Unggah file di channel.    │\n"
                  "└────────────────────────────┘",
            inline=False
        )
        embed.add_field(
            name="⚙️ Perintah",
            value="┌────────────────────────────┐\n"
                  "│ !scan       - Scan file/URL         │\n"
                  "│ !history [n]- Lihat riwayat scan    │\n"
                  "│ !help       - Tampilkan bantuan     │\n"
                  "└────────────────────────────┘",
            inline=False
        )
        embed.add_field(
            name="📁 File Didukung",
            value="┌────────────────────────────┐\n"
                  "│ **Format**: .lua, .txt, .zip, dll   │\n"
                  "│ **Maks**: 5MB                      │\n"
                  "│ **Arsip**: Maks 10 file            │\n"
                  "└────────────────────────────┘",
            inline=False
        )
        embed.add_field(
            name="🚨 Tingkat Bahaya",
            value="┌────────────────────────────┐\n"
                  "│ 🟢 **Aman**                 │\n"
                  "│ 🟡 **Mencurigakan**         │\n"
                  "│ 🟠 **Sangat Mencurigakan**  │\n"
                  "│ 🔴 **Berbahaya**            │\n"
                  "└────────────────────────────┘",
            inline=False
        )
        embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
        await interaction.response.send_message(embed=embed, ephemeral=True)

# Commands (scan, history, help) - scanned code adapted to use new purpose
@bot.command()
@commands.cooldown(1, 40, commands.BucketType.user)
async def scan(ctx_or_msg, url: str = None):
    # Support both context and message forwarded usage (as before)
    if isinstance(ctx_or_msg, discord.Message):
        channel = ctx_or_msg.channel
        user_id = ctx_or_msg.author.id
        context = None
    else:
        channel = ctx_or_msg.channel
        user_id = ctx_or_msg.author.id
        context = ctx_or_msg

    # Rate limiting per day
    today = datetime.date.today().isoformat()
    cursor.execute("SELECT scans_today FROM stats WHERE user_id=? AND last_reset=?", (user_id, today))
    row = cursor.fetchone()
    scans_today = row[0] if row else 0
    if scans_today >= 20:
        await channel.send("❌ Batas harian tercapai (20 scan/hari)! Coba besok.")
        return
    cursor.execute("INSERT OR REPLACE INTO stats (user_id, scans_today, last_reset) VALUES (?, ?, ?)",
                   (user_id, scans_today + 1, today))
    conn.commit()

    if len(ongoing_scans) >= 3:
        await channel.send("⏳ Antrean penuh (maks 3 scan bersamaan)! Tunggu sebentar.")
        return
    ongoing_scans.add(user_id)

    progress_msg = None
    try:
        if isinstance(ctx_or_msg, discord.Message):
            progress_msg = await channel.send("⏳ Memulai scan...")
        else:
            progress_msg = await ctx_or_msg.send("⏳ Memulai scan...")

        filepath = None
        filename = None
        # handle URL or attachment as before...
        if url:
            filename = url.split('/')[-1] or "file.lua"
            filepath = await download_from_url(url, filename)
            if not filepath:
                await progress_msg.edit(content="❌ Gagal mengunduh dari URL!")
                ongoing_scans.discard(user_id)
                return
            await progress_msg.edit(content=f"📥 Berhasil mengunduh {os.path.basename(filepath)}")
        else:
            # check attachments from ctx_or_msg or context
            msg_obj = ctx_or_msg if isinstance(ctx_or_msg, discord.Message) else ctx_or_msg.message
            if not msg_obj.attachments:
                await progress_msg.edit(content="❌ Harap unggah file atau berikan URL!")
                ongoing_scans.discard(user_id)
                return
            attachment = msg_obj.attachments[0]
            if attachment.size > MAX_SIZE or os.path.splitext(attachment.filename)[1].lower() not in SUPPORTED_EXTS:
                await progress_msg.edit(content="❌ File tidak didukung atau terlalu besar (maks 5MB)!")
                ongoing_scans.discard(user_id)
                return
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(attachment.filename)[1]) as tmp:
                filepath = tmp.name
            await attachment.save(filepath)
            filename = attachment.filename
            await progress_msg.edit(content=f"📂 Memuat {filename}")

        # Run scan
        level, conf, purpose, explanation, report_paths, sub_results = await do_scan(filepath, progress_msg, user_id)
        await progress_msg.edit(content="✅ Scan selesai! [▓▓▓▓▓▓] 100%")

        color_map = {"SAFE": 0x00ff00, "SUSPICIOUS": 0xffff00, "VERY SUSPICIOUS": 0xffa500, "DANGEROUS": 0xff0000}
        embed = discord.Embed(
            title=f"┌── {DANGER_LEVELS.get(level, '🟡')} Raxt Community: Hasil Scan ──┐",
            description=(
                f"**File**: `{os.path.basename(filepath)}`\n"
                f"**Status**: {DANGER_LEVELS.get(level, '🟡')} **{level}**\n"
                f"**Confidence**: {conf:.1f}%\n"
                f"**Purpose (tujuan)**: {purpose}\n\n"
                f"**Ringkasan**: {explanation[:350]}..."
            ),
            color=color_map.get(level, 0x00b7eb),
            timestamp=datetime.datetime.now()
        )
        if sub_results:
            embed.add_field(
                name="📂 File dalam Arsip",
                value="\n".join([f"{DANGER_LEVELS.get(r[1], '🟡')} {r[0]}: {r[1]} ({r[2]}%)" for r in sub_results]),
                inline=False
            )
        # Attach JSON + TXT report if exist
        files = [discord.File(p, os.path.basename(p)) for p in report_paths if os.path.exists(p)]
        embed.set_footer(text=f"🌟 Dibuat oleh Raxt Community | Dipindai pada {datetime.datetime.now().strftime('%A, %d %B %Y • %H:%M:%S')}")
        await progress_msg.edit(content=None, embed=embed, attachments=files, view=ScanButtons())

        # cleanup
        for p in report_paths:
            if os.path.exists(p):
                os.unlink(p)
        if filepath and os.path.exists(filepath):
            os.unlink(filepath)

    except Exception as e:
        logger.error(f"Scan error: {e}")
        if progress_msg:
            await progress_msg.edit(content=f"❌ Gagal scan: {str(e)}")
        else:
            await channel.send(f"❌ Gagal scan: {str(e)}")
    finally:
        ongoing_scans.discard(user_id)

# error handler and other commands (history, help) remain similar to previous script
@scan.error
async def scan_error(ctx, error):
    if isinstance(error, commands.CommandOnCooldown):
        await ctx.send(f"⏰ Tunggu {error.retry_after:.0f} detik lagi!")
    else:
        logger.error(f"Scan error: {error}")
        await ctx.send(f"❌ Error: {str(error)}")

@bot.command()
async def history(ctx, limit: int = 5):
    user_id = ctx.author.id
    cursor.execute("SELECT file_name, level, confidence, timestamp FROM scans WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
                   (user_id, min(limit, 20)))
    rows = cursor.fetchall()
    if not rows:
        await ctx.send("📋 Tidak ada riwayat scan.")
        return

    embed = discord.Embed(
        title="┌── 📋 Raxt Community: Riwayat Scan ──┐",
        color=0x00b7eb
    )
    for row in rows:
        fn, lvl, conf, ts = row
        embed.add_field(
            name=f"{DANGER_LEVELS.get(lvl, '🟡')} {fn[:50]}",
            value=f"Skor: {conf}% | Tanggal: {ts.split('T')[0]}",
            inline=False
        )
    embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
    await ctx.send(embed=embed, view=ScanButtons())

@bot.command()
async def help(ctx):
    guild = ctx.guild
    total_members = guild.member_count if guild else "Unknown"
    online_members = sum(1 for m in guild.members if m.status != discord.Status.offline) if guild else "Unknown"
    embed = discord.Embed(
        title="┌── 🛡️ Raxt Community Scanner: Bantuan ──┐",
        description="🔒 Bot keamanan untuk memindai file Lua/mod, dibuat oleh **Raxt Community**.",
        color=0x00b7eb
    )
    embed.add_field(
        name="👥 Statistik Server",
        value=f"Total Member: **{total_members}** | Online: **{online_members}**",
        inline=False
    )
    embed.add_field(
        name="🔍 Cara Pakai",
        value="• **Upload File**: Ketik `!scan` lalu unggah file.\n• **URL**: `!scan <URL>`\n• **Otomatis**: Unggah file di channel yang diizinkan.",
        inline=False
    )
    embed.add_field(
        name="⚙️ Perintah",
        value="`!scan` - Scan file/URL\n`!history [n]` - Lihat riwayat scan\n`!help` - Tampilkan bantuan",
        inline=False
    )
    embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
    await ctx.send(embed=embed, view=ScanButtons())

# on_ready: presence + post welcome embed to allowed channels
@bot.event
async def on_ready():
    logger.info(f"✅ Bot aktif sebagai {bot.user}")
    await bot.change_presence(activity=discord.Game(name="🔍 Scanning files safely with Raxt Community"), status=discord.Status.online)
    for guild in bot.guilds:
        online_members = sum(1 for m in guild.members if m.status != discord.Status.offline)
        total_members = guild.member_count
        embed = discord.Embed(
            title="🛡️ Raxt Community Scanner Aktif!",
            description=(
                "🧩 Creating channels that are temporary.\n"
                "⚙️ Configurable with a beautiful dashboard.\n\n"
                f"👥 **{total_members} Members** | 🟢 **{online_members} Online**\n\n"
                "Gunakan tombol di bawah untuk mulai scan file atau melihat bantuan!"
            ),
            color=0x00b7eb
        )
        embed.set_footer(text="🌟 Dibuat oleh Raxt Community")
        for channel in guild.text_channels:
            if channel.id in ALLOWED_CHANNELS:
                await channel.send(embed=embed, view=ScanButtons())

# on_message auto-scan (unchanged)
@bot.event
async def on_message(message):
    if message.author.bot:
        return
    if message.channel.id in ALLOWED_CHANNELS and message.attachments:
        await message.reply("🛡️ Memulai scan otomatis...")
        await scan(message, url=None)
    await bot.process_commands(message)

# helper: download_from_url (as before)
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
            with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1]) as tmp:
                tmp.write(resp.content)
                return tmp.name
    except Exception as e:
        logger.error(f"URL download error: {e}")
    return None

# global command error handling
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    logger.error(f"Command error: {error}")
    await ctx.send(f"❌ Error: {str(error)}")

if __name__ == "__main__":
    try:
        bot.run(DISCORD_TOKEN)
    except Exception as e:
        logger.error(f"Bot startup error: {e}")
    finally:
        if conn:
            conn.close()
            logger.info("DB connection closed.")
