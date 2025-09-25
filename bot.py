import discord
from discord.ext import commands
import requests
import os
import re
import time
from dotenv import load_dotenv

# Load token & API Key dari file .env
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# Pola mencurigakan untuk file teks
SUSPICIOUS_KEYWORDS = [
    "os.execute", "io.popen", "require('socket')", "http.", "fetch", "token",
    "keyboard", "keylog", "getkeystate", "onkeyup", "onkeydown", "winapi",
    "loadstring", "base64", "post", "url", "discord"
]

# Pola API mencurigakan untuk file binary
SUSPICIOUS_BIN_PATTERNS = [
    "GetAsyncKeyState", "SendInput", "WriteFile", "CreateFile", "HttpSend",
    "InternetOpen", "InternetConnect", "WinHttp", "Keylogger", "Discord"
]

def static_scan(filepath):
    suspicious_found = []
    ext = os.path.splitext(filepath)[1].lower()

    try:
        if ext in [".lua", ".cleo", ".moonloader"]:
            with open(filepath, "r", errors="ignore") as f:
                content = f.read().lower()
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw.lower() in content:
                        suspicious_found.append(kw)
        else:
            with open(filepath, "rb") as f:
                raw = f.read()
            content = re.findall(b"[ -~]{4,}", raw)
            text = "\n".join([c.decode(errors="ignore") for c in content])

            for kw in SUSPICIOUS_BIN_PATTERNS:
                if kw.lower() in text.lower():
                    suspicious_found.append(kw)

    except Exception as e:
        suspicious_found.append(f"Error: {e}")

    return suspicious_found

def scan_with_virustotal(filepath):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    with open(filepath, "rb") as f:
        files = {"file": (os.path.basename(filepath), f)}
        response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        return response.json()["data"]["id"]
    return None

def get_scan_result(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

@bot.event
async def on_ready():
    print(f"✅ Bot aktif sebagai {bot.user}")

@bot.command()
async def scan(ctx):
    if not ctx.message.attachments:
        await ctx.send("❌ Upload file mod (.lua, .asi, .cleo, dll) untuk discan!")
        return

    attachment = ctx.message.attachments[0]
    filepath = f"./{attachment.filename}"
    await attachment.save(filepath)
    await ctx.send(f"⏳ Men-scan `{attachment.filename}`...")

    # Static Scan
    suspicious = static_scan(filepath)
    if suspicious:
        await ctx.send("⚠️ Static scan menemukan pola mencurigakan:\n- " + "\n- ".join(suspicious))
    else:
        await ctx.send("🟢 Static scan tidak menemukan pola mencurigakan.")

    # VirusTotal Scan
    analysis_id = scan_with_virustotal(filepath)
    if not analysis_id:
        await ctx.send("⚠️ Gagal upload ke VirusTotal.")
        os.remove(filepath)
        return

    await ctx.send("🔍 File sedang dianalisis VirusTotal (~15 detik)...")
    time.sleep(15)

    result = get_scan_result(analysis_id)
    if result:
        stats = result["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)

        link = f"https://www.virustotal.com/gui/file-analysis/{analysis_id}"
        msg = (
            f"📊 Hasil VirusTotal `{attachment.filename}`:\n"
            f"🔴 Malicious: {malicious}\n"
            f"🟠 Suspicious: {suspicious}\n"
            f"🟢 Clean (undetected): {undetected}\n"
            f"🔗 Laporan detail: {link}"
        )
        await ctx.send(msg)
    else:
        await ctx.send("⚠️ Gagal mengambil hasil analisis.")

    os.remove(filepath)

bot.run(DISCORD_TOKEN)
