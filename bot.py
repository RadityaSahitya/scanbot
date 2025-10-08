import os
import io
import json
import pytz
import random
import discord
import aiohttp
from discord.ext import commands, tasks
from discord.ui import View, Button
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
ALLOWED_CHANNELS = os.getenv("ALLOWED_CHANNELS", "").split(",")
TIMEZONE = pytz.timezone("Asia/Jakarta")

intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

async def ai_reasoning_analysis(static_result: str, vt_result: dict):
    """Analisis tambahan dengan AI reasoning simulatif."""
    summary_text = f"{static_result}\n\n{vt_result}"
    danger_keywords = ["stealer", "keylogger", "encode", "obfuscate", "backdoor", "password", "token"]
    score = 100
    reasoning = []

    for word in danger_keywords:
        if word.lower() in summary_text.lower():
            score -= 10
            reasoning.append(f"⚠️ Pola mencurigakan: **{word}**")

    if vt_result.get("malicious", 0) > 0:
        score -= vt_result["malicious"] * 2
        reasoning.append("⚠️ VirusTotal mendeteksi file berbahaya.")
    elif vt_result.get("suspicious", 0) > 0:
        score -= vt_result["suspicious"]
        reasoning.append("⚠️ File mencurigakan menurut VirusTotal.")

    if not reasoning:
        reasoning.append("✅ Tidak ditemukan indikasi berbahaya dari AI reasoning.")

    score = max(0, min(100, score))
    reasoning.append(f"**Skor Keamanan:** {score}%")
    return reasoning, score

async def create_export_buttons(scan_data: dict):
    view = View()

    async def export_json(interaction):
        file = io.BytesIO(json.dumps(scan_data, indent=2).encode())
        await interaction.response.send_message(
            file=discord.File(file, "scan_result.json"), ephemeral=True
        )

    async def export_txt(interaction):
        text = "\n".join(f"{k}: {v}" for k, v in scan_data.items())
        file = io.BytesIO(text.encode())
        await interaction.response.send_message(
            file=discord.File(file, "scan_result.txt"), ephemeral=True
        )

    btn_json = Button(label="Export JSON", style=discord.ButtonStyle.green)
    btn_json.callback = export_json
    btn_txt = Button(label="Export TXT", style=discord.ButtonStyle.blurple)
    btn_txt.callback = export_txt
    view.add_item(btn_json)
    view.add_item(btn_txt)
    return view

async def static_analysis(file_bytes):
    """Analisis sederhana (mock)"""
    suspicious_patterns = ["io.open", "winapi", "CreateFile", "require('socket')"]
    found = [p for p in suspicious_patterns if p in file_bytes.decode(errors="ignore")]
    return found

async def vt_scan(file_bytes, filename):
    """Upload ke VirusTotal"""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": VT_API_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            with io.BytesIO(file_bytes) as f:
                form = aiohttp.FormData()
                form.add_field("file", f, filename=filename)
                async with session.post(url, headers=headers, data=form) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "malicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                            "suspicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0),
                            "clean": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("harmless", 0),
                        }
                    else:
                        return {"error": f"VT Upload gagal: {resp.status}"}
    except Exception as e:
        return {"error": str(e)}

@bot.command()
async def scan(ctx):
    if str(ctx.channel.id) not in ALLOWED_CHANNELS:
        return await ctx.reply("❌ Kamu tidak punya izin scan di channel ini.")

    if not ctx.message.attachments:
        return await ctx.reply("⚠️ Kirim file yang ingin di-scan.")

    attachment = ctx.message.attachments[0]
    if attachment.size > 20 * 1024 * 1024:
        return await ctx.reply("⚠️ File terlalu besar. Maks 20MB.")

    progress_msg = await ctx.send("⏳ Memulai scan...")
    file_bytes = await attachment.read()
    filename = attachment.filename

    static_findings = await static_analysis(file_bytes)
    vt_result = await vt_scan(file_bytes, filename)

    static_summary = f"{len(static_findings)} pola mencurigakan ditemukan:\n" + "\n".join(static_findings or ["-"])
    vt_summary = vt_result

    reasoning, score = await ai_reasoning_analysis(static_summary, vt_summary)

    embed = discord.Embed(
        title=f"🔍 Hasil Scan File: {filename}",
        color=discord.Color.red() if score < 50 else discord.Color.orange() if score < 80 else discord.Color.green(),
        description=f"**Status:** {'🟥 DANGEROUS' if score < 50 else '🟧 Suspicious' if score < 80 else '🟩 Safe'}\n"
                    f"**Skor Keamanan:** {score}%\n"
    )

    embed.add_field(name="🧠 AI Reasoning", value="\n".join(reasoning[:5]), inline=False)
    embed.add_field(name="📊 Static Analysis", value=static_summary[:1024], inline=False)
    embed.add_field(name="🧪 VirusTotal", value=json.dumps(vt_summary, indent=2)[:1024], inline=False)

    now = datetime.now(TIMEZONE)
    embed.set_footer(text=f"RAXT Community | {now.strftime('%A, %d %B %Y %H:%M:%S WIB')}")

    view = await create_export_buttons({
        "file_name": filename,
        "static": static_summary,
        "vt": vt_summary,
        "ai_reasoning": reasoning,
        "security_score": score
    })

    await progress_msg.edit(content=None, embed=embed, view=view)
@tasks.loop(minutes=1)
async def daily_tasks():
    now = datetime.now(TIMEZONE)
    hour = now.hour
    for channel_id in ALLOWED_CHANNELS:
        try:
            ch = bot.get_channel(int(channel_id))
            if not ch:
                continue
            if hour == 5:
                await ch.send("🌅 Selamat pagi! Jangan lupa ibadah dan semangat hari ini 💪")
            elif hour == 12:
                await ch.send("☀️ Selamat siang! Waktunya sholat Dzuhur untuk yang Muslim 🙏")
            elif hour == 15:
                await ch.send("🌇 Selamat sore! Jangan lupa istirahat sebentar 😌")
            elif hour == 18:
                await ch.send("🌆 Selamat malam! Waktunya sholat Maghrib & istirahat 💤")
            elif hour == 19:
                await ch.send("📿 Saatnya ibadah malam dan refleksi diri 💭")
        except Exception:
            continue
@bot.event
async def on_ready():
    print(f"✅ Bot aktif sebagai {bot.user}")
    daily_tasks.start()

bot.run(TOKEN)
