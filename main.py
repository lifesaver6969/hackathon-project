from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import requests
import re
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

app = FastAPI(title="ThreatLens AI Phishing Platform")

# --- 1. PASTE YOUR GEMINI API KEY HERE ---
GEMINI_API_KEY = "AQ.Ab8RN6IPDdVUqRPJjdt6KZCaLeV2HZ5Amzb0pAHebRbsNBDE8Q"

# --- 2. PASTE YOUR GMAIL CREDENTIALS HERE ---
SCANNER_EMAIL = "adityakhachane28@gmail.com"
SCANNER_APP_PASSWORD = "ghks pxfg xrdz mikw"

scan_history = []

class ManualScanRequest(BaseModel):
    sender: str
    subject: str
    body: str

def analyze_content_with_ai(body: str, from_addr: str = "", subject: str = "") -> dict:
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    
    if GEMINI_API_KEY and not GEMINI_API_KEY.startswith("PASTE_"):
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
            prompt = f"""
            You are ThreatLens AI, a cybersecurity phishing detector. Analyze this message for phishing, brand impersonation, sender spoofing, urgency, credential harvesting, and malicious URLs.
            Sender: {from_addr}
            Subject: {subject}
            Extracted URLs: {urls}
            Message Body: {body}

            Return ONLY a valid JSON object with these exact keys:
            {{
                "risk_score": <integer from 0 to 100>,
                "status": "<SAFE or SUSPICIOUS or CRITICAL PHISHING>",
                "flags": ["<specific reason 1>", "<specific reason 2>"],
                "advice": "<plain-English advice on what the user should do>"
            }}
            Scoring guide: 0-29 SAFE, 30-59 SUSPICIOUS, 60-100 CRITICAL PHISHING.
            """
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "temperature": 0.1
                }
            }
            res = requests.post(url, json=payload, timeout=15)
            if res.status_code == 200:
                text_resp = res.json()["candidates"][0]["content"]["parts"][0]["text"]
                ai_data = json.loads(text_resp)
                return {
                    "risk_score": min(max(int(ai_data.get("risk_score", 0)), 0), 100),
                    "status": ai_data.get("status", "SUSPICIOUS"),
                    "flags": ai_data.get("flags", []),
                    "detected_urls": urls,
                    "advice": ai_data.get("advice", "Proceed with caution.")
                }
            else:
                print(f"Gemini API HTTP Error {res.status_code}: {res.text}")
        except Exception as e:
            print(f"Gemini API Error: {e}")

    # Automatic fallback if API key is not set yet
    return {
        "risk_score": 75 if urls else 20,
        "status": "CRITICAL PHISHING" if urls else "SAFE",
        "flags": ["Fallback check active — verify GEMINI_API_KEY in main.py"],
        "detected_urls": urls,
        "advice": "Add a valid Gemini API key on line 15 of main.py for full AI analysis."
    }

def send_verdict_reply(to_address: str, original_subject: str, analysis: dict):
    if not SCANNER_APP_PASSWORD or SCANNER_APP_PASSWORD == "your-16-char-app-password":
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{analysis['status']}] ThreatLens Report: {original_subject}"
        msg["From"] = f"ThreatLens Security <{SCANNER_EMAIL}>"
        msg["To"] = to_address
        color = "#ef4444" if analysis["status"] == "CRITICAL PHISHING" else ("#f59e0b" if analysis["status"] == "SUSPICIOUS" else "#10b981")
        html_body = f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;padding:20px;border:1px solid #e5e7eb;border-radius:10px;">
            <h2 style="margin-top:0;color:#111827;">🔍 ThreatLens AI Security Report</h2>
            <div style="background:{color};color:white;display:inline-block;padding:6px 14px;border-radius:20px;font-weight:bold;margin-bottom:15px;">
                {analysis['status']} — Risk Score: {analysis['risk_score']}/100
            </div>
            <p style="background:#f3f4f6;padding:12px;border-radius:6px;color:#1f2937;"><strong>AI Advice:</strong> {analysis['advice']}</p>
            <ul>{''.join(f'<li>{f}</li>' for f in analysis['flags'])}</ul>
        </div>"""
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SCANNER_EMAIL, SCANNER_APP_PASSWORD)
            server.sendmail(SCANNER_EMAIL, to_address, msg.as_string())
    except Exception as e:
        print(f"Auto-reply error: {e}")

@app.post("/api/webhook/email")
async def receive_email(
    to: str = Form(...),
    from_address: str = Form(..., alias="from"),
    subject: Optional[str] = Form("No Subject"),
    text: Optional[str] = Form(""),
    html: Optional[str] = Form("")
):
    body = text if text else html or ""
    analysis = analyze_content_with_ai(body, from_address, subject)
    scan_history.insert(0, {
        "id": len(scan_history) + 1,
        "source": "Live Email Inbox (Gemini AI)",
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
        "from": from_address,
        "subject": subject,
        "body_preview": (body[:180] + "...") if len(body) > 180 else body,
        "analysis": analysis
    })
    clean_sender = re.findall(r'<(.+?)>', from_address)
    send_verdict_reply(clean_sender[0] if clean_sender else from_address, subject, analysis)
    return {"status": "success", "verdict": analysis}

@app.post("/api/analyze-manual")
async def analyze_manual(req: ManualScanRequest):
    analysis = analyze_content_with_ai(req.body, req.sender, req.subject)
    record = {
        "id": len(scan_history) + 1,
        "source": "Manual Web Scan (Gemini AI)",
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
        "from": req.sender or "Unknown Sender",
        "subject": req.subject or "Manual Text / SMS Check",
        "body_preview": (req.body[:180] + "...") if len(req.body) > 180 else req.body,
        "analysis": analysis
    }
    scan_history.insert(0, record)
    return record

@app.get("/api/scans")
async def get_scans():
    return scan_history

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ThreatLens | AI Phishing Detection</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 font-sans min-h-screen p-6 md:p-10">
    <div class="max-w-6xl mx-auto">
        <div class="flex justify-between items-center mb-8 border-b border-slate-800 pb-5">
            <div>
                <h1 class="text-3xl font-extrabold text-white flex items-center gap-3">
                    <span class="p-2 bg-indigo-600 rounded-lg text-xl">🔍</span> ThreatLens
                </h1>
                <p class="text-slate-400 text-sm mt-1">Instant visual clarity on suspicious emails, texts, and URLs — Powered by Gemini AI</p>
            </div>
            <div class="flex items-center gap-2 bg-slate-900 border border-slate-800 px-4 py-2 rounded-full">
                <span class="w-2.5 h-2.5 bg-emerald-500 rounded-full animate-ping"></span>
                <span class="text-xs text-emerald-400 font-semibold uppercase">Gemini AI Active</span>
            </div>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl"><div class="text-slate-400 text-xs uppercase">Total Analyzed</div><div id="stat-total" class="text-3xl font-bold mt-1">0</div></div>
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl"><div class="text-slate-400 text-xs uppercase">Phishing Blocked</div><div id="stat-phish" class="text-3xl font-bold mt-1 text-red-500">0</div></div>
            <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl"><div class="text-slate-400 text-xs uppercase">Safe Messages</div><div id="stat-clean" class="text-3xl font-bold mt-1 text-emerald-500">0</div></div>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
            <div class="lg:col-span-1 bg-slate-900 border border-slate-800 rounded-xl p-5 h-fit">
                <h2 class="text-base font-bold mb-1">⚡ AI Message & URL Scanner</h2>
                <p class="text-xs text-slate-400 mb-4">Paste an email, SMS, or link for deep AI inspection.</p>
                <div class="space-y-3">
                    <input id="m-sender" type="text" placeholder="Sender (e.g. PayPal <alert@gmail.com>)" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm">
                    <input id="m-subject" type="text" placeholder="Subject Line" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm">
                    <textarea id="m-body" rows="4" placeholder="Paste email or SMS message here..." class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm"></textarea>
                    <button id="scan-btn" onclick="runManualScan()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-lg text-sm">Analyze with Gemini AI</button>
                </div>
            </div>
            <div class="lg:col-span-2">
                <h2 class="text-base font-bold text-slate-300 mb-4">Live Security Feed</h2>
                <div id="feed" class="space-y-4">
                    <div class="text-center py-14 text-slate-500 bg-slate-900/40 rounded-xl border border-dashed border-slate-800">Waiting for messages...</div>
                </div>
            </div>
        </div>
    </div>
    <script>
        async function runManualScan() {
            const sender = document.getElementById('m-sender').value;
            const subject = document.getElementById('m-subject').value;
            const body = document.getElementById('m-body').value;
            const btn = document.getElementById('scan-btn');
            if (!body.trim()) return alert("Please enter a message to scan!");
            btn.innerText = "🤖 Analyzing..."; btn.disabled = true;
            try {
                await fetch('/api/analyze-manual', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({sender, subject, body})
                });
                document.getElementById('m-body').value = '';
                fetchScans();
            } finally {
                btn.innerText = "Analyze with Gemini AI"; btn.disabled = false;
            }
        }
        async function fetchScans() {
            const res = await fetch('/api/scans');
            const scans = await res.json();
            document.getElementById('stat-total').innerText = scans.length;
            document.getElementById('stat-phish').innerText = scans.filter(s => s.analysis.status === 'CRITICAL PHISHING').length;
            document.getElementById('stat-clean').innerText = scans.filter(s => s.analysis.status === 'SAFE').length;
            if (!scans.length) return;
            document.getElementById('feed').innerHTML = scans.map(item => {
                const isPhish = item.analysis.status === 'CRITICAL PHISHING';
                const isSusp = item.analysis.status === 'SUSPICIOUS';
                const badge = isPhish ? 'bg-red-500/15 text-red-400 border-red-500/40' : (isSusp ? 'bg-amber-500/15 text-amber-400 border-amber-500/40' : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40');
                const bar = isPhish ? 'bg-red-500' : (isSusp ? 'bg-amber-500' : 'bg-emerald-500');
                return `<div class="bg-slate-900 border border-slate-800 rounded-xl p-5">
                    <div class="flex justify-between items-start mb-3">
                        <div>
                            <span class="text-[11px] font-mono bg-slate-800 text-indigo-300 px-2 py-0.5 rounded">${item.source} &bull; ${item.timestamp}</span>
                            <h3 class="text-lg font-bold mt-1">${item.subject}</h3>
                            <p class="text-xs text-slate-400">Sender: <span class="text-slate-200 font-mono">${item.from}</span></p>
                        </div>
                        <span class="px-3 py-1 rounded-full text-xs font-bold border ${badge}">${item.analysis.status} (${item.analysis.risk_score}/100)</span>
                    </div>
                    <div class="w-full bg-slate-800 h-2 rounded-full overflow-hidden mb-4"><div class="${bar} h-full" style="width:${item.analysis.risk_score}%"></div></div>
                    <div class="bg-slate-950 border-l-4 border-indigo-500 p-3 rounded mb-4 text-xs"><strong>🤖 AI Advice:</strong> ${item.analysis.advice}</div>
                    <div class="space-y-1 text-xs mb-3">
                        ${item.analysis.flags.map(f => `<div class="text-amber-300">⚠️ ${f}</div>`).join('')}
                        ${item.analysis.detected_urls.map(u => `<div class="text-indigo-400 font-mono truncate">🔗 ${u}</div>`).join('')}
                    </div>
                </div>`;
            }).join('');
        }
        setInterval(fetchScans, 2000);
        fetchScans();
    </script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTML_PAGE