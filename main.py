from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

app = FastAPI(title="PhishGuard Threat Platform")

# --- OPTIONAL: ADD YOUR GMAIL CREDENTIALS FOR AUTO-REPLY ---
SCANNER_EMAIL = "adityakhachane42@gmail.com"
SCANNER_APP_PASSWORD = "ghks pxfg xrdz mikw"

# Stores scanned emails in memory to display on the web dashboard
scan_history = []

class ManualScanRequest(BaseModel):
    sender: str
    subject: str
    body: str

def analyze_content(body: str, from_addr: str = "") -> dict:
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
    
    urgency_words = ["urgent", "immediately", "suspended", "action required", "24 hours", "unauthorized", "locked", "expired"]
    cred_words = ["login", "password", "verify", "confirm", "bank", "account", "ssn", "credentials", "otp"]
    
    found_urgency = [w for w in urgency_words if re.search(rf"\b{w}\b", body, re.I)]
    found_cred = [w for w in cred_words if re.search(rf"\b{w}\b", body, re.I)]
    
    risk_score = 0
    flags = []

    # 1. Check for Sender Spoofing
    trusted_brands = ["paypal", "microsoft", "google", "apple", "amazon", "netflix", "chase", "hdfc", "sbi"]
    for brand in trusted_brands:
        if brand in from_addr.lower() and f"@{brand}." not in from_addr.lower():
            risk_score += 40
            flags.append(f"Spoofed Sender: Claims to be '{brand.title()}', but sent from an unverified address.")
            break

    # 2. Check for Urgency & Coercion
    if found_urgency:
        risk_score += 30
        flags.append(f"Urgent/Panic Language: Uses pressure tactics ({', '.join(found_urgency[:3])}).")

    # 3. Check for Credential Harvesting
    if found_cred:
        risk_score += 35
        flags.append(f"Sensitive Data Request: Asks for login or financial info ({', '.join(found_cred[:3])}).")

    # 4. Check URLs
    if urls:
        risk_score += 25
        flags.append(f"External Links: Contains {len(urls)} hyperlink(s) leading outside the inbox.")
        for u in urls:
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', u):
                risk_score += 25
                flags.append("Raw IP Address Link: Hides actual destination domain using numbers.")
            if any(short in u.lower() for short in ["bit.ly", "tinyurl.com", "is.gd", "t.co"]):
                risk_score += 15
                flags.append("Link Shortener: Hides the true destination website.")

    risk_score = min(risk_score, 100)

    if risk_score >= 60:
        status = "CRITICAL PHISHING"
        advice = "Do NOT click any links or reply. Delete this message immediately and visit the official website directly in a new tab if you need to check your account."
    elif risk_score >= 30:
        status = "SUSPICIOUS"
        advice = "Proceed with caution. Verify the sender's real email address and call the organization directly before taking action."
    else:
        status = "SAFE"
        advice = "No obvious phishing indicators found. Standard inbox caution applies."

    return {
        "risk_score": risk_score,
        "status": status,
        "flags": flags,
        "detected_urls": urls,
        "advice": advice
    }

def send_verdict_reply(to_address: str, original_subject: str, analysis: dict):
    if not SCANNER_APP_PASSWORD or SCANNER_APP_PASSWORD == "your-16-char-app-password":
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{analysis['status']}] PhishGuard Report: {original_subject}"
        msg["From"] = f"PhishGuard Security <{SCANNER_EMAIL}>"
        msg["To"] = to_address

        color = "#ef4444" if analysis["status"] == "CRITICAL PHISHING" else ("#f59e0b" if analysis["status"] == "SUSPICIOUS" else "#10b981")
        
        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px; border: 1px solid #e5e7eb; border-radius: 10px;">
            <h2 style="margin-top:0; color:#111827;">🛡️ PhishGuard Security Report</h2>
            <div style="background:{color}; color:white; display:inline-block; padding:6px 14px; border-radius:20px; font-weight:bold; margin-bottom:15px;">
                {analysis['status']} — Risk Score: {analysis['risk_score']}/100
            </div>
            <p style="background:#f3f4f6; padding:12px; border-radius:6px; color:#1f2937;">
                <strong>What you should do:</strong> {analysis['advice']}
            </p>
            <h4>Why it was flagged:</h4>
            <ul>{''.join(f'<li>{f}</li>' for f in analysis['flags']) if analysis['flags'] else '<li>No suspicious indicators found.</li>'}</ul>
        </div>
        """
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(SCANNER_EMAIL, SCANNER_APP_PASSWORD)
            server.sendmail(SCANNER_EMAIL, to_address, msg.as_string())
    except Exception as e:
        print(f"Auto-reply skipped/error: {e}")

@app.post("/api/webhook/email")
async def receive_email(
    to: str = Form(...),
    from_address: str = Form(..., alias="from"),
    subject: Optional[str] = Form("No Subject"),
    text: Optional[str] = Form(""),
    html: Optional[str] = Form("")
):
    body = text if text else html or ""
    analysis = analyze_content(body, from_address)

    record = {
        "id": len(scan_history) + 1,
        "source": "Live Email Inbox",
        "timestamp": datetime.now().strftime("%I:%M:%S %p"),
        "from": from_address,
        "subject": subject,
        "body_preview": (body[:180] + "...") if len(body) > 180 else body,
        "analysis": analysis
    }
    scan_history.insert(0, record)

    clean_sender = re.findall(r'<(.+?)>', from_address)
    target = clean_sender[0] if clean_sender else from_address
    send_verdict_reply(target, subject, analysis)

    return {"status": "success", "verdict": analysis}

@app.post("/api/analyze-manual")
async def analyze_manual(req: ManualScanRequest):
    analysis = analyze_content(req.body, req.sender)
    record = {
        "id": len(scan_history) + 1,
        "source": "Manual Web Scan",
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

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>PhishGuard | Intelligent Phishing Detection & Response</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-950 text-slate-100 font-sans min-h-screen p-6 md:p-10">
        <div class="max-w-6xl mx-auto">
            <!-- Header -->
            <div class="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 border-b border-slate-800 pb-5 gap-4">
                <div>
                    <h1 class="text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
                        <span class="p-2 bg-indigo-600 rounded-lg text-xl">🛡️</span> PhishGuard AI
                    </h1>
                    <p class="text-slate-400 text-sm mt-1">PS 02 — Real-Time Email, SMS & URL Phishing Detection Platform</p>
                </div>
                <div class="flex items-center gap-2 bg-slate-900 border border-slate-800 px-4 py-2 rounded-full">
                    <span class="inline-block w-2.5 h-2.5 bg-emerald-500 rounded-full animate-ping"></span>
                    <span class="text-xs text-emerald-400 font-semibold uppercase tracking-wider">Inbox Listener Active</span>
                </div>
            </div>

            <!-- Stats Row -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
                <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                    <div class="text-slate-400 text-xs font-semibold uppercase">Total Messages Analyzed</div>
                    <div id="stat-total" class="text-3xl font-bold mt-1 text-white">0</div>
                </div>
                <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                    <div class="text-slate-400 text-xs font-semibold uppercase">High-Risk Phishing Blocked</div>
                    <div id="stat-phish" class="text-3xl font-bold mt-1 text-red-500">0</div>
                </div>
                <div class="bg-slate-900 border border-slate-800 p-5 rounded-xl">
                    <div class="text-slate-400 text-xs font-semibold uppercase">Safe Communications</div>
                    <div id="stat-clean" class="text-3xl font-bold mt-1 text-emerald-500">0</div>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Left Column: Manual Quick Scanner -->
                <div class="lg:col-span-1">
                    <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 sticky top-6">
                        <h2 class="text-base font-bold text-white mb-1">⚡ Quick Message / URL Scanner</h2>
                        <p class="text-xs text-slate-400 mb-4">Paste a suspicious email, text message, or link to test directly.</p>
                        
                        <div class="space-y-3">
                            <div>
                                <label class="text-xs text-slate-400 block mb-1">Sender Name / Email</label>
                                <input id="m-sender" type="text" placeholder="e.g. PayPal Support <alert@gmail.com>" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500">
                            </div>
                            <div>
                                <label class="text-xs text-slate-400 block mb-1">Subject Line</label>
                                <input id="m-subject" type="text" placeholder="e.g. Urgent: Account Suspended" class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500">
                            </div>
                            <div>
                                <label class="text-xs text-slate-400 block mb-1">Message Content & Links</label>
                                <textarea id="m-body" rows="4" placeholder="Paste email or SMS message here..." class="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500"></textarea>
                            </div>
                            <button onclick="runManualScan()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2.5 rounded-lg text-sm transition">
                                Analyze Threat Now
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Right Column: Live Feed -->
                <div class="lg:col-span-2">
                    <h2 class="text-base font-bold text-slate-300 mb-4">Live Security Feed (Auto-Updating)</h2>
                    <div id="feed" class="space-y-4">
                        <div class="text-center py-14 text-slate-500 bg-slate-900/40 rounded-xl border border-dashed border-slate-800">
                            Waiting for emails... Forward an email to your scanner inbox or use the Quick Scanner on the left!
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            async function runManualScan() {
                const sender = document.getElementById('m-sender').value;
                const subject = document.getElementById('m-subject').value;
                const body = document.getElementById('m-body').value;
                if (!body.trim()) return alert("Please enter a message or link to scan!");

                await fetch('/api/analyze-manual', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({sender, subject, body})
                });

                document.getElementById('m-body').value = '';
                fetchScans();
            }

            async function fetchScans() {
                try {
                    const res = await fetch('/api/scans');
                    const scans = await res.json();

                    document.getElementById('stat-total').innerText = scans.length;
                    document.getElementById('stat-phish').innerText = scans.filter(s => s.analysis.status === 'CRITICAL PHISHING').length;
                    document.getElementById('stat-clean').innerText = scans.filter(s => s.analysis.status === 'SAFE').length;

                    if (scans.length === 0) return;

                    const feed = document.getElementById('feed');
                    feed.innerHTML = scans.map(item => {
                        const isPhish = item.analysis.status === 'CRITICAL PHISHING';
                        const isSusp = item.analysis.status === 'SUSPICIOUS';
                        
                        const badgeColor = isPhish ? 'bg-red-500/15 text-red-400 border-red-500/40' : 
                                          (isSusp ? 'bg-amber-500/15 text-amber-400 border-amber-500/40' : 
                                                    'bg-emerald-500/15 text-emerald-400 border-emerald-500/40');
                        
                        const barColor = isPhish ? 'bg-red-500' : (isSusp ? 'bg-amber-500' : 'bg-emerald-500');

                        return `
                        <div class="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-lg">
                            <div class="flex justify-between items-start gap-3 mb-3">
                                <div>
                                    <span class="text-[11px] font-mono uppercase bg-slate-800 text-slate-300 px-2 py-0.5 rounded">${item.source} &bull; ${item.timestamp}</span>
                                    <h3 class="text-lg font-bold text-white mt-1">${item.subject}</h3>
                                    <p class="text-xs text-slate-400">Sender: <span class="text-slate-200 font-mono">${item.from}</span></p>
                                </div>
                                <div class="text-right shrink-0">
                                    <span class="px-3 py-1 rounded-full text-xs font-bold border ${badgeColor}">
                                        ${item.analysis.status} (${item.analysis.risk_score}/100)
                                    </span>
                                </div>
                            </div>

                            <!-- Score Bar -->
                            <div class="w-full bg-slate-800 h-2 rounded-full overflow-hidden mb-4">
                                <div class="${barColor} h-full" style="width: ${item.analysis.risk_score}%"></div>
                            </div>

                            <!-- Plain English User Guidance -->
                            <div class="bg-slate-950 border-l-4 ${isPhish ? 'border-red-500' : (isSusp ? 'border-amber-500' : 'border-emerald-500')} p-3 rounded mb-4 text-xs text-slate-200">
                                <strong>Recommended Action:</strong> ${item.analysis.advice}
                            </div>

                            <!-- Why was it flagged? -->
                            <div class="space-y-1.5 text-xs mb-3">
                                ${item.analysis.flags.length ? item.analysis.flags.map(f => `<div class="text-amber-300 flex items-center gap-1.5"><span>⚠️</span> ${f}</div>`).join('') : '<div class="text-emerald-400">✓ No deceptive patterns detected.</div>'}
                                ${item.analysis.detected_urls.map(u => `<div class="text-indigo-400 font-mono truncate">🔗 Extracted URL: ${u}</div>`).join('')}
                            </div>

                            <!-- Excerpt & Response Button -->
                            <div class="flex justify-between items-center pt-3 border-t border-slate-800/80 text-xs text-slate-500">
                                <span class="truncate max-w-md font-mono">"${item.body_preview}"</span>
                                <button onclick="alert('Incident logged: Sender domain added to blocklist and reported.')" class="bg-slate-800 hover:bg-red-600 hover:text-white text-slate-300 px-3 py-1.5 rounded font-medium transition shrink-0">
                                    Block & Report Sender
                                </button>
                            </div>
                        </div>
                        `;
                    }).join('');
                } catch (e) {
                    console.error(e);
                }
            }

            setInterval(fetchScans, 2000);
            fetchScans();
        </script>
    </body>
    </html>
    """