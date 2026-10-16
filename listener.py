# listener.py
import imaplib
import email
from email.header import decode_header
import requests
import time

IMAP_SERVER = "imap.gmail.com"
EMAIL_USER = "@gmail.com"        # Your scanner Gmail
EMAIL_PASS = ""            # Your 16-character App Password
API_URL = "http://127.0.0.1:8000/api/webhook/email"

def clean_header(header_val):
    if not header_val:
        return ""
    decoded, enc = decode_header(header_val)[0]
    if isinstance(decoded, bytes):
        return decoded.decode(enc or "utf-8", errors="ignore")
    return str(decoded)

def poll_inbox():
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_USER, EMAIL_PASS)
        mail.select("inbox")

        # Search only for UNSEEN (unread) emails
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        for e_id in email_ids:
            _, msg_data = mail.fetch(e_id, "(RFC822)")
            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = clean_header(msg["Subject"])
            from_addr = clean_header(msg["From"])
            to_addr = clean_header(msg["To"])

            # Extract message body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    if content_type == "text/plain":
                        body = part.get_payload(decode=True).decode(errors="ignore")
                        break
                    elif content_type == "text/html" and not body:
                        body = part.get_payload(decode=True).decode(errors="ignore")
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            # Post directly to your local FastAPI endpoint
            payload = {
                "from": from_addr,
                "to": to_addr,
                "subject": subject,
                "text": body
            }
            
            res = requests.post(API_URL, data=payload)
            if res.status_code == 200:
                print(f"[PROCESSED] Successfully analyzed: '{subject}' from {from_addr}")

            # Mark email as read so it isn't processed again
            mail.store(e_id, "+FLAGS", "\\Seen")

        mail.logout()
    except Exception as err:
        print(f"Polling loop error: {err}")

if __name__ == "__main__":
    print(f"Monitoring {EMAIL_USER} in real time... (Press Ctrl+C to stop)")
    while True:
        poll_inbox()
        time.sleep(4)
