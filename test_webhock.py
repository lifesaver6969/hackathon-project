import requests

# Replace with your actual ngrok URL or localhost URL
URL = "https://substance-july-ploy.ngrok-free.dev/api/webhook/email"

payload = {
    "from": "security-alert@micros0ft-support.com",
    "to": "target-employee@hackathon.com",
    "subject": "Urgent: Your account is suspended!",
    "text": "Your account has been suspended immediately. Please verify your login credentials here: https://micros0ft-fake-login.com"
}

response = requests.post(URL, data=payload)
print("Server response code:", response.status_code)
print("Analysis result:", response.json())