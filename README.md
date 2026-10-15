# hackathon-project
get:- ngrok

run :- 
cd C:\Users\adity\phishing-detector
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000



run:-ngrok http 8000
