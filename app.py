import os
import json
import hmac
import hashlib
import requests
from flask import Flask, request

app = Flask(__name__)

ONEAPI_URL = os.environ.get('ONEAPI_URL', '').rstrip('/')
ONEAPI_TOKEN = os.environ.get('ONEAPI_TOKEN', '')
PADDLE_SECRET = os.environ.get('PADDLE_SECRET', '')

def verify_signature(body, signature):
    if not PADDLE_SECRET or not signature:
        return True
    computed = hmac.new(PADDLE_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)

def find_user_by_email(email):
    resp = requests.get(
        f"{ONEAPI_URL}/api/user/",
        headers={"Authorization": f"Bearer {ONEAPI_TOKEN}"},
        params={"page": 1, "size": 100}
    )
    if resp.status_code != 200:
        return None, 0
    users = resp.json().get("data", [])
    for u in users:
        if u.get("email") == email:
            return u["id"], u.get("quota", 0)
    return None, 0

def update_user_quota(user_id, new_quota):
    resp = requests.put(
        f"{ONEAPI_URL}/api/user/{user_id}",
        headers={
            "Authorization": f"Bearer {ONEAPI_TOKEN}",
            "Content-Type": "application/json"
        },
        json={"quota": new_quota}
    )
    return resp.status_code == 200

@app.route('/api/webhook', methods=['POST'])
def webhook():
    body = request.get_data()
    sig = request.headers.get('Paddle-Signature', '')
    
    if not verify_signature(body, sig):
        return 'Invalid signature', 403
    
    try:
        data = request.get_json()
    except:
        return 'Bad request', 400
    
    if data.get('event_type') != 'transaction.completed':
        return 'ok', 200
    
    custom = data.get('data', {}).get('custom_data', {})
    email = custom.get('email', '').strip()
    quota_to_add = int(custom.get('quota', 0))
    
    if not email or quota_to_add <= 0:
        return 'Missing email or quota', 400
    
    user_id, current_quota = find_user_by_email(email)
    if user_id is None:
        return f'User {email} not found', 404
    
    if update_user_quota(user_id, current_quota + quota_to_add):
        return f'Topup success: {email} +{quota_to_add}', 200
    else:
        return 'Update failed', 500

@app.route('/api/webhook', methods=['GET'])
def webhook_get():
    return 'ok', 200

@app.route('/', methods=['GET'])
def health():
    return 'ok', 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)

