import os, json, hmac, hashlib, requests, logging
from http.server import BaseHTTPRequestHandler

ONEAPI_URL = os.environ.get('ONEAPI_URL', '').rstrip('/')
ONEAPI_TOKEN = os.environ.get('ONEAPI_TOKEN', '')
PADDLE_SECRET = os.environ.get('PADDLE_SECRET', '')

def verify_signature(body, signature):
    if not PADDLE_SECRET or not signature:
        return True
    computed = hmac.new(PADDLE_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)

def find_user_by_email(email):
    if not ONEAPI_URL or not ONEAPI_TOKEN:
        logging.error("find_user_by_email: ONEAPI_URL or ONEAPI_TOKEN is not set")
        return None, 0
    try:
        resp = requests.get(
            f"{ONEAPI_URL}/api/user/",
            headers={"Authorization": f"Bearer {ONEAPI_TOKEN}"},
            params={"page": 1, "size": 100},
            timeout=5
        )
        if resp.status_code != 200:
            logging.error("find_user_by_email: unexpected status %s", resp.status_code)
            return None, 0
        users = resp.json().get("data", [])
        for u in users:
            if u.get("email") == email:
                return u["id"], u.get("quota", 0)
        return None, 0
    except requests.exceptions.RequestException as e:
        logging.error("find_user_by_email: request failed: %s", e)
        return None, 0

def update_user_quota(user_id, new_quota):
    if not ONEAPI_URL or not ONEAPI_TOKEN:
        logging.error("update_user_quota: ONEAPI_URL or ONEAPI_TOKEN is not set")
        return False
    try:
        resp = requests.put(
            f"{ONEAPI_URL}/api/user/{user_id}",
            headers={
                "Authorization": f"Bearer {ONEAPI_TOKEN}",
                "Content-Type": "application/json"
            },
            json={"quota": new_quota},
            timeout=5
        )
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        logging.error("update_user_quota: request failed: %s", e)
        return False

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        sig = self.headers.get('Paddle-Signature', '')
        if not verify_signature(body, sig):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b'Invalid signature')
            return

        try:
            data = json.loads(body)
        except:
            self.send_response(400)
            self.end_headers()
            return

        if data.get('event_type') != 'transaction.completed':
            self.send_response(200)
            self.end_headers()
            return

        custom = data.get('data', {}).get('custom_data', {})
        email = custom.get('email', '').strip()
        quota_to_add = int(custom.get('quota', 0))

        if not email or quota_to_add <= 0:
            self.send_response(400)
            self.end_headers()
            return

        user_id, current_quota = find_user_by_email(email)
        if user_id is None:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(f'User {email} not found'.encode())
            return

        if update_user_quota(user_id, current_quota + quota_to_add):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(f'Topup success: {email} +{quota_to_add}'.encode())
        else:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b'Update failed')

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'ok')
