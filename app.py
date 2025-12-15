from flask import Flask, request, jsonify

from api import stripe11

import os
import time
import threading

app = Flask(__name__)

def cleanup_cookies():
    """Background task to clean up old cookies"""
    while True:
        try:
            cookie_dir = 'cookies'
            if os.path.exists(cookie_dir):
                current_time = time.time()
                max_age = 20 * 60
                
                for filename in os.listdir(cookie_dir):
                    file_path = os.path.join(cookie_dir, filename)
                    if os.path.isfile(file_path):
                        file_mtime = os.path.getmtime(file_path)
                        if current_time - file_mtime > max_age:
                            try:
                                os.remove(file_path)
                                print(f"🗑️ Auto-deleted old cookie file: {filename}")
                            except Exception as e:
                                print(f"⚠️ Error deleting {filename}: {e}")
            
            time.sleep(60)
        except Exception as e:
            print(f"⚠️ Error in cookie cleanup task: {e}")
            time.sleep(60)

cleanup_thread = threading.Thread(target=cleanup_cookies, daemon=True)
cleanup_thread.start()


@app.route('/', methods=['GET'])
def home():
    """API Documentation"""
    documentation = {
        "service": "Payment API Service - Credit Card Validation with Stripe",
        "endpoints": [
            {
                "endpoint": "/api/stripe11",
                "description": "EPTES",
                "example_request": "/api/stripe11?auth=5444228403258437|11|2028|327"
            }
        ]
    }
    return jsonify(documentation), 200


@app.route('/api/stripe11', methods=['GET'])
def eptes_payment():
    """EPTES Payment Method API"""
    auth = request.args.get('auth', '')
    hcaptcha_token = request.args.get('hcaptcha', '')
    result, status_code = stripe11.handle_endpoint(auth, hcaptcha_token)
    return jsonify(result), status_code


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5020, debug=True)
