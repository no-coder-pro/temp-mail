# Copyright @ISmartCoder
# Updates Channel https://t.me/abirxdhackz
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import requests
import time
import re
import base64
import json
import gzip
import brotli
import cloudscraper
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
import threading
import uuid
import os
from functools import wraps

app = Flask(__name__)
CORS(app)

class TempMailService:
    def __init__(self):
        self.sessions = {}
        self.email_sessions = {}
        
    def decode_api_url(self, encoded_url):
        try:
            cleaned_url = re.sub(r'[^A-Za-z0-9+/=]', '', encoded_url)
            cleaned_url = cleaned_url.replace('f56', '6')
            cleaned_url = cleaned_url + '=' * (4 - len(cleaned_url) % 4) if len(cleaned_url) % 4 != 0 else cleaned_url
            decoded = base64.b64decode(cleaned_url).decode('utf-8')
            if not decoded.startswith('http'):
                decoded = 'https://' + decoded.lstrip('?:/')
            return decoded
        except Exception as e:
            print(f"[DEBUG] Error decoding API URL: {str(e)}")
            return None

    def decompress_response(self, response_text, headers):
        if headers.get('Content-Encoding') == 'gzip':
            try:
                return gzip.decompress(response_text.encode()).decode('utf-8')
            except Exception as e:
                print(f"[DEBUG] Error decompressing response: {str(e)}")
                return response_text
        return response_text

    def decompress_edu_response(self, response):
        content = response.content
        try:
            if not content:
                return None
            if response.headers.get('content-encoding') == 'gzip':
                return gzip.decompress(content).decode('utf-8')
            elif response.headers.get('content-encoding') == 'br':
                try:
                    return brotli.decompress(content).decode('utf-8')
                except brotli.error:
                    try:
                        return content.decode('utf-8')
                    except UnicodeDecodeError:
                        return None
            return content.decode('utf-8')
        except Exception:
            return None

    def extract_auth_token(self, html_content, cookies):
        try:
            jwt_patterns = [
                r'"jwt"\s*:\s*"(eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z0-9_-]+)"',
                r'"token"\s*:\s*"(eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z0-9_-]+)"',
                r'window\.token\s*=\s*[\'"]eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z0-9_-]+[\'"]',
                r'eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.[A-Za-z0-9_-]+'
            ]
            for pattern in jwt_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, str) and match.startswith('eyJ'):
                        return match
            return None
        except Exception as e:
            print(f"[DEBUG] Error extracting auth token: {str(e)}")
            return None

    def extract_email_from_html(self, soup):
        try:
            email_input = soup.find('input', {'id': 'mail'}) or soup.find('input', {'name': 'mail'})
            if email_input and email_input.get('value'):
                return email_input.get('value')
            email_span = soup.find('span', {'id': 'mail'})
            if email_span and email_span.get_text().strip():
                return email_span.get_text().strip()
            email_container = soup.find(['div', 'span'], class_=re.compile('email|mailbox|address|temp-mail', re.I))
            if email_container:
                email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
                match = re.search(email_pattern, email_container.get_text())
                if match:
                    return match.group()
            email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
            for text in soup.stripped_strings:
                match = re.search(email_pattern, text)
                if match and '@' in match.group() and '.' in match.group():
                    return match.group()
            return None
        except Exception as e:
            print(f"[DEBUG] Error extracting email from HTML: {str(e)}")
            return None

    def get_mailbox_and_token(self, api_url, cookies, scraper, ten_minute=False):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Origin': 'https://temp-mail.org',
                'Referer': 'https://temp-mail.org/en/10minutemail' if ten_minute else 'https://temp-mail.org/en/',
                'Sec-Ch-Ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-site',
                'Content-Type': 'application/json',
                'Priority': 'u=1, i'
            }
            if 'XSRF-TOKEN' in cookies:
                headers['X-XSRF-TOKEN'] = cookies['XSRF-TOKEN']
            print(f"[DEBUG] Requesting mailbox from: {api_url}/mailbox")
            response = scraper.post(f"{api_url}/mailbox", headers=headers, cookies=cookies, json={})
            print(f"[DEBUG] Mailbox response status: {response.status_code}")
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"[DEBUG] Mailbox response: {json.dumps(data, indent=2)}")
                    email = data.get('mailbox') or data.get('email') or data.get('address')
                    jwt_token = data.get('token') or data.get('jwt') or data.get('auth_token')
                    if jwt_token and jwt_token.startswith('eyJ'):
                        return email, jwt_token
                    else:
                        print(f"[DEBUG] No valid JWT token found in response")
                        return email, None
                except json.JSONDecodeError as e:
                    print(f"[DEBUG] JSON decode error: {str(e)}")
                    print(f"[DEBUG] Raw response: {response.text}")
                    return None, None
            else:
                print(f"[DEBUG] Mailbox request failed with status: {response.status_code}")
                print(f"[DEBUG] Response: {response.text}")
                response = scraper.get(f"{api_url}/mailbox", headers=headers, cookies=cookies)
                print(f"[DEBUG] GET mailbox response status: {response.status_code}")
                if response.status_code == 200:
                    try:
                        data = response.json()
                        print(f"[DEBUG] GET Mailbox response: {json.dumps(data, indent=2)}")
                        email = data.get('mailbox') or data.get('email') or data.get('address')
                        jwt_token = data.get('token') or data.get('jwt') or data.get('auth_token')
                        if jwt_token and jwt_token.startswith('eyJ'):
                            return email, jwt_token
                        else:
                            print(f"[DEBUG] No valid JWT token found in GET response")
                            return email, None
                    except json.JSONDecodeError as e:
                        print(f"[DEBUG] GET JSON decode error: {str(e)}")
                        print(f"[DEBUG] GET Raw response: {response.text}")
                        return None, None
                else:
                    print(f"[DEBUG] GET Mailbox request also failed with status: {response.status_code}")
                    return None, None
        except Exception as e:
            print(f"[DEBUG] Exception in get_mailbox_and_token: {str(e)}")
            return None, None

    def check_inbox(self, api_url, auth_token, cookies, email, scraper, ten_minute=False):
        try:
            print(f"[DEBUG] Making request to: {api_url}/messages")
            print(f"[DEBUG] Using auth token: {auth_token[:50] if auth_token else 'None'}...")
            print(f"[DEBUG] Using cookies: {list(cookies.keys())}")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Origin': 'https://temp-mail.org',
                'Referer': 'https://temp-mail.org/en/10minutemail' if ten_minute else 'https://temp-mail.org/en/',
                'Sec-Ch-Ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-site',
                'Priority': 'u=1, i'
            }
            if auth_token:
                headers['Authorization'] = f'Bearer {auth_token}'
            if 'XSRF-TOKEN' in cookies:
                headers['X-XSRF-TOKEN'] = cookies['XSRF-TOKEN']
            response = scraper.get(f"{api_url}/messages", headers=headers, cookies=cookies)
            print(f"[DEBUG] Response status: {response.status_code}")
            if response.status_code == 200:
                try:
                    inbox_data = response.json()
                    print(f"[DEBUG] Raw response: {json.dumps(inbox_data, indent=2)}")
                    if 'messages' in inbox_data:
                        messages = inbox_data['messages']
                        print(f"[DEBUG] Messages found: {len(messages)}")
                        if messages:
                            print(f"[DEBUG] First message: {messages[0]}")
                        return messages
                    elif isinstance(inbox_data, list):
                        messages = inbox_data
                        print(f"[DEBUG] Messages found: {len(messages)}")
                        return messages
                    else:
                        print(f"[DEBUG] No messages key found in response")
                        return []
                except json.JSONDecodeError as e:
                    print(f"[DEBUG] JSON decode error: {str(e)}")
                    print(f"[DEBUG] Raw response text: {response.text}")
                    return None
            else:
                print(f"[DEBUG] Response status: {response.status_code}")
                print(f"[DEBUG] Response headers: {dict(response.headers)}")
                print(f"[DEBUG] Raw response: {response.text[:500]}")
                return None
        except Exception as e:
            print(f"[DEBUG] Exception in check_inbox: {str(e)}")
            return None

    def generate_temp_mail(self, ten_minute=False):
        start_time = time.time()
        scraper = cloudscraper.create_scraper()
        try:
            url = 'https://temp-mail.org/en/10minutemail' if ten_minute else 'https://temp-mail.org/en/'
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Sec-Ch-Ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'Priority': 'u=0, i'
            }
            response = scraper.get(url, headers=headers, allow_redirects=True)
            print(f"[DEBUG] Response status for {url}: {response.status_code}")
            if response.status_code != 200:
                return {"error": f"Failed to connect to {url}"}, 500
            html_content = self.decompress_response(response.text, response.headers)
            cookies = dict(response.cookies)
            print(f"[DEBUG] Captured cookies: {cookies}")
            soup = BeautifulSoup(html_content, 'html.parser')
            api_url = None
            scripts = soup.find_all('script')
            for script in scripts:
                if script.string:
                    script_content = script.string
                    api_patterns = [
                        r"var api_url\s*=\s*'([^']+)'",
                        r'"api_url"\s*:\s*"([^"]+)"',
                        r'apiUrl\s*:\s*[\'"]([^\'"]+)[\'"]',
                        r'API_URL\s*=\s*[\'"]([^\'"]+)[\'"]'
                    ]
                    for pattern in api_patterns:
                        match = re.search(pattern, script_content)
                        if match:
                            encoded_api_url = match.group(1)
                            api_url = self.decode_api_url(encoded_api_url)
                            if api_url:
                                print(f"[DEBUG] Captured API URL: {api_url}")
                                break
                    if api_url:
                        break
            if not api_url:
                api_url = "https://web2.temp-mail.org"
                print(f"[DEBUG] Using default API URL: {api_url}")
            email, auth_token = self.get_mailbox_and_token(api_url, cookies, scraper, ten_minute)
            if not email or not auth_token:
                print("[DEBUG] Failed to get email/token from API, trying HTML extraction...")
                email = self.extract_email_from_html(soup)
                if not auth_token:
                    auth_token = self.extract_auth_token(html_content, cookies)
            if not email or not auth_token:
                return {"error": "Failed to generate temporary email"}, 500
            session_data = {
                'api_url': api_url,
                'email': email,
                'cookies': cookies,
                'scraper': scraper,
                'created_at': time.time(),
                'ten_minute': ten_minute
            }
            self.sessions[auth_token] = session_data
            time_taken = f"{time.time() - start_time:.2f}s"
            return {
                "api_owner": "@ISmartCoder",
                "api_dev": "@WeSmartDevelopers",
                "temp_mail": email,
                "access_token": auth_token,
                "time_taken": time_taken,
                "expires_at": (datetime.now() + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S') if ten_minute else "N/A"
            }
        except Exception as e:
            print(f"[DEBUG] Error in generate_temp_mail: {str(e)}")
            return {"error": f"Error generating temp mail: {str(e)}"}, 500

    def check_messages(self, token):
        if token not in self.sessions:
            return {"error": "Invalid or expired token"}, 404
        session = self.sessions[token]
        if session['ten_minute'] and (time.time() - session['created_at']) > 600:
            del self.sessions[token]
            return {"error": "10-minute email has expired"}, 410
        try:
            messages = self.check_inbox(
                session['api_url'],
                token,
                session['cookies'],
                session['email'],
                session['scraper'],
                session['ten_minute']
            )
            if messages is None:
                return {"error": "Failed to check inbox"}, 500
            enhanced_messages = []
            for message in messages:
                enhanced_message = message.copy()
                enhanced_message["api_dev"] = "@ISmartCoder"
                enhanced_message["api_updates"] = "@WeSmartDevelopers"
                if 'receivedAt' in enhanced_message:
                    try:
                        enhanced_message['receivedAt'] = datetime.fromtimestamp(
                            enhanced_message['receivedAt']
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    except:
                        pass
                enhanced_messages.append(enhanced_message)
            return {
                "mailbox": session['email'],
                "messages": enhanced_messages,
                "api_owner": "@ISmartCoder",
                "api_dev": "@WeSmartDevelopers",
                "expires_at": (datetime.fromtimestamp(session['created_at']) + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S') if session['ten_minute'] else "N/A"
            }
        except Exception as e:
            print(f"[DEBUG] Error in check_messages: {str(e)}")
            return {"error": f"Error checking messages: {str(e)}"}, 500

temp_mail_service = TempMailService()

@app.route('/tempmail/gen', methods=['GET'])
def generate_temp_mail_route():
    ten_minute = request.args.get('ten_minute', 'false').lower() == 'true'
    result = temp_mail_service.generate_temp_mail(ten_minute)
    status_code = result.pop('status_code', 200)
    return jsonify(result), status_code

@app.route('/tempmail/inbox', methods=['GET'])
def check_inbox_route():
    token = request.args.get('token')
    if not token:
        return jsonify({"error": "Missing token parameter"}), 400
    result = temp_mail_service.check_messages(token)
    status_code = result.pop('status_code', 200)
    return jsonify(result), status_code

@app.route('/')
def api_documentation():
    return jsonify({
        "api_name": "TempMail API",
        "api_owner": "@ISmartCoder",
        "api_dev": "@WeSmartDevelopers",
        "endpoints": {
            "/tempmail/gen": {
                "method": "GET",
                "description": "Generates a temporary email address.",
                "parameters": {
                    "ten_minute": "Optional. Set to 'true' for a 10-minute email, 'false' otherwise. Defaults to 'false'."
                },
                "example_response": {
                    "api_owner": "@ISmartCoder",
                    "api_dev": "@WeSmartDevelopers",
                    "temp_mail": "example@tempmail.org",
                    "access_token": "eyJ...",
                    "time_taken": "0.50s",
                    "expires_at": "N/A"
                }
            },
            "/tempmail/inbox": {
                "method": "GET",
                "description": "Checks the inbox of a temporary email address.",
                "parameters": {
                    "token": "Required. The access_token received from /tempmail/gen."
                },
                "example_response": {
                    "mailbox": "example@tempmail.org",
                    "messages": [
                        {
                            "id": "...",
                            "from": "sender@example.com",
                            "subject": "Test Subject",
                            "body": "Email body content...",
                            "receivedAt": "YYYY-MM-DD HH:MM:SS",
                            "api_dev": "@ISmartCoder",
                            "api_updates": "@WeSmartDevelopers"
                        }
                    ],
                    "api_owner": "@ISmartCoder",
                    "api_dev": "@WeSmartDevelopers",
                    "expires_at": "N/A"
                }
            }
        },
        "info": "Use the /tempmail/gen endpoint to get a temporary email and an access_token. Then use the /tempmail/inbox endpoint with the access_token to check for messages."
    })

if __name__ == '__main__':
    app.run(debug=True)
