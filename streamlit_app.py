import streamlit as st
import json
import requests
import uuid
from datetime import datetime
from typing import Optional, Dict, List
import hashlib
import time
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv
import sys
import shutil

# Load local .env file if present (for local testing)
load_dotenv()

# ----------------------------------
# Helper Rerun Function (No experimental)
# ----------------------------------
def rerun():
    # Instead of using st.experimental_rerun, we exit the script.
    # Streamlit will rerun the script on the next user interaction.
    sys.exit()


# ===========================
# 1. Security Management
# ===========================
class SecurityManager:
    def __init__(self):
        # Get SECRET_KEY from env/secrets or generate a new one
        secret_key = os.getenv('SECRET_KEY') or st.secrets.get("SECRET_KEY")
        if not secret_key:
            secret_key = Fernet.generate_key()
        else:
            # If provided as string, encode to bytes
            if isinstance(secret_key, str):
                secret_key = secret_key.encode()
        self.SECRET_KEY = secret_key
        self.cipher_suite = Fernet(self.SECRET_KEY)

        # Get user credentials from env/secrets
        admin_username = os.getenv('ADMIN_USERNAME') or st.secrets.get("ADMIN_USERNAME", "admin")
        admin_password = os.getenv('ADMIN_PASSWORD') or st.secrets.get("ADMIN_PASSWORD", "Unicorn2025")
        user_username = os.getenv('USER_USERNAME') or st.secrets.get("USER_USERNAME", "user")
        user_password = os.getenv('USER_PASSWORD') or st.secrets.get("USER_PASSWORD", "Unicorn2025")
        
        self.users = {
            admin_username: {
                "password_hash": self._hash_password(admin_password),
                "role": "admin",
                "attempts": 0,
                "last_attempt": 0,
                "last_login": None
            },
            user_username: {
                "password_hash": self._hash_password(user_password),
                "role": "user",
                "attempts": 0,
                "last_attempt": 0,
                "last_login": None
            }
        }
        
        # Security settings
        self.MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', st.secrets.get("MAX_ATTEMPTS", 3)))
        self.LOCKOUT_TIME = int(os.getenv('LOCKOUT_TIME', st.secrets.get("LOCKOUT_TIME", 300)))
        self.SESSION_DURATION = int(os.getenv('SESSION_DURATION', st.secrets.get("SESSION_DURATION", 86400)))

    def _hash_password(self, password: str) -> str:
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        # Use a string as the default salt, then encode it
        salt = os.getenv('SALT') or st.secrets.get("SALT", "fixed_salt_for_demo")
        salt = salt.encode('utf-8')
        return hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt, 
            100000
        ).hex()

    def _generate_session_token(self, username: str) -> str:
        timestamp = str(int(time.time()))
        token_data = f"{username}:{timestamp}"
        return self.cipher_suite.encrypt(token_data.encode()).decode()

    def verify_session_token(self, token: str) -> tuple[bool, str]:
        try:
            token_data = self.cipher_suite.decrypt(token.encode()).decode()
            username, timestamp = token_data.split(':')
            is_valid = (int(time.time()) - int(timestamp)) < self.SESSION_DURATION
            message = "Valid session" if is_valid else "Session expired"
            return is_valid, message
        except Exception as e:
            return False, f"Invalid session token: {str(e)}"

    def authenticate(self, username: str, password: str) -> tuple[bool, str]:
        if username not in self.users:
            return False, "Invalid username or password"
        
        user = self.users[username]
        current_time = time.time()
        
        if user["attempts"] >= self.MAX_ATTEMPTS:
            if current_time - user["last_attempt"] < self.LOCKOUT_TIME:
                return False, f"Account locked. Try again in {int(self.LOCKOUT_TIME - (current_time - user['last_attempt']))} seconds"
            else:
                user["attempts"] = 0
        
        try:
            if self._hash_password(password) == user["password_hash"]:
                user["attempts"] = 0
                user["last_login"] = current_time
                session_token = self._generate_session_token(username)
                return True, session_token
            else:
                user["attempts"] += 1
                user["last_attempt"] = current_time
                remaining_attempts = self.MAX_ATTEMPTS - user["attempts"]
                return False, f"Invalid username or password. {remaining_attempts} attempts remaining"
        except ValueError as e:
            return False, str(e)

security = SecurityManager()

# ===========================
# 2. LinkedIn Cookie Management
# ===========================

def get_chrome_binary_location():
    """
    Attempts to find the path to the Chrome or Chromium binary.
    Checks environment variables first, then default paths, then uses shutil.which.
    """
    # 1. Check environment variables
    if os.getenv("BRAVE_BINARY"):
        return os.getenv("BRAVE_BINARY")
    if os.getenv("CHROME_BINARY"):
        return os.getenv("CHROME_BINARY")
    
    # 2. Check common fixed paths on Linux
    possible_paths = [
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium-browser",
        "/usr/bin/chromium"
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # 3. Fallback: search in PATH via shutil.which
    for binary in ["google-chrome", "google-chrome-stable", "chromium-browser", "chromium"]:
        auto_path = shutil.which(binary)
        if auto_path:
            return auto_path

    return None

def setup_chromedriver():
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.chrome.service import Service
        driver_path = ChromeDriverManager().install()
        return Service(driver_path)
    except Exception as e:
        st.error(f"❌ Error setting up ChromeDriver: {str(e)}")
        return None

def get_linkedin_cookies() -> Optional[str]:
    try:
        st.info("Trying to get cookies from LinkedIn Sales Navigator...")
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC

        options = Options()
        # Use headless mode and other arguments recommended for Streamlit Cloud
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        
        # Determine the binary location using our helper
        binary_location = get_chrome_binary_location()
        if not binary_location:
            st.error("No Chrome or Brave binary found. Please set the BRAVE_BINARY or CHROME_BINARY environment variable.")
            return None
        else:
            options.binary_location = binary_location
            st.info(f"Using browser binary: {binary_location}")

        service = setup_chromedriver()
        if service is None:
            st.error("Failed to initialize ChromeDriver.")
            return None

        driver = webdriver.Chrome(service=service, options=options)
        driver.get("https://www.linkedin.com/sales")
        
        try:
            # Wait until the body element is present
            WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
        except Exception as e:
            st.error(f"Timeout waiting for LinkedIn page to load: {str(e)}")
            driver.quit()
            return None
        
        cookies = driver.get_cookies()
        linkedin_cookies = [
            {
                'name': cookie['name'],
                'value': cookie['value'],
                'domain': cookie.get('domain', ''),
                'path': cookie.get('path', '/'),
                'secure': cookie.get('secure', True),
                'httpOnly': cookie.get('httpOnly', True)
            }
            for cookie in cookies 
            if '.linkedin.com' in cookie.get('domain', '')
        ]
        
        driver.quit()
        
        if linkedin_cookies:
            return json.dumps(linkedin_cookies, indent=2)
        else:
            st.warning("No LinkedIn cookies found. Please log in to LinkedIn in your browser first.")
            return None

    except Exception as e:
        st.error(f"Error retrieving cookies: {str(e)}")
        return None
    
# ===========================
# 3. Webhook Integration
# ===========================
def generate_session_id() -> str:
    return str(uuid.uuid4())

def validate_url(url: str) -> bool:
    return url.startswith('https://www.linkedin.com/sales/')

def send_to_webhook(data: Dict) -> Optional[Dict]:
    WEBHOOK_URL = os.getenv('WEBHOOK_URL') or st.secrets.get("WEBHOOK_URL")
    BEARER_TOKEN = os.getenv('BEARER_TOKEN') or st.secrets.get("BEARER_TOKEN")
    
    metadata = {
        "source": "linkedin_scraper",
        "requestTimestamp": datetime.utcnow().isoformat(),
        "requireApifyLogs": True
    }
    
    payload = {**data, "metadata": metadata}
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(WEBHOOK_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error sending webhook request: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        st.error(f"Error parsing webhook response: {str(e)}")
        return None

def trigger_heyreach_campaign(session_id: str, email: str) -> Optional[Dict]:
    HEYREACH_WEBHOOK_URL = os.getenv('HEYREACH_WEBHOOK_URL') or st.secrets.get("HEYREACH_WEBHOOK_URL")
    BEARER_TOKEN = os.getenv('BEARER_TOKEN') or st.secrets.get("BEARER_TOKEN")
    
    payload = {
        "sessionId": session_id,
        "timestamp": datetime.utcnow().isoformat(),
        "email": email,
        "metadata": {
            "source": "heyreach_campaign",
            "requestTimestamp": datetime.utcnow().isoformat(),
            "requireApifyLogs": True
        }
    }
    
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(HEYREACH_WEBHOOK_URL, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        st.error(f"Error sending Heyreach campaign request: {str(e)}")
        return None
    except json.JSONDecodeError as e:
        st.error(f"Error parsing Heyreach webhook response: {str(e)}")
        return None

# ===========================
# 4. Apify Integration
# ===========================
class ApifyLogManager:
    def __init__(self):
        self.APIFY_API_TOKEN = st.secrets.get("APIFY_API_TOKEN")
        if not self.APIFY_API_TOKEN:
            st.error("APIFY_API_TOKEN is not configured in st.secrets.")
        
    def get_actor_logs(self, run_id: str) -> Optional[List[Dict]]:
        try:
            import http.client
            conn = http.client.HTTPSConnection("api.apify.com")
            headers = {
                'Accept': 'text/plain',
                'Authorization': f'Bearer {self.APIFY_API_TOKEN}'
            }
            conn.request("GET", f"/v2/logs/{run_id}", '', headers)
            response = conn.getresponse()
            
            if response.status != 200:
                st.error(f"Error fetching logs: HTTP {response.status}")
                return None
                
            data = response.read()
            log_text = data.decode("utf-8")
            log_entries = []
            for line in log_text.split('\n'):
                if line.strip():
                    try:
                        parts = line.strip().split(' ', 2)
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            level = parts[1]
                            message = parts[2]
                            log_entries.append({
                                "timestamp": timestamp,
                                "level": level,
                                "message": message
                            })
                    except Exception as e:
                        st.error(f"Error parsing log line: {str(e)}")
                        continue
            return log_entries
            
        except Exception as e:
            st.error(f"Error fetching Apify logs: {str(e)}")
            return None
        finally:
            if 'conn' in locals():
                conn.close()

def display_apify_logs(run_id: str):
    apify_manager = ApifyLogManager()
    with st.expander("View Apify Logs", expanded=True):
        st.markdown("""
        <style>
            .log-timestamp { color: #666666; font-family: monospace; }
            .log-info { color: #00ff00; font-weight: bold; }
            .log-message { color: #ffffff; font-family: monospace; }
        </style>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("🔄 Refresh Logs", key="refresh_logs", use_container_width=True):
                with st.spinner("Fetching logs..."):
                    logs = apify_manager.get_actor_logs(run_id)
                    if logs:
                        for log in logs:
                            timestamp = log.get("timestamp", "")
                            level = log.get("level", "")
                            message = log.get("message", "")
                            log_html = f"""
                            <div style='font-family: monospace; white-space: pre; margin: 2px 0;'>
                                <span class='log-timestamp'>{timestamp}</span> 
                                <span class='log-{level.lower()}'>{level}</span>: 
                                <span class='log-message'>{message}</span>
                            </div>
                            """
                            st.markdown(log_html, unsafe_allow_html=True)
                    else:
                        st.warning("No logs available or error fetching logs")

def process_webhook_response(response: Dict) -> str:
    try:
        run_id = response.get("apifyRunId")
        if not run_id:
            st.warning("No Apify run ID found in webhook response. Log viewing will be unavailable.")
            return ""
        return str(run_id)
    except Exception as e:
        st.error(f"Error processing webhook response: {str(e)}")
        return ""

# ===========================
# 5. Main Application
# ===========================
def main():
    st.set_page_config(
        page_title="LinkedIn Sales Navigator Scraper",
        page_icon="🔍",
        layout="wide"
    )
    
    # Initialize session states
    default_states = {
        "logged_in": False,
        "cookie_json": "",
        "scraper_logs": [],
        "session_token": None,
        "username": None,
        "last_activity": time.time(),
        "apify_run_id": None
    }
    
    for key, default_value in default_states.items():
        if key not in st.session_state:
            st.session_state[key] = default_value

    # Session timeout (30 minutes)
    if st.session_state.logged_in:
        if time.time() - st.session_state.last_activity > 1800:
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.warning("Session expired due to inactivity. Please log in again.")
            rerun()  # Force exit so that Streamlit reruns on next interaction
        st.session_state.last_activity = time.time()

    # Authentication Check
    if not st.session_state.get("logged_in"):
        with st.form("login_form"):
            st.subheader("Please Log In")
            username = st.text_input("Username").strip()
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                if not username or not password:
                    st.error("Please enter both username and password.")
                    return
                success, message = security.authenticate(username, password)
                if success:
                    st.session_state.update({
                        "logged_in": True,
                        "session_token": message,
                        "username": username,
                        "last_activity": time.time()
                    })
                    st.success("Login successful!")
                    rerun()  # Exit so that the updated session state is used on the next run
                else:
                    st.error(message)
        return

    # Logout Button
    if st.sidebar.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        rerun()  # Exit so that Streamlit resets the session state
        return

    # Main Interface
    st.title("LinkedIn Sales Navigator Scraper")
    st.sidebar.info(f"Logged in as: {st.session_state.get('username', 'Unknown')}")
    
    # LinkedIn Account Connection
    st.subheader("LinkedIn Account Connection")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if not st.session_state.cookie_json:
            if st.button("Connect to Your LinkedIn Sales Navigator Account"):
                with st.spinner("Connecting to LinkedIn Sales Navigator..."):
                    cookies = get_linkedin_cookies()
                    if cookies:
                        st.session_state.cookie_json = cookies
                        st.success("✅ Successfully connected to LinkedIn Sales Navigator!")
                        rerun()
                    else:
                        st.error("❌ Connection failed. Make sure you are logged into LinkedIn.")
        else:
            st.success("✅ Connected to LinkedIn Sales Navigator")
            if st.button("Reconnect Account"):
                with st.spinner("Reconnecting to LinkedIn Sales Navigator..."):
                    cookies = get_linkedin_cookies()
                    if cookies:
                        st.session_state.cookie_json = cookies
                        st.success("✅ Successfully reconnected!")
                        rerun()
                    else:
                        st.error("❌ Reconnection failed.")

    # ------------------------------------------
    # Manual Cookie Input Option (Performance Improvement)
    # ------------------------------------------
    with st.expander("Manual Cookie Input (Optional)", expanded=False):
        st.info("If automatic connection fails or you prefer to paste your cookie data manually, you can do so below. The input is masked for security.")
        with st.form("manual_cookie_form"):
            manual_cookie_input = st.text_input("Paste your LinkedIn session cookie", type="password", help="Your LinkedIn cookie data (in JSON format) will be masked.")
            manual_submit = st.form_submit_button("Submit Cookie")
            if manual_submit:
                if not manual_cookie_input:
                    st.error("Please paste your cookie data.")
                else:
                    try:
                        cookie_data = json.loads(manual_cookie_input)
                        st.session_state.cookie_json = json.dumps(cookie_data, indent=2)
                        st.success("Cookie data stored successfully!")
                        rerun()
                    except Exception as e:
                        st.error("Invalid cookie data. Please ensure it's a valid JSON string.")

    # Scraper Form
    with st.form("scraper_form"):
        search_url = st.text_input("Sales Navigator Search URL", help="Enter your Sales Navigator search URL").strip()
        col3, col4 = st.columns(2)
        with col3:
            num_leads = st.number_input("Number of Leads", min_value=1, max_value=1000, value=100)
        with col4:
            email = st.text_input("Email Address", help="Notifications will be sent here").strip()
        submitted = st.form_submit_button("Start Scrape & Enrich")
        if submitted:
            if not st.session_state.cookie_json:
                st.error("Please connect to LinkedIn Sales Navigator first.")
                return
            if not validate_url(search_url):
                st.error("Please enter a valid LinkedIn Sales Navigator URL.")
                return
            if not email or '@' not in email:
                st.error("Please enter a valid email address.")
                return
            
            payload = {
                "sessionId": generate_session_id(),
                "timestamp": datetime.utcnow().isoformat(),
                "cookieJson": json.loads(st.session_state.cookie_json),
                "searchUrl": search_url,
                "numLeads": num_leads,
                "email": email
            }
            
            with st.spinner("Processing request..."):
                response = send_to_webhook(payload)
                if response:
                    st.session_state.scraper_logs = response.get("scraperLogs", [])
                    apify_run_id = process_webhook_response(response)
                    if apify_run_id:
                        st.session_state.apify_run_id = apify_run_id
                    st.success("✅ Scraping initiated successfully!")

    # Display Scraper Logs
    if st.session_state.scraper_logs:
        with st.expander("View Scraper Logs", expanded=True):
            for log in st.session_state.scraper_logs:
                timestamp = log.get("timestamp", "")
                message = log.get("message", "")
                level = log.get("level", "info")
                if level == "error":
                    st.error(f"{timestamp}: {message}")
                elif level == "warning":
                    st.warning(f"{timestamp}: {message}")
                else:
                    st.info(f"{timestamp}: {message}")

    # Display Apify Logs if available
    if st.session_state.get("apify_run_id"):
        display_apify_logs(st.session_state.apify_run_id)

    # Heyreach Campaign Section
    st.subheader("LinkedIn Outreach Campaign")
    with st.form("heyreach_campaign_form"):
        campaign_email = st.text_input("Campaign Notification Email",
                                       value=st.session_state.get('last_email', ''),
                                       help="Email address for campaign notifications").strip()
        campaign_submitted = st.form_submit_button("Start LinkedIn Outreach Campaign")
        if campaign_submitted:
            if not campaign_email or '@' not in campaign_email:
                st.error("Please enter a valid email address.")
            else:
                with st.spinner("Initiating Heyreach campaign..."):
                    session_id = generate_session_id()
                    response = trigger_heyreach_campaign(session_id, campaign_email)
                    if response:
                        st.success("✅ Heyreach campaign initiated successfully!")
                        st.session_state['last_email'] = campaign_email
                    else:
                        st.error("❌ Failed to initiate Heyreach campaign. Please try again.")

if __name__ == "__main__":
    main()
