import streamlit as st
import json
import requests
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, List
import hashlib
import time
from cryptography.fernet import Fernet
import os

# ---------------------------
# 1. Security Management
# ---------------------------

class SecurityManager:
    def __init__(self):
        # Retrieve the secret key from st.secrets if available; otherwise, generate one.
        secret_key = st.secrets.get("SECRET_KEY", None)
        if secret_key is None:
            secret_key = Fernet.generate_key()
        elif isinstance(secret_key, str):
            secret_key = secret_key.encode()
        self.SECRET_KEY = secret_key
        self.cipher_suite = Fernet(self.SECRET_KEY)
        
        self.users = {
            "admin": {
                "password_hash": self._hash_password("admin12345678"),
                "role": "admin",
                "attempts": 0,
                "last_attempt": 0,
                "last_login": None
            },
            "user": {
                "password_hash": self._hash_password("user12345678"),
                "role": "user",
                "attempts": 0,
                "last_attempt": 0,
                "last_login": None
            }
        }
        
        self.MAX_ATTEMPTS = 3
        self.LOCKOUT_TIME = 300
        self.SESSION_DURATION = 86400  # 24 hours

    def _hash_password(self, password: str) -> str:
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
            
        # Retrieve the salt from st.secrets if available; otherwise, use a fixed salt.
        salt = st.secrets.get("SALT", b"fixed_salt_for_demo")
        if isinstance(salt, str):
            salt = salt.encode()
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

# Initialize security manager
security = SecurityManager()

# ---------------------------
# 2. LinkedIn Cookie Management
# ---------------------------

def setup_chromedriver():
    try:
        from webdriver_manager.chrome import ChromeDriverManager
        from selenium.webdriver.chrome.service import Service
        
        # Download and install the appropriate ChromeDriver
        driver_path = ChromeDriverManager().install()
        return Service(driver_path)
    except Exception as e:
        st.error(f"❌ Error setting up ChromeDriver: {str(e)}")
        return None
    
def get_linkedin_cookies() -> Optional[str]:
    try:
        st.info("Trying to get cookies from Brave...")
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        import time
        
        # Set up Brave browser options
        options = Options()
        options.binary_location = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
        
        # Create driver and get cookies
        try:
            driver = webdriver.Chrome(options=options)
            driver.get("https://www.linkedin.com/sales")
            time.sleep(30)  # Wait for cookies to load
            
            # Get all cookies as array
            cookies = driver.get_cookies()
            
            # Filter LinkedIn cookies and maintain array format
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
                st.warning("No LinkedIn cookies found. Please log in to LinkedIn in Brave.")
                return None
                
        except Exception as e:
            st.error(f"Error with Selenium: {str(e)}")
            return None
            
    except Exception as e:
        st.error(f"Error retrieving cookies: {str(e)}")
        return None

# ---------------------------
# 3. Webhook Integration
# ---------------------------

def generate_session_id() -> str:
    return str(uuid.uuid4())

def validate_url(url: str) -> bool:
    return url.startswith('https://www.linkedin.com/sales/')

def send_to_webhook(data: Dict) -> Optional[Dict]:
    WEBHOOK_URL = "https://aliiiens.app.n8n.cloud/webhook/invoke_agent"
    # Retrieve the BEARER_TOKEN from st.secrets (or use default)
    BEARER_TOKEN = st.secrets.get("BEARER_TOKEN", "Unicorn2025@@@")
    
    # Add metadata for Apify tracking
    metadata = {
        "source": "linkedin_scraper",
        "requestTimestamp": datetime.utcnow().isoformat(),
        "requireApifyLogs": True
    }
    
    # Combine the data with metadata
    payload = {
        **data,
        "metadata": metadata
    }
    
    headers = {
        "Authorization": f"Bearer {BEARER_TOKEN}",
        "Content-Type": "application/json"
    }
    
    try:
        # Debug information
        st.write("Sending request to webhook...")
        st.write("Request URL:", WEBHOOK_URL)
        st.write("Request Headers:", {k: v for k, v in headers.items() if k != "Authorization"})
        st.write("Payload Structure:", {k: type(v).__name__ for k, v in payload.items()})
        
        # Make the request with increased timeout
        response = requests.post(
            WEBHOOK_URL, 
            json=payload, 
            headers=headers,
            timeout=30  # Increase timeout to 30 seconds
        )
        
        # Debug response
        st.write("Response Status Code:", response.status_code)
        st.write("Response Headers:", dict(response.headers))
        
        try:
            response_text = response.text
            st.write("Response Content:", response_text[:500] + "..." if len(response_text) > 500 else response_text)
        except:
            st.write("Could not read response content")
            
        response.raise_for_status()
        
        return response.json()
        
    except requests.exceptions.RequestException as e:
        st.error(f"Error sending request: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            st.error(f"Response Status Code: {e.response.status_code}")
            st.error(f"Response Content: {e.response.text}")
        return None
    except json.JSONDecodeError as e:
        st.error(f"Error parsing webhook response: {str(e)}")
        return None

def trigger_heyreach_campaign(session_id: str, email: str) -> Optional[Dict]:
    """
    Trigger Heyreach campaign through n8n webhook
    
    Args:
        session_id (str): Unique session identifier
        email (str): Email address for campaign notifications
        
    Returns:
        Optional[Dict]: Webhook response or None if request fails
    """
    HEYREACH_WEBHOOK_URL = "https://aliiiens.app.n8n.cloud/webhook/heyreach_campaign"  # Replace with your actual webhook URL
    # Retrieve the BEARER_TOKEN from st.secrets (or use default)
    BEARER_TOKEN = st.secrets.get("BEARER_TOKEN", "Unicorn2025@@@")
    
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
        # Debug information
        st.write("Sending Heyreach campaign request...")
        st.write("Request URL:", HEYREACH_WEBHOOK_URL)
        st.write("Request Headers:", {k: v for k, v in headers.items() if k != "Authorization"})
        st.write("Payload Structure:", {k: type(v).__name__ for k, v in payload.items()})
        
        response = requests.post(
            HEYREACH_WEBHOOK_URL,
            json=payload,
            headers=headers,
            timeout=30
        )
        
        # Debug response
        st.write("Response Status Code:", response.status_code)
        st.write("Response Headers:", dict(response.headers))
        
        try:
            response_text = response.text
            st.write("Response Content:", response_text[:500] + "..." if len(response_text) > 500 else response_text)
        except:
            st.write("Could not read response content")
            
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        st.error(f"Error sending Heyreach campaign request: {str(e)}")
        if hasattr(e, 'response') and e.response is not None:
            st.error(f"Response Status Code: {e.response.status_code}")
            st.error(f"Response Content: {e.response.text}")
        return None
    except json.JSONDecodeError as e:
        st.error(f"Error parsing Heyreach webhook response: {str(e)}")
        return None

# ---------------------------
# 4. Apify Integration
# ---------------------------

class ApifyLogManager:
    def __init__(self):
        self.APIFY_API_TOKEN = st.secrets["APIFY_API_TOKEN"]
        
    def get_actor_logs(self, run_id: str) -> Optional[List[Dict]]:
        """
        Fetch logs for a specific actor run using http.client
        
        Args:
            run_id (str): The ID of the actor run
            
        Returns:
            Optional[List[Dict]]: List of log entries or None if request fails
        """
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
            
            # Parse log text into structured format
            log_entries = []
            for line in log_text.split('\n'):
                if line.strip():
                    try:
                        # Parse the log line
                        parts = line.strip().split(' ', 2)  # Split into max 3 parts
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
    """
    Display Apify actor logs in the Streamlit UI with console-style formatting
    
    Args:
        run_id (str): The ID of the actor run
    """
    apify_manager = ApifyLogManager()
    
    with st.expander("View Apify Logs", expanded=True):
        # Custom CSS for log display
        st.markdown("""
        <style>
            .log-timestamp { color: #666666; font-family: monospace; }
            .log-actor { color: #ffffff; font-weight: bold; }
            .log-info { color: #00ff00; font-weight: bold; }
            .log-message { color: #ffffff; font-family: monospace; }
            .stMarkdown { line-height: 1.2; }
        </style>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("🔄 Refresh Logs", use_container_width=True):
                with st.spinner("Fetching logs..."):
                    logs = apify_manager.get_actor_logs(run_id)
                    
                    if logs:
                        # Create a container for logs
                        log_container = st.container()
                        
                        with log_container:
                            for log in logs:
                                timestamp = log.get("timestamp", "")
                                level = log.get("level", "")
                                message = log.get("message", "")
                                
                                # Format the log entry with HTML styling
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
    """
    Process webhook response to extract Apify run ID.
    """
    try:
        run_id = response.get("apifyRunId")
        
        if not run_id:
            st.warning("No Apify run ID found in webhook response. Log viewing will be unavailable.")
            return ""
            
        return str(run_id)
        
    except Exception as e:
        st.error(f"Error processing webhook response: {str(e)}")
        return ""

# ---------------------------
# 5. Main Application
# ---------------------------

def main():
    st.set_page_config(
        page_title="LinkedIn Sales Navigator Scraper",
        page_icon="🔍",
        layout="wide"
    )

    # Initialize session states with better type handling
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

    # Session timeout check (30 minutes)
    if st.session_state.logged_in:
        if time.time() - st.session_state.last_activity > 1800:  # 30 minutes
            for key in st.session_state.keys():
                del st.session_state[key]
            st.warning("Session expired due to inactivity. Please log in again.")
            st.rerun()
        st.session_state.last_activity = time.time()

    # Authentication Check with improved validation
    if not st.session_state.get("logged_in"):
        with st.form("login_form"):
            st.subheader("Please Log In")
            username = st.text_input("Username").strip()
            password = st.text_input("Password", type="password")
            col1, col2 = st.columns([1, 4])
            with col1:
                submitted = st.form_submit_button("Login", use_container_width=True)
            
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
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(message)
        return

    # Logout Button
    if st.sidebar.button("Logout"):
        for key in st.session_state.keys():
            del st.session_state[key]
        st.rerun()
        return

    # Main Application Interface
    st.title("LinkedIn Sales Navigator Scraper")
    st.sidebar.info(f"Logged in as: {st.session_state.get('username', 'Unknown')}")

    # ---------------------------
    # LinkedIn Account Connection
    # ---------------------------
    st.subheader("LinkedIn Account Connection")
    
    # Let the user choose between automatic retrieval and manual input.
    cookie_method = st.radio(
        "Choose LinkedIn Cookie Retrieval Method",
        options=["Automatic Retrieval", "Manual Input"],
        index=0,
        help="Select 'Manual Input' to paste your cookie data securely (the input will be masked)."
    )
    
    if cookie_method == "Manual Input":
        manual_cookie = st.text_input(
            "Paste your LinkedIn session cookie here",
            type="password",
            help="Paste your cookie JSON here. The content will be hidden for security purposes."
        )
        if manual_cookie:
            st.session_state.cookie_json = manual_cookie
            st.success("✅ Cookie data received manually!")
    else:
        # Center the button using columns
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            if not st.session_state.cookie_json:
                if st.button("Connect to Your LinkedIn Sales Navigator Account", use_container_width=True):
                    with st.spinner("Connecting to LinkedIn Sales Navigator..."):
                        cookies = get_linkedin_cookies()
                        if cookies:
                            st.session_state.cookie_json = cookies
                            st.success("✅ Successfully connected to LinkedIn Sales Navigator!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ Connection failed. Please make sure you're logged into LinkedIn Sales Navigator in Brave browser.")
            else:
                st.success("✅ Connected to LinkedIn Sales Navigator")
                if st.button("Reconnect Account", use_container_width=True):
                    with st.spinner("Reconnecting to LinkedIn Sales Navigator..."):
                        cookies = get_linkedin_cookies()
                        if cookies:
                            st.session_state.cookie_json = cookies
                            st.success("✅ Successfully reconnected to LinkedIn Sales Navigator!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("❌ Reconnection failed. Please make sure you're logged into LinkedIn Sales Navigator in Brave browser.")

    # Scraper Form
    with st.form("scraper_form"):
        search_url = st.text_input(
            "Sales Navigator Search URL",
            help="Enter your Sales Navigator search URL"
        ).strip()
        
        col3, col4 = st.columns(2)
        with col3:
            num_leads = st.number_input(
                "Number of Leads",
                min_value=1,
                max_value=1000,
                value=100
            )
        with col4:
            email = st.text_input(
                "Email Address",
                help="Notifications will be sent here"
            ).strip()
        
        submitted = st.form_submit_button("Start Scraping", use_container_width=True)
        
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
                    # Store Apify run ID from webhook response
                    apify_run_id = process_webhook_response(response)
                    if apify_run_id:
                        st.session_state.apify_run_id = apify_run_id
                    st.success("✅ Scraping initiated successfully!")

    # Display Logs
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

    # Display Apify Logs if run ID is available
    if st.session_state.get("apify_run_id"):
        display_apify_logs(st.session_state.apify_run_id)

    # Heyreach Campaign Section
    st.subheader("LinkedIn Outreach Campaign")
    
    with st.form("heyreach_campaign_form"):
        email = st.text_input(
            "Campaign Notification Email",
            value=st.session_state.get('last_email', ''),  # Use previously entered email if available
            help="Email address for campaign notifications"
        ).strip()
        
        campaign_submitted = st.form_submit_button("Start LinkedIn Outreach Campaign", use_container_width=True)
        
        if campaign_submitted:
            if not email or '@' not in email:
                st.error("Please enter a valid email address.")
            else:
                with st.spinner("Initiating Heyreach campaign..."):
                    session_id = generate_session_id()  # Reuse the existing session ID generator
                    response = trigger_heyreach_campaign(session_id, email)
                    
                    if response:
                        st.success("✅ Heyreach campaign initiated successfully!")
                        st.session_state['last_email'] = email  # Store email for future use
                    else:
                        st.error("❌ Failed to initiate Heyreach campaign. Please try again.")

if __name__ == "__main__":
    main()
