import streamlit as st
import pandas as pd
import re, os, json, time, base64
from email.mime.text import MIMEText
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ---------------- CONFIG -----------------
SCOPES = [
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.readonly",
]
BOUNCE_KEYWORDS = [
    "address not found","user unknown","recipient address rejected",
    "no such user","does not exist","invalid recipient","mailbox unavailable",
    "unknown recipient","rejected recipient","550 5.1.1","553 5.1.2","554 5.1.1",
    "mailbox full","over quota","delivery failure","mail delivery subsystem"
]
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# ----- GOOGLE OAUTH CONFIG -----
CLIENT_ID = st.secrets["google"]["client_id"]
CLIENT_SECRET = st.secrets["google"]["client_secret"]
REDIRECT_URI = st.secrets["google"].get(
    "redirect_uri",
    "https://your-app-url.streamlit.app/"
)

def client_config():
    return {"web":{"client_id":CLIENT_ID,"client_secret":CLIENT_SECRET,
                    "auth_uri":"https://accounts.google.com/o/oauth2/auth",
                    "token_uri":"https://oauth2.googleapis.com/token"}}

# ---------------- SESSION STATE -----------------
if "accounts" not in st.session_state:
    st.session_state["accounts"] = {}
if "selected_account" not in st.session_state:
    st.session_state["selected_account"] = None
if "oauth_state" not in st.session_state:
    st.session_state["oauth_state"] = None
if "processed_oauth_code" not in st.session_state:
    st.session_state["processed_oauth_code"] = False

# ---------------- HELPERS -----------------
def save_account(email:str, creds_json:str):
    st.session_state["accounts"][email] = creds_json

def creds_from_json(creds_json:str):
    info = json.loads(creds_json)
    creds = Credentials.from_authorized_user_info(info, scopes=SCOPES)
    try:
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            save_account(info.get("email"), creds.to_json())
    except: pass
    return creds

def build_service(email:str):
    creds_json = st.session_state["accounts"].get(email)
    if not creds_json: raise ValueError("No credentials")
    creds = creds_from_json(creds_json)
    return build("gmail","v1",credentials=creds)

def create_flow():
    return Flow.from_client_config(client_config(), scopes=SCOPES, redirect_uri=REDIRECT_URI)

def start_oauth_flow():
    flow = create_flow()
    auth_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
    st.session_state["oauth_state"] = state
    return auth_url

def finish_oauth_with_code(code:str, state:str):
    flow = create_flow()
    flow.fetch_token(code=code)
    creds = flow.credentials
    service = build("gmail","v1",credentials=creds)
    profile = service.users().getProfile(userId="me").execute()
    email = profile.get("emailAddress")
    info = json.loads(creds.to_json()); info["email"] = email
    save_account(email, json.dumps(info))
    st.success(f"Connected: {email}")

def create_message(sender, to, subject, body):
    msg = MIMEText(body)
    msg["to"] = to; msg["from"]=sender; msg["subject"]=subject
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return {"raw":raw}

def send_email(service, to):
    try:
        msg = create_message("me", to, f"Test {int(time.time())}", "Automated test body")
        service.users().messages().send(userId="me", body=msg).execute()
        return "SENT"
    except: return "FAILED"

def get_message_body(service, msg_id):
    try:
        msg = service.users().messages().get(userId="me", id=msg_id, format="full").execute()
        parts = msg.get("payload", {}).get("parts", [])
        body = ""
        for p in parts:
            data = p.get("body",{}).get("data")
            if data: body += base64.urlsafe_b64decode(data).decode("utf-8","ignore").lower()
        return body
    except: return ""

def fetch_messages(service, query, max_results=100):
    try:
        resp = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
        return [m["id"] for m in resp.get("messages",[])]
    except: return []

def validate_email(email): return bool(EMAIL_REGEX.match(email))

# ----------------- UI -----------------
st.set_page_config(page_title="Gmail Bulk Sender & Bounce Checker", layout="wide")
st.title("📧 Gmail Bulk Sender & Bounce Checker")

col1,col2 = st.columns([2,3])
with col1:
    if st.button("Connect Gmail account"):
        auth_url = start_oauth_flow()
        st.markdown(f"[Click to sign-in]({auth_url})")
params = st.query_params
if "code" in params and not st.session_state["processed_oauth_code"]:
    finish_oauth_with_code(params["code"][0], params.get("state",[None])[0])
    st.session_state["processed_oauth_code"]=True
    st.experimental_set_query_params()

with col2:
    st.subheader("Connected Accounts")
    for acc in st.session_state["accounts"]:
        st.button(acc, key=acc, on_click=lambda a=acc: st.session_state.update({"selected_account":a}))

tab1,tab2 = st.tabs(["📤 Bulk Sender","📥 Bounce Checker"])

with tab1:
    st.subheader("Bulk Email Sender")
    if st.session_state.get("selected_account"):
        account = st.session_state["selected_account"]
        uploaded = st.file_uploader("Upload CSV with column 'email'", type="csv")
        if uploaded:
            df = pd.read_csv(uploaded)
            if st.button("Send Emails"):
                service = build_service(account)
                results=[]
                for e in df["email"]:
                    e = e.strip()
                    if not validate_email(e): results.append((e,"INVALID")); continue
                    status = send_email(service, e)
                    results.append((e,status))
                st.dataframe(pd.DataFrame(results, columns=["Email","Status"]))

with tab2:
    st.subheader("Bounce Checker")
    if st.session_state.get("selected_account"):
        account = st.session_state["selected_account"]
        query = st.text_input("Gmail search query (for bounces)", value="subject:(Undelivered OR Delivery Status Notification)")
        max_r = st.number_input("Max messages", 10, 500, 100, 10)
        if st.button("Check Bounces"):
            service = build_service(account)
            msg_ids = fetch_messages(service, query, max_r)
            results=[]
            for m in msg_ids:
                body = get_message_body(service, m)
                is_bounce = any(k in body for k in BOUNCE_KEYWORDS)
                results.append((m,"BOUNCE" if is_bounce else "OK"))
            st.dataframe(pd.DataFrame(results, columns=["Message ID","Status"]))
