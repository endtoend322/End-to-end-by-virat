import streamlit as st
import os
from database import init_db, save_config, get_logs
from worker import start_worker, stop_worker, worker_status

# Page config
st.set_page_config(page_title="Automation Dashboard", layout="wide")

# Init DB
init_db()

st.title("🔵 Advanced Automation Dashboard")

# ---------- TARGET SETTINGS ----------
st.header("🎯 Target Settings")

chat_id = st.text_input("Chat / E2E ID")
whatsapp_no = st.text_input("WhatsApp Chat Number")
facebook_id = st.text_input("Facebook Chat ID")
name_prefix = st.text_input("Name Prefix")
delay = st.slider("Delay (Seconds)", 1, 300, 30)

# ---------- COOKIE CONFIG ----------
st.header("🍪 Cookies Configuration")
cookie_mode = st.radio("Cookie Mode", ["Single Cookie", "Multiple Cookies (TXT Upload)"])
cookie_file = st.file_uploader("Upload Cookie File (.txt)", type=["txt"])

# ---------- MESSAGE FILE ----------
st.header("💬 Upload Message File")
message_file = st.file_uploader("Upload Messages (.txt)", type=["txt"])

# ---------- SAVE CONFIG ----------
if st.button("✅ Submit Configuration"):
    config = {
        "chat_id": chat_id,
        "whatsapp_no": whatsapp_no,
        "facebook_id": facebook_id,
        "name_prefix": name_prefix,
        "delay": delay,
        "cookie_mode": cookie_mode
    }

    save_config(config)

    os.makedirs("uploads", exist_ok=True)

    if cookie_file:
        with open(os.path.join("uploads", cookie_file.name), "wb") as f:
            f.write(cookie_file.getbuffer())

    if message_file:
        with open(os.path.join("uploads", message_file.name), "wb") as f:
            f.write(message_file.getbuffer())

    st.success("Configuration Saved Successfully")

# ---------- WORKER CONTROLS ----------
st.header("⚙️ Background Worker Controls")

col1, col2 = st.columns(2)

with col1:
    if st.button("🚀 Start Worker"):
        start_worker(delay)
        st.success("Worker Started")

with col2:
    if st.button("🛑 Stop Worker"):
        stop_worker()
        st.warning("Worker Stopped")

st.info(f"Worker Status: {worker_status()}")

# ---------- LIVE LOGS ----------
st.header("🖥 Live Logs")

logs = get_logs()

for log in logs:
    st.text(log)

st.markdown("---")
st.markdown("All Rights Reserved © 2026")
