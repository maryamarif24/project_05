import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# --- File for persistence ---
DATA_FILE = "data_store.json"

# --- Key management ---
@st.cache_resource
def load_cipher():
    key = Fernet.generate_key()
    return Fernet(key)

cipher = load_cipher()

# --- Load or initialize data ---
def load_data():
    if os.path.exists(DATA_FILE) and os.path.getsize(DATA_FILE) > 0:
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# --- Strong hash using PBKDF2 ---
def hash_passkey(passkey, salt="studifinity_salt"):
    key = pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000)
    return urlsafe_b64encode(key).decode()

# --- Encrypt & Decrypt ---
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Session State ---
if "data_store" not in st.session_state:
    st.session_state.data_store = load_data()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "authorized" not in st.session_state:
    st.session_state.authorized = False

if "current_user" not in st.session_state:
    st.session_state.current_user = ""

# --- UI: Login/Register ---
def login_page():
    st.subheader("👤 Login / Register")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login / Register"):
        if username and password:
            hashed_pass = hash_passkey(password)
            users = st.session_state.data_store

            if username not in users:
                # Register new user
                users[username] = {"password": hashed_pass, "entries": {}}
                st.success("✅ New user registered.")
            elif users[username]["password"] != hashed_pass:
                st.error("❌ Incorrect password.")
                return

            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            save_data(users)
            st.rerun()
        else:
            st.warning("Please enter both username and password.")

# --- Main App ---
st.title("🛡️ Secure Data Encryption System")

# --- Handle login flow ---
if not st.session_state.current_user or not st.session_state.authorized:
    login_page()
    st.stop()

# --- App Navigation ---
menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigate", menu)

if choice == "Home":
    st.subheader(f"🏠 Welcome, {st.session_state.current_user}!")
    st.write("Securely store and retrieve your encrypted data.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Set a passkey to protect this data:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            user_entries = st.session_state.data_store[st.session_state.current_user]["entries"]
            user_entries[encrypted_text] = hashed_passkey
            save_data(st.session_state.data_store)

            st.success("✅ Data encrypted and stored successfully.")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Paste your encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            user_entries = st.session_state.data_store[st.session_state.current_user]["entries"]
            hashed_input = hash_passkey(passkey)

            if encrypted_text in user_entries and user_entries[encrypted_text] == hashed_input:
                decrypted = decrypt_data(encrypted_text)
                st.success("✅ Decrypted Data:")
                st.code(decrypted)
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.session_state.current_user = ""
                    st.warning("🚫 Too many failed attempts. Logging out...")
                    st.rerun()
        else:
            st.error("⚠️ Please fill all fields.")

elif choice == "Logout":
    st.session_state.current_user = ""
    st.session_state.failed_attempts = 0
    st.session_state.authorized = False
    st.success("🔓 Logged out.")
    st.rerun()
