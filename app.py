import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Global In-Memory Storage ---
stored_data = {}  # {"<encrypted>": {"encrypted_text": ..., "passkey": ...}}
failed_attempts = st.session_state.get("failed_attempts", 0)

# --- Generate Key and Cipher ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed:
            st.session_state["failed_attempts"] = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    # Wrong attempt
    st.session_state["failed_attempts"] = st.session_state.get("failed_attempts", 0) + 1
    return None

# --- Streamlit UI ---
st.title("🔐 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📍 Navigate", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.markdown("""
    This app allows you to:
    - 🔒 Store text securely with a passkey
    - 🔑 Retrieve it only with the correct passkey
    - 🚫 Get locked out after 3 failed attempts
    """)

elif choice == "Store Data":
    st.subheader("📥 Store Secure Data")
    text = st.text_area("Enter the text you want to encrypt:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Encrypt & Store"):
        if text and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(text)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language='text')
        else:
            st.warning("❗Please fill out both fields.")

elif choice == "Retrieve Data":
    st.subheader("🔓 Retrieve Data")

    if st.session_state.get("failed_attempts", 0) >= 3:
        st.warning("🚫 Too many failed attempts. Redirecting to Login.")
        st.switch_page("Login")

    encrypted_input = st.text_area("Paste your encrypted text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)

            if result:
                st.success("✅ Decryption successful!")
                st.code(result, language='text')
            else:
                remaining = 3 - st.session_state.get("failed_attempts", 0)
                st.error(f"❌ Wrong passkey! Attempts left: {remaining}")

                if remaining <= 0:
                    st.warning("🔒 Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.warning("❗Please enter both encrypted text and passkey.")

elif choice == "Login":
    st.subheader("🔐 Re-Login to Unlock Access")
    login_pass = st.text_input("Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state["failed_attempts"] = 0
            st.success("✅ Logged in successfully.")
            st.info("🔄 You may now retry decryption.")
        else:
            st.error("❌ Incorrect master password.")
