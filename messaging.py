"""
NetWatch Messaging Service
Handles sending notifications via various channels (FCM, SMS, etc.)
"""

import os
import json
import streamlit as st
import firebase_admin
from firebase_admin import credentials, messaging

# --- Constants and Configuration ---

# Path to the Firebase service account credentials JSON file.
# IMPORTANT: You must obtain this file from your Firebase project console.
# 1. Go to Project Settings -> Service accounts.
# 2. Click "Generate new private key".
# 3. Save the downloaded JSON file in the project directory (e.g., as 'firebase-credentials.json').
# 4. For security, consider adding this filename to your .gitignore file.
FIREBASE_CREDS_PATH = "firebase-credentials.json"

# --- Initialization ---

def is_fcm_initialized():
    """Checks if the Firebase app has already been initialized."""
    return bool(firebase_admin._apps)

def init_fcm():
    """
    Initializes the Firebase Admin SDK.
    Returns True if successful, False otherwise.
    """
    if is_fcm_initialized():
        return True

    if os.path.exists(FIREBASE_CREDS_PATH):
        try:
            cred = credentials.Certificate(FIREBASE_CREDS_PATH)
            firebase_admin.initialize_app(cred)
            st.success("Firebase (FCM) foi inicializado com sucesso!")
            return True
        except Exception as e:
            st.error(f"Falha ao inicializar o Firebase: {e}")
            st.warning(f"Verifique se o arquivo '{FIREBASE_CREDS_PATH}' é uma credencial de conta de serviço válida do Firebase.")
            return False
    else:
        # Don't show an error on startup, only when the user tries to send a message.
        return False

# --- Message Sending ---

def send_fcm_message(token: str, title: str, body: str, data: dict = None) -> bool:
    """
    Sends a single FCM message to a specific device token.

    Args:
        token: The FCM registration token of the target device.
        title: The notification title.
        body: The notification body.
        data: An optional dictionary of key-value pairs to send in the message payload.

    Returns:
        True if the message was sent successfully, False otherwise.
    """
    if not is_fcm_initialized():
        if not init_fcm():
            st.error("O serviço de mensagens Firebase (FCM) não está configurado.")
            st.info(f"Para usar o FCM, baixe sua credencial de conta de serviço em seu projeto Firebase e salve-a como `{FIREBASE_CREDS_PATH}` no diretório do projeto.")
            return False

    if not token:
        st.warning("O dispositivo selecionado não possui um token FCM registrado.")
        return False

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        data=data or {},
        token=token,
    )

    try:
        response = messaging.send(message)
        st.success(f"Mensagem enviada com sucesso para o dispositivo! ID da mensagem: {response}")
        return True
    except Exception as e:
        st.error(f"Falha ao enviar mensagem FCM: {e}")
        # Common issue: token is invalid or expired.
        if "registration-token-not-registered" in str(e):
            st.warning("O token FCM do dispositivo não é mais válido. O aplicativo no dispositivo pode precisar ser reinstalado ou registrar um novo token.")
        return False
