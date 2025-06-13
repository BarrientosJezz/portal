import streamlit as st
import base64
from cryptography.fernet import Fernet

# La clave de desencriptación va en secrets.toml (no en GitHub)
decryption_key = st.secrets["DECRYPTION_KEY"]
encrypted_url = "Z0FBQUFBQm9TNDgtaXpZXzVoYWxyYXpPMkZxcWc3anQzNmF3YnhxX2xjdXJVR3JUaGtzUXNyTldQV1EyMlF5N3VHc0lSNGU3VlZxWmY5d29ycFRzNmhnUzRKdmwtTG1BSm9qQTJsWFNjbGw2eTA0ZG12bzRaVUVRcDdFRlo2RDFadHZuelV5MkdqZllTNXdUYUNqX3d2RHJZOTVJYllaaHNQRzdldEpETGNPcUs3OG9NRFF6MTNiYjg1Vy1LODVab1U2aDV2QkhSM1BxeDJHbHhvTVByLUJ0b0FHS0NRV0gyQkNRUUFqTnNFWlFFc0piT1RuaVFraWRQQkprWVpqRVRuUGhqLUhtdjVRTXNZZm1Lc0Zub2xELTFCZmlsb3FlclE9PQ==" # Esta sí puede estar en el código

def decrypt_url(encrypted_url, key):
    f = Fernet(key.encode())
    decrypted = f.decrypt(base64.b64decode(encrypted_url))
    return decrypted.decode()

# Desencriptar y mostrar
powerbi_url = decrypt_url(encrypted_url, decryption_key)
st.components.v1.iframe(powerbi_url, height=600)
