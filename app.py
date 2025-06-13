import streamlit as st
import base64

def simple_decrypt(encrypted_text, key):
    # Decodificar base64
    decoded = base64.b64decode(encrypted_text)
    # XOR simple con la clave
    result = ""
    for i, char in enumerate(decoded):
        result += chr(char ^ ord(key[i % len(key)]))
    return result

# En tu app
decryption_key = st.secrets["SIMPLE_KEY"]  # Puede ser cualquier string
encrypted_url = "Z0FBQUFBQm9TNDgtaXpZXzVoYWxyYXpPMkZxcWc3anQzNmF3YnhxX2xjdXJVR3JUaGtzUXNyTldQV1EyMlF5N3VHc0lSNGU3VlZxWmY5d29ycFRzNmhnUzRKdmwtTG1BSm9qQTJsWFNjbGw2eTA0ZG12bzRaVUVRcDdFRlo2RDFadHZuelV5MkdqZllTNXdUYUNqX3d2RHJZOTVJYllaaHNQRzdldEpETGNPcUs3OG9NRFF6MTNiYjg1Vy1LODVab1U2aDV2QkhSM1BxeDJHbHhvTVByLUJ0b0FHS0NRV0gyQkNRUUFqTnNFWlFFc0piT1RuaVFraWRQQkprWVpqRVRuUGhqLUhtdjVRTXNZZm1Lc0Zub2xELTFCZmlsb3FlclE9PQ=="
powerbi_url = simple_decrypt(encrypted_url, decryption_key)
