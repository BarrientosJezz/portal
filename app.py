import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def crear_clave_desde_password(password, salt):
    """
    Crea una clave de encriptación determinística desde un password y salt
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encriptar_url(url, clave_fernet):
    """Encripta una URL usando la clave proporcionada"""
    try:
        f = Fernet(clave_fernet)
        # Encriptar la URL
        url_encriptada_bytes = f.encrypt(url.encode('utf-8'))
        # Codificar a base64 para almacenamiento seguro
        url_encriptada = base64.urlsafe_b64encode(url_encriptada_bytes).decode('utf-8')
        return url_encriptada
    except Exception as e:
        print(f"❌ Error al encriptar URL: {str(e)}")
        return None

def desencriptar_url(url_encriptada, clave_fernet):
    """Desencripta una URL para verificar que funcione"""
    try:
        f = Fernet(clave_fernet)
        # Decodificar la URL encriptada
        url_encriptada_bytes = base64.urlsafe_b64decode(url_encriptada.encode('utf-8'))
        # Desencriptar
        url_bytes = f.decrypt(url_encriptada_bytes)
        return url_bytes.decode('utf-8')
    except Exception as e:
        print(f"❌ Error al desencriptar URL: {str(e)}")
        return None

# ⚠️ TUS CREDENCIALES (las mismas que tienes en Streamlit Secrets)
PASSWORD = "powerbi_encrypt_pass_2024"
SALT = "powerbi_encrypt_salt_2024"

# 🔑 Generar clave de encriptación
clave_fernet = crear_clave_desde_password(PASSWORD, SALT)
print("✅ Clave de encriptación generada correctamente")
print(f"🔑 Clave generada: {clave_fernet.decode()[:20]}...")

# 📊 AQUÍ DEBES PONER TUS URLs REALES DE POWER BI
# ⚠️ REEMPLAZA ESTAS URLs CON LAS TUYAS REALES
urls_reales = {
    "dashboard_ventas": "https://app.powerbi.com/view?r=eyJrIjoiXX...TU_URL_REAL_VENTAS",
    "analisis_financiero": "https://app.powerbi.com/view?r=eyJrIjoiXX...TU_URL_REAL_FINANCIERO",
    "kpis_operativos": "https://app.powerbi.com/view?r=eyJrIjoiXX...TU_URL_REAL_KPIS",
    "reporte_ejecutivo": "https://app.powerbi.com/view?r=eyJrIjoiXX...TU_URL_REAL_EJECUTIVO",
    "metricas_marketing": "https://app.powerbi.com/view?r=eyJrIjoiXX...TU_URL_REAL_MARKETING",
    "analisis_trade": "https://app.powerbi.com/view?r=eyJrIjoiXX...TU_URL_REAL_TRADE",
    "dashboard_contact_center": "https://app.powerbi.com/view?r=eyJrIjoiXX...TU_URL_REAL_CONTACT"
}

print("\n" + "="*80)
print("🔐 GENERANDO URLs ENCRIPTADAS")
print("="*80)

# Encriptar cada URL
urls_encriptadas = {}
for nombre, url in urls_reales.items():
    print(f"\n📊 Procesando: {nombre}")
    print(f"🔗 URL original: {url[:50]}...")
    
    # Encriptar
    url_encriptada = encriptar_url(url, clave_fernet)
    
    if url_encriptada:
        urls_encriptadas[nombre] = url_encriptada
        print(f"✅ Encriptación exitosa")
        print(f"🔒 URL encriptada: {url_encriptada[:50]}...")
        
        # Verificar desencriptación
        url_verificada = desencriptar_url(url_encriptada, clave_fernet)
        if url_verificada == url:
            print(f"✅ Verificación exitosa")
        else:
            print(f"❌ Error en verificación")
    else:
        print(f"❌ Error al encriptar {nombre}")

print("\n" + "="*80)
print("📋 CÓDIGO PYTHON PARA TU APLICACIÓN")
print("="*80)

# Generar código Python para copiar y pegar
codigo_urls = """
# ✅ URLs ENCRIPTADAS - GENERADAS CON TUS CREDENCIALES
URLS_ENCRIPTADAS = {
"""

for nombre, url_encriptada in urls_encriptadas.items():
    codigo_urls += f'    "{nombre}": "{url_encriptada}",\n'

codigo_urls += "}"

print(codigo_urls)

print("\n" + "="*80)
print("📝 INSTRUCCIONES")
print("="*80)

print("""
1. ⚠️  IMPORTANTE: Reemplaza las URLs de ejemplo en 'urls_reales' con tus URLs reales de Power BI
2. 🔄 Ejecuta este script nuevamente después de poner tus URLs reales
3. 📋 Copia el código generado (URLS_ENCRIPTADAS) 
4. 🔧 Reemplaza el diccionario URLS_ENCRIPTADAS en tu aplicación Streamlit
5. 🚀 Despliega tu aplicación

🔒 SEGURIDAD:
- Las URLs encriptadas son seguras para GitHub público
- Solo se pueden desencriptar con PASSWORD y SALT correctos
- Mantén PASSWORD y SALT seguros en Streamlit Secrets

🆘 SI SIGUES TENIENDO PROBLEMAS:
- Verifica que PASSWORD y SALT en Streamlit Secrets sean exactamente:
  PASSWORD = "powerbi_encrypt_pass_2024"
  SALT = "powerbi_encrypt_salt_2024"
- Asegúrate de que no haya espacios extra en los secrets
""")

print("\n" + "="*50)
print("🎯 URLs DE EJEMPLO PARA TESTING")
print("="*50)

# Generar URLs de ejemplo para testing
urls_testing = {
    "dashboard_ventas": "https://httpbin.org/html",
    "analisis_financiero": "https://httpbin.org/json", 
    "kpis_operativos": "https://example.com",
}

print("\nSi quieres probar la funcionalidad antes de tener las URLs reales:")
urls_testing_encriptadas = {}

for nombre, url in urls_testing.items():
    url_encriptada = encriptar_url(url, clave_fernet)
    if url_encriptada:
        urls_testing_encriptadas[nombre] = url_encriptada

codigo_testing = """
# 🧪 URLs ENCRIPTADAS PARA TESTING (reemplazar después)
URLS_ENCRIPTADAS = {
"""

for nombre, url_encriptada in urls_testing_encriptadas.items():
    codigo_testing += f'    "{nombre}": "{url_encriptada}",\n'

# Agregar las demás con URLs dummy
urls_dummy = ["kpis_operativos", "reporte_ejecutivo", "metricas_marketing", "analisis_trade", "dashboard_contact_center"]
for nombre in urls_dummy:
    if nombre not in urls_testing_encriptadas:
        url_dummy_encriptada = encriptar_url("https://example.com", clave_fernet)
        codigo_testing += f'    "{nombre}": "{url_dummy_encriptada}",\n'

codigo_testing += "}"

print(codigo_testing)
