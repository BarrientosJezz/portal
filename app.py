import streamlit as st
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import traceback

st.set_page_config(page_title="Portal Power BI - Debug", page_icon="🔍", layout="wide")

def crear_clave(password, salt):
    """Crea una clave de encriptación usando PBKDF2"""
    try:
        st.write(f"🔍 Creando clave con password: '{password}' y salt: '{salt}'")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode('utf-8'),
            iterations=100000
        )
        clave_bytes = kdf.derive(password.encode('utf-8'))
        clave_b64 = base64.urlsafe_b64encode(clave_bytes)
        st.write(f"🔍 Clave generada: {clave_b64}")
        return clave_b64
    except Exception as e:
        st.error(f"❌ Error creando clave: {e}")
        st.write(traceback.format_exc())
        return None

def test_encriptacion_simple():
    """Test básico de encriptación/desencriptación"""
    st.header("🧪 Test de Encriptación Básico")
    
    # Parámetros de prueba
    password_test = "test123"
    salt_test = "salt123"
    url_test = "https://www.google.com"
    
    st.write(f"**Parámetros de prueba:**")
    st.write(f"- Password: {password_test}")
    st.write(f"- Salt: {salt_test}")
    st.write(f"- URL: {url_test}")
    
    try:
        # Step 1: Crear clave
        st.subheader("Paso 1: Crear Clave")
        clave = crear_clave(password_test, salt_test)
        if not clave:
            st.error("❌ Falló creación de clave")
            return
        
        # Step 2: Encriptar
        st.subheader("Paso 2: Encriptar URL")
        f = Fernet(clave)
        url_encriptada_bytes = f.encrypt(url_test.encode('utf-8'))
        url_encriptada_b64 = base64.urlsafe_b64encode(url_encriptada_bytes).decode('utf-8')
        st.write(f"🔍 URL encriptada: {url_encriptada_b64}")
        
        # Step 3: Desencriptar
        st.subheader("Paso 3: Desencriptar URL")
        url_encriptada_bytes_decoded = base64.urlsafe_b64decode(url_encriptada_b64.encode('utf-8'))
        url_desencriptada = f.decrypt(url_encriptada_bytes_decoded).decode('utf-8')
        st.write(f"🔍 URL desencriptada: {url_desencriptada}")
        
        # Verificar
        if url_desencriptada == url_test:
            st.success("✅ Test básico EXITOSO")
            return url_encriptada_b64
        else:
            st.error("❌ Test básico FALLÓ")
            
    except Exception as e:
        st.error(f"❌ Error en test básico: {e}")
        st.code(traceback.format_exc())
    
    return None

def test_url_original():
    """Test con la URL encriptada original del código"""
    st.header("🔬 Test con URL Original")
    
    url_original = "gAAAAABoS6gIgq_tP2hti2I7nU2hfUPw00DU0rWUmsUtT8ES5DVslx0DwWPdI4OOgzTD9hS2rwObVxSu8s40InWSjBRzypk_5-ASHwLOMLLw-gX_jP3pmTokaFG6Ghty0IqyK839vOtz1l3MEncolHI7gMFDYLg13BXKw5Fatj-3yYHGtQeR7JcXvECtJ6UhSpcsoKX-ahQj6ISUogWq8EcHHnbXPS9wrxgQfd2BVZugn03sHi7QLur8HZlmHk5XEfdUnI6l-lQdl3Fyf9kxCTB2hiDTIGPUow=="
    
    st.write(f"**URL encriptada original:**")
    st.code(url_original)
    st.write(f"**Longitud:** {len(url_original)} caracteres")
    
    # Probar con diferentes combinaciones de password/salt
    combinaciones = [
        ("test_password", "test_salt"),
        ("comercial123", "test_salt"),
        ("test123", "salt123"),
        ("", ""),
        ("admin", "portal"),
        ("powerbi", "dashboard")
    ]
    
    for i, (pwd, salt) in enumerate(combinaciones):
        if not pwd or not salt:
            continue
            
        st.subheader(f"Intento {i+1}: pwd='{pwd}', salt='{salt}'")
        
        try:
            clave = crear_clave(pwd, salt)
            if clave:
                f = Fernet(clave)
                url_bytes = base64.urlsafe_b64decode(url_original.encode('utf-8'))
                url_desencriptada = f.decrypt(url_bytes).decode('utf-8')
                st.success(f"✅ ÉXITO: {url_desencriptada}")
                return
        except Exception as e:
            st.warning(f"❌ Falló: {str(e)}")
    
    st.error("❌ Ninguna combinación funcionó")

def interfaz_manual():
    """Interfaz para pruebas manuales"""
    st.header("🛠️ Pruebas Manuales")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Parámetros")
        password = st.text_input("Password:", value="test_password")
        salt = st.text_input("Salt:", value="test_salt")
        
    with col2:
        st.subheader("URL")
        url_input = st.text_area(
            "URL encriptada:", 
            value="gAAAAABoS6gIgq_tP2hti2I7nU2hfUPw00DU0rWUmsUtT8ES5DVslx0DwWPdI4OOgzTD9hS2rwObVxSu8s40InWSjBRzypk_5-ASHwLOMLLw-gX_jP3pmTokaFG6Ghty0IqyK839vOtz1l3MEncolHI7gMFDYLg13BXKw5Fatj-3yYHGtQeR7JcXvECtJ6UhSpcsoKX-ahQj6ISUogWq8EcHHnbXPS9wrxgQfd2BVZugn03sHi7QLur8HZlmHk5XEfdUnI6l-lQdl3Fyf9kxCTB2hiDTIGPUow==",
            height=100
        )
    
    if st.button("🚀 Probar Desencriptación"):
        if password and salt and url_input:
            try:
                st.write("**Proceso paso a paso:**")
                
                # Crear clave
                st.write("1. Creando clave...")
                clave = crear_clave(password, salt)
                if not clave:
                    st.error("Falló crear clave")
                    return
                
                # Crear Fernet
                st.write("2. Creando objeto Fernet...")
                f = Fernet(clave)
                st.success("✅ Fernet creado")
                
                # Decodificar base64
                st.write("3. Decodificando base64...")
                url_bytes = base64.urlsafe_b64decode(url_input.strip().encode('utf-8'))
                st.success(f"✅ Decodificado: {len(url_bytes)} bytes")
                
                # Desencriptar
                st.write("4. Desencriptando...")
                url_desencriptada = f.decrypt(url_bytes).decode('utf-8')
                
                st.success("🎉 ÉXITO!")
                st.write(f"**URL desencriptada:** {url_desencriptada}")
                
                # Mostrar iframe si es URL válida
                if url_desencriptada.startswith(('http://', 'https://')):
                    st.write("**Vista previa:**")
                    st.components.v1.iframe(src=url_desencriptada, height=400)
                
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
                st.write("**Detalle del error:**")
                st.code(traceback.format_exc())
        else:
            st.warning("⚠️ Completa todos los campos")

def main():
    st.title("🔍 Diagnóstico Portal Power BI")
    st.markdown("---")
    
    # Información del sistema
    st.sidebar.header("📊 Info del Sistema")
    try:
        import cryptography
        st.sidebar.success(f"✅ Cryptography: {cryptography.__version__}")
    except:
        st.sidebar.error("❌ Cryptography no disponible")
    
    # Menú principal
    opcion = st.sidebar.selectbox(
        "Selecciona una opción:",
        [
            "🧪 Test Básico",
            "🔬 Test URL Original", 
            "🛠️ Pruebas Manuales",
            "📋 Portal Original"
        ]
    )
    
    if opcion == "🧪 Test Básico":
        url_test = test_encriptacion_simple()
        if url_test:
            st.info(f"💡 Usa esta URL encriptada para tus pruebas: {url_test}")
    
    elif opcion == "🔬 Test URL Original":
        test_url_original()
    
    elif opcion == "🛠️ Pruebas Manuales":
        interfaz_manual()
    
    elif opcion == "📋 Portal Original":
        st.info("🚧 Implementa aquí tu portal original una vez que funcione la desencriptación")
        
        # Portal básico simplificado
        password = st.text_input("Password de prueba:", value="test_password", type="password")
        salt = st.text_input("Salt de prueba:", value="test_salt")
        
        if password and salt:
            # Usar URL generada del test básico
            url_encriptada = "gAAAAABnC8XhvW_9Z0K1wKjYOHp6qgX5Z7lJ4gHrKlmNOPsABcDEFGHI"  # Ejemplo
            
            try:
                clave = crear_clave(password, salt)
                if clave:
                    st.success("✅ Clave creada correctamente")
                    st.write("Listo para usar en tu portal!")
            except Exception as e:
                st.error(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
