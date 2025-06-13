import streamlit as st
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

st.set_page_config(page_title="Portal Power BI", page_icon="📊", layout="wide")

def crear_clave(password, salt):
    """Crea una clave de encriptación usando PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encriptar_url(url, clave):
    """Encripta una URL usando Fernet"""
    try:
        f = Fernet(clave)
        url_encriptada = f.encrypt(url.encode())
        return base64.urlsafe_b64encode(url_encriptada).decode()
    except Exception as e:
        st.error(f"❌ Error al encriptar: {e}")
        return None

def desencriptar_url(url_encriptada, clave):
    """Desencripta una URL usando Fernet con debugging mejorado"""
    try:
        f = Fernet(clave)
        
        # Debugging: mostrar información en modo desarrollo
        if st.session_state.get('modo_debug', False):
            st.write(f"🔍 Debug - Clave generada: {clave}")
            st.write(f"🔍 Debug - URL encriptada recibida: {url_encriptada[:50]}...")
        
        # Decodificar base64
        url_bytes = base64.urlsafe_b64decode(url_encriptada.encode())
        
        # Desencriptar
        url_desencriptada = f.decrypt(url_bytes).decode()
        
        if st.session_state.get('modo_debug', False):
            st.write(f"🔍 Debug - URL desencriptada: {url_desencriptada}")
        
        return url_desencriptada
        
    except Exception as e:
        st.error(f"❌ Error desencriptación: {str(e)}")
        
        # Información adicional de debugging
        with st.expander("🔍 Información de Debug"):
            st.write(f"**Tipo de error:** {type(e).__name__}")
            st.write(f"**Mensaje:** {str(e)}")
            st.write(f"**Longitud URL encriptada:** {len(url_encriptada) if url_encriptada else 'None'}")
            
            if hasattr(e, 'args') and e.args:
                st.write(f"**Args del error:** {e.args}")
        
        return None

# URLs de ejemplo (reemplaza con tus URLs reales de Power BI)
URLS_EJEMPLO = {
    "dashboard_ventas": "https://app.powerbi.com/view?r=eyJrIjoiZXhhbXBsZSIsInQiOiJjIn0%3D",
    "analisis_financiero": "https://app.powerbi.com/view?r=eyJrIjoiZmluYW5jaWFsIiwidCI6ImMifQ%3D%3D",
    "kpis_operativos": "https://app.powerbi.com/view?r=eyJrIjoib3BlcmF0aXZvcyIsInQiOiJjIn0%3D"
}

# Configuración - URLs encriptadas (se generarán automáticamente)
URLS_ENCRIPTADAS = {
    "dashboard_ventas": "gAAAAABoS6gIgq_tP2hti2I7nU2hfUPw00DU0rWUmsUtT8ES5DVslx0DwWPdI4OOgzTD9hS2rwObVxSu8s40InWSjBRzypk_5-ASHwLOMLLw-gX_jP3pmTokaFG6Ghty0IqyK839vOtz1l3MEncolHI7gMFDYLg13BXKw5Fatj-3yYHGtQeR7JcXvECtJ6UhSpcsoKX-ahQj6ISUogWq8EcHHnbXPS9wrxgQfd2BVZugn03sHi7QLur8HZlmHk5XEfdUnI6l-lQdl3Fyf9kxCTB2hiDTIGPUow==",
    "analisis_financiero": "",
    "kpis_operativos": ""
}

TITULOS = {
    "dashboard_ventas": "📈 Dashboard Ventas",
    "analisis_financiero": "💰 Análisis Financiero", 
    "kpis_operativos": "🎯 KPIs Operativos"
}

AREAS = {
    "Comercial": {
        "icono": "💼",
        "reportes": ["dashboard_ventas", "analisis_financiero"],
        "password": "comercial123"
    },
    "Marketing": {
        "icono": "📢",
        "reportes": ["dashboard_ventas", "kpis_operativos"], 
        "password": "marketing123"
    },
    "Administrador": {
        "icono": "⚙️",
        "reportes": ["dashboard_ventas", "analisis_financiero", "kpis_operativos"],
        "password": "admin123"
    }
}

def obtener_clave():
    """Obtiene la clave de encriptación"""
    # Modo desarrollo
    if st.session_state.get('modo_desarrollo', False):
        password = st.text_input("Password:", value="test_password", type="password")
        salt = st.text_input("Salt:", value="test_salt")
        if password and salt:
            return crear_clave(password, salt)
        return None
    
    # Producción - usar secrets
    try:
        if hasattr(st, 'secrets') and "PASSWORD" in st.secrets and "SALT" in st.secrets:
            return crear_clave(st.secrets["PASSWORD"], st.secrets["SALT"])
    except:
        pass
    
    # Fallback para testing
    st.warning("⚠️ Usando credenciales de prueba. Configura secrets para producción.")
    return crear_clave("test_password", "test_salt")

def herramienta_encriptacion():
    """Herramienta para generar URLs encriptadas"""
    st.title("🔧 Herramienta de Encriptación")
    
    clave = obtener_clave()
    if not clave:
        st.error("❌ Primero configura las credenciales")
        return
    
    st.subheader("📝 Generar URLs Encriptadas")
    
    for reporte_id, titulo in TITULOS.items():
        with st.expander(f"{titulo}"):
            url_original = st.text_input(
                f"URL original para {titulo}:",
                value=URLS_EJEMPLO.get(reporte_id, ""),
                key=f"url_{reporte_id}"
            )
            
            if st.button(f"🔐 Encriptar {titulo}", key=f"btn_{reporte_id}"):
                if url_original:
                    url_encriptada = encriptar_url(url_original, clave)
                    if url_encriptada:
                        st.success("✅ URL encriptada generada:")
                        st.code(f'"{reporte_id}": "{url_encriptada}"')
                        
                        # Test de desencriptación
                        url_test = desencriptar_url(url_encriptada, clave)
                        if url_test == url_original:
                            st.success("✅ Test de desencriptación exitoso")
                        else:
                            st.error("❌ Error en test de desencriptación")
                else:
                    st.warning("⚠️ Ingresa una URL")

def main():
    # Inicializar sesión
    if 'area' not in st.session_state:
        st.session_state.area = None
    if 'autenticado' not in st.session_state:
        st.session_state.autenticado = False
    if 'modo_desarrollo' not in st.session_state:
        st.session_state.modo_desarrollo = False
    if 'modo_debug' not in st.session_state:
        st.session_state.modo_debug = False

    # Sidebar para configuración
    with st.sidebar:
        st.title("⚙️ Configuración")
        
        # Modo desarrollo
        nuevo_modo_dev = st.checkbox("🔧 Modo Desarrollo", value=st.session_state.modo_desarrollo)
        if nuevo_modo_dev != st.session_state.modo_desarrollo:
            st.session_state.modo_desarrollo = nuevo_modo_dev
            st.rerun()
        
        # Modo debug
        if st.session_state.modo_desarrollo:
            st.session_state.modo_debug = st.checkbox("🔍 Modo Debug", value=st.session_state.modo_debug)
        
        # Herramienta de encriptación
        if st.session_state.modo_desarrollo:
            if st.button("🔧 Herramienta Encriptación"):
                st.session_state.mostrar_herramienta = True
                st.rerun()

    # Mostrar herramienta de encriptación si está activada
    if st.session_state.get('mostrar_herramienta', False):
        herramienta_encriptacion()
        if st.button("⬅️ Volver al Portal"):
            st.session_state.mostrar_herramienta = False
            st.rerun()
        return

    # Selección de área
    if not st.session_state.area:
        st.title("🏢 Portal Power BI")
        st.markdown("### Selecciona tu área:")
        
        # Crear columnas dinámicamente
        areas_list = list(AREAS.items())
        cols = st.columns(len(areas_list))
        
        for i, (area, config) in enumerate(areas_list):
            with cols[i]:
                if st.button(f"{config['icono']} {area}", key=area, use_container_width=True):
                    st.session_state.area = area
                    st.rerun()
        
        # Información de debug
        if st.session_state.modo_desarrollo:
            st.info("🔧 Modo desarrollo activado")
            
        return

    # Login
    area_actual = st.session_state.area
    if not st.session_state.autenticado:
        config = AREAS[area_actual]
        st.title(f"{config['icono']} Acceso {area_actual}")
        
        with st.form("login"):
            password = st.text_input("Contraseña:", type="password")
            if st.form_submit_button("🚀 Acceder"):
                if password == config["password"]:
                    st.session_state.autenticado = True
                    st.success("✅ Acceso concedido")
                    st.rerun()
                else:
                    st.error("❌ Contraseña incorrecta")
        
        # Mostrar credenciales en modo desarrollo
        if st.session_state.modo_desarrollo:
            st.info(f"🔧 Credencial de prueba: {config['password']}")
        
        if st.button("⬅️ Cambiar área"):
            st.session_state.area = None
            st.rerun()
        return

    # Portal principal
    config = AREAS[area_actual]
    st.title(f"{config['icono']} Portal {area_actual}")
    
    # Sidebar para reportes
    with st.sidebar:
        st.title("📋 Reportes")
        reporte = st.selectbox(
            "Seleccionar:",
            config["reportes"],
            format_func=lambda x: TITULOS.get(x, x)
        )
        
        altura = st.slider("Altura iframe:", 400, 1000, 600)
        
        if st.button("🚪 Cerrar sesión"):
            st.session_state.autenticado = False
            st.session_state.area = None
            st.rerun()

    # Mostrar reporte
    st.subheader(TITULOS.get(reporte, reporte))
    
    # Obtener clave
    clave = obtener_clave()
    if not clave:
        st.error("❌ No se pudo obtener la clave de encriptación")
        return
    
    # Verificar si existe URL encriptada
    if reporte not in URLS_ENCRIPTADAS or not URLS_ENCRIPTADAS[reporte]:
        st.warning("⚠️ URL no configurada para este reporte")
        if st.session_state.modo_desarrollo:
            st.info("💡 Usa la herramienta de encriptación para generar la URL")
        return
    
    # Desencriptar y mostrar
    with st.spinner("🔓 Cargando reporte..."):
        url = desencriptar_url(URLS_ENCRIPTADAS[reporte], clave)
    
    if url:
        st.success("✅ Reporte cargado correctamente")
        st.components.v1.iframe(src=url, height=altura, scrolling=True)
    else:
        st.error("❌ No se pudo cargar el reporte")
        
        with st.expander("💡 Posibles soluciones"):
            st.markdown("""
            **Causas comunes del error:**
            1. **Clave incorrecta:** Password o Salt no coinciden con los usados para encriptar
            2. **URL malformada:** La URL encriptada está corrupta o incompleta
            3. **Configuración:** Problema en la configuración de secrets
            
            **Soluciones:**
            1. Verifica que PASSWORD y SALT en secrets coincidan con los usados para encriptar
            2. Regenera las URLs encriptadas usando la herramienta (modo desarrollo)
            3. Prueba con modo desarrollo primero
            4. Verifica que las URLs de Power BI sean válidas
            """)

if __name__ == "__main__":
    main()
