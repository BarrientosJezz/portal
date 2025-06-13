import streamlit as st
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

st.set_page_config(page_title="Portal Power BI", page_icon="📊", layout="wide")

def crear_clave(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def desencriptar_url(url_encriptada, clave):
    try:
        f = Fernet(clave)
        url_bytes = base64.urlsafe_b64decode(url_encriptada.encode())
        return f.decrypt(url_bytes).decode()
    except Exception as e:
        st.error(f"❌ Error desencriptación: {e}")
        return None

# Configuración simplificada
URLS_ENCRIPTADAS = {
    "dashboard_ventas": "gAAAAABoS6gIgq_tP2hti2I7nU2hfUPw00DU0rWUmsUtT8ES5DVslx0DwWPdI4OOgzTD9hS2rwObVxSu8s40InWSjBRzypk_5-ASHwLOMLLw-gX_jP3pmTokaFG6Ghty0IqyK839vOtz1l3MEncolHI7gMFDYLg13BXKw5Fatj-3yYHGtQeR7JcXvECtJ6UhSpcsoKX-ahQj6ISUogWq8EcHHnbXPS9wrxgQfd2BVZugn03sHi7QLur8HZlmHk5XEfdUnI6l-lQdl3Fyf9kxCTB2hiDTIGPUow==",
    "analisis_financiero": "URL_2_AQUI",
    "kpis_operativos": "URL_3_AQUI"
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
    }
}

def obtener_clave():
    # Modo desarrollo - reemplaza con st.secrets en producción
    if st.checkbox("🔧 Modo desarrollo"):
        password = st.text_input("Password:", value="test_password", type="password")
        salt = st.text_input("Salt:", value="test_salt")
        if password and salt:
            return crear_clave(password, salt)
    
    # Producción
    if "PASSWORD" in st.secrets and "SALT" in st.secrets:
        return crear_clave(st.secrets["PASSWORD"], st.secrets["SALT"])
    
    st.error("❌ Configura PASSWORD y SALT en Streamlit Secrets")
    st.stop()

def main():
    # Inicializar sesión
    if 'area' not in st.session_state:
        st.session_state.area = None
    if 'autenticado' not in st.session_state:
        st.session_state.autenticado = False

    # Selección de área
    if not st.session_state.area:
        st.title("🏢 Portal Power BI")
        st.markdown("### Selecciona tu área:")
        
        col1, col2 = st.columns(2)
        for i, (area, config) in enumerate(AREAS.items()):
            with col1 if i % 2 == 0 else col2:
                if st.button(f"{config['icono']} {area}", key=area, use_container_width=True):
                    st.session_state.area = area
                    st.rerun()
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
        
        if st.button("⬅️ Cambiar área"):
            st.session_state.area = None
            st.rerun()
        return

    # Portal principal
    config = AREAS[area_actual]
    st.title(f"{config['icono']} Portal {area_actual}")
    
    # Sidebar
    st.sidebar.title("📋 Reportes")
    reporte = st.sidebar.selectbox(
        "Seleccionar:",
        config["reportes"],
        format_func=lambda x: TITULOS.get(x, x)
    )
    
    altura = st.sidebar.slider("Altura:", 400, 1000, 600)
    
    if st.sidebar.button("🚪 Cerrar sesión"):
        st.session_state.autenticado = False
        st.session_state.area = None
        st.rerun()

    # Mostrar reporte
    st.subheader(TITULOS.get(reporte, reporte))
    
    # Obtener y desencriptar URL
    clave = obtener_clave()
    if clave and reporte in URLS_ENCRIPTADAS:
        with st.spinner("🔓 Cargando..."):
            url = desencriptar_url(URLS_ENCRIPTADAS[reporte], clave)
        
        if url:
            st.components.v1.iframe(src=url, height=altura, scrolling=True)
        else:
            st.error("❌ No se pudo cargar el reporte")
            with st.expander("💡 Soluciones"):
                st.markdown("""
                1. Verifica PASSWORD y SALT en secrets
                2. Regenera URLs encriptadas
                3. Usa modo desarrollo para testing
                """)
    else:
        st.warning("⚠️ Reporte no disponible")

if __name__ == "__main__":
    main()
