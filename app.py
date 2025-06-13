import streamlit as st
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuración de la página
st.set_page_config(
    page_title="Portal Power BI",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

def crear_clave_desde_password(password, salt):
    """
    Crea una clave de encriptación determinística desde un password y salt
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),  # Convertir el salt a bytes
        iterations=100000,
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def desencriptar_url(url_encriptada, clave_fernet):
    """Desencripta una URL usando la clave proporcionada"""
    try:
        f = Fernet(clave_fernet)
        # Decodificar la URL encriptada
        url_encriptada_bytes = base64.urlsafe_b64decode(url_encriptada.encode('utf-8'))
        # Desencriptar
        url_bytes = f.decrypt(url_encriptada_bytes)
        return url_bytes.decode('utf-8')
    except Exception as e:
        st.error(f"❌ Error al desencriptar URL: {str(e)}")
        return None

# ✅ URLs ENCRIPTADAS - SEGURO ESTAR EN GITHUB PÚBLICO
# Reemplaza estas URLs con las que genere tu script de encriptación
URLS_ENCRIPTADAS = {
    "dashboard_ventas": "gAAAAABh_ejemplo_url_encriptada_1_aqui",
    "analisis_financiero": "gAAAAABh_ejemplo_url_encriptada_2_aqui", 
    "kpis_operativos": "gAAAAABh_ejemplo_url_encriptada_3_aqui",
    "reporte_ejecutivo": "gAAAAABh_ejemplo_url_encriptada_4_aqui"
}

# Títulos amigables para los reportes
TITULOS_REPORTES = {
    "dashboard_ventas": "📈 Dashboard de Ventas",
    "analisis_financiero": "💰 Análisis Financiero", 
    "kpis_operativos": "🎯 KPIs Operativos",
    "reporte_ejecutivo": "👔 Reporte Ejecutivo"
}

# Descripciones de los reportes
DESCRIPCIONES_REPORTES = {
    "dashboard_ventas": "Métricas de ventas, tendencias y análisis de performance",
    "analisis_financiero": "Estados financieros, flujo de caja y análisis de rentabilidad",
    "kpis_operativos": "Indicadores clave de rendimiento operativo",
    "reporte_ejecutivo": "Resumen ejecutivo con métricas consolidadas"
}

def obtener_clave_desencriptacion():
    """
    Obtiene la clave de desencriptación desde Streamlit Secrets
    ❌ NUNCA desde el código público de GitHub
    """
    try:
        # Verificar si existen las configuraciones necesarias en secrets
        if "PASSWORD" not in st.secrets:
            st.error("❌ **Error de Configuración**")
            st.error("No se encontró PASSWORD en la configuración segura.")
            st.info("📋 **Para administradores**: Configura PASSWORD en Streamlit Secrets")
            st.stop()
        
        if "SALT" not in st.secrets:
            st.error("❌ **Error de Configuración**")
            st.error("No se encontró SALT en la configuración segura.")
            st.info("📋 **Para administradores**: Configura SALT en Streamlit Secrets")
            st.stop()
        
        # Obtener password y salt desde secrets
        password = st.secrets["PASSWORD"]
        salt = st.secrets["SALT"]
        
        # Generar clave de encriptación
        clave_fernet = crear_clave_desde_password(password, salt)
        return clave_fernet
        
    except Exception as e:
        st.error(f"❌ **Error de Seguridad**: {str(e)}")
        st.error("No se pudo acceder a la configuración de encriptación")
        st.stop()

def mostrar_reporte_individual():
    """Muestra un reporte seleccionado individualmente"""
    
    st.title("🏢 Portal de Reportes Power BI")
    st.markdown("Accede a todos los reportes de Business Intelligence de forma segura")
    st.markdown("---")
    
    # Obtener clave de desencriptación
    clave_fernet = obtener_clave_desencriptacion()
    
    # Sidebar para selección de reporte
    st.sidebar.title("📋 Seleccionar Reporte")
    st.sidebar.markdown("Elige el reporte que deseas visualizar:")
    
    reporte_seleccionado = st.sidebar.selectbox(
        "📊 Reportes disponibles:",
        options=list(URLS_ENCRIPTADAS.keys()),
        format_func=lambda x: TITULOS_REPORTES.get(x, x),
        index=0
    )
    
    # Configuraciones de visualización
    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ Configuración")
    altura_iframe = st.sidebar.slider("📏 Altura del reporte", 400, 1200, 700, 50)
    
    # Información del reporte seleccionado
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader(TITULOS_REPORTES.get(reporte_seleccionado, reporte_seleccionado))
        st.markdown(f"*{DESCRIPCIONES_REPORTES.get(reporte_seleccionado, 'Reporte de Power BI')}*")
    
    with col2:
        st.metric("📊 Reportes", len(URLS_ENCRIPTADAS))
    
    # Desencriptar la URL seleccionada
    url_encriptada = URLS_ENCRIPTADAS[reporte_seleccionado]
    
    with st.spinner("🔓 Desencriptando y cargando reporte..."):
        url_desencriptada = desencriptar_url(url_encriptada, clave_fernet)
    
    if url_desencriptada:
        # Mostrar el reporte embebido
        st.markdown("### 📊 Visualización del Reporte")
        
        # Contenedor para el iframe
        with st.container():
            st.components.v1.iframe(
                src=url_desencriptada,
                width=None,  # Usar ancho completo
                height=altura_iframe,
                scrolling=True
            )
        
        # Botones de acción
        col1, col2, col3 = st.columns([1, 1, 2])
        
        with col1:
            if st.button("🔄 Actualizar"):
                st.rerun()
        
        with col2:
            if st.button("🔗 Nueva Pestaña"):
                st.markdown(f'<a href="{url_desencriptada}" target="_blank">🔗 Abrir en nueva pestaña</a>', 
                           unsafe_allow_html=True)
    
    else:
        st.error("❌ **No se pudo cargar el reporte**")
        st.error("Verifica que la configuración de encriptación sea correcta")

def mostrar_multiples_reportes():
    """Muestra todos los reportes en pestañas"""
    
    st.title("📊 Panel de Reportes Completo")
    st.markdown("Visualiza todos los reportes Power BI en un solo lugar")
    st.markdown("---")
    
    # Obtener clave de desencriptación
    clave_fernet = obtener_clave_desencriptacion()
    
    # Configuración de altura
    altura_iframe = st.sidebar.slider("📏 Altura de reportes", 400, 1000, 600, 50)
    
    # Crear pestañas para cada reporte
    tab_names = [TITULOS_REPORTES.get(k, k) for k in URLS_ENCRIPTADAS.keys()]
    tabs = st.tabs(tab_names)
    
    # Mostrar cada reporte en su pestaña correspondiente
    for i, (reporte_key, url_encriptada) in enumerate(URLS_ENCRIPTADAS.items()):
        with tabs[i]:
            st.markdown(f"**{DESCRIPCIONES_REPORTES.get(reporte_key, '')}**")
            
            with st.spinner("🔓 Cargando reporte..."):
                url_desencriptada = desencriptar_url(url_encriptada, clave_fernet)
            
            if url_desencriptada:
                st.components.v1.iframe(
                    src=url_desencriptada,
                    height=altura_iframe,
                    scrolling=True
                )
            else:
                st.error(f"❌ Error al cargar el reporte: {TITULOS_REPORTES.get(reporte_key, reporte_key)}")

def main():
    """Función principal de la aplicación"""
    
    # CSS personalizado
    st.markdown("""
    <style>
    .main-header {
        text-align: center;
        padding: 1rem 0;
        background: linear-gradient(90deg, #1f4e79, #2e75b6);
        color: white;
        margin: -1rem -1rem 2rem -1rem;
        border-radius: 0 0 10px 10px;
    }
    .metric-card {
        background: #f0f2f6;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #2e75b6;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Sidebar para navegación
    st.sidebar.title("🚀 Navegación")
    modo_visualizacion = st.sidebar.radio(
        "Selecciona el modo de visualización:",
        ["📊 Reporte Individual", "📋 Todos los Reportes"],
        index=0
    )
    
    # Información del sistema
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ℹ️ Información")
    st.sidebar.info(f"📊 **Reportes disponibles:** {len(URLS_ENCRIPTADAS)}")
    st.sidebar.success("🔒 **Conexión segura:** Activada")
    
    # Mostrar el modo seleccionado
    if modo_visualizacion == "📊 Reporte Individual":
        mostrar_reporte_individual()
    else:
        mostrar_multiples_reportes()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 1rem;'>
        🔒 <strong>Portal Seguro Power BI</strong> • Desarrollado con Streamlit<br>
        <small>Todos los reportes están protegidos con encriptación avanzada</small>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
