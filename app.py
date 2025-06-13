import streamlit as st
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

# Configuración de la página
st.set_page_config(
    page_title="Portal Power BI",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)



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
    "reporte_ejecutivo": "gAAAAABh_ejemplo_url_encriptada_4_aqui",
    "dashboard_marketing": "gAAAAABh_ejemplo_url_encriptada_5_aqui",
    "analisis_rrhh": "gAAAAABh_ejemplo_url_encriptada_6_aqui"
}

# Títulos amigables para los reportes
TITULOS_REPORTES = {
    "dashboard_ventas": "📈 Dashboard de Ventas",
    "analisis_financiero": "💰 Análisis Financiero", 
    "kpis_operativos": "🎯 KPIs Operativos",
    "reporte_ejecutivo": "👔 Reporte Ejecutivo",
    "dashboard_marketing": "📊 Dashboard Marketing",
    "analisis_rrhh": "👥 Análisis RRHH"
}

# Descripciones de los reportes
DESCRIPCIONES_REPORTES = {
    "dashboard_ventas": "Métricas de ventas, tendencias y análisis de performance",
    "analisis_financiero": "Estados financieros, flujo de caja y análisis de rentabilidad",
    "kpis_operativos": "Indicadores clave de rendimiento operativo",
    "reporte_ejecutivo": "Resumen ejecutivo con métricas consolidadas",
    "dashboard_marketing": "Análisis de campañas, ROI y métricas de marketing",
    "analisis_rrhh": "Métricas de recursos humanos y análisis de personal"
}

# 🔐 CONFIGURACIÓN DE USUARIOS Y PERMISOS
# Usuarios con sus contraseñas hasheadas y permisos de reportes
def hash_password(password):
    """Genera hash seguro de la contraseña"""
    return hashlib.sha256(password.encode()).hexdigest()

def obtener_usuarios():
    """
    Obtiene la configuración de usuarios desde Streamlit Secrets
    Formato en secrets.toml:
    [users]
    admin = "hash_de_contraseña"
    ventas = "hash_de_contraseña"
    finanzas = "hash_de_contraseña"
    
    [permissions]
    admin = ["dashboard_ventas", "analisis_financiero", "kpis_operativos", "reporte_ejecutivo", "dashboard_marketing", "analisis_rrhh"]
    ventas = ["dashboard_ventas", "kpis_operativos", "dashboard_marketing"]
    finanzas = ["analisis_financiero", "reporte_ejecutivo"]
    """
    try:
        users = dict(st.secrets["users"])
        permissions = dict(st.secrets["permissions"])
        return users, permissions
    except Exception as e:
        st.error("❌ Error al cargar configuración de usuarios")
        return {}, {}

def verificar_login(username, password):
    """Verifica las credenciales del usuario"""
    users, permissions = obtener_usuarios()
    
    if username in users:
        password_hash = hash_password(password)
        if users[username] == password_hash:
            return True, permissions.get(username, [])
    
    return False, []

def mostrar_login():
    """Pantalla de login"""
    st.markdown("""
    <div style='text-align: center; padding: 2rem 0;'>
        <h1>🔐 Portal Power BI</h1>
        <p style='color: #666; font-size: 1.2em;'>Acceso Seguro a Reportes</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Crear columnas para centrar el formulario
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        with st.container():
            st.markdown("### 👤 Iniciar Sesión")
            
            # Formulario de login
            with st.form("login_form"):
                username = st.text_input("👤 Usuario:", placeholder="Ingresa tu usuario")
                password = st.text_input("🔑 Contraseña:", type="password", placeholder="Ingresa tu contraseña")
                
                col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
                with col_btn2:
                    submit_button = st.form_submit_button("🚀 Acceder", use_container_width=True)
                
                if submit_button:
                    if username and password:
                        is_valid, user_permissions = verificar_login(username, password)
                        
                        if is_valid:
                            # Guardar sesión del usuario
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            st.session_state.user_permissions = user_permissions
                            st.success("✅ ¡Login exitoso!")
                            st.rerun()
                        else:
                            st.error("❌ Usuario o contraseña incorrectos")
                    else:
                        st.warning("⚠️ Por favor completa todos los campos")
    
    # Información de usuarios de ejemplo (solo para desarrollo)
    if st.checkbox("ℹ️ Mostrar usuarios de ejemplo"):
        st.info("""
        **Usuarios de ejemplo:**
        - admin / admin123
        - ventas / ventas123  
        - finanzas / finanzas123
        
        *Cambia estos usuarios en la configuración de secrets*
        """)

def obtener_clave_desencriptacion():
    """
    Obtiene la clave de desencriptación desde Streamlit Secrets
    ❌ NUNCA desde el código público de GitHub
    """
    try:
        # Verificar si existe la configuración en secrets
        if "PASSWORD" not in st.secrets:
            st.error("❌ **Error de Configuración**")
            st.error("No se encontró la clave de desencriptación en la configuración segura.")
            st.info("📋 **Para administradores**: Configura PASSWORD en Streamlit Secrets")
            st.stop()
        
        # Obtener password desde secrets y generar clave
        password = st.secrets["PASSWORD"]
        clave_fernet = crear_clave_desde_password(password)
        return clave_fernet
        
    except Exception as e:
        st.error(f"❌ **Error de Seguridad**: {str(e)}")
        st.error("No se pudo acceder a la configuración de encriptación")
        st.stop()

def obtener_reportes_permitidos():
    """Obtiene los reportes que el usuario tiene permiso para ver"""
    user_permissions = st.session_state.get('user_permissions', [])
    
    # Filtrar URLs y títulos según permisos del usuario
    reportes_permitidos = {}
    titulos_permitidos = {}
    descripciones_permitidas = {}
    
    for reporte_key in user_permissions:
        if reporte_key in URLS_ENCRIPTADAS:
            reportes_permitidos[reporte_key] = URLS_ENCRIPTADAS[reporte_key]
            titulos_permitidos[reporte_key] = TITULOS_REPORTES.get(reporte_key, reporte_key)
            descripciones_permitidas[reporte_key] = DESCRIPCIONES_REPORTES.get(reporte_key, "")
    
    return reportes_permitidos, titulos_permitidos, descripciones_permitidas

def mostrar_header_usuario():
    """Muestra información del usuario logueado en el header"""
    username = st.session_state.get('username', 'Usuario')
    num_reportes = len(st.session_state.get('user_permissions', []))
    
    col1, col2, col3 = st.columns([2, 1, 1])
    
    with col1:
        st.markdown(f"### 👋 Bienvenido, **{username}**")
    
    with col2:
        st.metric("📊 Reportes disponibles", num_reportes)
    
    with col3:
        if st.button("🚪 Cerrar Sesión"):
            # Limpiar sesión
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

def mostrar_reporte_individual():
    """Muestra un reporte seleccionado individualmente"""
    
    # Header con información del usuario
    mostrar_header_usuario()
    st.markdown("---")
    
    # Obtener reportes permitidos para el usuario
    reportes_permitidos, titulos_permitidos, descripciones_permitidas = obtener_reportes_permitidos()
    
    if not reportes_permitidos:
        st.warning("⚠️ No tienes permisos para ver ningún reporte.")
        st.info("Contacta al administrador para obtener acceso.")
        return
    
    # Obtener clave de desencriptación
    clave_fernet = obtener_clave_desencriptacion()
    
    # Sidebar para selección de reporte
    st.sidebar.title("📋 Tus Reportes")
    st.sidebar.markdown("Reportes disponibles para tu usuario:")
    
    reporte_seleccionado = st.sidebar.selectbox(
        "📊 Seleccionar reporte:",
        options=list(reportes_permitidos.keys()),
        format_func=lambda x: titulos_permitidos.get(x, x),
        index=0
    )
    
    # Configuraciones de visualización
    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ Configuración")
    altura_iframe = st.sidebar.slider("📏 Altura del reporte", 400, 1200, 700, 50)
    
    # Información del reporte seleccionado
    st.subheader(titulos_permitidos.get(reporte_seleccionado, reporte_seleccionado))
    st.markdown(f"*{descripciones_permitidas.get(reporte_seleccionado, 'Reporte de Power BI')}*")
    
    # Desencriptar la URL seleccionada
    url_encriptada = reportes_permitidos[reporte_seleccionado]
    
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
        
        # Solo botón de actualizar
        if st.button("🔄 Actualizar Reporte"):
            st.rerun()
    
    else:
        st.error("❌ **No se pudo cargar el reporte**")
        st.error("Verifica que la configuración de encriptación sea correcta")

def mostrar_multiples_reportes():
    """Muestra todos los reportes permitidos en pestañas"""
    
    # Header con información del usuario
    mostrar_header_usuario()
    st.markdown("---")
    
    # Obtener reportes permitidos para el usuario
    reportes_permitidos, titulos_permitidos, descripciones_permitidas = obtener_reportes_permitidos()
    
    if not reportes_permitidos:
        st.warning("⚠️ No tienes permisos para ver ningún reporte.")
        st.info("Contacta al administrador para obtener acceso.")
        return
    
    # Obtener clave de desencriptación
    clave_fernet = obtener_clave_desencriptacion()
    
    # Configuración de altura
    altura_iframe = st.sidebar.slider("📏 Altura de reportes", 400, 1000, 600, 50)
    
    # Crear pestañas para cada reporte permitido
    tab_names = [titulos_permitidos.get(k, k) for k in reportes_permitidos.keys()]
    tabs = st.tabs(tab_names)
    
    # Mostrar cada reporte en su pestaña correspondiente
    for i, (reporte_key, url_encriptada) in enumerate(reportes_permitidos.items()):
        with tabs[i]:
            st.markdown(f"**{descripciones_permitidas.get(reporte_key, '')}**")
            
            with st.spinner("🔓 Cargando reporte..."):
                url_desencriptada = desencriptar_url(url_encriptada, clave_fernet)
            
            if url_desencriptada:
                st.components.v1.iframe(
                    src=url_desencriptada,
                    height=altura_iframe,
                    scrolling=True
                )
            else:
                st.error(f"❌ Error al cargar el reporte: {titulos_permitidos.get(reporte_key, reporte_key)}")

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
    .login-container {
        max-width: 400px;
        margin: 0 auto;
        padding: 2rem;
        background: #f8f9fa;
        border-radius: 10px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Verificar si el usuario está logueado
    if not st.session_state.get('logged_in', False):
        mostrar_login()
        return
    
    # Usuario logueado - mostrar aplicación principal
    st.sidebar.title("🚀 Navegación")
    modo_visualizacion = st.sidebar.radio(
        "Selecciona el modo de visualización:",
        ["📊 Reporte Individual", "📋 Todos los Reportes"],
        index=0
    )
    
    # Información del usuario en sidebar
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ℹ️ Tu Sesión")
    username = st.session_state.get('username', 'Usuario')
    num_reportes = len(st.session_state.get('user_permissions', []))
    
    st.sidebar.info(f"👤 **Usuario:** {username}")
    st.sidebar.success(f"📊 **Reportes:** {num_reportes}")
    st.sidebar.success("🔒 **Estado:** Conectado")
    
    # Mostrar el modo seleccionado
    if modo_visualizacion == "📊 Reporte Individual":
        mostrar_reporte_individual()
    else:
        mostrar_multiples_reportes()
    
    # Footer
    st.markdown("---")
    st.markdown(f"""
    <div style='text-align: center; color: #666; padding: 1rem;'>
        🔒 <strong>Portal Seguro Power BI</strong> • Usuario: {username}<br>
        <small>Sesión activa • Reportes protegidos con encriptación avanzada</small>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
