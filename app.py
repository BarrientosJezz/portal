import streamlit as st
import base64
import time
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
    """Desencripta una URL usando la clave proporcionada - VERSIÓN CORREGIDA"""
    try:
        f = Fernet(clave_fernet)
        # ✅ CORRECCIÓN: Trabajar directamente con el token de Fernet
        # NO aplicar base64decode - Fernet ya maneja esto internamente
        url_bytes = f.decrypt(url_encriptada.encode('utf-8'))
        return url_bytes.decode('utf-8')
    except Exception as e:
        # Agregar más detalles del error para debugging
        st.error(f"❌ Error al desencriptar URL: {str(e)}")
        st.error(f"🔍 Detalles: Tipo de error: {type(e).__name__}")
        st.error(f"🔍 Token recibido: {url_encriptada[:20]}...")
        return None

def debug_desencriptacion():
    """Función de debugging para verificar la configuración"""
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔧 Debug Info")
    
    try:
        # Verificar secrets
        password = st.secrets.get("PASSWORD", "NO_ENCONTRADO")
        salt = st.secrets.get("SALT", "NO_ENCONTRADO")
        
        st.sidebar.text(f"PASSWORD: {'✅' if password != 'NO_ENCONTRADO' else '❌'}")
        st.sidebar.text(f"SALT: {'✅' if salt != 'NO_ENCONTRADO' else '❌'}")
        
        # Verificar si los valores coinciden con los esperados
        password_correcto = password == "powerbi_encrypt_pass_2024"
        salt_correcto = salt == "powerbi_encrypt_salt_2024"
        
        st.sidebar.text(f"Pass Match: {'✅' if password_correcto else '❌'}")
        st.sidebar.text(f"Salt Match: {'✅' if salt_correcto else '❌'}")
        
        if not password_correcto:
            st.sidebar.error(f"❌ PASSWORD esperado: powerbi_encrypt_pass_2024")
            st.sidebar.error(f"PASSWORD actual: {password}")
        
        if not salt_correcto:
            st.sidebar.error(f"❌ SALT esperado: powerbi_encrypt_salt_2024")  
            st.sidebar.error(f"SALT actual: {salt}")
            
    except Exception as e:
        st.sidebar.error(f"Error en debug: {str(e)}")

# ✅ URLs ENCRIPTADAS - SEGURO ESTAR EN GITHUB PÚBLICO
# Reemplaza estas URLs con las que genere tu script de encriptación
URLS_ENCRIPTADAS = {
    "dashboard_ventas": "gAAAAABoTAF9CO9xjBiy3mYHHkO7VqSgknpe9RXG3Rwx4mMRquE02nYB8jvgvTlJ6XJckp_8ih4gYYV_lgFmKb0QXdjWMy7B8RohvNMfYDYs-lwKKVxgEwauS8_t0raCBL2A5zCjyqfFkafLbJ_tsz7bKSrURJGTndbAiAGbNBih6gyD-C3mkJ-56Q66bRFaXoqKDCa63cNXPoLA0ZYX0lqJzQsz3vIsh9_YRuPfZxHpmXVsXQsikXKwHifC17XiwHy71Kzt-QrE7Az2r6m2nczmsZWVuieFWg==",
    "analisis_financiero": "gAAAAABh_ejemplo_url_encriptada_2_aqui", 
    "kpis_operativos": "gAAAAABh_ejemplo_url_encriptada_3_aqui",
    "reporte_ejecutivo": "gAAAAABh_ejemplo_url_encriptada_4_aqui",
    "metricas_marketing": "gAAAAABh_ejemplo_url_encriptada_5_aqui",
    "analisis_trade": "gAAAAABh_ejemplo_url_encriptada_6_aqui",
    "dashboard_contact_center": "gAAAAABh_ejemplo_url_encriptada_7_aqui"
}

# Títulos amigables para los reportes
TITULOS_REPORTES = {
    "dashboard_ventas": "📈 Dashboard de Ventas",
    "analisis_financiero": "💰 Análisis Financiero", 
    "kpis_operativos": "🎯 KPIs Operativos",
    "reporte_ejecutivo": "👔 Reporte Ejecutivo",
    "metricas_marketing": "📢 Métricas de Marketing",
    "analisis_trade": "🏪 Análisis Trade",
    "dashboard_contact_center": "📞 Dashboard Contact Center"
}

# Descripciones de los reportes
DESCRIPCIONES_REPORTES = {
    "dashboard_ventas": "Métricas de ventas, tendencias y análisis de performance",
    "analisis_financiero": "Estados financieros, flujo de caja y análisis de rentabilidad",
    "kpis_operativos": "Indicadores clave de rendimiento operativo",
    "reporte_ejecutivo": "Resumen ejecutivo con métricas consolidadas",
    "metricas_marketing": "Campañas, ROI, métricas digitales y análisis de marketing",
    "analisis_trade": "Análisis de canales, trade marketing y punto de venta",
    "dashboard_contact_center": "Métricas de atención al cliente y contact center"
}

# 👥 CONFIGURACIÓN DE USUARIOS POR ÁREA
AREAS_USUARIOS = {
    "Comercial": {
        "icono": "💼",
        "descripcion": "Área Comercial y Ventas",
        "reportes_permitidos": ["dashboard_ventas", "analisis_financiero", "kpis_operativos", "reporte_ejecutivo"],
        "password_key": "PASSWORD_COMERCIAL",
        "requiere_region": False  # ← NUEVO: No requiere selección de región
    },
    "Marketing": {
        "icono": "📢",
        "descripcion": "Área de Marketing y Comunicaciones",
        "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos", "reporte_ejecutivo"],
        "password_key": "PASSWORD_MARKETING",
        "requiere_region": True,  # ← NUEVO: Requiere selección de región
        "regiones": {
            "Bolivia": {
                "icono": "🇧🇴",
                "password_key": "PASSWORD_MARKETING_BOLIVIA",
                "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos", "reporte_ejecutivo"]
            },
            "Santa Cruz": {
                "icono": "🏙️",
                "password_key": "PASSWORD_MARKETING_SANTA_CRUZ",
                "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos"]
            }
        }
    },
    "Trade": {
        "icono": "🏪",
        "descripcion": "Área de Trade Marketing",
        "reportes_permitidos": ["analisis_trade", "dashboard_ventas", "kpis_operativos"],
        "password_key": "PASSWORD_TRADE",
        "requiere_region": True,  # ← NUEVO: Requiere selección de región
        "regiones": {
            "Bolivia": {
                "icono": "🇧🇴",
                "password_key": "PASSWORD_TRADE_BOLIVIA",
                "reportes_permitidos": ["analisis_trade", "dashboard_ventas", "kpis_operativos"]
            },
            "Santa Cruz": {
                "icono": "🏙️",
                "password_key": "PASSWORD_TRADE_SANTA_CRUZ",
                "reportes_permitidos": ["analisis_trade", "dashboard_ventas"]
            }
        }
    },
    "Contact Center": {
        "icono": "📞",
        "descripcion": "Área de Contact Center",
        "reportes_permitidos": ["dashboard_contact_center", "kpis_operativos"],
        "password_key": "PASSWORD_CONTACT_CENTER",
        "requiere_region": False  # ← NUEVO: No requiere selección de región
    }
}

def mostrar_seleccion_region(area):
    """
    Muestra la pantalla de selección de región para áreas que lo requieren
    """
    config_area = AREAS_USUARIOS[area]
    
    st.markdown(f"""
    <div style='text-align: center; padding: 2rem; background: linear-gradient(135deg, #2196F3 0%, #21CBF3 100%); 
                color: white; border-radius: 15px; margin-bottom: 2rem;'>
        <h1>{config_area['icono']} {area} - Selección de Región</h1>
        <p style='font-size: 1.2em; margin: 0;'>{config_area['descripcion']}</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 🌍 Selecciona tu Región de Trabajo")
    st.markdown("Elige la región para acceder a los reportes correspondientes:")
    st.markdown("---")
    
    # Crear columnas para las regiones
    regiones = list(config_area["regiones"].keys())
    if len(regiones) == 2:
        col1, col2 = st.columns(2)
        columnas = [col1, col2]
    else:
        columnas = [st.columns(1)[0]]  # Una sola columna si hay más o menos regiones
    
    # Mostrar cada región como una tarjeta
    for i, region in enumerate(regiones):
        config_region = config_area["regiones"][region]
        
        # Determinar la columna
        columna = columnas[i % len(columnas)]
        
        with columna:
            # Tarjeta de la región
            st.markdown(f"""
            <div style='background: #f8f9fa; padding: 1.5rem; border-radius: 10px; 
                       border-left: 4px solid #2196F3; margin-bottom: 1rem;
                       box-shadow: 0 2px 4px rgba(0,0,0,0.1);'>
                <h3 style='color: #1976D2; margin-top: 0;'>{config_region['icono']} {region}</h3>
                <p style='color: #555; margin: 0.5rem 0;'>Región {region}</p>
                <p style='color: #777; font-size: 0.9em; margin: 0.5rem 0 0 0;'>
                    📊 {len(config_region['reportes_permitidos'])} reportes disponibles
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            # Botón para seleccionar región
            if st.button(
                f"Seleccionar {region}", 
                key=f"btn_region_{area}_{region}", 
                use_container_width=True,
                help=f"Acceder a {area} - {region}"
            ):
                st.session_state[f"region_seleccionada_{area}"] = region
                st.rerun()
    
    # Botón para regresar
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("⬅️ Regresar a Selección de Área", use_container_width=True):
            st.session_state.area_seleccionada = None
            st.rerun()
    
    # Información adicional
    st.markdown("---")
    st.info(f"🌍 **Selección de Región**: Cada región tiene acceso a reportes específicos para {area}")


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

def verificar_password_area(area, password_ingresado, region=None):
    """
    Verifica la contraseña para un área específica y región (si aplica)
    """
    try:
        config_area = AREAS_USUARIOS[area]
        
        # Si el área requiere región y se proporcionó región
        if config_area.get("requiere_region", False) and region:
            if region not in config_area["regiones"]:
                st.error(f"❌ Región {region} no válida para {area}")
                return False
            
            # Obtener configuración de la región
            config_region = config_area["regiones"][region]
            password_key = config_region["password_key"]
        else:
            # Usar password_key del área principal
            password_key = config_area["password_key"]
        
        # Verificar si existe la contraseña en secrets
        if password_key not in st.secrets:
            st.error(f"❌ **Error de Configuración**")
            st.error(f"No se encontró {password_key} en la configuración segura.")
            st.info("📋 **Para administradores**: Configura las contraseñas en Streamlit Secrets")
            return False
        
        # Obtener contraseña desde secrets
        password_correcto = st.secrets[password_key]
        
        # Verificar contraseña
        return password_ingresado == password_correcto
        
    except Exception as e:
        st.error(f"❌ **Error de Autenticación**: {str(e)}")
        return False

def mostrar_pantalla_login(area, region=None):
    """
    Muestra la pantalla de login para un área específica y región (si aplica)
    """
    config_area = AREAS_USUARIOS[area]
    
    # Determinar título y descripción
    if region:
        config_region = config_area["regiones"][region]
        titulo = f"{config_region['icono']} {area} - {region}"
        descripcion = f"{config_area['descripcion']} - Región {region}"
    else:
        titulo = f"{config_area['icono']} Acceso {area}"
        descripcion = config_area['descripcion']
    
    st.markdown(f"""
    <div style='text-align: center; padding: 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; border-radius: 15px; margin-bottom: 2rem;'>
        <h1>{titulo}</h1>
        <p style='font-size: 1.2em; margin: 0;'>{descripcion}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Formulario de login con región específica
    form_key = f"login_form_{area}" + (f"_{region}" if region else "")
    with st.form(key=form_key):
        st.markdown("### 🔐 Ingresa tu Contraseña")
        
        # Mensaje personalizado según región
        if region:
            st.markdown(f"Introduce la contraseña para acceder a **{area} - {region}**:")
        else:
            st.markdown(f"Introduce la contraseña para acceder al área **{area}**:")
        
        password = st.text_input(
            "Contraseña:",
            type="password",
            placeholder="Ingresa la contraseña...",
            key=f"password_{area}" + (f"_{region}" if region else "")
        )
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            submit_button = st.form_submit_button(
                f"🚀 Acceder",
                use_container_width=True
            )
        
        if submit_button:
            if password:
                if verificar_password_area(area, password, region):
                    # Autenticación exitosa
                    auth_key = f"authenticated_{area}" + (f"_{region}" if region else "")
                    st.session_state[auth_key] = True
                    
                    # Guardar región seleccionada
                    if region:
                        st.session_state[f"region_seleccionada_{area}"] = region
                    
                    success_msg = f"✅ **Acceso concedido a {area}"
                    if region:
                        success_msg += f" - {region}"
                    success_msg += "**"
                    
                    st.success(success_msg)
                    st.balloons()
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error("❌ **Contraseña incorrecta**")
                    st.error("Verifica la contraseña e inténtalo nuevamente")
            else:
                st.warning("⚠️ **Por favor ingresa una contraseña**")
    
    # Botón para regresar (con lógica de región)
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if region:
            # Si está en login de región, regresar a selección de región
            if st.button("⬅️ Regresar a Selección de Región", use_container_width=True):
                if f"region_seleccionada_{area}" in st.session_state:
                    del st.session_state[f"region_seleccionada_{area}"]
                st.rerun()
        else:
            # Si no hay región, regresar a selección de área
            if st.button("⬅️ Regresar a Selección de Área", use_container_width=True):
                st.session_state.area_seleccionada = None
                st.rerun()

def seleccionar_area_usuario():
    """Permite al usuario seleccionar su área de trabajo y región si es necesario"""
    if 'area_seleccionada' not in st.session_state:
        st.session_state.area_seleccionada = None
    
    # Si no hay área seleccionada, mostrar pantalla de selección
    if st.session_state.area_seleccionada is None:
        # ... (código existente para mostrar selección de área)
        return False
    
    area_actual = st.session_state.area_seleccionada
    config_area = AREAS_USUARIOS[area_actual]
    
    # NUEVO: Verificar si el área requiere selección de región
    if config_area.get("requiere_region", False):
        # Verificar si ya se seleccionó región
        region_key = f"region_seleccionada_{area_actual}"
        if region_key not in st.session_state:
            # Mostrar pantalla de selección de región
            mostrar_seleccion_region(area_actual)
            return False
        
        # Obtener región seleccionada
        region_actual = st.session_state[region_key]
        
        # Verificar autenticación para área + región
        auth_key = f"authenticated_{area_actual}_{region_actual}"
        if auth_key not in st.session_state or not st.session_state[auth_key]:
            mostrar_pantalla_login(area_actual, region_actual)
            return False
    else:
        # Área sin región - verificar autenticación normal
        auth_key = f"authenticated_{area_actual}"
        if auth_key not in st.session_state or not st.session_state[auth_key]:
            mostrar_pantalla_login(area_actual)
            return False
    
    return True


def obtener_reportes_por_area(area, region=None):
    """Obtiene los reportes permitidos para un área específica y región"""
    if area not in AREAS_USUARIOS:
        return {}
    
    config_area = AREAS_USUARIOS[area]
    
    # Si el área requiere región y se proporcionó región
    if config_area.get("requiere_region", False) and region:
        if region not in config_area["regiones"]:
            return {}
        
        # Obtener reportes de la región específica
        reportes_permitidos = config_area["regiones"][region]["reportes_permitidos"]
    else:
        # Usar reportes del área principal
        reportes_permitidos = config_area["reportes_permitidos"]
    
    # Filtrar URLs disponibles
    reportes_filtrados = {}
    for reporte_key in reportes_permitidos:
        if reporte_key in URLS_ENCRIPTADAS:
            reportes_filtrados[reporte_key] = URLS_ENCRIPTADAS[reporte_key]
    
    return reportes_filtrados

def mostrar_reporte_individual():
    """Muestra un reporte seleccionado individualmente"""
    
    area_actual = st.session_state.area_seleccionada
    config_area = AREAS_USUARIOS[area_actual]
    
    st.title(f"{config_area['icono']} Portal {area_actual}")
    st.markdown(f"**{config_area['descripcion']}** - Accede a tus reportes autorizados")
    st.markdown("---")
    
    # Obtener reportes permitidos para el área
    reportes_area = obtener_reportes_por_area(area_actual)
    
    if not reportes_area:
        st.warning(f"⚠️ No hay reportes configurados para el área {area_actual}")
        return
    
    # Obtener clave de desencriptación
    clave_fernet = obtener_clave_desencriptacion()
    
    # Sidebar para selección de reporte
    st.sidebar.title("📋 Seleccionar Reporte")
    st.sidebar.markdown("Reportes disponibles para tu área:")
    
    reporte_seleccionado = st.sidebar.selectbox(
        "📊 Reportes disponibles:",
        options=list(reportes_area.keys()),
        format_func=lambda x: TITULOS_REPORTES.get(x, x),
        index=0
    )
    
    # Configuraciones de visualización
    st.sidebar.markdown("---")
    st.sidebar.subheader("⚙️ Configuración")
    altura_iframe = st.sidebar.slider("📏 Altura del reporte", 400, 1200, 700, 50)
    
    # Botón para cambiar de área
    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Cambiar Área", use_container_width=True):
        st.session_state.area_seleccionada = None
        st.rerun()
    
    # Botón para cerrar sesión del área actual
    if st.sidebar.button("🚪 Cerrar Sesión", use_container_width=True):
        # Limpiar autenticación del área actual
        if f"authenticated_{area_actual}" in st.session_state:
            del st.session_state[f"authenticated_{area_actual}"]
        st.session_state.area_seleccionada = None
        st.success(f"✅ Sesión cerrada para {area_actual}")
        st.rerun()
    
    # Información del reporte seleccionado
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.subheader(TITULOS_REPORTES.get(reporte_seleccionado, reporte_seleccionado))
        st.markdown(f"*{DESCRIPCIONES_REPORTES.get(reporte_seleccionado, 'Reporte de Power BI')}*")
    
    with col2:
        st.metric("📊 Reportes", len(reportes_area))
    
    # Desencriptar la URL seleccionada
    url_encriptada = reportes_area[reporte_seleccionado]
    
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
        
        # Botón de actualizar
        col1, col2, col3 = st.columns([1, 3, 1])
        with col2:
            if st.button("🔄 Actualizar Reporte", use_container_width=True):
                st.rerun()
    
    else:
        st.error("❌ **No se pudo cargar el reporte**")
        st.error("Verifica que la configuración de encriptación sea correcta")

def mostrar_multiples_reportes():
    """Muestra todos los reportes permitidos en pestañas"""
    
    area_actual = st.session_state.area_seleccionada
    config_area = AREAS_USUARIOS[area_actual]
    
    st.title(f"{config_area['icono']} Panel Completo - {area_actual}")
    st.markdown(f"**{config_area['descripcion']}** - Todos tus reportes en un solo lugar")
    st.markdown("---")
    
    # Obtener reportes permitidos para el área
    reportes_area = obtener_reportes_por_area(area_actual)
    
    if not reportes_area:
        st.warning(f"⚠️ No hay reportes configurados para el área {area_actual}")
        return
    
    # Obtener clave de desencriptación
    clave_fernet = obtener_clave_desencriptacion()
    
    # Configuración de altura
    altura_iframe = st.sidebar.slider("📏 Altura de reportes", 400, 1000, 600, 50)
    
    # Botón para cambiar de área
    st.sidebar.markdown("---")
    if st.sidebar.button("🔄 Cambiar Área", use_container_width=True):
        st.session_state.area_seleccionada = None
        st.rerun()
    
    # Crear pestañas para cada reporte permitido
    tab_names = [TITULOS_REPORTES.get(k, k) for k in reportes_area.keys()]
    tabs = st.tabs(tab_names)
    
    # Mostrar cada reporte en su pestaña correspondiente
    for i, (reporte_key, url_encriptada) in enumerate(reportes_area.items()):
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
    
    /* Estilos personalizados para botones de área */
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.75rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        background: linear-gradient(135deg, #5a67d8 0%, #667eea 100%);
    }
    
    /* Hover effect para las tarjetas de área */
    .area-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Verificar si el usuario ha seleccionado su área
    if not seleccionar_area_usuario():
        return
    
    # Una vez seleccionada el área, mostrar la navegación
    area_actual = st.session_state.area_seleccionada
    config_area = AREAS_USUARIOS[area_actual]
    
    # Sidebar para navegación
    st.sidebar.title("🚀 Navegación")
    st.sidebar.markdown(f"**Usuario:** {config_area['icono']} {area_actual}")
    st.sidebar.markdown("---")
    
    modo_visualizacion = st.sidebar.radio(
        "Selecciona el modo de visualización:",
        ["📊 Reporte Individual", "📋 Todos los Reportes"],
        index=0
    )
    
    # Información del sistema
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ℹ️ Información")
    reportes_disponibles = len(AREAS_USUARIOS[area_actual]["reportes_permitidos"])
    st.sidebar.info(f"📊 **Reportes disponibles:** {reportes_disponibles}")
    st.sidebar.success("🔒 **Conexión segura:** Activada")
    
    # AGREGAR ESTA LÍNEA PARA DEBUG
    debug_desencriptacion()
    
    # Mostrar el modo seleccionado
    if modo_visualizacion == "📊 Reporte Individual":
        mostrar_reporte_individual()
    else:
        mostrar_multiples_reportes()
    
    # Footer
    st.markdown("---")
    st.markdown(f"""
    <div style='text-align: center; color: #666; padding: 1rem;'>
        🔒 <strong>Portal Seguro Power BI</strong> • {config_area['icono']} Área: {area_actual}<br>
        <small>Acceso controlado por área • Reportes protegidos con encriptación avanzada</small>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
