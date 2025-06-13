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
    "dashboard_ventas": "gAAAAABoS6gIgq_tP2hti2I7nU2hfUPw00DU0rWUmsUtT8ES5DVslx0DwWPdI4OOgzTD9hS2rwObVxSu8s40InWSjBRzypk_5-ASHwLOMLLw-gX_jP3pmTokaFG6Ghty0IqyK839vOtz1l3MEncolHI7gMFDYLg13BXKw5Fatj-3yYHGtQeR7JcXvECtJ6UhSpcsoKX-ahQj6ISUogWq8EcHHnbXPS9wrxgQfd2BVZugn03sHi7QLur8HZlmHk5XEfdUnI6l-lQdl3Fyf9kxCTB2hiDTIGPUow==",
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
        "password_key": "PASSWORD_COMERCIAL"
    },
    "Marketing": {
        "icono": "📢",
        "descripcion": "Área de Marketing y Comunicaciones",
        "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos", "reporte_ejecutivo"],
        "password_key": "PASSWORD_MARKETING"
    },
    "Trade": {
        "icono": "🏪",
        "descripcion": "Área de Trade Marketing",
        "reportes_permitidos": ["analisis_trade", "dashboard_ventas", "kpis_operativos"],
        "password_key": "PASSWORD_TRADE"
    },
    "Contact Center": {
        "icono": "📞",
        "descripcion": "Área de Contact Center",
        "reportes_permitidos": ["dashboard_contact_center", "kpis_operativos"],
        "password_key": "PASSWORD_CONTACT_CENTER"
    }
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

def verificar_password_area(area, password_ingresado):
    """
    Verifica la contraseña para un área específica
    """
    try:
        config_area = AREAS_USUARIOS[area]
        password_key = config_area["password_key"]
        
        # Verificar si existe la contraseña en secrets
        if password_key not in st.secrets:
            st.error(f"❌ **Error de Configuración**")
            st.error(f"No se encontró {password_key} en la configuración segura.")
            st.info("📋 **Para administradores**: Configura las contraseñas de área en Streamlit Secrets")
            return False
        
        # Obtener contraseña desde secrets
        password_correcto = st.secrets[password_key]
        
        # Verificar contraseña
        return password_ingresado == password_correcto
        
    except Exception as e:
        st.error(f"❌ **Error de Autenticación**: {str(e)}")
        return False

def mostrar_pantalla_login(area):
    """
    Muestra la pantalla de login para un área específica
    """
    config_area = AREAS_USUARIOS[area]
    
    st.markdown(f"""
    <div style='text-align: center; padding: 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                color: white; border-radius: 15px; margin-bottom: 2rem;'>
        <h1>{config_area['icono']} Acceso {area}</h1>
        <p style='font-size: 1.2em; margin: 0;'>{config_area['descripcion']}</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Formulario de login
    with st.form(key=f"login_form_{area}"):
        st.markdown("### 🔐 Ingresa tu Contraseña")
        st.markdown(f"Introduce la contraseña para acceder al área **{area}**:")
        
        password = st.text_input(
            "Contraseña:",
            type="password",
            placeholder="Ingresa la contraseña del área...",
            key=f"password_{area}"
        )
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            submit_button = st.form_submit_button(
                f"🚀 Acceder a {area}",
                use_container_width=True
            )
        
        if submit_button:
            if password:
                if verificar_password_area(area, password):
                    # Autenticación exitosa
                    st.session_state[f"authenticated_{area}"] = True
                    st.success(f"✅ **Acceso concedido a {area}**")
                    st.balloons()
                    time.sleep(1)  # Pequeña pausa para mostrar el mensaje
                    st.rerun()
                else:
                    # Contraseña incorrecta
                    st.error("❌ **Contraseña incorrecta**")
                    st.error("Verifica la contraseña e inténtalo nuevamente")
            else:
                st.warning("⚠️ **Por favor ingresa una contraseña**")
    
    # Botón para regresar
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("⬅️ Regresar a Selección de Área", use_container_width=True):
            st.session_state.area_seleccionada = None
            st.rerun()
    
    # Información adicional
    st.markdown("---")
    st.info(f"🔒 **Seguridad**: El acceso al área {area} está protegido por contraseña")
    st.markdown(f"""
    <div style='background: #f8f9fa; padding: 1rem; border-radius: 8px; border-left: 4px solid #17a2b8;'>
        <strong>📊 Reportes disponibles en {area}:</strong><br>
        • {len(config_area['reportes_permitidos'])} reportes autorizados<br>
        • Acceso seguro y controlado<br>
        • Datos protegidos con encriptación
    </div>
    """, unsafe_allow_html=True)

def seleccionar_area_usuario():
    """Permite al usuario seleccionar su área de trabajo"""
    if 'area_seleccionada' not in st.session_state:
        st.session_state.area_seleccionada = None
    
    # Si no hay área seleccionada, mostrar pantalla de selección
    if st.session_state.area_seleccionada is None:
        st.title("🏢 Portal de Reportes Power BI")
        st.markdown("### 👥 Selecciona tu Área de Trabajo")
        st.markdown("Elige tu área para acceder a los reportes correspondientes:")
        st.markdown("---")
        
        # Colores personalizados para cada área
        colores_areas = {
            "Comercial": {
                "fondo": "#e8f4fd",  # Azul claro
                "borde": "#1976d2",  # Azul
                "titulo": "#0d47a1",  # Azul oscuro
                "boton": "#1976d2"   # Azul para botón
            },
            "Marketing": {
                "fondo": "#fce4ec",  # Rosa claro
                "borde": "#e91e63",  # Rosa
                "titulo": "#ad1457",  # Rosa oscuro
                "boton": "#e91e63"   # Rosa para botón
            },
            "Trade": {
                "fondo": "#f3e5f5",  # Morado claro
                "borde": "#9c27b0",  # Morado
                "titulo": "#6a1b9a",  # Morado oscuro
                "boton": "#9c27b0"   # Morado para botón
            },
            "Contact Center": {
                "fondo": "#e8f5e8",  # Verde claro
                "borde": "#4caf50",  # Verde
                "titulo": "#2e7d32",  # Verde oscuro
                "boton": "#4caf50"   # Verde para botón
            }
        }
        
        # Crear botones para cada área
        col1, col2 = st.columns(2)
        
        areas_lista = list(AREAS_USUARIOS.keys())
        
        for i, area in enumerate(areas_lista):
            config_area = AREAS_USUARIOS[area]
            colores = colores_areas.get(area, colores_areas["Comercial"])  # Color por defecto
            
            # Alternar columnas
            columna = col1 if i % 2 == 0 else col2
            
            with columna:
                st.markdown(f"""
                <div class='area-card' style='background: {colores["fondo"]}; padding: 1.5rem; border-radius: 10px; 
                           border-left: 4px solid {colores["borde"]}; margin-bottom: 1rem;
                           box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: all 0.3s ease;
                           cursor: pointer;'>
                    <h3 style='color: {colores["titulo"]}; margin-top: 0;'>{config_area['icono']} {area}</h3>
                    <p style='color: #555; margin: 0.5rem 0;'>{config_area['descripcion']}</p>
                    <p style='color: #777; font-size: 0.9em; margin: 0.5rem 0 0 0;'>
                        📊 {len(config_area['reportes_permitidos'])} reportes disponibles
                    </p>
                </div>
                """, unsafe_allow_html=True)
                
                # Botón personalizado con color del área
                if st.button(
                    f"Acceder como {area}", 
                    key=f"btn_{area}", 
                    use_container_width=True,
                    help=f"Ingresar al área {area}"
                ):
                    st.session_state.area_seleccionada = area
                    st.rerun()
                
                st.markdown("<br>", unsafe_allow_html=True)
        
        # Información adicional
        st.markdown("---")
        st.info("🔒 **Acceso Controlado:** Solo verás los reportes autorizados para tu área de trabajo")
        return False
    
    # Verificar si el usuario está autenticado para el área seleccionada
    area_actual = st.session_state.area_seleccionada
    if f"authenticated_{area_actual}" not in st.session_state or not st.session_state[f"authenticated_{area_actual}"]:
        # Mostrar pantalla de login
        mostrar_pantalla_login(area_actual)
        return False
    
    return True

def obtener_reportes_por_area(area):
    """Obtiene los reportes permitidos para un área específica"""
    if area not in AREAS_USUARIOS:
        return {}
    
    reportes_permitidos = AREAS_USUARIOS[area]["reportes_permitidos"]
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
