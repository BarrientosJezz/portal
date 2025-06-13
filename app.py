import streamlit as st
import base64
import json
import hashlib
import secrets
from datetime import datetime, timedelta
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

def crear_clave_desde_password(password):
    """Crea una clave de encriptación determinística desde un password"""
    salt = b'powerbi_encrypt_salt_2024'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def desencriptar_url(url_encriptada, clave_fernet):
    """Desencripta una URL usando la clave proporcionada"""
    try:
        f = Fernet(clave_fernet)
        url_encriptada_bytes = base64.urlsafe_b64decode(url_encriptada.encode('utf-8'))
        url_bytes = f.decrypt(url_encriptada_bytes)
        return url_bytes.decode('utf-8')
    except Exception as e:
        st.error(f"❌ Error al desencriptar URL: {str(e)}")
        return None

def hash_password(password):
    """Genera un hash seguro de la contraseña"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    """Verifica si la contraseña coincide con el hash"""
    return hash_password(password) == hashed

def generate_password(length=12):
    """Genera una contraseña aleatoria"""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def encriptar_datos_usuarios(datos_usuarios, password_master):
    """Encripta los datos de usuarios"""
    try:
        clave = crear_clave_desde_password(password_master)
        f = Fernet(clave)
        datos_json = json.dumps(datos_usuarios)
        datos_encriptados = f.encrypt(datos_json.encode())
        return base64.urlsafe_b64encode(datos_encriptados).decode()
    except Exception as e:
        st.error(f"Error al encriptar datos: {str(e)}")
        return None

def desencriptar_datos_usuarios(datos_encriptados, password_master):
    """Desencripta los datos de usuarios"""
    try:
        clave = crear_clave_desde_password(password_master)
        f = Fernet(clave)
        datos_bytes = base64.urlsafe_b64decode(datos_encriptados.encode())
        datos_desencriptados = f.decrypt(datos_bytes)
        return json.loads(datos_desencriptados.decode())
    except Exception as e:
        return None

# ✅ DATOS DE USUARIOS ENCRIPTADOS - SEGURO EN GITHUB
# Reemplaza este string con el generado por tu script de encriptación de usuarios
USUARIOS_ENCRIPTADOS = """
gAAAAABh_ejemplo_datos_usuarios_encriptados_aqui_reemplazar_con_datos_reales
"""

# URLs ENCRIPTADAS POR DEPARTAMENTO
URLS_ENCRIPTADAS = {
    "ventas": {
        "dashboard_ventas": "gAAAAABh_ejemplo_url_encriptada_ventas_1",
        "analisis_clientes": "gAAAAABh_ejemplo_url_encriptada_ventas_2",
        "forecasting": "gAAAAABh_ejemplo_url_encriptada_ventas_3"
    },
    "finanzas": {
        "estados_financieros": "gAAAAABh_ejemplo_url_encriptada_finanzas_1",
        "flujo_caja": "gAAAAABh_ejemplo_url_encriptada_finanzas_2",
        "presupuesto": "gAAAAABh_ejemplo_url_encriptada_finanzas_3"
    },
    "operaciones": {
        "kpis_operativos": "gAAAAABh_ejemplo_url_encriptada_ops_1",
        "productividad": "gAAAAABh_ejemplo_url_encriptada_ops_2",
        "calidad": "gAAAAABh_ejemplo_url_encriptada_ops_3"
    },
    "ejecutivo": {
        "dashboard_ejecutivo": "gAAAAABh_ejemplo_url_encriptada_exec_1",
        "resumen_general": "gAAAAABh_ejemplo_url_encriptada_exec_2",
        "kpis_estrategicos": "gAAAAABh_ejemplo_url_encriptada_exec_3"
    }
}

# CONFIGURACIÓN DE DEPARTAMENTOS Y TÍTULOS
DEPARTAMENTOS = {
    "ventas": {
        "nombre": "💰 Ventas",
        "icono": "💰",
        "reportes": {
            "dashboard_ventas": "📈 Dashboard de Ventas",
            "analisis_clientes": "👥 Análisis de Clientes",
            "forecasting": "🔮 Forecasting"
        }
    },
    "finanzas": {
        "nombre": "💼 Finanzas",
        "icono": "💼",
        "reportes": {
            "estados_financieros": "📊 Estados Financieros",
            "flujo_caja": "💸 Flujo de Caja",
            "presupuesto": "📋 Presupuesto"
        }
    },
    "operaciones": {
        "nombre": "⚙️ Operaciones",
        "icono": "⚙️",
        "reportes": {
            "kpis_operativos": "🎯 KPIs Operativos",
            "productividad": "📈 Productividad",
            "calidad": "✅ Calidad"
        }
    },
    "ejecutivo": {
        "nombre": "👔 Ejecutivo",
        "icono": "👔",
        "reportes": {
            "dashboard_ejecutivo": "🏢 Dashboard Ejecutivo",
            "resumen_general": "📋 Resumen General",
            "kpis_estrategicos": "🎯 KPIs Estratégicos"
        }
    }
}

def obtener_configuracion_segura():
    """Obtiene las configuraciones desde Streamlit Secrets"""
    try:
        if "PASSWORD" not in st.secrets or "MASTER_PASSWORD" not in st.secrets:
            st.error("❌ **Error de Configuración**")
            st.error("Faltan configuraciones de seguridad.")
            st.info("📋 **Para administradores**: Configura PASSWORD y MASTER_PASSWORD en Streamlit Secrets")
            st.stop()
        
        password_urls = st.secrets["PASSWORD"]
        password_master = st.secrets["MASTER_PASSWORD"]
        
        clave_fernet = crear_clave_desde_password(password_urls)
        return clave_fernet, password_master
        
    except Exception as e:
        st.error(f"❌ **Error de Seguridad**: {str(e)}")
        st.stop()

def cargar_usuarios():
    """Carga y desencripta los datos de usuarios"""
    _, password_master = obtener_configuracion_segura()
    
    usuarios = desencriptar_datos_usuarios(USUARIOS_ENCRIPTADOS.strip(), password_master)
    
    if usuarios is None:
        # Datos por defecto si no se pueden desencriptar
        return {
            "admin": {
                "password_hash": hash_password("admin123"),
                "role": "admin",
                "departamentos": ["ventas", "finanzas", "operaciones", "ejecutivo"],
                "nombre": "Administrador",
                "ultimo_acceso": None,
                "activo": True
            }
        }
    
    return usuarios

def guardar_usuarios(usuarios):
    """Encripta y devuelve los datos de usuarios para actualizar en el código"""
    _, password_master = obtener_configuracion_segura()
    return encriptar_datos_usuarios(usuarios, password_master)

def login_form():
    """Formulario de login"""
    st.markdown("""
    <div style='text-align: center; padding: 2rem 0;'>
        <h1>🏢 Portal Power BI</h1>
        <h3>🔒 Acceso Seguro</h3>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("login_form"):
        st.markdown("### 👤 Iniciar Sesión")
        username = st.text_input("👤 Usuario", placeholder="Ingresa tu usuario")
        password = st.text_input("🔑 Contraseña", type="password", placeholder="Ingresa tu contraseña")
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            submit = st.form_submit_button("🚀 Iniciar Sesión", use_container_width=True)
        
        if submit:
            if username and password:
                usuarios = cargar_usuarios()
                
                if username in usuarios and usuarios[username].get("activo", True):
                    if verify_password(password, usuarios[username]["password_hash"]):
                        # Login exitoso
                        st.session_state.authenticated = True
                        st.session_state.username = username
                        st.session_state.user_data = usuarios[username]
                        
                        # Actualizar último acceso
                        usuarios[username]["ultimo_acceso"] = datetime.now().isoformat()
                        
                        st.success("✅ Login exitoso!")
                        st.rerun()
                    else:
                        st.error("❌ Contraseña incorrecta")
                else:
                    st.error("❌ Usuario no encontrado o inactivo")
            else:
                st.warning("⚠️ Por favor completa todos los campos")

def admin_panel():
    """Panel de administración para gestionar usuarios"""
    st.title("⚙️ Panel de Administración")
    st.markdown("Gestión de usuarios y permisos")
    st.markdown("---")
    
    usuarios = cargar_usuarios()
    
    tab1, tab2, tab3 = st.tabs(["👥 Gestionar Usuarios", "➕ Crear Usuario", "📊 Estadísticas"])
    
    with tab1:
        st.subheader("👥 Usuarios del Sistema")
        
        for username, data in usuarios.items():
            if username == "admin":
                continue
                
            with st.expander(f"👤 {data.get('nombre', username)} ({username})"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Rol:** {data.get('role', 'user')}")
                    st.write(f"**Estado:** {'✅ Activo' if data.get('activo', True) else '❌ Inactivo'}")
                    st.write(f"**Departamentos:** {', '.join(data.get('departamentos', []))}")
                
                with col2:
                    if data.get('ultimo_acceso'):
                        ultimo_acceso = datetime.fromisoformat(data['ultimo_acceso'])
                        st.write(f"**Último acceso:** {ultimo_acceso.strftime('%d/%m/%Y %H:%M')}")
                    else:
                        st.write("**Último acceso:** Nunca")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if st.button(f"🔑 Restablecer Contraseña", key=f"reset_{username}"):
                        nueva_password = generate_password()
                        usuarios[username]["password_hash"] = hash_password(nueva_password)
                        st.success(f"✅ Nueva contraseña para {username}: **{nueva_password}**")
                        st.info("⚠️ **Importante:** Guarda esta contraseña, no se mostrará nuevamente")
                
                with col2:
                    estado_actual = data.get('activo', True)
                    if st.button(f"{'❌ Desactivar' if estado_actual else '✅ Activar'}", key=f"toggle_{username}"):
                        usuarios[username]["activo"] = not estado_actual
                        st.success(f"Usuario {username} {'activado' if not estado_actual else 'desactivado'}")
                
                with col3:
                    if st.button(f"🗑️ Eliminar", key=f"delete_{username}"):
                        if st.session_state.get(f"confirm_delete_{username}", False):
                            del usuarios[username]
                            st.success(f"Usuario {username} eliminado")
                            st.rerun()
                        else:
                            st.session_state[f"confirm_delete_{username}"] = True
                            st.warning("⚠️ Haz clic nuevamente para confirmar")
    
    with tab2:
        st.subheader("➕ Crear Nuevo Usuario")
        
        with st.form("crear_usuario"):
            nuevo_username = st.text_input("👤 Nombre de usuario")
            nuevo_nombre = st.text_input("📛 Nombre completo")
            nuevo_rol = st.selectbox("👔 Rol", ["user", "admin"])
            
            st.markdown("**📂 Departamentos con acceso:**")
            departamentos_seleccionados = []
            
            cols = st.columns(2)
            for i, (dept_key, dept_info) in enumerate(DEPARTAMENTOS.items()):
                with cols[i % 2]:
                    if st.checkbox(f"{dept_info['icono']} {dept_info['nombre']}", key=f"dept_{dept_key}"):
                        departamentos_seleccionados.append(dept_key)
            
            generar_password_auto = st.checkbox("🎲 Generar contraseña automáticamente", value=True)
            
            if not generar_password_auto:
                nueva_password = st.text_input("🔑 Contraseña", type="password")
            
            if st.form_submit_button("➕ Crear Usuario"):
                if nuevo_username and nuevo_nombre and departamentos_seleccionados:
                    if nuevo_username not in usuarios:
                        if generar_password_auto:
                            nueva_password = generate_password()
                        
                        usuarios[nuevo_username] = {
                            "password_hash": hash_password(nueva_password),
                            "role": nuevo_rol,
                            "departamentos": departamentos_seleccionados,
                            "nombre": nuevo_nombre,
                            "ultimo_acceso": None,
                            "activo": True
                        }
                        
                        st.success(f"✅ Usuario {nuevo_username} creado exitosamente")
                        st.info(f"🔑 **Contraseña:** {nueva_password}")
                        st.warning("⚠️ **Importante:** Guarda esta contraseña, no se mostrará nuevamente")
                    else:
                        st.error("❌ El usuario ya existe")
                else:
                    st.warning("⚠️ Completa todos los campos requeridos")
    
    with tab3:
        st.subheader("📊 Estadísticas del Sistema")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            total_usuarios = len([u for u in usuarios.values() if u.get('activo', True)])
            st.metric("👥 Usuarios Activos", total_usuarios)
        
        with col2:
            admin_count = len([u for u in usuarios.values() if u.get('role') == 'admin'])
            st.metric("👔 Administradores", admin_count)
        
        with col3:
            total_reportes = sum(len(dept_urls) for dept_urls in URLS_ENCRIPTADAS.values())
            st.metric("📊 Total Reportes", total_reportes)
        
        with col4:
            usuarios_con_acceso = len([u for u in usuarios.values() if u.get('ultimo_acceso')])
            st.metric("🔄 Han Accedido", usuarios_con_acceso)
    
    # Mostrar información para actualizar el código
    if st.button("🔄 Generar Datos Encriptados Actualizados"):
        datos_encriptados = guardar_usuarios(usuarios)
        if datos_encriptados:
            st.markdown("### 📋 Actualizar Código")
            st.info("Copia el siguiente texto y reemplaza la variable USUARIOS_ENCRIPTADOS en el código:")
            st.code(datos_encriptados, language="text")

def mostrar_reportes():
    """Muestra los reportes según los permisos del usuario"""
    user_data = st.session_state.user_data
    departamentos_usuario = user_data.get("departamentos", [])
    
    st.title(f"📊 Portal de Reportes - {user_data.get('nombre', st.session_state.username)}")
    st.markdown("Accede a tus reportes autorizados")
    st.markdown("---")
    
    # Configuración de altura
    altura_iframe = st.sidebar.slider("📏 Altura de reportes", 400, 1000, 700, 50)
    
    # Crear pestañas para cada departamento autorizado
    tabs_disponibles = []
    tabs_nombres = []
    
    for dept_key in departamentos_usuario:
        if dept_key in DEPARTAMENTOS:
            tabs_disponibles.append(dept_key)
            tabs_nombres.append(DEPARTAMENTOS[dept_key]["nombre"])
    
    if not tabs_disponibles:
        st.warning("⚠️ No tienes acceso a ningún departamento. Contacta al administrador.")
        return
    
    # Crear las pestañas
    tabs = st.tabs(tabs_nombres)
    clave_fernet, _ = obtener_configuracion_segura()
    
    # Mostrar reportes en cada pestaña
    for i, dept_key in enumerate(tabs_disponibles):
        with tabs[i]:
            dept_info = DEPARTAMENTOS[dept_key]
            st.markdown(f"### {dept_info['icono']} Reportes de {dept_info['nombre']}")
            
            # Sub-pestañas para cada reporte del departamento
            reportes_dept = dept_info["reportes"]
            if dept_key in URLS_ENCRIPTADAS:
                sub_tabs_nombres = list(reportes_dept.values())
                sub_tabs = st.tabs(sub_tabs_nombres)
                
                for j, (reporte_key, titulo_reporte) in enumerate(reportes_dept.items()):
                    with sub_tabs[j]:
                        if reporte_key in URLS_ENCRIPTADAS[dept_key]:
                            url_encriptada = URLS_ENCRIPTADAS[dept_key][reporte_key]
                            
                            with st.spinner("🔓 Cargando reporte..."):
                                url_desencriptada = desencriptar_url(url_encriptada, clave_fernet)
                            
                            if url_desencriptada:
                                # Mostrar métricas del reporte
                                col1, col2 = st.columns([3, 1])
                                with col1:
                                    st.markdown(f"**📊 {titulo_reporte}**")
                                with col2:
                                    if st.button("🔄 Actualizar", key=f"refresh_{dept_key}_{reporte_key}"):
                                        st.rerun()
                                
                                # Iframe del reporte
                                st.components.v1.iframe(
                                    src=url_desencriptada,
                                    height=altura_iframe,
                                    scrolling=True
                                )
                            else:
                                st.error(f"❌ Error al cargar el reporte: {titulo_reporte}")
                        else:
                            st.warning(f"⚠️ Reporte {titulo_reporte} no disponible")

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
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        padding-left: 20px;
        padding-right: 20px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Verificar autenticación
    if not st.session_state.get("authenticated", False):
        login_form()
        return
    
    # Sidebar con información del usuario
    user_data = st.session_state.user_data
    st.sidebar.title("👤 Usuario")
    st.sidebar.success(f"**{user_data.get('nombre', st.session_state.username)}**")
    st.sidebar.info(f"**Rol:** {user_data.get('role', 'user')}")
    
    # Navegación
    st.sidebar.title("🚀 Navegación")
    
    opciones_menu = ["📊 Reportes"]
    if user_data.get('role') == 'admin':
        opciones_menu.append("⚙️ Administración")
    
    opcion_seleccionada = st.sidebar.radio("Selecciona una opción:", opciones_menu)
    
    # Botón de logout
    st.sidebar.markdown("---")
    if st.sidebar.button("🚪 Cerrar Sesión"):
        for key in list(st.session_state.keys()):
            if key.startswith(('authenticated', 'username', 'user_data')):
                del st.session_state[key]
        st.rerun()
    
    # Mostrar la opción seleccionada
    if opcion_seleccionada == "📊 Reportes":
        mostrar_reportes()
    elif opcion_seleccionada == "⚙️ Administración" and user_data.get('role') == 'admin':
        admin_panel()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666; padding: 1rem;'>
        🔒 <strong>Portal Seguro Power BI</strong> • Sistema de Autenticación Activo<br>
        <small>Reportes protegidos con encriptación y control de acceso por roles</small>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
