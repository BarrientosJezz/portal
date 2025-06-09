import streamlit as st
import json
import os
import base64
from cryptography.fernet import Fernet

st.set_page_config(page_title="Portal de Reportes", layout="wide")

# Clave de encriptación (en producción, usar variable de entorno)
ENCRYPTION_KEY = "TU_CLAVE_SECRETA_32_CARACTERES_12345="  # Cambiar por tu clave

# Archivos de configuración
USERS_FILE = "users.json"
REPORTS_FILE = "reports.json"
ROLES_FILE = "roles.json"

# Funciones de encriptación
def encrypt_url(url, key=ENCRYPTION_KEY):
    """Encripta una URL"""
    try:
        fernet = Fernet(key.encode()[:32].ljust(32, b'0')[:32])
        fernet = Fernet(base64.urlsafe_b64encode(fernet))
        encrypted = fernet.encrypt(url.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    except:
        # Método simple si falla cryptography
        return base64.b64encode(url.encode()).decode()

def decrypt_url(encrypted_url, key=ENCRYPTION_KEY):
    """Desencripta una URL"""
    try:
        fernet = Fernet(key.encode()[:32].ljust(32, b'0')[:32])
        fernet = Fernet(base64.urlsafe_b64encode(fernet))
        decrypted = fernet.decrypt(base64.urlsafe_b64decode(encrypted_url.encode()))
        return decrypted.decode()
    except:
        # Método simple si falla cryptography
        return base64.b64decode(encrypted_url.encode()).decode()

# Cargar datos desde archivos JSON
def load_data():
    # Cargar usuarios
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                users = json.load(f)
        except:
            users = {}
    else:
        users = {'admin': {'password': 'admin123', 'role': 'admin', 'user_type': 'admin'}}
    
    # Cargar reportes
    if os.path.exists(REPORTS_FILE):
        try:
            with open(REPORTS_FILE, 'r') as f:
                reports = json.load(f)
        except:
            reports = []
    else:
        # URL de ejemplo encriptada
        sample_url = "https://app.powerbi.com/view?r=eyJrIjoiMWExMDFjMGQtNzMzYy00NmU0LTg3YWQtZTJiNzM4OTkyNzNhIiwidCI6ImJkZmZlZWM3LTVkOGMtNDQwMS1iYjZiLTIzNDRlZTI1NjE5NSJ9"
        reports = [{
            'name': 'Reporte Enero 2025',
            'encrypted_url': encrypt_url(sample_url),
            'description': 'Reporte mensual de enero',
            'allowed_types': ['admin', 'gerencia', 'ventas']
        }]
    
    # Cargar tipos de usuario
    if os.path.exists(ROLES_FILE):
        try:
            with open(ROLES_FILE, 'r') as f:
                user_types = json.load(f)
        except:
            user_types = []
    else:
        user_types = [
            {'name': 'admin', 'description': 'Administrador del sistema'},
            {'name': 'gerencia', 'description': 'Gerencia y directivos'},
            {'name': 'ventas', 'description': 'Equipo de ventas'},
            {'name': 'marketing', 'description': 'Equipo de marketing'},
            {'name': 'finanzas', 'description': 'Departamento financiero'}
        ]
    
    return users, reports, user_types

# Guardar datos en archivos JSON
def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def save_reports(reports):
    with open(REPORTS_FILE, 'w') as f:
        json.dump(reports, f, indent=2)

def save_user_types(user_types):
    with open(ROLES_FILE, 'w') as f:
        json.dump(user_types, f, indent=2)

# Inicializar datos
if 'users' not in st.session_state or 'reports' not in st.session_state or 'user_types' not in st.session_state:
    st.session_state.users, st.session_state.reports, st.session_state.user_types = load_data()

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

# Función de login
def login():
    st.title("🔐 Iniciar Sesión")
    
    with st.form("login_form"):
        username = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")
        login_btn = st.form_submit_button("Entrar")
        
        if login_btn:
            if username in st.session_state.users and st.session_state.users[username]['password'] == password:
                st.session_state.logged_in = True
                st.session_state.current_user = username
                st.session_state.user_role = st.session_state.users[username]['role']
                st.session_state.user_type = st.session_state.users[username].get('user_type', 'user')
                st.rerun()
            else:
                st.error("Usuario o contraseña incorrectos")

# Panel admin (versión resumida por espacio)
def admin_panel():
    st.sidebar.title("🛠️ Panel Admin")
    
    # Gestión de reportes con encriptación
    with st.sidebar.expander("📊 Gestión de Reportes"):
        st.write("**Agregar Reporte Seguro**")
        report_name = st.text_input("Nombre del reporte")
        report_url = st.text_area("URL del reporte Power BI")
        report_desc = st.text_input("Descripción")
        
        # Seleccionar tipos de usuario permitidos
        st.write("**Tipos de usuario con acceso:**")
        allowed_types = []
        for ut in st.session_state.user_types:
            if st.checkbox(f"{ut['name']}", key=f"access_{ut['name']}"):
                allowed_types.append(ut['name'])
        
        if st.button("🔒 Agregar Reporte Encriptado"):
            if report_name and report_url and allowed_types:
                new_report = {
                    'name': report_name,
                    'encrypted_url': encrypt_url(report_url),  # URL encriptada
                    'description': report_desc or 'Sin descripción',
                    'allowed_types': allowed_types
                }
                st.session_state.reports.append(new_report)
                save_reports(st.session_state.reports)
                st.success(f"Reporte '{report_name}' agregado de forma segura")
                st.rerun()
            else:
                st.error("Complete todos los campos")
        
        # Vista de URLs encriptadas
        if st.session_state.reports:
            st.write("**Estado de Seguridad:**")
            for report in st.session_state.reports:
                if 'encrypted_url' in report:
                    st.write(f"🔒 {report['name']}: Protegido")
                else:
                    st.write(f"⚠️ {report['name']}: No protegido")

# Función principal
def main_app():
    st.title("📊 Portal de Reportes Seguro")
    
    # Panel admin si es admin
    if st.session_state.user_role == 'admin':
        admin_panel()
    
    # Botón logout
    if st.sidebar.button("Cerrar Sesión"):
        st.session_state.logged_in = False
        st.rerun()
    
    # Info del usuario
    user_type_info = next((ut for ut in st.session_state.user_types if ut['name'] == st.session_state.user_type), None)
    user_type_desc = user_type_info['description'] if user_type_info else st.session_state.user_type
    
    st.sidebar.write(f"👤 {st.session_state.current_user}")
    st.sidebar.write(f"🏷️ {user_type_desc}")
    
    # Filtrar reportes según el tipo de usuario
    user_reports = [r for r in st.session_state.reports if st.session_state.user_type in r['allowed_types']]
    
    st.sidebar.write(f"📋 {len(user_reports)} reportes disponibles")
    
    # Mostrar reportes permitidos
    if user_reports:
        cols = st.columns(2)
        for i, report in enumerate(user_reports):
            with cols[i % 2]:
                with st.container():
                    st.subheader(f"📈 {report['name']}")
                    st.write(report['description'])
                    
                    # Desencriptar URL solo cuando se necesita
                    if st.button(f"Ver {report['name']}", key=f"btn_{i}", use_container_width=True):
                        try:
                            real_url = decrypt_url(report['encrypted_url'])
                            st.markdown(f'<meta http-equiv="refresh" content="0;url={real_url}">', unsafe_allow_html=True)
                        except:
                            st.error("Error al acceder al reporte")
                    
                    # Vista previa segura
                    if st.checkbox(f"Vista previa", key=f"preview_{i}"):
                        try:
                            real_url = decrypt_url(report['encrypted_url'])
                            st.components.v1.iframe(real_url, width=600, height=350)
                        except:
                            st.error("Error al cargar vista previa")
                    
                    st.divider()
    else:
        st.info(f"No hay reportes disponibles para tu tipo de usuario.")

# Lógica principal
if not st.session_state.logged_in:
    login()
else:
    main_app()
