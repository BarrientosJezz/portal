import streamlit as st
import json
import os
import base64

st.set_page_config(page_title="Portal de Reportes", layout="wide")

# Archivos de configuración
USERS_FILE = "users.json"
REPORTS_FILE = "reports.json"
ROLES_FILE = "roles.json"

# Funciones de encriptación simples
def encrypt_url(url):
    """Encripta una URL usando base64"""
    return base64.b64encode(url.encode()).decode()

def decrypt_url(encrypted_url):
    """Desencripta una URL"""
    try:
        return base64.b64decode(encrypted_url.encode()).decode()
    except:
        return encrypted_url  # Si no está encriptada, devolver original

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
        sample_url = "https://app.powerbi.com/view?r=eyJrIjoiMWExMDFjMGQtNzMzYy00NmU0LTg3YWQtZTJiNzM4OTkyNzNhIiwidCI6ImJkZmZlZWM3LTVkOGMtNDQwMS1iYjZiLTIzNDRlZTI1NjE5NSJ9"
        reports = [{
            'id': 'report_1',
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

if 'selected_report' not in st.session_state:
    st.session_state.selected_report = None

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

# Panel admin
def admin_panel():
    st.sidebar.title("🛠️ Panel Admin")
    
    # Gestión de tipos de usuario
    with st.sidebar.expander("🏷️ Tipos de Usuario"):
        st.write("**Crear Tipo de Usuario**")
        new_type_name = st.text_input("Nombre del tipo", key="new_type")
        new_type_desc = st.text_input("Descripción", key="new_type_desc")
        if st.button("Crear Tipo"):
            if new_type_name:
                new_type = {'name': new_type_name, 'description': new_type_desc or 'Sin descripción'}
                st.session_state.user_types.append(new_type)
                save_user_types(st.session_state.user_types)
                st.success(f"Tipo '{new_type_name}' creado")
                st.rerun()
    
    # Gestión de usuarios
    with st.sidebar.expander("👤 Gestión de Usuarios"):
        st.write("**Crear Usuario**")
        new_user = st.text_input("Nuevo usuario")
        new_pass = st.text_input("Nueva contraseña", type="password")
        
        type_names = [ut['name'] for ut in st.session_state.user_types]
        selected_type = st.selectbox("Tipo de usuario", type_names, key="user_type_select")
        
        if st.button("Crear Usuario"):
            if new_user and new_pass:
                st.session_state.users[new_user] = {
                    'password': new_pass, 
                    'role': 'user',
                    'user_type': selected_type
                }
                save_users(st.session_state.users)
                st.success(f"Usuario {new_user} creado")
                st.rerun()
    
    # Gestión de reportes
    with st.sidebar.expander("📊 Gestión de Reportes"):
        st.write("**Agregar Reporte**")
        report_name = st.text_input("Nombre del reporte")
        report_url = st.text_area("URL del reporte Power BI")
        report_desc = st.text_input("Descripción")
        
        st.write("**Tipos de usuario con acceso:**")
        allowed_types = []
        for ut in st.session_state.user_types:
            if st.checkbox(f"{ut['name']}", key=f"access_{ut['name']}"):
                allowed_types.append(ut['name'])
        
        if st.button("Agregar Reporte"):
            if report_name and report_url and allowed_types:
                # Generar ID único
                report_id = f"report_{len(st.session_state.reports) + 1}"
                new_report = {
                    'id': report_id,
                    'name': report_name,
                    'encrypted_url': encrypt_url(report_url),
                    'description': report_desc or 'Sin descripción',
                    'allowed_types': allowed_types
                }
                st.session_state.reports.append(new_report)
                save_reports(st.session_state.reports)
                st.success(f"Reporte '{report_name}' agregado")
                st.rerun()

# Función principal
def main_app():
    # Filtrar reportes según el tipo de usuario
    user_reports = [r for r in st.session_state.reports if st.session_state.user_type in r['allowed_types']]
    
    # Sidebar con información del usuario
    st.sidebar.title("📊 Portal de Reportes")
    
    # Panel admin si es admin
    if st.session_state.user_role == 'admin':
        admin_panel()
    
    # Info del usuario
    user_type_info = next((ut for ut in st.session_state.user_types if ut['name'] == st.session_state.user_type), None)
    user_type_desc = user_type_info['description'] if user_type_info else st.session_state.user_type
    
    st.sidebar.write("---")
    st.sidebar.write(f"👤 **{st.session_state.current_user}**")
    st.sidebar.write(f"🏷️ {user_type_desc}")
    st.sidebar.write(f"📋 {len(user_reports)} reportes disponibles")
    
    # Menú de navegación
    st.sidebar.write("---")
    st.sidebar.write("### 📊 Mis Reportes")
    
    # Botón para volver al dashboard
    if st.sidebar.button("🏠 Dashboard Principal", use_container_width=True):
        st.session_state.selected_report = None
        st.rerun()
    
    # Lista de reportes en el sidebar
    if user_reports:
        for report in user_reports:
            if st.sidebar.button(f"📈 {report['name']}", key=f"nav_{report['id']}", use_container_width=True):
                st.session_state.selected_report = report['id']
                st.rerun()
    
    # Botón logout
    st.sidebar.write("---")
    if st.sidebar.button("🚪 Cerrar Sesión", use_container_width=True):
        st.session_state.logged_in = False
        st.session_state.selected_report = None
        st.rerun()
    
    # Contenido principal
    if st.session_state.selected_report is None:
        # Dashboard principal
        st.title("📊 Dashboard Principal")
        st.write(f"Bienvenido **{st.session_state.current_user}** - {user_type_desc}")
        
        if user_reports:
            st.write("### Tus Reportes Disponibles")
            
            # Mostrar reportes en tarjetas
            cols = st.columns(min(3, len(user_reports)))
            for i, report in enumerate(user_reports):
                with cols[i % len(cols)]:
                    with st.container():
                        st.markdown(f"""
                        <div style="border: 1px solid #ddd; border-radius: 10px; padding: 20px; margin: 10px 0;">
                            <h4>📈 {report['name']}</h4>
                            <p>{report['description']}</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        if st.button(f"Abrir {report['name']}", key=f"open_{report['id']}", use_container_width=True):
                            st.session_state.selected_report = report['id']
                            st.rerun()
        else:
            st.info("No tienes reportes disponibles. Contacta al administrador.")
    
    else:
        # Mostrar reporte seleccionado
        selected_report = next((r for r in user_reports if r['id'] == st.session_state.selected_report), None)
        
        if selected_report:
            st.title(f"📈 {selected_report['name']}")
            st.write(selected_report['description'])
            
            # Mostrar el reporte en iframe
            try:
                real_url = decrypt_url(selected_report['encrypted_url'])
                st.components.v1.iframe(real_url, width=None, height=600, scrolling=True)
            except Exception as e:
                st.error("Error al cargar el reporte")
                st.write("Puedes intentar abrir el reporte en una nueva ventana:")
                if st.button("🔗 Abrir en Nueva Ventana"):
                    real_url = decrypt_url(selected_report['encrypted_url'])
                    st.markdown(f'<meta http-equiv="refresh" content="0;url={real_url}">', unsafe_allow_html=True)
        else:
            st.error("Reporte no encontrado")
            st.session_state.selected_report = None
            st.rerun()

# Lógica principal
if not st.session_state.logged_in:
    login()
else:
    main_app()
