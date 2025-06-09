import streamlit as st
import json
import os

st.set_page_config(page_title="Portal de Reportes", layout="wide")

# Archivos de configuración
USERS_FILE = "users.json"
REPORTS_FILE = "reports.json"
ROLES_FILE = "roles.json"

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
        reports = [{
            'name': 'Reporte Enero 2025',
            'url': 'https://app.powerbi.com/view?r=eyJrIjoiMWExMDFjMGQtNzMzYy00NmU0LTg3YWQtZTJiNzM4OTkyNzNhIiwidCI6ImJkZmZlZWM3LTVkOGMtNDQwMS1iYjZiLTIzNDRlZTI1NjE5NSJ9',
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
        
        # Mostrar tipos existentes
        if st.session_state.user_types:
            st.write("**Tipos existentes:**")
            for ut in st.session_state.user_types:
                st.write(f"• {ut['name']}: {ut['description']}")
    
    # Crear usuario
    with st.sidebar.expander("👤 Gestión de Usuarios"):
        st.write("**Crear Usuario**")
        new_user = st.text_input("Nuevo usuario")
        new_pass = st.text_input("Nueva contraseña", type="password")
        
        # Seleccionar tipo de usuario
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
                st.success(f"Usuario {new_user} creado como {selected_type}")
                st.rerun()
        
        # Resetear contraseña
        user_list = [u for u in st.session_state.users.keys() if u != 'admin']
        if user_list:
            st.write("**Resetear Contraseña**")
            selected_user = st.selectbox("Usuario a resetear", user_list)
            new_password = st.text_input("Nueva contraseña", type="password", key="reset_pass")
            if st.button("Resetear Contraseña"):
                if new_password:
                    st.session_state.users[selected_user]['password'] = new_password
                    save_users(st.session_state.users)
                    st.success(f"Contraseña de {selected_user} actualizada")
                    st.rerun()
            
            # Cambiar tipo de usuario
            st.write("**Cambiar Tipo de Usuario**")
            current_type = st.session_state.users[selected_user].get('user_type', 'user')
            st.write(f"Tipo actual: {current_type}")
            new_user_type = st.selectbox("Nuevo tipo", type_names, key="change_type")
            if st.button("Cambiar Tipo"):
                st.session_state.users[selected_user]['user_type'] = new_user_type
                save_users(st.session_state.users)
                st.success(f"Tipo de {selected_user} cambiado a {new_user_type}")
                st.rerun()
    
    # Gestión de reportes
    with st.sidebar.expander("📊 Gestión de Reportes"):
        st.write("**Agregar Reporte**")
        report_name = st.text_input("Nombre del reporte")
        report_url = st.text_area("URL del reporte Power BI")
        report_desc = st.text_input("Descripción")
        
        # Seleccionar tipos de usuario permitidos
        st.write("**Tipos de usuario con acceso:**")
        allowed_types = []
        for ut in st.session_state.user_types:
            if st.checkbox(f"{ut['name']} - {ut['description']}", key=f"access_{ut['name']}"):
                allowed_types.append(ut['name'])
        
        if st.button("Agregar Reporte"):
            if report_name and report_url and allowed_types:
                new_report = {
                    'name': report_name,
                    'url': report_url,
                    'description': report_desc or 'Sin descripción',
                    'allowed_types': allowed_types
                }
                st.session_state.reports.append(new_report)
                save_reports(st.session_state.reports)
                st.success(f"Reporte '{report_name}' agregado")
                st.rerun()
            else:
                st.error("Complete todos los campos y seleccione al menos un tipo de usuario")
        
        # Modificar permisos de reportes existentes
        if st.session_state.reports:
            st.write("**Modificar Permisos**")
            report_names = [r['name'] for r in st.session_state.reports]
            report_to_modify = st.selectbox("Seleccionar reporte", report_names, key="modify_report")
            
            # Mostrar permisos actuales
            current_report = next(r for r in st.session_state.reports if r['name'] == report_to_modify)
            st.write(f"Acceso actual: {', '.join(current_report['allowed_types'])}")
            
            # Nuevos permisos
            new_allowed_types = []
            for ut in st.session_state.user_types:
                default_checked = ut['name'] in current_report['allowed_types']
                if st.checkbox(f"{ut['name']}", value=default_checked, key=f"modify_{ut['name']}"):
                    new_allowed_types.append(ut['name'])
            
            if st.button("Actualizar Permisos"):
                if new_allowed_types:
                    for report in st.session_state.reports:
                        if report['name'] == report_to_modify:
                            report['allowed_types'] = new_allowed_types
                            break
                    save_reports(st.session_state.reports)
                    st.success(f"Permisos actualizados para '{report_to_modify}'")
                    st.rerun()
        
        # Eliminar reporte
        if st.session_state.reports:
            st.write("**Eliminar Reporte**")
            report_to_delete = st.selectbox("Eliminar reporte", report_names, key="delete_report")
            if st.button("🗑️ Eliminar Reporte"):
                st.session_state.reports = [r for r in st.session_state.reports if r['name'] != report_to_delete]
                save_reports(st.session_state.reports)
                st.success(f"Reporte '{report_to_delete}' eliminado")
                st.rerun()

# Función principal
def main_app():
    st.title("📊 Portal de Reportes")
    
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
                    st.caption(f"Acceso: {', '.join(report['allowed_types'])}")
                    
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        if st.button(f"Ver {report['name']}", key=f"btn_{i}", use_container_width=True):
                            st.markdown(f'<meta http-equiv="refresh" content="0;url={report['url']}">', unsafe_allow_html=True)
                    
                    # Vista previa
                    if st.checkbox(f"Vista previa", key=f"preview_{i}"):
                        st.components.v1.iframe(report['url'], width=600, height=350)
                    
                    st.divider()
    else:
        st.info(f"No hay reportes disponibles para el tipo de usuario '{st.session_state.user_type}'. Contacta al administrador.")

# Lógica principal
if not st.session_state.logged_in:
    login()
else:
    main_app()