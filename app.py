import streamlit as st
import hashlib
import base64
from datetime import datetime
import json

# Configuración de la página
st.set_page_config(
    page_title="Portal de Reportes",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

class LinkProtector:
    """Clase para proteger links usando diferentes métodos simples"""
    
    @staticmethod
    def method_1_base64_simple(url):
        """Método 1: Codificación Base64 simple"""
        encoded = base64.b64encode(url.encode()).decode()
        return encoded
    
    @staticmethod
    def method_1_decode(encoded_url):
        """Decodifica Base64 simple"""
        try:
            decoded = base64.b64decode(encoded_url.encode()).decode()
            return decoded
        except:
            return None
    
    @staticmethod
    def method_2_caesar_cipher(url, shift=13):
        """Método 2: Cifrado César simple"""
        result = ""
        for char in url:
            if char.isalpha():
                ascii_offset = 65 if char.isupper() else 97
                result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            else:
                result += char
        return base64.b64encode(result.encode()).decode()
    
    @staticmethod
    def method_2_decode(encoded_url, shift=13):
        """Decodifica Cifrado César"""
        try:
            decoded_b64 = base64.b64decode(encoded_url.encode()).decode()
            result = ""
            for char in decoded_b64:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    result += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    result += char
            return result
        except:
            return None
    
    @staticmethod
    def method_3_reverse_split(url):
        """Método 3: Invertir y dividir la URL"""
        reversed_url = url[::-1]  # Invertir
        # Dividir en partes y codificar cada parte
        parts = [reversed_url[i:i+10] for i in range(0, len(reversed_url), 10)]
        encoded_parts = [base64.b64encode(part.encode()).decode() for part in parts]
        return "|||".join(encoded_parts)
    
    @staticmethod
    def method_3_decode(encoded_url):
        """Decodifica método de inversión y división"""
        try:
            parts = encoded_url.split("|||")
            decoded_parts = [base64.b64decode(part.encode()).decode() for part in parts]
            reversed_url = "".join(decoded_parts)
            return reversed_url[::-1]  # Invertir de vuelta
        except:
            return None
    
    @staticmethod
    def method_4_hash_reference(url, reports_dict):
        """Método 4: Usar hash como referencia"""
        url_hash = hashlib.md5(url.encode()).hexdigest()[:16]
        reports_dict[url_hash] = url
        return url_hash

def load_reports_data():
    """Carga los datos de los reportes con diferentes métodos de protección"""
    
    # Diccionario para el método 4 (hash reference)
    hash_references = {}
    
    # URLs originales (estas NO estarían en el código en producción)
    original_urls = {
        1: "https://app.powerbi.com/view?r=eyJrIjoiYWJjMTIzIiwidCI6IjQ1NjcifQ%3D%3D",
        2: "https://datastudio.google.com/reporting/def456/page/ghi789",
        3: "https://tableau.example.com/views/inventory/dashboard"
    }
    
    protector = LinkProtector()
    
    return [
        {
            "id": 1,
            "titulo": "Reporte de Ventas Mensual",
            "descripcion": "Análisis detallado de ventas del mes actual",
            "categoria": "Ventas",
            "fecha_creacion": "2024-01-15",
            "protected_url": protector.method_1_base64_simple(original_urls[1]),
            "protection_method": "base64",
            "acceso": "admin"
        },
        {
            "id": 2,
            "titulo": "Dashboard Financiero",
            "descripcion": "Métricas financieras y KPIs principales",
            "categoria": "Finanzas",
            "fecha_creacion": "2024-01-10",
            "protected_url": protector.method_2_caesar_cipher(original_urls[2]),
            "protection_method": "caesar",
            "acceso": "usuario"
        },
        {
            "id": 3,
            "titulo": "Análisis de Inventario",
            "descripcion": "Estado actual del inventario y proyecciones",
            "categoria": "Operaciones",
            "fecha_creacion": "2024-01-08",
            "protected_url": protector.method_3_reverse_split(original_urls[3]),
            "protection_method": "reverse_split",
            "acceso": "usuario"
        }
    ], hash_references

def authenticate_user():
    """Sistema de autenticación simple"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    if not st.session_state.authenticated:
        st.title("🔐 Acceso al Portal de Reportes")
        
        # Obtener credenciales de secrets o usar por defecto
        try:
            valid_users = st.secrets["auth"]["users"]
            valid_passwords = st.secrets["auth"]["passwords"]
        except:
            # Credenciales por defecto para demo
            valid_users = ["admin", "usuario"]
            valid_passwords = ["admin123", "user123"]
            st.warning("⚠️ Usando credenciales por defecto. Configura secrets.toml para producción.")
        
        with st.form("login_form"):
            st.subheader("Ingresa tus credenciales")
            username = st.text_input("Usuario")
            password = st.text_input("Contraseña", type="password")
            
            if st.form_submit_button("Iniciar Sesión"):
                if username in valid_users and password in valid_passwords:
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.success("✅ Acceso autorizado")
                    st.rerun()
                else:
                    st.error("❌ Credenciales incorrectas")
        
        st.info("👥 Usuarios demo: admin/admin123, usuario/user123")
        return False
    
    return True

def decode_protected_url(protected_url, method):
    """Decodifica la URL protegida según el método usado"""
    protector = LinkProtector()
    
    if method == "base64":
        return protector.method_1_decode(protected_url)
    elif method == "caesar":
        return protector.method_2_decode(protected_url)
    elif method == "reverse_split":
        return protector.method_3_decode(protected_url)
    else:
        return None

def main():
    # Verificar autenticación
    if not authenticate_user():
        return
    
    # Título principal
    st.title("📊 Portal de Reportes Empresariales")
    st.markdown(f"**Bienvenido, {st.session_state.username}** | [Cerrar Sesión](javascript:void(0))")
    
    # Botón de logout
    if st.button("🚪 Cerrar Sesión", key="logout"):
        st.session_state.authenticated = False
        st.rerun()
    
    st.markdown("---")
    
    # Cargar datos de reportes
    reports_data, hash_references = load_reports_data()
    
    # Sidebar para filtros
    st.sidebar.header("🔍 Filtros")
    
    # Filtros
    categorias = list(set([report["categoria"] for report in reports_data]))
    categoria_seleccionada = st.sidebar.selectbox(
        "Seleccionar Categoría:",
        ["Todas"] + categorias
    )
    
    # Filtrar reportes
    reportes_filtrados = reports_data
    if categoria_seleccionada != "Todas":
        reportes_filtrados = [r for r in reportes_filtrados if r["categoria"] == categoria_seleccionada]
    
    # Mostrar estadísticas
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Reportes", len(reports_data))
    with col2:
        st.metric("Reportes Filtrados", len(reportes_filtrados))
    with col3:
        st.metric("Métodos de Protección", len(set([r["protection_method"] for r in reports_data])))
    
    st.markdown("---")
    
    # Mostrar reportes
    st.header("📋 Reportes Disponibles")
    
    for report in reportes_filtrados:
        with st.container():
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                st.subheader(f"📊 {report['titulo']}")
                st.write(f"**Descripción:** {report['descripcion']}")
                st.write(f"**Categoría:** {report['categoria']}")
                st.write(f"**Fecha:** {report['fecha_creacion']}")
                st.write(f"**Protección:** {report['protection_method']}")
                
                # Mostrar URL protegida (truncada)
                protected_preview = report['protected_url'][:50] + "..." if len(report['protected_url']) > 50 else report['protected_url']
                st.code(f"URL protegida: {protected_preview}")
            
            with col2:
                # Botón para decodificar
                if st.button(f"🔓 Decodificar", key=f"decode_{report['id']}"):
                    decoded_url = decode_protected_url(report['protected_url'], report['protection_method'])
                    if decoded_url:
                        st.success("✅ URL decodificada:")
                        st.code(decoded_url)
                    else:
                        st.error("❌ Error al decodificar")
            
            with col3:
                # Botón para acceder
                if st.button(f"🚀 Acceder", key=f"access_{report['id']}"):
                    decoded_url = decode_protected_url(report['protected_url'], report['protection_method'])
                    if decoded_url:
                        st.markdown(f"[🔗 Abrir Reporte]({decoded_url})")
                    else:
                        st.error("❌ No se pudo acceder")
        
        st.markdown("---")
    
    # Panel de herramientas (solo para admin)
    if st.session_state.username == "admin" and st.sidebar.checkbox("🔧 Herramientas Admin"):
        st.header("🔧 Panel de Administración")
        
        tab1, tab2, tab3 = st.tabs(["🔒 Proteger URLs", "🧪 Probar Métodos", "📊 Estadísticas"])
        
        with tab1:
            st.subheader("Proteger Nueva URL")
            
            url_input = st.text_input("URL a proteger:")
            method_choice = st.selectbox("Método de protección:", 
                                       ["base64", "caesar", "reverse_split"])
            
            if st.button("🔒 Proteger URL") and url_input:
                protector = LinkProtector()
                
                if method_choice == "base64":
                    protected = protector.method_1_base64_simple(url_input)
                elif method_choice == "caesar":
                    protected = protector.method_2_caesar_cipher(url_input)
                elif method_choice == "reverse_split":
                    protected = protector.method_3_reverse_split(url_input)
                
                st.success(f"✅ URL protegida con método {method_choice}:")
                st.code(protected)
                
                # Verificar que se puede decodificar
                decoded = decode_protected_url(protected, method_choice)
                if decoded == url_input:
                    st.success("✅ Verificación exitosa")
                else:
                    st.error("❌ Error en la verificación")
        
        with tab2:
            st.subheader("Comparar Métodos de Protección")
            
            test_url = st.text_input("URL de prueba:", "https://ejemplo.com/reporte")
            
            if st.button("🧪 Probar Todos los Métodos"):
                protector = LinkProtector()
                
                methods = {
                    "Base64 Simple": protector.method_1_base64_simple(test_url),
                    "Caesar Cipher": protector.method_2_caesar_cipher(test_url),
                    "Reverse Split": protector.method_3_reverse_split(test_url)
                }
                
                for method_name, protected_url in methods.items():
                    st.write(f"**{method_name}:**")
                    st.code(protected_url)
                    st.write(f"Longitud: {len(protected_url)} caracteres")
                    st.markdown("---")
        
        with tab3:
            st.subheader("Estadísticas de Protección")
            
            # Estadísticas por método
            method_counts = {}
            for report in reports_data:
                method = report['protection_method']
                method_counts[method] = method_counts.get(method, 0) + 1
            
            for method, count in method_counts.items():
                st.metric(f"Método {method}", count)

if __name__ == "__main__":
    main()
