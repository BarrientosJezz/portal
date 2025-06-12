import streamlit as st
import base64
from cryptography.fernet import Fernet
import pandas as pd
from datetime import datetime
import json

# Configuración de la página
st.set_page_config(
    page_title="Portal de Reportes",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

def validate_and_create_fernet(key):
    """Valida y crea un objeto Fernet con la clave proporcionada."""
    try:
        # Si la clave es None o vacía
        if not key:
            return None, "La clave está vacía"
        
        # Si la clave es muy corta, probablemente no es válida
        if len(key) < 20:
            return None, "La clave es demasiado corta"
        
        # Intentar crear el objeto Fernet
        if isinstance(key, str):
            fernet = Fernet(key.encode())
        else:
            fernet = Fernet(key)
        
        return fernet, None
    
    except ValueError as e:
        return None, str(e)
    except Exception as e:
        return None, f"Error inesperado: {str(e)}"

class ReportDecryptor:
    def __init__(self):
        """Inicializa el desencriptador sin clave."""
        self.fernet = None
    
    def set_key(self, encryption_key):
        """Establece la clave de encriptación."""
        fernet, error = validate_and_create_fernet(encryption_key)
        if error:
            raise ValueError(error)
        self.fernet = fernet
    
    def decrypt_url(self, encrypted_url):
        """Desencripta una URL encriptada."""
        if not self.fernet:
            return None, "No se ha establecido una clave válida"
        
        try:
            # Decodificar base64
            encrypted_data = base64.b64decode(encrypted_url.encode())
            # Desencriptar
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode(), None
        except Exception as e:
            return None, f"Error al desencriptar: {str(e)}"

def generate_sample_key():
    """Genera una clave de ejemplo válida."""
    return Fernet.generate_key().decode()

def load_reports_data():
    """Carga los datos de los reportes. En producción, esto vendría de una base de datos."""
    return [
        {
            "id": 1,
            "titulo": "Reporte de Ventas Mensual",
            "descripcion": "Análisis detallado de ventas del mes actual",
            "categoria": "Ventas",
            "fecha_creacion": "2024-01-15",
            "encrypted_url": "ejemplo_url_encriptada_1",
            "acceso": "admin"
        },
        {
            "id": 2,
            "titulo": "Dashboard Financiero",
            "descripcion": "Métricas financieras y KPIs principales",
            "categoria": "Finanzas",
            "fecha_creacion": "2024-01-10",
            "encrypted_url": "ejemplo_url_encriptada_2",
            "acceso": "usuario"
        },
        {
            "id": 3,
            "titulo": "Análisis de Inventario",
            "descripcion": "Estado actual del inventario y proyecciones",
            "categoria": "Operaciones",
            "fecha_creacion": "2024-01-08",
            "encrypted_url": "ejemplo_url_encriptada_3",
            "acceso": "usuario"
        }
    ]

def show_key_setup_interface():
    """Muestra la interfaz para configurar la clave."""
    st.error("🔑 Configuración de Clave Requerida")
    
    st.markdown("""
    ### 📋 Instrucciones de Configuración
    
    Tu aplicación necesita una clave de encriptación válida. Sigue estos pasos:
    """)
    
    tab1, tab2, tab3 = st.tabs(["🔧 Generar Clave", "📝 Configurar Secrets", "❓ Ayuda"])
    
    with tab1:
        st.subheader("Generar Nueva Clave")
        
        if st.button("🔑 Generar Clave Válida", type="primary"):
            try:
                new_key = generate_sample_key()
                st.success("✅ Clave generada exitosamente:")
                st.code(new_key, language="text")
                
                # Verificar que la clave funciona
                test_fernet, test_error = validate_and_create_fernet(new_key)
                if test_error:
                    st.error(f"❌ Error validando clave: {test_error}")
                else:
                    st.success("✅ Clave validada correctamente")
                    
                    # Mostrar ejemplo de encriptación
                    st.info("🧪 Prueba de encriptación:")
                    test_url = "https://ejemplo.com/reporte"
                    encrypted_data = test_fernet.encrypt(test_url.encode())
                    encrypted_b64 = base64.b64encode(encrypted_data).decode()
                    st.code(f"URL original: {test_url}")
                    st.code(f"URL encriptada: {encrypted_b64}")
                    
            except Exception as e:
                st.error(f"❌ Error generando clave: {str(e)}")
    
    with tab2:
        st.subheader("Configurar en Streamlit")
        
        st.markdown("""
        **Para aplicaciones locales:**
        
        1. Crea el archivo `.streamlit/secrets.toml` en tu proyecto
        2. Agrega el siguiente contenido:
        
        ```toml
        [encryption]
        key = "tu_clave_generada_aqui"
        ```
        
        **Para Streamlit Cloud:**
        
        1. Ve a la configuración de tu app (Manage app)
        2. Busca la sección "Secrets"
        3. Agrega:
        
        ```toml
        [encryption]
        key = "tu_clave_generada_aqui"
        ```
        """)
    
    with tab3:
        st.subheader("Preguntas Frecuentes")
        
        with st.expander("¿Qué es una clave Fernet?"):
            st.write("""
            Fernet es un sistema de encriptación simétrica que requiere una clave específica:
            - 32 bytes de longitud
            - Codificada en base64 URL-safe
            - Generada aleatoriamente para máxima seguridad
            """)
        
        with st.expander("¿Por qué veo este error?"):
            st.write("""
            El error indica que:
            1. No tienes configurado el archivo secrets.toml, O
            2. La clave en secrets.toml no tiene el formato correcto, O
            3. La clave está vacía o corrupta
            """)
        
        with st.expander("¿Es seguro generar la clave aquí?"):
            st.write("""
            Sí, la clave se genera localmente in tu navegador usando librerías criptográficas estándar.
            Sin embargo, para máxima seguridad en producción, genera la clave en tu entorno local.
            """)

def main():
    # Título principal
    st.title("📊 Portal de Reportes Empresariales")
    st.markdown("---")
    
    # Intentar obtener la clave de encriptación
    encryption_key = None
    key_error = None
    
    # Verificar secrets
    try:
        if hasattr(st, 'secrets') and 'encryption' in st.secrets and 'key' in st.secrets['encryption']:
            encryption_key = st.secrets["encryption"]["key"]
        else:
            key_error = "No se encontró la configuración de clave en secrets"
    except Exception as e:
        key_error = f"Error accediendo a secrets: {str(e)}"
    
    # Si no hay clave, mostrar interfaz de configuración
    if not encryption_key or key_error:
        show_key_setup_interface()
        if key_error:
            st.error(f"🔍 Detalle del error: {key_error}")
        return
    
    # Intentar crear el desencriptador
    decryptor = ReportDecryptor()
    try:
        decryptor.set_key(encryption_key)
        st.success("🔐 Clave de encriptación configurada correctamente")
    except ValueError as e:
        st.error(f"❌ Error con la clave de encriptación: {str(e)}")
        show_key_setup_interface()
        return
    except Exception as e:
        st.error(f"❌ Error inesperado: {str(e)}")
        show_key_setup_interface()
        return
    
    # Sidebar para filtros
    st.sidebar.header("🔍 Filtros")
    
    # Cargar datos de reportes
    reports_data = load_reports_data()
    
    # Filtros
    categorias = list(set([report["categoria"] for report in reports_data]))
    categoria_seleccionada = st.sidebar.selectbox(
        "Seleccionar Categoría:",
        ["Todas"] + categorias
    )
    
    # Filtro por fecha
    fecha_desde = st.sidebar.date_input("Desde:", datetime(2024, 1, 1))
    fecha_hasta = st.sidebar.date_input("Hasta:", datetime.now())
    
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
        st.metric("Categorías", len(categorias))
    
    st.markdown("---")
    
    # Mostrar reportes en cards
    st.header("📋 Reportes Disponibles")
    
    # Crear grid de reportes
    for i, report in enumerate(reportes_filtrados):
        with st.container():
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                st.subheader(f"📊 {report['titulo']}")
                st.write(f"**Descripción:** {report['descripcion']}")
                st.write(f"**Categoría:** {report['categoria']}")
                st.write(f"**Fecha:** {report['fecha_creacion']}")
                st.write(f"**Acceso:** {report['acceso']}")
            
            with col2:
                # Botón para desencriptar y mostrar URL
                if st.button(f"🔓 Ver URL", key=f"decrypt_{report['id']}"):
                    decrypted_url, error = decryptor.decrypt_url(report['encrypted_url'])
                    if error:
                        st.error(f"Error: {error}")
                    else:
                        st.success("URL desencriptada:")
                        st.code(decrypted_url)
            
            with col3:
                # Botón para acceder al reporte
                if st.button(f"🚀 Acceder", key=f"access_{report['id']}"):
                    decrypted_url, error = decryptor.decrypt_url(report['encrypted_url'])
                    if error:
                        st.error(f"Error al acceder: {error}")
                    else:
                        st.markdown(f"[🔗 Abrir Reporte]({decrypted_url})")
        
        st.markdown("---")
    
    # Sección de administración (opcional)
    if st.sidebar.checkbox("🔧 Modo Administrador"):
        st.header("🔧 Panel de Administración")
        
        with st.expander("➕ Agregar Nuevo Reporte"):
            with st.form("nuevo_reporte"):
                titulo = st.text_input("Título del Reporte")
                descripcion = st.text_area("Descripción")
                categoria = st.selectbox("Categoría", categorias + ["Nueva categoría"])
                url_encriptada = st.text_area("URL Encriptada")
                
                if st.form_submit_button("Agregar Reporte"):
                    st.success("Reporte agregado exitosamente!")
        
        with st.expander("🔑 Herramientas de Encriptación"):
            st.subheader("Encriptar Nueva URL")
            url_a_encriptar = st.text_input("URL a encriptar:")
            
            if st.button("🔒 Encriptar") and url_a_encriptar:
                try:
                    # Encriptar la URL
                    encrypted_data = decryptor.fernet.encrypt(url_a_encriptar.encode())
                    encrypted_url = base64.b64encode(encrypted_data).decode()
                    
                    st.success("URL encriptada exitosamente:")
                    st.code(encrypted_url)
                    
                    # Verificar desencriptación
                    verified_url, verify_error = decryptor.decrypt_url(encrypted_url)
                    if verify_error:
                        st.error(f"❌ Error en la verificación: {verify_error}")
                    elif verified_url == url_a_encriptar:
                        st.success("✅ Verificación exitosa: La URL se puede desencriptar correctamente")
                    else:
                        st.error("❌ Error: Las URLs no coinciden en la verificación")
                except Exception as e:
                    st.error(f"Error al encriptar: {str(e)}")
    
    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: gray;'>
            <p>Portal de Reportes v2.0 | Desarrollado con Streamlit</p>
        </div>
        """, 
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
