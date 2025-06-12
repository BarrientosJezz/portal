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

class ReportDecryptor:
    def __init__(self, encryption_key):
        """Inicializa el desencriptador con la clave de encriptación."""
        self.fernet = Fernet(encryption_key.encode())
    
    def decrypt_url(self, encrypted_url):
        """Desencripta una URL encriptada."""
        try:
            # Decodificar base64
            encrypted_data = base64.b64decode(encrypted_url.encode())
            # Desencriptar
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode()
        except Exception as e:
            st.error(f"Error al desencriptar URL: {str(e)}")
            return None

def load_reports_data():
    """Carga los datos de los reportes. En producción, esto vendría de una base de datos."""
    return [
        {
            "id": 1,
            "titulo": "Reporte de Ventas Mensual",
            "descripcion": "Análisis detallado de ventas del mes actual",
            "categoria": "Ventas",
            "fecha_creacion": "2024-01-15",
            "encrypted_url": "Z0FBQUFBQm9TenZQZmQ2TEE4dkxBQ09yMlV1c2t3X0NvWGZHLW9yOGF2d25weFlfWmNlVHgzRUxLaUpJLUl0MHkzMGdfOE1LcnZMQkdXMGk4bDl5TnNmX2VwZ2l1bkJaRWlKYUJxbDhsMTI5RkZrUERqQVJtb1lEaVFsaUg3UHZPbGEybDJJeGZQTnkwS3ZPSzFsNm12T1MtQXRJbWtUV18zT0VwVWU1UWh0bzc5RG9GYjZNai13dmJtZjNsdzdVWEVyS2tqcDVPNUlNc01GMUliYnNPajhyN1hKNmw1T0ZGRzNOLUU4RnJLUWQ2VUZhOVF1ZFpEcXRHM3VUbmxvSTU3di1KcGJ4VjlZVEV6X2VjWnRSWHZWVnFKcS1LX19PLXc9PQ==",
            "acceso": "admin"
        },
        {
            "id": 2,
            "titulo": "Dashboard Financiero",
            "descripcion": "Métricas financieras y KPIs principales",
            "categoria": "Finanzas",
            "fecha_creacion": "2024-01-10",
            "encrypted_url": "otro_link_encriptado_ejemplo",
            "acceso": "usuario"
        },
        {
            "id": 3,
            "titulo": "Análisis de Inventario",
            "descripcion": "Estado actual del inventario y proyecciones",
            "categoria": "Operaciones",
            "fecha_creacion": "2024-01-08",
            "encrypted_url": "otro_link_encriptado_ejemplo2",
            "acceso": "usuario"
        }
    ]

def main():
    # Título principal
    st.title("📊 Portal de Reportes Empresariales")
    st.markdown("---")
    
    # Verificar si existe la clave de desencriptación en secrets
    try:
        encryption_key = st.secrets["encryption"]["key"]
        decryptor = ReportDecryptor(encryption_key)
    except KeyError:
        st.error("❌ Error: Clave de desencriptación no encontrada en secrets.toml")
        st.info("Por favor, configura la clave de desencriptación en el archivo secrets.toml")
        st.stop()
    
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
                    decrypted_url = decryptor.decrypt_url(report['encrypted_url'])
                    if decrypted_url:
                        st.success("URL desencriptada:")
                        st.code(decrypted_url)
                    else:
                        st.error("No se pudo desencriptar la URL")
            
            with col3:
                # Botón para acceder al reporte
                if st.button(f"🚀 Acceder", key=f"access_{report['id']}"):
                    decrypted_url = decryptor.decrypt_url(report['encrypted_url'])
                    if decrypted_url:
                        st.markdown(f"[🔗 Abrir Reporte]({decrypted_url})")
                    else:
                        st.error("Error al acceder al reporte")
        
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
                    # Aquí podrías agregar lógica para guardar en base de datos
                    st.success("Reporte agregado exitosamente!")
        
        with st.expander("🔑 Herramientas de Encriptación"):
            st.subheader("Encriptar Nueva URL")
            url_a_encriptar = st.text_input("URL a encriptar:")
            
            if st.button("🔒 Encriptar"):
                if url_a_encriptar:
                    try:
                        # Encriptar la URL
                        encrypted_data = decryptor.fernet.encrypt(url_a_encriptar.encode())
                        encrypted_url = base64.b64encode(encrypted_data).decode()
                        
                        st.success("URL encriptada exitosamente:")
                        st.code(encrypted_url)
                        
                        # Verificar desencriptación
                        verified_url = decryptor.decrypt_url(encrypted_url)
                        if verified_url == url_a_encriptar:
                            st.success("✅ Verificación exitosa: La URL se puede desencriptar correctamente")
                        else:
                            st.error("❌ Error en la verificación")
                    except Exception as e:
                        st.error(f"Error al encriptar: {str(e)}")
    
    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: gray;'>
            <p>Portal de Reportes v1.0 | Desarrollado con Streamlit</p>
        </div>
        """, 
        unsafe_allow_html=True
    )

if __name__ == "__main__":
    main()
