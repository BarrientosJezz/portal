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
    "2024 08 AGO": "gAAAAABoT5jt5lq98ExRBmvSH9sMh9PkCLtbQso0lzM1drn8ohEr4tPLSho83Mv-M05aOmFSRj9QV2SmtUvILZSdzn9h0HqkPaxqBi_hpx8BPEbKS1MaHd3WEB8_VnHfSl-Vuv8wjEgqydQkfqNxLkCgE3x6mwdZ9DVkx-PNkbiPvChSvET0TcVHIWGTKOK-uj4Pg0i7VJkz3ndmHwBbWiCboL7LPbRr16rOb8c_23awS6Pn1SCSyRBxMX2Hjk6_3uyub9AKnipAhqIHLAx8W88TL_QAbgk0nQ==",
    "2024 09 SEP": "gAAAAABoT5jt1RCkknB3XF0vcuga0zu0YvmU3cL8xPv5ZBpd3ehVfCBHjroWyGFaCxyuTqdZssHGHu7tUXXRk__ZNMEeROhxmHQ7AqCWhRd6CenaGsiQnR1anwLIsiLyH_wgkM_XXBBg6YutYSOU1N5yALMsfP3U_Gs0e1aFGvcu12KjnmGe0aJj4Llka8YHEzLfSjhPH27OXvXUJO4lJYTOw5KbFAYj3NTerM-7E1f9Tgjn3trSxXige9rb9mueRVh44upnQX4PPe8mpnF1-dXCQsfWiR76gg==",
    "2024 10 OCT": "gAAAAABoT5jtKGbJSZkKxoWrMP3HTajVP6CRRfF9cHGobUv6_y9o3xdyWF2HwsX-FwxIblUsS-IV9jmW3Qlsx56fKa2LJkObVBtENCIz8FzY11omImN53GcGjWCfJea_kPPaOkAs71_UqwlLVx479bjMFe-w4t76QdwRmI1v4rkNNcq18PmpqeRzkcP074A34TnHgkuf0ngDvaI95D5Br27fNr0tgzlBgaJYHyV2j_cx7MV9890WN9-JjAhpuBvjMwNOXuq8gO-glBV5A4fFUMpVgcoLGTjhbg==",
    "2024 11 NOV": "gAAAAABoT5jto39kcP5KyXjHoyVcvTjxR8fswPuPTz5CCONHfW-rLrbwB0Rjdsnnu-JiDxKH3v2DTpCn8fk8nkWHdWUWtT_WqLkAP7MmbqTdRyCxHxx8wMxOnfS05xBvyQoqzRNiZhwTCcZEQHFU43iBAIhiTbAMoCaz5OGMxb_KHC1zg5y5MqPmn4qBPpDPNDdJzuVp6itIdDht_Lg-I8LCElic_k6Y5WEFrBtj1l-nhsr7gXTSBZs7sgcBlDURLQPJafiq3UwtJps8yPeNqfhfic21ojRtJg==",
    "2024 12 DIC": "gAAAAABoT5jt6q7HayGJxtxL4azL-bIAUi78d6fmnGZTO4DvaV5pnEw9st-Dd-k-0grU29Z5FRP15YzGwYZc7EqT50JJBSFkKmpjfnhPBIoAYlHT5WLEpDnVzIul4XvrhSD67JvVbi4F1VmYD8ldx8RjfWhSLFWRzTmt6npbJ2hvssfT1vEp1tvtICJmQidtgMcvzbZaiJ7Zfiagy8E9nnQloJdi_hPMzs-l54VA7GSgyMwg4vcrpKHP0S119_OjiT1pWWWBFIpcnpXLOWRJSGUlZOdmucgZsw==",
    "2025 01 ENE": "gAAAAABoT5jtxaqrHYh9bl4iIgjLhPwR5SzjRTinMYtEp8iDKT8hkbNh4ctcelyN2d-Cy3WrlH4aGR4pp6z04swyHK9QQX4BDAy7yKtzgwDinti-N2m5cjwjwFVzA8iX66Y7rQeWHaMNygMotXn1cfgfezxBplmX-1U8qvFM7VkkKDmFaMF-u_Mo67wG4r4VBxF_uL-psJeJJ1Uq-bUSk-9amhxncx56CIwnYg_iKK2otDSLki1UtjLvp2GS1I9Yhq_iWwoirbulXE5S-rmFS5Q1iwj7dGGzTw==",
    "2025 02 FEB": "gAAAAABoT5jtV5nhz8PO-Lj5rkNEJx1TU3zSvE99MzMBVhtVS4jAZAFxj8gMH8Ga4h82SFiIToWICbN_BVguJP_5Bf4rjjzKrSVTeAmRZQsxl3OQO3wqx9zbTdHPSVXNbnhN9G9smx2WH-xPBalO783S5FJW-myuqhDoQWdesDDphtk1Mf-WTMuFBLlkrecWBYt5z1pGnnpZ7u7OteHwI37k3CoczE-dPfyZpFwomblaUBqYLODBP7PohM5hshGumb2SFYqO8WI_KyEMndWr7FdaNy6OO4SvoA==",
    "2025 03 MAR": "gAAAAABoT5jt92-BE2i9pux0ixT0ootH0EiIZV350mFbv6JFxj6YMIlel7ZnwuohJDeZRTvPiGCDFUP4pOdW4l1Gpeg9d7MdcI9pmxJgxnKNPtuKSK_g10-Lnahu4O_1aTB8BXxEJPFoPNT-EKJO2EXrnTn3Zmua61GIa4tLXFfl64yvTTmgdikfJ88_MwT4LdlDxyWybB5xIEZJiIa4zDd5RTji6wtIVIiscB7aQH_JKYkxBWKMakfdmu7rKqF0CJsyFqQJ3B32SxWwesPjcHGY5L_s8a2lDw==",
    "2025 04 ABR": "gAAAAABoT5jtD733HM5CmAsKg3y2lKTXn4le2_df40tM-6kNC0B8Z_oSM-qnEp6ZGa2AGapF6XmkBXteFuGWH99J8qUfkWMYSy6w-F3rcVCz6Sz48oVkXW0OxMXx4I_E6mWzJgOW-XwS8GW8LXXGeQF10gUaR7-ZSEeldqt_Z91R9DE-H5ejYuDyJGrHZT_a9cF6s9f7lEEvNUODRQ2HW0H1vsASKDlYYYuwLDP7vtnIQ328VdLdQbI8gn7vNqWT4s5VQdmz-SPjNsLAbj2Lme4by5WScEhYZw==",
    "2025 05 MAY": "gAAAAABoT5jtXD6Mbd24WDJ0x44RgTusQcvqa6qeG45RcpYsnTzxbFQ7RtulfulTEUl7QAAcenufFdW-bsNbE-qzIpDcYfzEVyGE7l9ZggOvdh4Ovvt8crRJXgjl6kkxPTFFtdBoHgLYyV4je-0C7bkW-NXlqA2OJ98ZLmxgXttL1B9j9-jBCqxOSpADyy9qK0IkhUZL1Bigrqi71ucKZUq9GwJ1Yhhktdx85z0gYqQJDGiUY5yd9mJNAMSg7NL13DwEn8Yct1MfbXtj4cz2nicyGHqyM8DpBg==",
    "2025 06 JUN": "gAAAAABocR_yMIggTC-1VKq3BIV3iYvJA02s85uhc38y6vxQRcCD18K9RJK51hU-h4QqjNpFg_Zya8I5HlUssgCMyDzm4NvDjp-MoreCdztZI7lzT1Aj-x00l3kng4MsCuyes0Seu8bGpdP-GFBfn8OvMI0YRmKbtGX6RArhSU7w6i-TZJ_qrUFGgT6o0ip6cPVgy1vTg6zgURZTNXcr9Win9phD8-gIz265YhN8iDzrqZQ9RA8who6lLKZaoHAtPl-og3-aeF59fVVq7N-3qKX2DRTdXAaTFg==",
    "Mes_actual": "gAAAAABoUcBPynLVYd98Rz1V18d2hLkiYoINkmEpGcG2jsA45yp8x9GHwNWG6pMf-v43AN4zhbXDxTXmJOVjdjmT1YBtdHOHLuB3T6MDVL0vDu9-rfU4qRpMKclhmYxeUnUbGykm9qYQo9C4ielJOqWVuroNG4xmgbdfrhmFibx4m8DtWe0j30IgyDE7DEPy3KUFJLV-EaeDa9JiSoDCUynSC4kbFaQ-HGfnjcTzf1NEL3P8Uaory6CWoTyruGrSSLv43ZJSm557ozAJ0DmF47XVXr7fSMwLlg==",
    "analisis_financiero": "gAAAAABh_ejemplo_url_encriptada_2_aqui", 
    "kpis_operativos": "gAAAAABh_ejemplo_url_encriptada_3_aqui",
    "reporte_ejecutivo": "gAAAAABh_ejemplo_url_encriptada_4_aqui",
    "metricas_marketing": "gAAAAABh_ejemplo_url_encriptada_5_aqui",
    "analisis_trade": "gAAAAABh_ejemplo_url_encriptada_6_aqui",
    "dashboard_contact_center": "gAAAAABh_ejemplo_url_encriptada_7_aqui"
}

# Títulos amigables para los reportes
TITULOS_REPORTES = {
    "2024 08 AGO": "📈 Ago-2024",
    "2024 09 SEP": "📈 Sep-2024",
    "2024 10 OCT": "📈 Oct-2024",
    "2024 11 NOV": "📈 Nov-2024",
    "2024 12 DIC": "📈 Dic-2024",
    "2025 01 ENE": "📈 Ene-2025",
    "2025 02 FEB": "📈 Feb-2025",
    "2025 03 MAR": "📈 Mar-2025",
    "2025 04 ABR": "📈 Abr-2025",
    "2025 05 MAY": "📈 May-2025",
    "2025 06 JUN": "📈 Jun-2025",
    "Mes_actual": "📈 Mes actual",
    "analisis_financiero": "💰 Análisis Financiero", 
    "kpis_operativos": "🎯 KPIs Operativos",
    "reporte_ejecutivo": "👔 Reporte Ejecutivo",
    "metricas_marketing": "📢 Métricas de Marketing",
    "analisis_trade": "🏪 Análisis Trade",
    "dashboard_contact_center": "📞 Dashboard Contact Center"
}

# Descripciones de los reportes
DESCRIPCIONES_REPORTES = {
    "2024 08 AGO": "Métricas de ventas al cierre del mes",
    "2024 09 SEP": "Métricas de ventas al cierre del mes",
    "2024 10 OCT": "Métricas de ventas al cierre del mes",
    "2024 11 NOV": "Métricas de ventas al cierre del mes",
    "2024 12 DIC": "Métricas de ventas al cierre del mes",
    "2025 01 ENE": "Métricas de ventas al cierre del mes",
    "2025 02 FEB": "Métricas de ventas al cierre del mes",
    "2025 03 MAR": "Métricas de ventas al cierre del mes",
    "2025 04 ABR": "Métricas de ventas al cierre del mes",
    "2025 05 MAY": "Métricas de ventas al cierre del mes",
    "2025 06 JUN": "Métricas de ventas al cierre del mes",
    "Mes_actual": "Métricas de ventas a la fecha del informe",
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
        "descripcion": "Área Comercial & Ventas",
        "reportes_permitidos": ["2024 08 AGO","2024 09 SEP","2024 10 OCT","2024 11 NOV","2024 12 DIC","2025 01 ENE","2025 02 FEB","2025 03 MAR","2025 04 ABR","2025 05 MAY",
                                "Mes_actual"],
        "password_key": "PASSWORD_COMERCIAL",
        "requiere_region": True,  # ← NUEVO: No requiere selección de región
        "regiones": {
            "Bolivia": {
                "icono": "<svg width=\"24\" height=\"24\" viewBox=\"0 0 64 64\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"8\" y=\"16\" width=\"48\" height=\"10.67\" fill=\"#DC143C\"/><rect x=\"8\" y=\"26.67\" width=\"48\" height=\"10.67\" fill=\"#FFD700\"/><rect x=\"8\" y=\"37.33\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"16\" width=\"48\" height=\"32\" fill=\"none\" stroke=\"#333\" stroke-width=\"1\"/><rect x=\"6\" y=\"12\" width=\"2\" height=\"40\" fill=\"#8B4513\"/></svg>","password_key": "PASSWORD_MARKETING_BOLIVIA",
                "password_key": "PASSWORD_COMERCIAL_BOLIVIA",
                "reportes_permitidos": ["2024 08 AGO","2024 09 SEP","2024 10 OCT","2024 11 NOV","2024 12 DIC","2025 01 ENE","2025 02 FEB","2025 03 MAR","2025 04 ABR","2025 05 MAY",
                                        "Mes_actual"]
            },
            "Santa Cruz": {
                "icono": "<svg width=\"24\" height=\"24\" viewBox=\"0 0 64 64\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"8\" y=\"16\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"26.67\" width=\"48\" height=\"10.67\" fill=\"#FFFFFF\"/><rect x=\"8\" y=\"37.33\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"16\" width=\"48\" height=\"32\" fill=\"none\" stroke=\"#333\" stroke-width=\"1\"/><rect x=\"6\" y=\"12\" width=\"2\" height=\"40\" fill=\"#8B4513\"/></svg>",
                "password_key": "PASSWORD_COMERCIAL_SANTA_CRUZ",
                "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos"]
            }
        }
    },
    "Marketing": {
        "icono": "📢",
        "descripcion": "Área de Marketing & Publicidad",
        "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos", "reporte_ejecutivo"],
        "password_key": "PASSWORD_MARKETING",
        "requiere_region": True,  # ← NUEVO: Requiere selección de región
        "regiones": {
            "Bolivia": {
                "icono": "<svg width=\"24\" height=\"24\" viewBox=\"0 0 64 64\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"8\" y=\"16\" width=\"48\" height=\"10.67\" fill=\"#DC143C\"/><rect x=\"8\" y=\"26.67\" width=\"48\" height=\"10.67\" fill=\"#FFD700\"/><rect x=\"8\" y=\"37.33\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"16\" width=\"48\" height=\"32\" fill=\"none\" stroke=\"#333\" stroke-width=\"1\"/><rect x=\"6\" y=\"12\" width=\"2\" height=\"40\" fill=\"#8B4513\"/></svg>","password_key": "PASSWORD_MARKETING_BOLIVIA",
                "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos", "reporte_ejecutivo"]
            },
            "Santa Cruz": {
                "icono": "<svg width=\"24\" height=\"24\" viewBox=\"0 0 64 64\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"8\" y=\"16\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"26.67\" width=\"48\" height=\"10.67\" fill=\"#FFFFFF\"/><rect x=\"8\" y=\"37.33\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"16\" width=\"48\" height=\"32\" fill=\"none\" stroke=\"#333\" stroke-width=\"1\"/><rect x=\"6\" y=\"12\" width=\"2\" height=\"40\" fill=\"#8B4513\"/></svg>",
                "password_key": "PASSWORD_MARKETING_SANTA_CRUZ",
                "reportes_permitidos": ["metricas_marketing", "dashboard_ventas", "kpis_operativos"]
            }
        }
    },
    "Trade & Eventos": {
        "icono": "🏪",
        "descripcion": "Área de Trade & Eventos",
        "reportes_permitidos": ["analisis_trade", "dashboard_ventas", "kpis_operativos"],
        "password_key": "PASSWORD_TRADE",
        "requiere_region": True,  # ← NUEVO: Requiere selección de región
        "regiones": {
            "Bolivia": {
                "icono": "<svg width=\"24\" height=\"24\" viewBox=\"0 0 64 64\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"8\" y=\"16\" width=\"48\" height=\"10.67\" fill=\"#DC143C\"/><rect x=\"8\" y=\"26.67\" width=\"48\" height=\"10.67\" fill=\"#FFD700\"/><rect x=\"8\" y=\"37.33\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"16\" width=\"48\" height=\"32\" fill=\"none\" stroke=\"#333\" stroke-width=\"1\"/><rect x=\"6\" y=\"12\" width=\"2\" height=\"40\" fill=\"#8B4513\"/></svg>","password_key": "PASSWORD_TRADE_BOLIVIA",
                "reportes_permitidos": ["analisis_trade", "dashboard_ventas", "kpis_operativos"]
            },
            "Santa Cruz": {
                "icono": "<svg width=\"24\" height=\"24\" viewBox=\"0 0 64 64\" xmlns=\"http://www.w3.org/2000/svg\"><rect x=\"8\" y=\"16\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"26.67\" width=\"48\" height=\"10.67\" fill=\"#FFFFFF\"/><rect x=\"8\" y=\"37.33\" width=\"48\" height=\"10.67\" fill=\"#228B22\"/><rect x=\"8\" y=\"16\" width=\"48\" height=\"32\" fill=\"none\" stroke=\"#333\" stroke-width=\"1\"/><rect x=\"6\" y=\"12\" width=\"2\" height=\"40\" fill=\"#8B4513\"/></svg>",
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

def mostrar_pantalla_seleccion_area():
    """Muestra la pantalla inicial de selección de área"""
    # Header principal
    st.markdown("""
    <div style='text-align: center; padding: 2rem; background: linear-gradient(135deg, #1f4e79 0%, #2e75b6 100%); 
                color: white; border-radius: 15px; margin-bottom: 2rem;'>
        <h1>📊 Portal Power BI Corporativo</h1>
        <p style='font-size: 1.2em; margin: 0;'>Acceso Seguro por Área de Trabajo</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 🏢 Selecciona tu Área de Trabajo")
    st.markdown("Elige el área para acceder a los reportes correspondientes:")
    st.markdown("---")
    
    # Crear columnas para las áreas
    areas = list(AREAS_USUARIOS.keys())
    
    # Dividir en columnas según el número de áreas
    if len(areas) <= 2:
        cols = st.columns(len(areas))
    else:
        cols = st.columns(2)  # Máximo 2 columnas
    
    # Mostrar cada área como una tarjeta
    for i, area in enumerate(areas):
        config_area = AREAS_USUARIOS[area]
        
        # Determinar la columna
        col_index = i % len(cols)
        
        with cols[col_index]:
            # Tarjeta del área
            st.markdown(f"""
            <div class='area-card' style='background: #f8f9fa; padding: 1.5rem; border-radius: 10px; 
                       border-left: 4px solid #2e75b6; margin-bottom: 1rem;
                       box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: all 0.3s ease;'>
                <h3 style='color: #1976D2; margin-top: 0;'>{config_area['icono']} {area}</h3>
                <p style='color: #555; margin: 0.5rem 0;'>{config_area['descripcion']}</p>
                <p style='color: #777; font-size: 0.9em; margin: 0.5rem 0 0 0;'>
                    📊 {len(config_area['reportes_permitidos'])} reportes disponibles
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            # Botón para seleccionar área
            if st.button(
                f"Acceder a {area}", 
                key=f"btn_area_{area}", 
                use_container_width=True,
                help=f"Ingresar al área {area}"
            ):
                st.session_state.area_seleccionada = area
                st.rerun()
    
    # Información adicional
    st.markdown("---")
    st.info("🔒 **Acceso Seguro**: Cada área tiene contraseñas específicas y reportes autorizados")
    
    # Estadísticas
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("🏢 Áreas", len(AREAS_USUARIOS))
    with col2:
        total_reportes = len(URLS_ENCRIPTADAS)
        st.metric("📊 Reportes", total_reportes)
    with col3:
        st.metric("🔒 Encriptación", "AES-256")

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
                    mostrar_spinner_personalizado()
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
        mostrar_pantalla_seleccion_area()
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
    
    # Obtener región si aplica
    region_actual = None
    if config_area.get("requiere_region", False):
        region_actual = st.session_state.get(f"region_seleccionada_{area_actual}")
    
    # Título con región si aplica
    titulo = f"{config_area['icono']} Portal {area_actual}"
    if region_actual:
        titulo += f" - {region_actual}"
    
    st.title(titulo)
    st.markdown(f"**{config_area['descripcion']}** - Accede a tus reportes autorizados")
    st.markdown("---")
    
    # Obtener reportes permitidos para el área y región
    reportes_area = obtener_reportes_por_area(area_actual, region_actual)
    
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
        # Limpiar datos de región si existen
        for key in list(st.session_state.keys()):
            if key.startswith("region_seleccionada_") or key.startswith("authenticated_"):
                del st.session_state[key]
        st.rerun()
    
    # Botón para cerrar sesión del área actual
    if st.sidebar.button("🚪 Cerrar Sesión", use_container_width=True):
        # Limpiar autenticación del área actual
        for key in list(st.session_state.keys()):
            if key.startswith(f"authenticated_{area_actual}"):
                del st.session_state[key]
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

# ========== OPCIÓN 1: NIEVE (st.snow()) ==========
# Reemplaza st.balloons() con:
#st.snow()

# ========== OPCIÓN 2: ANIMACIONES CSS PERSONALIZADAS ==========
def mostrar_animacion_success():
    """Animación personalizada de éxito con CSS"""
    st.markdown("""
    <style>
    @keyframes slideInDown {
        from { opacity: 0; transform: translate3d(0, -100%, 0); }
        to { opacity: 1; transform: translate3d(0, 0, 0); }
    }
    @keyframes pulse {
        from { transform: scale3d(1, 1, 1); }
        50% { transform: scale3d(1.05, 1.05, 1.05); }
        to { transform: scale3d(1, 1, 1); }
    }
    .success-animation {
        animation: slideInDown 0.8s ease-out, pulse 1.5s ease-in-out infinite;
        background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        color: white;
        padding: 1rem;
        border-radius: 10px;
        text-align: center;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(76, 175, 80, 0.3);
    }
    </style>
    <div class="success-animation">
        ✅ <strong>¡Acceso Concedido!</strong> 🎉
    </div>
    """, unsafe_allow_html=True)

# ========== OPCIÓN 3: CONFETTI CSS ==========
def mostrar_confetti():
    """Animación de confetti CSS"""
    st.markdown("""
    <style>
    @keyframes confetti-fall {
        0% { transform: translateY(-100vh) rotate(0deg); opacity: 1; }
        100% { transform: translateY(100vh) rotate(720deg); opacity: 0; }
    }
    .confetti {
        position: fixed;
        top: -10px;
        left: 50%;
        width: 10px;
        height: 10px;
        background: #f39c12;
        animation: confetti-fall 3s linear infinite;
        z-index: 1000;
    }
    .confetti:nth-child(1) { left: 10%; background: #e74c3c; animation-delay: 0s; }
    .confetti:nth-child(2) { left: 20%; background: #3498db; animation-delay: 0.2s; }
    .confetti:nth-child(3) { left: 30%; background: #2ecc71; animation-delay: 0.4s; }
    .confetti:nth-child(4) { left: 40%; background: #f39c12; animation-delay: 0.6s; }
    .confetti:nth-child(5) { left: 60%; background: #9b59b6; animation-delay: 0.8s; }
    .confetti:nth-child(6) { left: 70%; background: #e67e22; animation-delay: 1s; }
    .confetti:nth-child(7) { left: 80%; background: #1abc9c; animation-delay: 1.2s; }
    .confetti:nth-child(8) { left: 90%; background: #34495e; animation-delay: 1.4s; }
    </style>
    <div class="confetti"></div>
    <div class="confetti"></div>
    <div class="confetti"></div>
    <div class="confetti"></div>
    <div class="confetti"></div>
    <div class="confetti"></div>
    <div class="confetti"></div>
    <div class="confetti"></div>
    """, unsafe_allow_html=True)

# ========== OPCIÓN 4: MENSAJE CON FADEOUT ==========
def mostrar_mensaje_fadeout(mensaje, tipo="success"):
    """Mensaje que desaparece gradualmente"""
    color_bg = {
        "success": "#d4edda",
        "info": "#d1ecf1", 
        "warning": "#fff3cd",
        "error": "#f8d7da"
    }
    
    color_text = {
        "success": "#155724",
        "info": "#0c5460",
        "warning": "#856404", 
        "error": "#721c24"
    }
    
    st.markdown(f"""
    <style>
    @keyframes fadeOut {{
        0% {{ opacity: 1; transform: translateY(0); }}
        70% {{ opacity: 1; transform: translateY(0); }}
        100% {{ opacity: 0; transform: translateY(-20px); }}
    }}
    .fade-message {{
        background-color: {color_bg.get(tipo, color_bg["success"])};
        color: {color_text.get(tipo, color_text["success"])};
        padding: 1rem;
        border-radius: 8px;
        text-align: center;
        font-weight: bold;
        animation: fadeOut 3s ease-in-out forwards;
        border: 1px solid {color_text.get(tipo, color_text["success"])}40;
    }}
    </style>
    <div class="fade-message">{mensaje}</div>
    """, unsafe_allow_html=True)

# ========== OPCIÓN 5: LOADING SPINNER PERSONALIZADO ==========
def mostrar_spinner_personalizado():
    """Spinner personalizado mientras se carga"""
    st.markdown("""
    <style>
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    .custom-spinner {
        border: 7px solid #f3f3f3;
        border-top: 7px solid #3498db;
        border-radius: 50%;
        width: 70px;
        height: 70px;
        animation: spin 1s linear infinite;
        margin: 40px auto;
    }
    .spinner-container {
        text-align: center;
        padding: 2rem;
    }
    </style>
    <div class="spinner-container">
        <div class="custom-spinner"></div>
        <p>🔓 Autenticando acceso...</p>
    </div>
    """, unsafe_allow_html=True)

# ========== OPCIÓN 6: PROGRESS BAR ANIMADO ==========
def mostrar_progress_bar_animado():
    """Barra de progreso animada"""
    progress_bar = st.progress(0)
    for i in range(100):
        time.sleep(0.02)  # Ajusta la velocidad
        progress_bar.progress(i + 1)
    progress_bar.empty()

# ========== OPCIÓN 7: TOAST NOTIFICATION ==========
def mostrar_toast_notification(mensaje):
    """Notificación estilo toast"""
    st.markdown(f"""
    <style>
    @keyframes slideInRight {{
        from {{ transform: translateX(100%); opacity: 0; }}
        to {{ transform: translateX(0); opacity: 1; }}
    }}
    @keyframes slideOutRight {{
        from {{ transform: translateX(0); opacity: 1; }}
        to {{ transform: translateX(100%); opacity: 0; }}
    }}
    .toast-notification {{
        position: fixed;
        top: 20px;
        right: 20px;
        background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        animation: slideInRight 0.5s ease-out, slideOutRight 0.5s ease-in 2.5s forwards;
        z-index: 1000;
        font-weight: bold;
    }}
    </style>
    <div class="toast-notification">
        {mensaje}
    </div>
    """, unsafe_allow_html=True)

# ========== IMPLEMENTACIÓN EN TU CÓDIGO ==========
def verificar_password_area_con_animacion(area, password_ingresado, region=None):
    """Versión modificada con diferentes animaciones"""
    try:
        config_area = AREAS_USUARIOS[area]
        
        # ... (resto del código de verificación) ...
        
        if password_ingresado == password_correcto:
            # OPCIÓN 1: Nieve
            #st.snow()
            
            # OPCIÓN 2: Animación CSS personalizada
            # mostrar_animacion_success()
            
            # OPCIÓN 3: Confetti
            # mostrar_confetti()
            
            # OPCIÓN 4: Mensaje con fadeout
            # mostrar_mensaje_fadeout("✅ ¡Acceso Concedido Exitosamente! 🎉")
            
            # OPCIÓN 5: Toast notification
            # mostrar_toast_notification("✅ Acceso Autorizado")
            
            # OPCIÓN 6: Progress bar animado
            # mostrar_progress_bar_animado()
            
            return True
        else:
            return False
            
    except Exception as e:
        st.error(f"❌ **Error de Autenticación**: {str(e)}")
        return False

# ========== EJEMPLO DE USO EN mostrar_pantalla_login ==========
# En la función mostrar_pantalla_login, reemplaza:
# st.balloons()

# Por cualquiera de estas opciones:
# st.snow()  # Más elegante para entorno corporativo
# mostrar_animacion_success()  # Animación personalizada
# mostrar_toast_notification("✅ Acceso Concedido")  # Notificación moderna

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
        <small>Desarrollado por EBG</small>
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
