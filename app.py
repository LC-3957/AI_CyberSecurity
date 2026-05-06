import sys
import os
import streamlit as st

# ── Rutas del proyecto ──
ROOT_DIR    = os.path.dirname(__file__)
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
sys.path.append(ROOT_DIR)
sys.path.append(BACKEND_DIR)

# ── Imports del proyecto ──
from backend.ai_analista import analizar_completo
from backend.main import (
    revisar_headers,
    validar_ssl,
    detectar_tecnologias,
    escanear_puertos,
    detectar_formularios,
    buscar_rutas
)
from login import mostrar_login, cerrar_sesion

# ── CONFIG ──
st.set_page_config(
    page_title="WebShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ── AUTENTICACIÓN ──
if not mostrar_login():
    st.stop()

# ───────── CSS ─────────
css_path = os.path.join(ROOT_DIR, "assets", "style.css")
with open(css_path, encoding="utf-8") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ── CSS EXTRA PARA MEJORAS ──
st.markdown("""
<style>
/* Texto del chatbot siempre oscuro */
[data-testid="stChatMessageContent"] p,
[data-testid="stChatMessageContent"] li,
[data-testid="stChatMessageContent"] span,
[data-testid="stChatMessageContent"] strong,
[data-testid="stChatMessageContent"] em,
[data-testid="stChatMessageContent"] code {
    color: #0f172a !important;
}
[data-testid="stChatMessageContent"] {
    background: white !important;
    border-radius: 10px !important;
    padding: 10px 14px !important;
}

/* Usuario más grande */
.usuario-bar {
    font-size: 1.1rem;
    font-weight: 700;
    color: #1e3a8a;
    font-family: 'Inter', sans-serif;
    padding: 6px 0;
}

/* Input con primera letra mayúscula */
.stTextInput input {
    text-transform: capitalize;
}
.stTextInput input[type="password"] {
    text-transform: none !important;
}
</style>
""", unsafe_allow_html=True)

# ── AVISO ETICO ARRIBA ──
st.markdown("""
<div class="etica-box">
    <span>AVISO ETICO</span> &nbsp;Esta herramienta esta disenada exclusivamente para analizar sitios web
    sobre los que se tiene <span>autorizacion explicita</span>.
</div>
""", unsafe_allow_html=True)

# ── USUARIO Y BOTON SALIR ──
nombre = st.session_state.get("nombre_actual", "")
col_a, col_b = st.columns([8, 1])
with col_a:
    st.markdown(
        f'<div class="usuario-bar">Bienvenido, {nombre}</div>',
        unsafe_allow_html=True
    )
with col_b:
    if st.button("Salir", type="secondary"):
        cerrar_sesion()

# ───────── HERO ─────────
st.markdown("""
<div class="hero-wrapper">
    <div class="hero-eyebrow">Web Security Intelligence Platform</div>
    <h1 class="hero-title">WebShield AI</h1>
    <p class="hero-sub">Analisis de seguridad web asistido por inteligencia artificial.<br>
    Detecta, interpreta y prioriza riesgos en segundos.</p>
    <div class="hero-divider"></div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="section-title-main">Analisis de seguridad web asistido por IA</div>
<div class="section-sub-main">
    Detecta, interpreta y prioriza riesgos en segundos.<br>
    Inteligencia artificial aplicada a la defensa digital.
</div>
""", unsafe_allow_html=True)

# ───────── INPUT ─────────
st.markdown('<div class="input-label">Ingresa la URL autorizada a analizar</div>', unsafe_allow_html=True)

col1, col2 = st.columns([5, 1])
with col1:
    url_input = st.text_input("url", placeholder="https://sitio.com", label_visibility="collapsed")
with col2:
    analizar = st.button("ANALIZAR", type="primary", use_container_width=True)

# ───────── LÓGICA PRINCIPAL ─────────
if analizar:
    if not url_input.startswith("http"):
        st.error("Ingresa una URL valida que comience con http:// o https://")
        st.stop()

    # Contenedor fijo para el progreso — no hace scroll
    progreso_container = st.container()

    with progreso_container:
        st.info(f"Analizando: **{url_input}**")
        barra = st.progress(0, text="Iniciando analisis...")

        barra.progress(10, text="Revisando encabezados HTTP de seguridad...")
        headers_seg = revisar_headers(url_input)

        barra.progress(30, text="Validando certificado SSL/HTTPS...")
        ssl_ok = validar_ssl(url_input)

        barra.progress(50, text="Detectando tecnologias visibles...")
        tecnologias = detectar_tecnologias(url_input)

        barra.progress(65, text="Escaneando puertos...")
        puertos = escanear_puertos(url_input)

        barra.progress(80, text="Buscando formularios y rutas expuestas...")
        formularios = detectar_formularios(url_input)
        rutas       = buscar_rutas(url_input)

        barra.progress(100, text="Validaciones completadas. Procesando con IA...")

        scan_json = {
            "url_analizada":     url_input,
            "headers_seguridad": headers_seg,
            "ssl_valido":        ssl_ok,
            "tecnologias":       tecnologias,
            "puertos_abiertos":  puertos,
            "formularios":       formularios,
            "rutas_expuestas":   rutas
        }

        try:
            resultado_ia = analizar_completo(scan_json)
        except Exception as e:
            st.error(f"Error en analisis IA: {e}")
            st.stop()

        barra.empty()

    # Guardar en sesion
    st.session_state["scan_json"]     = scan_json
    st.session_state["resultado_ia"]  = resultado_ia
    st.session_state["url_analizada"] = url_input
    # NO resetear chat_messages para no borrar el historial

# ── Mostrar resultados si hay analisis en sesion ──
if "resultado_ia" in st.session_state:
    r = st.session_state["resultado_ia"]

    st.markdown(f'<div class="result-card">{r["resumen"]}</div>',           unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["riesgos"]}</div>',           unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["impacto"]}</div>',           unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["mitigaciones"]}</div>',      unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["resumen_ejecutivo"]}</div>', unsafe_allow_html=True)

    # ───────── CHATBOT ─────────
    with st.expander("Consulta al Asistente de Seguridad", expanded=True):

        if "chat_messages" not in st.session_state:
            st.session_state.chat_messages = []

        # Mostrar historial
        for message in st.session_state.chat_messages:
            with st.chat_message(message["role"]):
                st.markdown(message["content"])

        if user_question := st.chat_input("Pregunta sobre el analisis, ej: cual es el riesgo mas urgente?"):

            st.session_state.chat_messages.append({"role": "user", "content": user_question})
            with st.chat_message("user"):
                st.markdown(user_question)

            scan_ctx   = st.session_state.get("scan_json", {})
            result_ctx = st.session_state.get("resultado_ia", {})
            url_ctx    = st.session_state.get("url_analizada", "")

            contexto = f"""
Eres un asistente experto en ciberseguridad. El usuario ya realizo un analisis de seguridad web.
Responde UNICAMENTE basandote en los datos del analisis proporcionado. No inventes informacion.
Responde en español, de forma clara y sin tecnicismos innecesarios.

URL analizada: {url_ctx}

Hallazgos tecnicos del escaneo:
{scan_ctx}

Analisis de IA (resumen, riesgos, impacto, mitigaciones, resumen ejecutivo):
{result_ctx}
"""

            with st.chat_message("assistant"):
                placeholder = st.empty()
                placeholder.markdown("Consultando el analisis...")

                try:
                    import anthropic
                    try:
                        api_key = st.secrets["ANTHROPIC_API_KEY"]
                    except Exception:
                        api_key = os.environ.get("ANTHROPIC_API_KEY")

                    client = anthropic.Anthropic(api_key=api_key)
                    response = client.messages.create(
                        model="claude-sonnet-4-6",
                        max_tokens=1024,
                        system=contexto,
                        messages=[{"role": "user", "content": user_question}]
                    )

                    respuesta = response.content[0].text
                    placeholder.markdown(respuesta)
                    st.session_state.chat_messages.append({"role": "assistant", "content": respuesta})

                except Exception as e:
                    error_msg = f"Error al consultar el asistente: {str(e)}"
                    placeholder.markdown(error_msg)
                    st.session_state.chat_messages.append({"role": "assistant", "content": error_msg})

elif "scan_json" not in st.session_state:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon"></div>
        <div class="empty-state-text">INGRESA UNA URL PARA COMENZAR</div>
    </div>
    """, unsafe_allow_html=True)

# ───────── FOOTER ─────────
st.markdown("""
<div class="footer">
    WEBSHIELD AI · HERRAMIENTAS DE CIBERSEGURIDAD · PROF. PABLO NACHEZ · UNIVERSIDAD IBEROAMERICANA LEON 2026
</div>
""", unsafe_allow_html=True)