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

# ── CONFIG — debe ir antes del login ──
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

# ── BOTÓN CERRAR SESIÓN ──
nombre = st.session_state.get("nombre_actual", "")
col_a, col_b = st.columns([8, 1])
with col_a:
    st.markdown(
        f'<div style="font-size:0.75rem; color:#475569; font-family:monospace;">👤 {nombre}</div>',
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
    <p class="hero-sub">Análisis de seguridad web asistido por inteligencia artificial.<br>
    Detecta, interpreta y prioriza riesgos en segundos.</p>
    <div class="hero-divider"></div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="section-title-main">Análisis de seguridad web asistido por IA</div>
<div class="section-sub-main">
    Detecta, interpreta y prioriza riesgos en segundos.<br>
    Inteligencia artificial aplicada a la defensa digital.
</div>
""", unsafe_allow_html=True)

# ───────── AVISO ÉTICO ─────────
st.markdown("""
<div class="etica-box">
    <span>⚠️ AVISO ÉTICO</span> &nbsp;Esta herramienta está diseñada exclusivamente para analizar sitios web
    sobre los que se tiene <span>autorización explícita</span>.
</div>
""", unsafe_allow_html=True)

# ───────── INPUT ─────────
st.markdown('<div class="input-label">Ingresa la URL autorizada a analizar</div>', unsafe_allow_html=True)

col1, col2 = st.columns([5, 1])
with col1:
    url_input = st.text_input("url", placeholder="https://sitio.com", label_visibility="collapsed")
with col2:
    analizar = st.button("ANALIZAR →", type="primary", use_container_width=True)

# ───────── LÓGICA PRINCIPAL ─────────
if analizar:
    if not url_input.startswith("http"):
        st.error("⚠ Ingresa una URL válida que comience con http:// o https://")
        st.stop()

    # ── Ejecutar las 6 validaciones directamente (sin servidor FastAPI) ──
    with st.spinner("[ 01/02 ] Ejecutando validaciones de seguridad..."):
        try:
            scan_json = {
                "url_analizada":     url_input,
                "headers_seguridad": revisar_headers(url_input),
                "ssl_valido":        validar_ssl(url_input),
                "tecnologias":       detectar_tecnologias(url_input),
                "puertos_abiertos":  escanear_puertos(url_input),
                "formularios":       detectar_formularios(url_input),
                "rutas_expuestas":   buscar_rutas(url_input)
            }
        except Exception as e:
            st.error(f"❌ Error al ejecutar el análisis: {e}")
            st.stop()

    # ── Analizar con IA ──
    with st.spinner("[ 02/02 ] Procesando hallazgos con inteligencia artificial..."):
        try:
            resultado_ia = analizar_completo(scan_json)
        except Exception as e:
            st.error(f"❌ Error en análisis IA: {e}")
            st.stop()

    # ── Guardar en sesión para el chatbot ──
    st.session_state["scan_json"]     = scan_json
    st.session_state["resultado_ia"]  = resultado_ia
    st.session_state["url_analizada"] = url_input
    st.session_state["chat_messages"] = []

    # ── Mostrar las 5 secciones de IA ──
    st.markdown(f'<div class="result-card">{resultado_ia["resumen"]}</div>',          unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{resultado_ia["riesgos"]}</div>',          unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{resultado_ia["impacto"]}</div>',          unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{resultado_ia["mitigaciones"]}</div>',     unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{resultado_ia["resumen_ejecutivo"]}</div>',unsafe_allow_html=True)

elif "scan_json" not in st.session_state:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon">🛡️</div>
        <div class="empty-state-text">INGRESA UNA URL PARA COMENZAR</div>
    </div>
    """, unsafe_allow_html=True)

# ───────── CHATBOT ─────────
if "scan_json" in st.session_state:

    st.markdown("---")
    st.markdown("### 💬 Asistente de consultas")

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    if user_question := st.chat_input("Pregunta algo sobre el análisis, ej: ¿cuál es el riesgo más urgente?"):

        st.session_state.chat_messages.append({"role": "user", "content": user_question})
        with st.chat_message("user"):
            st.markdown(user_question)

        scan_ctx   = st.session_state.get("scan_json", {})
        result_ctx = st.session_state.get("resultado_ia", {})
        url_ctx    = st.session_state.get("url_analizada", "")

        contexto = f"""
Eres un asistente experto en ciberseguridad. El usuario ya realizó un análisis de seguridad web.
Responde ÚNICAMENTE basándote en los datos del análisis proporcionado. No inventes información.
Responde en español, de forma clara y sin tecnicismos innecesarios.

URL analizada: {url_ctx}

Hallazgos técnicos del escaneo:
{scan_ctx}

Análisis de IA (resumen, riesgos, impacto, mitigaciones, resumen ejecutivo):
{result_ctx}
"""

        with st.chat_message("assistant"):
            placeholder = st.empty()
            placeholder.markdown("🤔 *Consultando el análisis...*")

            try:
                import anthropic

                # Lee la API key desde Streamlit secrets o .env
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
                error_msg = f"❌ Error al consultar el asistente: `{str(e)}`"
                placeholder.markdown(error_msg)
                st.session_state.chat_messages.append({"role": "assistant", "content": error_msg})

# ───────── FOOTER ─────────
st.markdown("""
<div class="footer">
    WEBSHIELD AI · HERRAMIENTAS DE CIBERSEGURIDAD · PROF. PABLO NÁCHEZ · UNIVERSIDAD IBEROAMERICANA LEÓN 2026
</div>
""", unsafe_allow_html=True)