import sys
import os
import requests
import streamlit as st

sys.path.append(os.path.join(os.path.dirname(__file__), "backend"))
from ai_analista import analizar_completo

st.set_page_config(
    page_title="Web AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ───────── CSS ─────────
css_path = os.path.join(os.path.dirname(__file__), "assets", "style.css")
with open(css_path, encoding="utf-8") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ───────── HERO ─────────
st.markdown("""
<div class="hero-wrapper">
    <div class="hero-eyebrow"> Web Security Intelligence Platform</div>
    <h1 class="hero-title">WebShield AI</h1>
    <p class="hero-sub">Análisis de seguridad web asistido por inteligencia artificial.<br>Detecta, interpreta y prioriza riesgos en segundos.</p>
    <div class="hero-divider"></div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="section-title-main">
Análisis de seguridad web asistido por IA</div>
<div class="section-sub-main">
Detecta, interpreta y prioriza riesgos en segundos.<br>
Inteligencia artificial aplicada a la defensa digital.
</div>
""", unsafe_allow_html=True)

# ───────── AVISO ─────────
st.markdown("""
<div class="etica-box">
    <span>⚠️ AVISO ÉTICO </span> &nbsp;Esta herramienta está diseñada exclusivamente para analizar sitios web
    sobre los que se tiene <span>autorización explícita</span>.
</div>
""", unsafe_allow_html=True)

# ───────── INPUT ─────────
st.markdown('<div class="input-label"> Ingresa la URL autorizada a analizar</div>', unsafe_allow_html=True)

col1, col2 = st.columns([5, 1])
with col1:
    url_input = st.text_input("url", placeholder="https://sitio.com", label_visibility="collapsed")
with col2:
    analizar = st.button("ANALIZAR →", type="primary", use_container_width=True)

st.markdown('</div>', unsafe_allow_html=True)

# ───────── LÓGICA ─────────
BACKEND_URL = "http://127.0.0.1:8000/scan"

if analizar:
    if not url_input.startswith("http"):
        st.error("URL inválida")
        st.stop()

    res = requests.post(BACKEND_URL, json={"url": url_input})
    scan_json = res.json()
    resultado_ia = analizar_completo(scan_json)

    # Guardar datos en sesión para que el chatbot los use
    st.session_state["scan_json"]     = scan_json
    st.session_state["resultado_ia"]  = resultado_ia
    st.session_state["url_analizada"] = url_input
    st.session_state["chat_messages"] = []  # Resetear chat al hacer nuevo análisis

    st.markdown(f'<div class="result-card">{resultado_ia["resumen"]}</div>', unsafe_allow_html=True)

elif "scan_json" not in st.session_state:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon">🛡️</div>
        <div class="empty-state-text">
            INGRESA UNA URL PARA COMENZAR
        </div>
    </div>
    """, unsafe_allow_html=True)

# ───────── CHATBOT — SECCIÓN DE EMI ─────────
# Solo mostrar el chat si ya hay un análisis hecho
if "scan_json" in st.session_state:

    st.markdown("---")
    st.markdown("### 💬 Asistente de consultas")

    # Inicializar historial del chat
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    # Mostrar historial previo
    for message in st.session_state.chat_messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # Entrada del usuario
    if user_question := st.chat_input("Pregunta algo sobre el análisis, ej: ¿cuál es el riesgo más urgente?"):

        # Mostrar pregunta del usuario
        st.session_state.chat_messages.append({"role": "user", "content": user_question})
        with st.chat_message("user"):
            st.markdown(user_question)

        # Preparar contexto con los datos del análisis
        scan_json     = st.session_state.get("scan_json", {})
        resultado_ia  = st.session_state.get("resultado_ia", {})
        url_analizada = st.session_state.get("url_analizada", "")

        contexto = f"""
Eres un asistente experto en ciberseguridad. El usuario ya realizó un análisis de seguridad web.
Responde ÚNICAMENTE basándote en los datos del análisis proporcionado. No inventes información.
Responde en español, de forma clara y sin tecnicismos innecesarios.

URL analizada: {url_analizada}

Hallazgos técnicos del escaneo:
{scan_json}

Análisis de IA (resumen, riesgos, impacto, mitigaciones, resumen ejecutivo):
{resultado_ia}
"""

        # Llamar a Claude para responder
        with st.chat_message("assistant"):
            respuesta_placeholder = st.empty()
            respuesta_placeholder.markdown("🤔 *Consultando el análisis...*")

            try:
                import anthropic
                client = anthropic.Anthropic()

                response = client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=1024,
                    system=contexto,
                    messages=[
                        {"role": "user", "content": user_question}
                    ]
                )

                respuesta = response.content[0].text
                respuesta_placeholder.markdown(respuesta)
                st.session_state.chat_messages.append({"role": "assistant", "content": respuesta})

            except Exception as e:
                error_msg = f"❌ Error al consultar el asistente: `{str(e)}`"
                respuesta_placeholder.markdown(error_msg)
                st.session_state.chat_messages.append({"role": "assistant", "content": error_msg})