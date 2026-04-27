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
#st.markdown('<div class="input-card">', unsafe_allow_html=True)
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

    st.markdown(f'<div class="result-card">{resultado_ia["resumen"]}</div>', unsafe_allow_html=True)

else:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon">🛡️</div>
        <div class="empty-state-text">
            INGRESA UNA URL PARA COMENZAR
        </div>
    </div>
    """, unsafe_allow_html=True)