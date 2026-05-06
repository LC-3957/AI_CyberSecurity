import sys, os, streamlit as st

ROOT_DIR    = os.path.dirname(__file__)
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
sys.path.append(ROOT_DIR)
sys.path.append(BACKEND_DIR)

from backend.ai_analista import analizar_completo
from backend.main import (
    revisar_headers, validar_ssl, detectar_tecnologias,
    escanear_puertos, detectar_formularios, buscar_rutas
)
from login import mostrar_login, cerrar_sesion

st.set_page_config(
    page_title="WebShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

if not mostrar_login():
    st.stop()

# ── CSS ──
css_path = os.path.join(ROOT_DIR, "assets", "style.css")
with open(css_path, encoding="utf-8") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ── TOPBAR ──
nombre    = st.session_state.get("nombre_actual", "")
iniciales = "".join([p[0].upper() for p in nombre.split()[:2]]) if nombre else "U"

st.markdown(f"""
<div class="topbar">
    <div class="topbar-brand">
        <span class="topbar-brand-icon">🛡️</span>
        WebShield AI
    </div>
    <div class="topbar-right">
        <div class="topbar-avatar">{iniciales}</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ── AVISO ETICO ──
st.markdown("""
<div class="etica-box">
    <span>⚖️</span>
    <div><span>AVISO ÉTICO</span> &nbsp;Esta herramienta está diseñada exclusivamente para analizar sitios web sobre los que se tiene <strong>autorización explícita</strong>.</div>
</div>
""", unsafe_allow_html=True)

# ── BIENVENIDA + SALIR ──
col_a, col_b = st.columns([8, 1])
with col_a:
    st.markdown(f'<div class="usuario-bar">Bienvenid@, {nombre}</div>', unsafe_allow_html=True)
with col_b:
    if st.button("⇥  Salir", type="secondary"):
        cerrar_sesion()

# ── HERO ──
st.markdown("""
<div class="main-content-wrapper">
<div style="text-align:center; margin: 1.2rem 0 0.4rem;">
    <div style="
        width: 68px; height: 68px;
        background: linear-gradient(135deg, #0f2456, #1e3a8a);
        border-radius: 50%;
        display: inline-flex; align-items: center; justify-content: center;
        font-size: 1.7rem;
        box-shadow: 0 8px 25px rgba(15,36,86,0.35);
        margin-bottom: 0.8rem;
    ">🛡️</div>
</div>
<div class="section-title-main">Análisis de seguridad web asistido por IA</div>
<div class="section-sub-main">
    Detecta, interpreta y prioriza riesgos en segundos.<br>
    Inteligencia artificial aplicada a la defensa digital.
</div>
""", unsafe_allow_html=True)

# ── INPUT CARD ──
st.markdown("""
<div style="
    background: linear-gradient(135deg, #0d1e40, #162454);
    border-radius: 18px;
    padding: 1.4rem 1.8rem 1.2rem;
    box-shadow: 0 15px 40px rgba(7,22,62,0.3);
    border: 1px solid rgba(255,255,255,0.07);
    margin-bottom: 1.5rem;
">
<div class="input-label">🌐 &nbsp;Ingresa la URL autorizada a analizar</div>
""", unsafe_allow_html=True)

col1, col2 = st.columns([5, 1])
with col1:
    url_input = st.text_input("url", placeholder="https://sitio.com", label_visibility="collapsed")
with col2:
    analizar = st.button("ANALIZAR →", type="primary", use_container_width=True)

st.markdown("</div>", unsafe_allow_html=True)

# ── ANÁLISIS ──
if analizar:
    if not url_input.startswith("http"):
        st.error("Ingresa una URL válida que comience con http:// o https://")
        st.stop()

    with st.container():
        st.info(f"Analizando: **{url_input}**")
        barra = st.progress(0, text="Iniciando análisis...")

        barra.progress(10, text="Revisando encabezados HTTP de seguridad...")
        headers_seg = revisar_headers(url_input)
        barra.progress(30, text="Validando certificado SSL/HTTPS...")
        ssl_ok = validar_ssl(url_input)
        barra.progress(50, text="Detectando tecnologías visibles...")
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
            st.error(f"Error en análisis IA: {e}")
            st.stop()

        barra.empty()

    st.session_state["scan_json"]     = scan_json
    st.session_state["resultado_ia"]  = resultado_ia
    st.session_state["url_analizada"] = url_input
    st.rerun()

# ── RESULTADOS ──
if "resultado_ia" in st.session_state:
    r = st.session_state["resultado_ia"]

    # Botones — Nueva consulta y Descargar reporte
    _, bcol1, bcol2 = st.columns([4, 1, 1])
    with bcol1:
        st.markdown('<div class="nueva-consulta-btn">', unsafe_allow_html=True)
        if st.button("↺  Nueva consulta", type="secondary", use_container_width=True):
            for k in ["scan_json", "resultado_ia", "url_analizada", "chat_messages"]:
                st.session_state.pop(k, None)
            st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
    with bcol2:
        url_analizada = st.session_state.get("url_analizada", "")
        reporte_txt = f"""WEBSHIELD AI — REPORTE DE SEGURIDAD
=====================================
URL analizada: {url_analizada}
Generado por: WebShield AI | Universidad Iberoamericana León 2026

{'='*60}
RESUMEN DE HALLAZGOS
{'='*60}
{r['resumen']}

{'='*60}
CLASIFICACIÓN DE RIESGOS
{'='*60}
{r['riesgos']}

{'='*60}
IMPACTO POTENCIAL
{'='*60}
{r['impacto']}

{'='*60}
MITIGACIONES RECOMENDADAS
{'='*60}
{r['mitigaciones']}

{'='*60}
RESUMEN EJECUTIVO
{'='*60}
{r['resumen_ejecutivo']}

=====================================
Herramientas de Ciberseguridad | Prof. Pablo Náchez
Universidad Iberoamericana León 2026
"""
        nombre_archivo = url_analizada.replace("https://", "").replace("http://", "").replace("/", "_")[:40]
        st.download_button(
            label="⬇  Descargar reporte",
            data=reporte_txt.encode("utf-8"),
            file_name=f"webshield_{nombre_archivo}.txt",
            mime="text/plain",
            use_container_width=True
        )

    # Resultados con st.markdown nativo dentro de containers con fondo
    secciones = [
        ("resumen", "Resumen de Hallazgos"),
        ("riesgos", "Clasificacion de Riesgos"),
        ("impacto", "Impacto Potencial"),
        ("mitigaciones", "Mitigaciones Recomendadas"),
        ("resumen_ejecutivo", "Resumen Ejecutivo"),
    ]
    for key, titulo in secciones:
        st.markdown(f"""
        <div style="
            background: whitesmoke;
            border-radius: 16px;
            padding: 0.6rem 1.4rem 0.2rem;
            margin-bottom: 0.5rem;
            box-shadow: 0 4px 20px rgba(0,0,0,0.06);
            border: 1px solid #edf5ff;
        "></div>
        """, unsafe_allow_html=True)
        st.markdown(r[key])

    # ── CHATBOT ──
    st.markdown("""
    <div style="
        background: linear-gradient(135deg, #0f2456, #1e3a8a);
        border-radius: 16px 16px 0 0;
        padding: 0.9rem 1.4rem;
        margin-top: 2rem;
        display: flex; align-items: center; gap: 0.8rem;
    ">
        <div style="
            width:34px; height:34px;
            background: linear-gradient(135deg,#c9962c,#e8b84b);
            border-radius:50%; display:flex; align-items:center;
            justify-content:center; font-size:0.95rem; flex-shrink:0;
        ">🛡️</div>
        <div>
            <div style="color:white; font-weight:700; font-size:0.88rem;">Asistente WebShield</div>
            <div style="color:#93c5fd; font-size:0.68rem;">Consulta dudas sobre el análisis</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    if not st.session_state.chat_messages:
        with st.chat_message("assistant", avatar="🛡️"):
            st.markdown("Hola, soy el asistente de WebShield. Puedo responder tus dudas sobre el análisis realizado. ¿En qué te puedo ayudar?")

    for message in st.session_state.chat_messages:
        avatar = "🛡️" if message["role"] == "assistant" else "👤"
        with st.chat_message(message["role"], avatar=avatar):
            st.markdown(message["content"])

    if user_question := st.chat_input("Escribe tu pregunta sobre el análisis..."):
        st.session_state.chat_messages.append({"role": "user", "content": user_question})
        with st.chat_message("user", avatar="👤"):
            st.markdown(user_question)

        contexto = f"""Eres un asistente experto en ciberseguridad. Responde ÚNICAMENTE basándote en el análisis proporcionado.
Responde en español, de forma clara y concisa. No uses emojis.
URL analizada: {st.session_state.get('url_analizada','')}
Hallazgos: {st.session_state.get('scan_json',{})}
Análisis IA: {st.session_state.get('resultado_ia',{})}"""

        with st.chat_message("assistant", avatar="🛡️"):
            placeholder = st.empty()
            placeholder.markdown("Consultando el análisis...")
            try:
                import anthropic
                try:    api_key = st.secrets["ANTHROPIC_API_KEY"]
                except: api_key = os.environ.get("ANTHROPIC_API_KEY")
                client   = anthropic.Anthropic(api_key=api_key)
                response = client.messages.create(
                    model="claude-sonnet-4-6", max_tokens=512,
                    system=contexto,
                    messages=[{"role": "user", "content": user_question}]
                )
                respuesta = response.content[0].text
                placeholder.markdown(respuesta)
                st.session_state.chat_messages.append({"role": "assistant", "content": respuesta})
            except Exception as e:
                error_msg = f"Error al consultar: {str(e)}"
                placeholder.markdown(error_msg)
                st.session_state.chat_messages.append({"role": "assistant", "content": error_msg})

elif "scan_json" not in st.session_state:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon">🛡️</div>
        <div class="empty-state-text">Ingresa una URL para comenzar</div>
    </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("""
<div class="footer">
    WEBSHIELD AI · HERRAMIENTAS DE CIBERSEGURIDAD · UNIVERSIDAD IBEROAMERICANA LEÓN 2026
</div>
""", unsafe_allow_html=True)