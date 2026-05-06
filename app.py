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
nombre   = st.session_state.get("nombre_actual", "")
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
    st.markdown(f'<div class="usuario-bar">Bienvenido, {nombre}</div>', unsafe_allow_html=True)
with col_b:
    if st.button("⇥  Salir", type="secondary"):
        cerrar_sesion()

# ── HERO ──
st.markdown("""
<div class="main-content-wrapper">
<div style="text-align:center; margin: 1.5rem 0 0.5rem;">
    <div style="
        width: 80px; height: 80px;
        background: linear-gradient(135deg, #0f2456, #1e3a8a);
        border-radius: 50%;
        display: inline-flex; align-items: center; justify-content: center;
        font-size: 2rem;
        box-shadow: 0 8px 25px rgba(15,36,86,0.35);
        margin-bottom: 1rem;
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
    padding: 1.6rem 1.8rem 1.4rem;
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

# ── LÓGICA PRINCIPAL ──
if analizar:
    if not url_input.startswith("http"):
        st.error("Ingresa una URL válida que comience con http:// o https://")
        st.stop()

    progreso_container = st.container()
    with progreso_container:
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

# ── RESULTADOS ──
if "resultado_ia" in st.session_state:
    r = st.session_state["resultado_ia"]

    st.markdown(f'<div class="result-card">{r["resumen"]}</div>',           unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["riesgos"]}</div>',           unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["impacto"]}</div>',           unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["mitigaciones"]}</div>',      unsafe_allow_html=True)
    st.markdown(f'<div class="result-card">{r["resumen_ejecutivo"]}</div>', unsafe_allow_html=True)

    # ── CHATBOT FLOTANTE ──
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    # Procesar pregunta enviada desde el widget
    if "widget_question" in st.session_state and st.session_state.widget_question:
        user_question = st.session_state.widget_question
        st.session_state.widget_question = ""

        scan_ctx   = st.session_state.get("scan_json", {})
        result_ctx = st.session_state.get("resultado_ia", {})
        url_ctx    = st.session_state.get("url_analizada", "")

        contexto = f"""Eres un asistente experto en ciberseguridad. El usuario ya realizó un análisis de seguridad web.
Responde ÚNICAMENTE basándote en los datos del análisis proporcionado. No inventes información.
Responde en español, de forma clara y concisa, sin tecnicismos innecesarios.
URL analizada: {url_ctx}
Hallazgos técnicos: {scan_ctx}
Análisis de IA: {result_ctx}"""

        try:
            import anthropic
            try:
                api_key = st.secrets["ANTHROPIC_API_KEY"]
            except Exception:
                api_key = os.environ.get("ANTHROPIC_API_KEY")
            client   = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=512,
                system=contexto,
                messages=[{"role": "user", "content": user_question}]
            )
            respuesta = response.content[0].text
        except Exception as e:
            respuesta = f"Error al consultar: {str(e)}"

        st.session_state.chat_messages.append({"role": "user",      "content": user_question})
        st.session_state.chat_messages.append({"role": "assistant", "content": respuesta})
        st.rerun()

    # Construir historial HTML para el widget
    mensajes_html = ""
    for m in st.session_state.chat_messages:
        cls     = "chat-msg-bot" if m["role"] == "assistant" else "chat-msg-user"
        texto   = m["content"].replace("\n", "<br>").replace('"', '&quot;')
        mensajes_html += f'<div class="{cls}">{texto}</div>'

    if not mensajes_html:
        mensajes_html = '<div class="chat-msg-bot">Hola! Puedo responder preguntas sobre el análisis. ¿En qué te ayudo?</div>'

    st.markdown(f"""
    <!-- Botón flotante -->
    <button id="chat-widget-btn" onclick="toggleChat()">💬</button>

    <!-- Ventana del chat -->
    <div id="chat-widget-window">
        <div id="chat-widget-header">
            <div id="chat-widget-header-icon">🛡️</div>
            <div>
                <div id="chat-widget-header-title">Asistente WebShield</div>
                <div id="chat-widget-header-sub">Consulta sobre el análisis</div>
            </div>
            <button id="chat-widget-close" onclick="toggleChat()">✕</button>
        </div>
        <div id="chat-widget-messages" id="chatMessages">
            {mensajes_html}
        </div>
        <div id="chat-widget-input-row">
            <input id="chat-widget-input" type="text" placeholder="Escribe tu pregunta..."
                   onkeydown="if(event.key==='Enter') sendMsg()"/>
            <button id="chat-widget-send" onclick="sendMsg()">➤</button>
        </div>
    </div>

    <script>
    function toggleChat() {{
        const win = document.getElementById('chat-widget-window');
        win.classList.toggle('open');
        if (win.classList.contains('open')) {{
            scrollBottom();
            document.getElementById('chat-widget-input').focus();
        }}
    }}

    function scrollBottom() {{
        const msgs = document.getElementById('chat-widget-messages');
        if (msgs) msgs.scrollTop = msgs.scrollHeight;
    }}

    function sendMsg() {{
        const input = document.getElementById('chat-widget-input');
        const text  = input.value.trim();
        if (!text) return;
        input.value = '';

        // Inyectar en un input oculto de Streamlit y disparar
        const stInputs = window.parent.document.querySelectorAll('input[type="text"]');
        for (let inp of stInputs) {{
            if (inp.placeholder && inp.placeholder.includes('Pregunta')) {{
                const nativeInput = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
                nativeInput.set.call(inp, text);
                inp.dispatchEvent(new Event('input', {{ bubbles: true }}));
                setTimeout(() => {{
                    inp.dispatchEvent(new KeyboardEvent('keydown', {{ key: 'Enter', keyCode: 13, bubbles: true }}));
                }}, 100);
                break;
            }}
        }}
    }}

    // Auto-scroll al abrir
    window.addEventListener('load', scrollBottom);
    setTimeout(scrollBottom, 500);
    </script>
    """, unsafe_allow_html=True)

    # Input oculto que recibe la pregunta del widget
    pregunta_widget = st.text_input("Pregunta al asistente", key="chat_input_hidden",
                                     label_visibility="hidden", placeholder="Pregunta sobre el análisis")
    if pregunta_widget:
        st.session_state.widget_question = pregunta_widget
        st.rerun()

elif "scan_json" not in st.session_state:
    st.markdown("""
    <div class="empty-state">
        <div class="empty-state-icon">🛡️</div>
        <div class="empty-state-text">Ingresa una URL para comenzar</div>
    </div>
    </div>
    """, unsafe_allow_html=True)

# ── FOOTER ──
st.markdown("""
<div class="footer">
    WEBSHIELD AI · HERRAMIENTAS DE CIBERSEGURIDAD · UNIVERSIDAD IBEROAMERICANA LEÓN 2026
</div>
""", unsafe_allow_html=True)