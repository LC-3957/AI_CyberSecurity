"""
login.py — WebShield AI | Formulario centrado lado derecho, fondo natural
"""

import bcrypt, hmac, hashlib, time, os, json, tempfile
import streamlit as st
from dotenv import load_dotenv
load_dotenv()

USUARIOS = {
    "lyz":   {"nombre": "Lyzzet Valenzuela",          "hash": "$2b$12$1Ev0/3PvtcIB46c9vg68W.7Pg5pMS1DXfQFUKE.K3fSakzwDkyvqK"},
    "diego": {"nombre": "Diego Flores",               "hash": "$2b$12$0FxH5r.QGXoY24RbG3XWe.QMQ7qAeGfGKBxlFh7RIIiadb8WSvFgK"},
    "emi":   {"nombre": "Francisco Emiliano Guillen", "hash": "$2b$12$8e6jPLNiYfNssol/yhZ5DuANa1xl7nQploYLg5d1yq5LpOkt2jPCu"},
}

MAX_INTENTOS     = 3
BLOQUEO_SEGUNDOS = 120
SESION_SEGUNDOS  = 7200

try:
    SECRET_KEY = st.secrets["SESSION_SECRET"]
except Exception:
    SECRET_KEY = os.environ.get("SESSION_SECRET", "webshield-ibero-2026")

IBERO_URL = "https://raw.githubusercontent.com/LC-3957/AI_CyberSecurity/main/assets/images/ibero.jpeg"

# ── Archivo persistente de bloqueos (sobrevive recargas) ──
_LOCK_FILE = os.path.join(tempfile.gettempdir(), "webshield_lockouts.json")

def _leer_bloqueos():
    try:
        if os.path.exists(_LOCK_FILE):
            with open(_LOCK_FILE, "r") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _guardar_bloqueos(data):
    try:
        with open(_LOCK_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass

IBERO_URL = "https://raw.githubusercontent.com/LC-3957/AI_CyberSecurity/main/assets/images/ibero.jpeg"


def _generar_token(usuario):
    ts  = str(int(time.time()))
    msg = f"{usuario}:{ts}"
    sig = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return f"{msg}:{sig}"

def _validar_token(token):
    try:
        partes = token.split(":")
        if len(partes) != 3: return None
        usuario, ts, sig = partes
        msg      = f"{usuario}:{ts}"
        esperada = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, esperada): return None
        if time.time() - int(ts) > SESION_SEGUNDOS: return None
        return usuario
    except Exception:
        return None

def _bloqueado(usuario):
    data = _leer_bloqueos()
    info = data.get(usuario, {})
    intentos = info.get("intentos", 0)
    tb       = info.get("bloqueo", 0)
    if intentos >= MAX_INTENTOS and tb > 0:
        restante = int(tb - time.time())
        if restante > 0:
            return True, restante
        # Expiró — limpiar
        data[usuario] = {"intentos": 0, "bloqueo": 0}
        _guardar_bloqueos(data)
    return False, 0

def _fallo(usuario):
    data = _leer_bloqueos()
    info = data.get(usuario, {"intentos": 0, "bloqueo": 0})
    info["intentos"] = info.get("intentos", 0) + 1
    if info["intentos"] >= MAX_INTENTOS:
        info["bloqueo"] = time.time() + BLOQUEO_SEGUNDOS
    data[usuario] = info
    _guardar_bloqueos(data)

def _reset(usuario):
    data = _leer_bloqueos()
    data[usuario] = {"intentos": 0, "bloqueo": 0}
    _guardar_bloqueos(data)

def verificar_credenciales(usuario, password):
    usuario = usuario.lower().strip()
    if usuario not in USUARIOS:
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return False
    h = USUARIOS[usuario]["hash"]
    if isinstance(h, str): h = h.encode()
    return bcrypt.checkpw(password.encode(), h)


def mostrar_login():
    token = st.session_state.get("session_token")
    if token:
        u = _validar_token(token)
        if u:
            st.session_state["usuario_actual"] = u
            st.session_state["nombre_actual"]  = USUARIOS[u]["nombre"]
            return True
        del st.session_state["session_token"]

    st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');

* {{ font-family: "Inter", sans-serif !important; box-sizing: border-box; }}

[data-testid="stHeader"], [data-testid="stToolbar"],
[data-testid="stDecoration"], #MainMenu, footer, header {{
    visibility: hidden !important; height: 0 !important; display: none !important;
}}

[data-testid="stAppViewContainer"] {{
    background: url("{IBERO_URL}") center center / cover no-repeat fixed !important;
    min-height: 100vh !important;
}}

.block-container {{
    padding: 2rem 0 5rem 0 !important;
    max-width: 100% !important;
}}
[data-testid="stVerticalBlock"] {{ gap: 0 !important; }}
[data-testid="column"] {{ background: transparent !important; }}

/* ── TITULO encima del card ── */
.login-header {{
    text-align: center;
    padding: 0 0 1.2rem 0;
    margin-top: 3rem;
}}
.login-header-shield {{ font-size: 2.8rem; margin-bottom: 0.3rem; }}
.login-header-title {{
    font-size: 2rem; font-weight: 800;
    color: #0f2456;
    margin-bottom: 0.1rem;
    text-shadow: 0 1px 3px rgba(255,255,255,0.6);
}}
.login-header-sub {{
    font-size: 0.88rem;
    color: #1e3a8a;
    text-shadow: 0 1px 2px rgba(255,255,255,0.5);
}}

/* ── CARD azul oscuro — glass effect + profundidad ── */
.login-card {{
    background: #0a1535;
    border-radius: 20px 20px 0 0;
    padding: 1.8rem 2.2rem 1.6rem;
    box-shadow:
        0 0 0 1px rgba(255,255,255,0.1),
        0 8px 32px rgba(0,0,0,0.5),
        0 2px 8px rgba(0,0,0,0.35),
        inset 0 1px 0 rgba(255,255,255,0.08);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border: 1px solid rgba(255,255,255,0.1);
    width: 100%;
    margin-top: 20px;
}}

.access-card {{
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 14px; padding: 1rem 1.3rem; margin-bottom: 0.5rem;
    display:flex; align-items:center; gap:0.9rem;
}}
.access-icon  {{ font-size:1.7rem; flex-shrink:0; }}
.access-title {{ color:white; font-weight:700; font-size:0.9rem; margin-bottom:0.1rem; }}
.access-sub   {{ color:#c9962c; font-size:0.74rem; font-weight:600; }}

/* stForm — mismo azul, continua el card */
[data-testid="stForm"] {{
    background: #0a1535 !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-top: none !important;
    border-radius: 0 0 20px 20px !important;
    padding: 0.5rem 2.2rem 2rem !important;
    box-shadow:
        0 20px 60px rgba(0,0,0,0.55),
        0 4px 16px rgba(0,0,0,0.3),
        inset 0 -1px 0 rgba(255,255,255,0.05) !important;
    margin-top: -2px !important;
}}

/* Labels */
.stTextInput label {{
    font-size:0.75rem !important; font-weight:700 !important;
    color:#ffffff !important; letter-spacing:0.12em !important;
    text-transform:uppercase !important;
}}

/* Inputs */
.stTextInput > div > div > input {{
    background: rgba(255,255,255,0.06) !important;
    border: 1.5px solid rgba(255,255,255,0.15) !important;
    border-radius: 10px !important;
    color: #ffffff !important;
    font-size: 1rem !important;
    padding: 0.75rem 1rem !important;
    transition: all 0.25s ease !important;
}}
.stTextInput > div > div > input::placeholder {{ color:rgba(255,255,255,0.4) !important; }}
.stTextInput > div > div > input:focus {{
    border-color: rgba(99,179,237,0.9) !important;
    box-shadow: 0 0 0 3px rgba(99,179,237,0.2), 0 0 14px rgba(99,179,237,0.15) !important;
    background: rgba(255,255,255,0.09) !important;
}}

.stTextInput > div > div > div > button {{
    background: rgba(255,255,255,0.1) !important;
    border: none !important; color: white !important; border-radius: 6px !important;
}}

/* Boton dorado con glow y animacion elegante */
[data-testid="stFormSubmitButton"] > button {{
    background: linear-gradient(90deg, #a07010, #c9962c, #e8b84b, #c9962c, #a07010) !important;
    background-size: 200% auto !important;
    color: #0f172a !important;
    font-size: 0.95rem !important;
    font-weight: 800 !important;
    letter-spacing: 0.12em !important;
    border-radius: 10px !important;
    border: none !important;
    padding: 0.82rem !important;
    width: 100% !important;
    margin-top: 0.8rem !important;
    transition: background-position 0.4s ease, transform 0.2s ease, box-shadow 0.2s ease !important;
    box-shadow: 0 4px 15px rgba(184,134,11,0.3) !important;
}}
[data-testid="stFormSubmitButton"] > button:hover {{
    background-position: right center !important;
    transform: translateY(-2px) scale(1.01) !important;
    box-shadow: 0 8px 25px rgba(184,134,11,0.55), 0 0 20px rgba(232,184,75,0.3) !important;
}}
[data-testid="stFormSubmitButton"] > button:active {{
    transform: translateY(0px) scale(0.99) !important;
}}

/* ── FEATURES — card, hover, iconos grandes ── */
.features-card {{
    background: #EDF7FF;
    border-radius: 16px;
    padding: 1.6rem 1.5rem;
    margin-top: 1.2rem;
    box-shadow: 0 8px 25px rgba(0,0,0,0.25);
    border: 1px solid rgba(255,255,255,0.12);
}}
.features-row {{
    display: flex;
    gap: 0.8rem;
    justify-content: center;
}}
.feat {{
    text-align: center;
    flex: 1;
    padding: 0.8rem 0.5rem;
    border-radius: 10px;
    transition: background 0.2s ease, transform 0.2s ease;
    cursor: default;
}}
.feat:hover {{
    background: rgba(255,255,255,0.12);
    transform: translateY(-2px);
}}
.feat-icon  {{ font-size: 1.8rem; margin-bottom: 0.4rem; }}
.feat-title {{ font-size: 0.72rem; font-weight: 700; color: #0f2456; margin-bottom: 0.25rem; }}
.feat-desc  {{ font-size: 0.62rem; color: #1a1a2e; line-height: 1.5; }}

/* Badge Ibero */
.ibero-badge {{
    position:fixed; bottom:2.8rem; left:2rem;
    display:flex; align-items:center; gap:0.8rem; z-index:20;
}}
.ibero-circle {{
    width:46px; height:46px;
    background:linear-gradient(135deg,#c9962c,#e8b84b);
    border-radius:50%; display:flex; align-items:center;
    justify-content:center; font-size:1.25rem;
    box-shadow:0 2px 10px rgba(0,0,0,0.35);
}}
.ibero-info {{ color:white; }}
.ibero-name {{
    font-size:0.68rem; font-weight:800;
    letter-spacing:0.06em; text-transform:uppercase; line-height:1.35;
    text-shadow:0 1px 4px rgba(0,0,0,0.7);
}}

.login-footer {{
    position:fixed; bottom:0; left:0; right:0;
    background:#0f2456; color:#64748b; text-align:center;
    font-size:0.6rem; letter-spacing:0.1em;
    padding:0.5rem; text-transform:uppercase; z-index:998;
}}
</style>
""", unsafe_allow_html=True)

    # Badge + Footer
    st.markdown("""
    <div class="ibero-badge">
        <div class="ibero-info">
            <div class="ibero-name">Universidad<br>Iberoamericana<br>León</div>
        </div>
    </div>
    <div class="login-footer">
        🛡️ &nbsp; WebShield AI &nbsp;·&nbsp; Herramientas de Ciberseguridad &nbsp;
    </div>
    """, unsafe_allow_html=True)

    _, col, margin = st.columns([1, 1.2, 0.15])
    with col:

        st.markdown("""
        <div class="login-header">
            <div class="login-header-shield">🛡️</div>
            <div class="login-header-title">WebShield AI</div>
            <div class="login-header-sub">Asistente de Seguridad Web con IA</div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div class="login-card">
            <div class="access-card">
                <div class="access-icon">🔐</div>
                <div>
                    <div class="access-title">Acceso restringido — Solo equipo autorizado</div>
                    <div class="access-sub">Universidad Iberoamericana León &nbsp;·&nbsp; 2026</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Verificar bloqueo activo AL CARGAR la pagina ──
        usuario_guardado = st.session_state.get("ultimo_usuario", "")
        if usuario_guardado:
            bloq, rest = _bloqueado(usuario_guardado)
            if bloq:
                m, s = rest // 60, rest % 60
                st.error(f"Cuenta bloqueada. Espera {m}m {s}s antes de intentar de nuevo.")
                st.info("Recarga la pagina para actualizar el tiempo restante.")
                st.stop()

        with st.form("login_form", clear_on_submit=False):
            usuario_input  = st.text_input("USUARIO:", placeholder="👤  tu usuario")
            st.markdown("<div style='margin-top:0.4rem'></div>", unsafe_allow_html=True)
            password_input = st.text_input("CONTRASEÑA:", type="password", placeholder="🔒  tu contraseña")
            st.markdown("<div style='margin-top:0.2rem'></div>", unsafe_allow_html=True)
            submit         = st.form_submit_button("INGRESAR →", use_container_width=True)

            if submit:
                u = usuario_input.lower().strip()
                st.session_state["ultimo_usuario"] = u  # recordar para verificar al recargar
                bloq, rest = _bloqueado(u)
                if bloq:
                    m, s = rest // 60, rest % 60
                    st.error(f"Cuenta bloqueada. Espera {m}m {s}s antes de intentar de nuevo.")
                    st.stop()
                    return False
                if verificar_credenciales(u, password_input):
                    _reset(u)
                    tok = _generar_token(u)
                    st.session_state["session_token"]  = tok
                    st.session_state["usuario_actual"] = u
                    st.session_state["nombre_actual"]  = USUARIOS[u]["nombre"]
                    st.rerun()
                else:
                    _fallo(u)
                    data     = _leer_bloqueos()
                    usados   = data.get(u, {}).get("intentos", 0)
                    restantes = MAX_INTENTOS - usados
                    if restantes > 0:
                        st.error(f"Usuario o contraseña incorrectos. Intentos restantes: {restantes}")
                    else:
                        st.error(f"Demasiados intentos fallidos. Cuenta bloqueada por {BLOQUEO_SEGUNDOS // 60} minutos. Recarga la pagina para ver el tiempo restante.")

        st.markdown("""
        <div class="features-card">
            <div class="features-row">
                <div class="feat">
                    <div class="feat-icon">🔎</div>
                    <div class="feat-title">Escaneo web</div>
                    <div class="feat-desc">Detecta vulnerabilidades en headers, SSL, puertos y tecnologías expuestas.</div>
                </div>
                <div class="feat">
                    <div class="feat-icon">🤖</div>
                    <div class="feat-title">Análisis con IA</div>
                    <div class="feat-desc">Clasifica riesgos y explica cada hallazgo con recomendaciones concretas.</div>
                </div>
                <div class="feat">
                    <div class="feat-icon">💬</div>
                    <div class="feat-title">Asistente de dudas</div>
                    <div class="feat-desc">Pregúntale al asistente sobre los resultados del análisis en tiempo real.</div>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    return False


def cerrar_sesion():
    for k in ["session_token","usuario_actual","nombre_actual",
              "scan_json","resultado_ia","url_analizada","chat_messages"]:
        st.session_state.pop(k, None)
    st.rerun()