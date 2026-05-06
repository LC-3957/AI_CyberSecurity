"""
login.py — WebShield AI | Formulario centrado lado derecho, fondo natural
"""

import bcrypt, hmac, hashlib, time, os
import streamlit as st
from dotenv import load_dotenv
load_dotenv()

USUARIOS = {
    "lyz":   {"nombre": "Lyzzet Valenzuela",          "hash": "$2b$12$1Ev0/3PvtcIB46c9vg68W.7Pg5pMS1DXfQFUKE.K3fSakzwDkyvqK"},
    "diego": {"nombre": "Diego Flores",               "hash": "$2b$12$0FxH5r.QGXoY24RbG3XWe.QMQ7qAeGfGKBxlFh7RIIiadb8WSvFgK"},
    "emi":   {"nombre": "Francisco Emiliano Guillen", "hash": "$2b$12$8e6jPLNiYfNssol/yhZ5DuANa1xl7nQploYLg5d1yq5LpOkt2jPCu"},
}

MAX_INTENTOS     = 3
BLOQUEO_SEGUNDOS = 300
SESION_SEGUNDOS  = 7200

try:
    SECRET_KEY = st.secrets["SESSION_SECRET"]
except Exception:
    SECRET_KEY = os.environ.get("SESSION_SECRET", "webshield-ibero-2026")

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
    intentos = st.session_state.get(f"intentos_{usuario}", 0)
    tb       = st.session_state.get(f"bloqueo_{usuario}", 0)
    if intentos >= MAX_INTENTOS and tb > 0:
        restante = int(tb - time.time())
        if restante > 0: return True, restante
        st.session_state[f"intentos_{usuario}"] = 0
        st.session_state[f"bloqueo_{usuario}"]  = 0
    return False, 0

def _fallo(usuario):
    n = st.session_state.get(f"intentos_{usuario}", 0) + 1
    st.session_state[f"intentos_{usuario}"] = n
    if n >= MAX_INTENTOS:
        st.session_state[f"bloqueo_{usuario}"] = time.time() + BLOQUEO_SEGUNDOS

def _reset(usuario):
    st.session_state[f"intentos_{usuario}"] = 0
    st.session_state[f"bloqueo_{usuario}"]  = 0

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

/* ── TITULO encima del card — sin fondo ── */
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

/* ── CARD azul oscuro — solo acceso restringido + inputs ── */
.login-card {{
    background: #0a1535;
    border-radius: 20px 20px 0 0;
    padding: 1.8rem 2.2rem 1.6rem;
    box-shadow: 0 0 0 1px rgba(255,255,255,0.06);
    width: 100%;
    margin-top: 20px
}}

.access-card {{
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 14px; padding: 1rem 1.3rem; margin-bottom: 0.5rem;
    display:flex; align-items:center; gap:0.9rem;
}}
.access-icon  {{ font-size:1.7rem; flex-shrink:0; }}
.access-title {{ color:white; font-weight:700; font-size:0.9rem; margin-bottom:0.1rem; }}
.access-sub   {{ color:#c9962c; font-size:0.74rem; font-weight:600; }}

/* stForm — mismo azul oscuro, continua el card */
[data-testid="stForm"] {{
    background: #0a1535 !important;
    border: 1px solid rgba(255,255,255,0.06) !important;
    border-top: none !important;
    border-radius: 0 0 20px 20px !important;
    padding: 0.5rem 2.2rem 2rem !important;
    box-shadow: 0 20px 60px rgba(0,0,0,0.5) !important;
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
    background: rgba(255,255,255,0.07) !important;
    border: 1.5px solid rgba(255,255,255,0.18) !important;
    border-radius: 10px !important;
    color: #ffffff !important;
    font-size: 1rem !important;
    padding: 0.75rem 1rem !important;
}}
.stTextInput > div > div > input::placeholder {{ color:rgba(255,255,255,0.35) !important; }}
.stTextInput > div > div > input:focus {{
    border-color: rgba(201,150,44,0.7) !important;
    box-shadow: 0 0 0 3px rgba(201,150,44,0.15) !important;
    background: rgba(255,255,255,0.1) !important;
}}
.stTextInput > div > div > div > button {{
    background: rgba(255,255,255,0.1) !important;
    border: none !important; color: white !important; border-radius: 6px !important;
}}

/* Boton dorado */
[data-testid="stFormSubmitButton"] > button {{
    background: linear-gradient(90deg, #b8860b, #d4a017, #e8b84b) !important;
    color: #0f172a !important; font-size:0.95rem !important;
    font-weight:800 !important; letter-spacing:0.12em !important;
    border-radius:10px !important; border:none !important;
    padding:0.82rem !important; width:100% !important;
    margin-top:0.8rem !important; transition:all 0.2s !important;
}}
[data-testid="stFormSubmitButton"] > button:hover {{
    filter:brightness(1.1) !important; transform:translateY(-1px) !important;
    box-shadow:0 6px 20px rgba(184,134,11,0.45) !important;
}}

/* ── FEATURES en card celeste ── */
.features-card {{
    background: #425D78;
    border-radius: 16px;
    padding: 1.4rem 1.5rem;
    margin-top: 1.2rem;
    box-shadow: 0 8px 25px rgba(0,0,0,0.25);
    border: 1px solid rgba(255,255,255,0.12);
}}
.features-row {{
    display:flex; gap:1.2rem; justify-content:center;
}}
.feat       {{ text-align:center; flex:1; }}
.feat-icon  {{ font-size:1.35rem; margin-bottom:0.2rem; }}
.feat-title {{ font-size:0.7rem; font-weight:700; color:#e8b84b; }}
.feat-desc  {{ font-size:0.62rem; color:#cbd5e1; line-height:1.4; }}

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

        # ── TITULO — fuera del card, sin fondo ──
        st.markdown("""
        <div class="login-header">
            <div class="login-header-shield">🛡️</div>
            <div class="login-header-title">WebShield AI</div>
            <div class="login-header-sub">Asistente de Seguridad Web con IA</div>
        </div>
        """, unsafe_allow_html=True)

        # ── CARD azul oscuro ──
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

        # ── FORM (continúa el card) ──
        with st.form("login_form", clear_on_submit=False):
            usuario_input  = st.text_input("USUARIO:", placeholder="tu usuario")
            st.markdown("<div style='margin-top:0.4rem'></div>", unsafe_allow_html=True)
            password_input = st.text_input("CONTRASEÑA:", type="password", placeholder="tu contraseña")
            st.markdown("<div style='margin-top:0.2rem'></div>", unsafe_allow_html=True)
            submit         = st.form_submit_button("INGRESAR →", use_container_width=True)

            if submit:
                u = usuario_input.lower().strip()
                bloq, rest = _bloqueado(u)
                if bloq:
                    m, s = rest // 60, rest % 60
                    st.error(f"Cuenta bloqueada. Intenta en {m}m {s}s.")
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
                    usados    = st.session_state.get(f"intentos_{u}", 0)
                    restantes = MAX_INTENTOS - usados
                    if restantes > 0:
                        st.error(f"Usuario o contraseña incorrectos. Intentos restantes: {restantes}")
                    else:
                        st.error(f"Cuenta bloqueada por {BLOQUEO_SEGUNDOS // 60} minutos.")

        # ── FEATURES en card celeste ──
        st.markdown("""
        <div class="features-card">
            <div class="features-row">
                <div class="feat">
                    <div class="feat-icon">🛡️</div>
                    <div class="feat-title">Protección inteligente</div>
                    <div class="feat-desc">IA que identifica y previene amenazas web en tiempo real.</div>
                </div>
                <div class="feat">
                    <div class="feat-icon">🔍</div>
                    <div class="feat-title">Análisis continuo</div>
                    <div class="feat-desc">Monitoreo y análisis de sitios para mantenerte seguro.</div>
                </div>
                <div class="feat">
                    <div class="feat-icon">🔒</div>
                    <div class="feat-title">Confidencial y seguro</div>
                    <div class="feat-desc">Datos protegidos con los más altos estándares.</div>
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