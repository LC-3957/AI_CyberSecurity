"""
login.py — Autenticacion segura con diseño inline (Streamlit Cloud compatible)
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

_IBERO_B64 = "/assets/images/ibero.jpeg"


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
        msg = f"{usuario}:{ts}"
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
    # ── sesion activa ──
    token = st.session_state.get("session_token")
    if token:
        u = _validar_token(token)
        if u:
            st.session_state["usuario_actual"] = u
            st.session_state["nombre_actual"]  = USUARIOS[u]["nombre"]
            return True
        del st.session_state["session_token"]

    # ── CSS inline ──
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap');

    html, body, [data-testid="stAppViewContainer"] {
        font-family: "Inter", sans-serif !important;
        margin: 0; padding: 0;
    }

    [data-testid="stAppViewContainer"] {
        background:
            linear-gradient(to right, rgba(7,22,62,0.88) 0%, rgba(7,22,62,0.55) 38%, rgba(7,22,62,0.1) 58%, transparent 72%),
            url("data:image/jpeg;base64,{_IBERO_B64}") center/cover no-repeat fixed !important;
        min-height: 100vh;
    }

    [data-testid="stHeader"], [data-testid="stToolbar"],
    [data-testid="stDecoration"], #MainMenu, footer, header {
    visibility: hidden !important; display: none !important;
    }

    [data-testid="stMainBlockContainer"] {
        padding-top: 0 !important;
        padding-bottom: 0 !important;
    }

    /* Contenedor principal: centrado vertical */
    [data-testid="stVerticalBlock"] > [data-testid="stVerticalBlock"] {
        background: rgba(255,255,255,0.97) !important;
        border-radius: 20px !important;
        padding: 2.5rem 2.5rem !important;
        box-shadow: 0 25px 60px rgba(0,0,0,0.4) !important;
    }

    /* Logo shield */
    .logo-shield {
        text-align: center;
        font-size: 3.2rem;
        margin-bottom: 0.2rem;
    }

    .login-title {
        font-size: 2rem;
        font-weight: 800;
        color: #0f2456;
        text-align: center;
        margin-bottom: 0.1rem;
    }

    .login-sub {
        font-size: 0.88rem;
        color: #64748b;
        text-align: center;
        margin-bottom: 1.6rem;
    }

    /* Card azul acceso restringido */
    .access-card {
        background: linear-gradient(135deg, #0f2456 0%, #1e3a8a 100%);
        border-radius: 14px;
        padding: 1rem 1.4rem;
        margin-bottom: 1.6rem;
        display: flex;
        align-items: center;
        gap: 0.9rem;
    }
    .access-icon { font-size: 1.8rem; flex-shrink: 0; }
    .access-title { color: white; font-weight: 700; font-size: 0.92rem; margin-bottom: 0.15rem; }
    .access-sub { color: #c9962c; font-size: 0.75rem; font-weight: 600; }

    /* Labels */
    .stTextInput label {
        font-size: 0.78rem !important;
        font-weight: 700 !important;
        color: #1e3a8a !important;
        letter-spacing: 0.1em !important;
        text-transform: uppercase !important;
    }

    /* Inputs */
    .stTextInput > div > div > input {
        background: #f8fafc !important;
        border: 1.5px solid #cbd5e1 !important;
        border-radius: 10px !important;
        color: #0f172a !important;
        font-size: 1rem !important;
        padding: 0.75rem 1rem !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: #1e3a8a !important;
        box-shadow: 0 0 0 3px rgba(30,58,138,0.15) !important;
        background: white !important;
    }

    /* Boton dorado */
    [data-testid="stFormSubmitButton"] > button {
        background: linear-gradient(90deg, #b8860b 0%, #d4a017 50%, #e8b84b 100%) !important;
        color: #0f172a !important;
        font-size: 0.95rem !important;
        font-weight: 800 !important;
        letter-spacing: 0.12em !important;
        border-radius: 10px !important;
        border: none !important;
        padding: 0.8rem 1rem !important;
        width: 100% !important;
        margin-top: 0.6rem !important;
        transition: all 0.2s ease !important;
    }
    [data-testid="stFormSubmitButton"] > button:hover {
        filter: brightness(1.08) !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 20px rgba(184,134,11,0.4) !important;
    }

    /* Franja de features */
    .features-row {
        display: flex;
        gap: 1.2rem;
        justify-content: center;
        margin-top: 1.4rem;
        padding-top: 1.4rem;
        border-top: 1px solid #e2e8f0;
    }
    .feat { text-align: center; flex: 1; }
    .feat-icon { font-size: 1.4rem; margin-bottom: 0.25rem; }
    .feat-title { font-size: 0.72rem; font-weight: 700; color: #1e3a8a; }
    .feat-desc { font-size: 0.63rem; color: #64748b; line-height: 1.4; }

    /* Ibero badge inferior izquierdo */
    .ibero-badge {
        position: fixed;
        bottom: 2.5rem;
        left: 2.5rem;
        display: flex;
        align-items: center;
        gap: 0.9rem;
    }
    .ibero-circle {
        width: 48px; height: 48px;
        background: linear-gradient(135deg, #c9962c, #e8b84b);
        border-radius: 50%;
        display: flex; align-items: center; justify-content: center;
        font-size: 1.3rem;
    }
    .ibero-info { color: white; }
    .ibero-name {
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.06em;
        text-transform: uppercase;
        line-height: 1.3;
    }

    /* Footer */
    .login-footer {
        position: fixed; bottom: 0; left: 0; right: 0;
        background: rgba(7,22,62,0.95);
        color: #64748b;
        text-align: center;
        font-size: 0.62rem;
        letter-spacing: 0.1em;
        padding: 0.55rem;
        text-transform: uppercase;
    }
    </style>
""", unsafe_allow_html=True)

    # ── Ibero badge fijo (esquina inferior izq) ──
    st.markdown("""
    <div class="ibero-badge">
        <div class="ibero-circle">🏛️</div>
        <div class="ibero-info">
            <div class="ibero-name">Universidad<br>Iberoamericana<br>León</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Footer ──
    st.markdown("""
    <div class="login-footer">
        🛡️ &nbsp; WebShield AI &nbsp;·&nbsp; Herramientas de Ciberseguridad &nbsp;·&nbsp; Prof. Pablo Náchez
    </div>
    """, unsafe_allow_html=True)

    # ── Columnas: vacía izq | formulario centro | vacía der ──
    _, col, _ = st.columns([1.2, 1, 1.2])
    with col:
        st.markdown('<div class="logo-shield">🛡️</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-title">WebShield AI</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-sub">Asistente de Seguridad Web con IA</div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="access-card">
            <div class="access-icon">🔐</div>
            <div>
                <div class="access-title">Acceso restringido — Solo equipo autorizado</div>
                <div class="access-sub">Universidad Iberoamericana León &nbsp;·&nbsp; 2026</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            usuario_input  = st.text_input("USUARIO", placeholder="tu usuario")
            password_input = st.text_input("CONTRASEÑA", type="password", placeholder="tu contraseña")
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

        st.markdown("""
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
        """, unsafe_allow_html=True)

    return False


def cerrar_sesion():
    for k in ["session_token","usuario_actual","nombre_actual",
              "scan_json","resultado_ia","url_analizada","chat_messages"]:
        st.session_state.pop(k, None)
    st.rerun()