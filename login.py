"""
login.py — Sistema de autenticacion seguro
Proyecto Final: Asistente de Seguridad Web con IA
Materia: Herramientas de Ciberseguridad | Prof. Pablo Nachez
Universidad Iberoamericana Leon — 2026
"""

import bcrypt
import hmac
import hashlib
import time
import os
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# ────────────────────────────────────────────
#  USUARIOS — hashes generados con generar_hashes.py
# ────────────────────────────────────────────
USUARIOS = {
    "lyz": {
        "nombre": "Lyzzet Valenzuela",
        "hash": "$2b$12$1Ev0/3PvtcIB46c9vg68W.7Pg5pMS1DXfQFUKE.K3fSakzwDkyvqK"
    },
    "diego": {
        "nombre": "Diego Flores",
        "hash": "$2b$12$0FxH5r.QGXoY24RbG3XWe.QMQ7qAeGfGKBxlFh7RIIiadb8WSvFgK"
    },
    "emi": {
        "nombre": "Francisco Emiliano Guillen",
        "hash": "$2b$12$8e6jPLNiYfNssol/yhZ5DuANa1xl7nQploYLg5d1yq5LpOkt2jPCu"
    }
}

MAX_INTENTOS     = 3
BLOQUEO_SEGUNDOS = 300
SESION_SEGUNDOS  = 7200
SECRET_KEY       = st.secrets.get("SESSION_SECRET", os.environ.get("SESSION_SECRET", "webshield-ibero-2026"))


# ────────────────────────────────────────────
#  FUNCIONES DE SEGURIDAD
# ────────────────────────────────────────────

def _generar_token(usuario: str) -> str:
    timestamp = str(int(time.time()))
    mensaje   = f"{usuario}:{timestamp}"
    firma     = hmac.new(SECRET_KEY.encode(), mensaje.encode(), hashlib.sha256).hexdigest()
    return f"{mensaje}:{firma}"


def _validar_token(token: str) -> str | None:
    try:
        partes = token.split(":")
        if len(partes) != 3:
            return None
        usuario, timestamp, firma_recibida = partes
        mensaje        = f"{usuario}:{timestamp}"
        firma_esperada = hmac.new(SECRET_KEY.encode(), mensaje.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(firma_recibida, firma_esperada):
            return None
        if time.time() - int(timestamp) > SESION_SEGUNDOS:
            return None
        return usuario
    except Exception:
        return None


# ── Bloqueo persistente usando query_params como storage temporal ──
def _clave_bloqueo(usuario: str) -> str:
    return f"bloqueo_{usuario}"

def _clave_intentos(usuario: str) -> str:
    return f"intentos_{usuario}"

def _esta_bloqueado(usuario: str) -> tuple[bool, int]:
    intentos       = st.session_state.get(_clave_intentos(usuario), 0)
    tiempo_bloqueo = st.session_state.get(_clave_bloqueo(usuario), 0)

    if intentos >= MAX_INTENTOS and tiempo_bloqueo > 0:
        restante = int(tiempo_bloqueo - time.time())
        if restante > 0:
            return True, restante
        else:
            st.session_state[_clave_intentos(usuario)] = 0
            st.session_state[_clave_bloqueo(usuario)]  = 0

    return False, 0


def _registrar_intento_fallido(usuario: str):
    intentos = st.session_state.get(_clave_intentos(usuario), 0) + 1
    st.session_state[_clave_intentos(usuario)] = intentos
    if intentos >= MAX_INTENTOS:
        st.session_state[_clave_bloqueo(usuario)] = time.time() + BLOQUEO_SEGUNDOS


def _resetear_intentos(usuario: str):
    st.session_state[_clave_intentos(usuario)] = 0
    st.session_state[_clave_bloqueo(usuario)]  = 0


def verificar_credenciales(usuario: str, password: str) -> bool:
    usuario = usuario.lower().strip()
    if usuario not in USUARIOS:
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return False
    hash_guardado = USUARIOS[usuario]["hash"]
    if isinstance(hash_guardado, str):
        hash_guardado = hash_guardado.encode("utf-8")
    return bcrypt.checkpw(password.encode("utf-8"), hash_guardado)


# ────────────────────────────────────────────
#  PANTALLA DE LOGIN
# ────────────────────────────────────────────

def mostrar_login() -> bool:

    cargar_css()  
    # Verificar sesion activa
    token = st.session_state.get("session_token")
    if token:
        usuario = _validar_token(token)
        if usuario:
            st.session_state["usuario_actual"] = usuario
            st.session_state["nombre_actual"]  = USUARIOS[usuario]["nombre"]
            return True
        else:
            del st.session_state["session_token"]

    # CSS del login

    def cargar_css():
        with open("assets/login.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

    # Layout centrado
    _, col, _ = st.columns([1, 1.4, 1])

    with col:
        st.markdown('<div class="login-container">', unsafe_allow_html=True)

        st.markdown('<div class="login-logo">🛡️</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-title">WebShield AI</div>', unsafe_allow_html=True)
        st.markdown('<div class="login-sub">Asistente de Seguridad Web con IA</div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="login-badge">
            Acceso restringido — Solo equipo autorizado<br>
            Universidad Iberoamericana Leon · 2026
        </div>
        """, unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            usuario_input  = st.text_input("USUARIO", placeholder="Escribe tu usuario")
            password_input = st.text_input("CONTRASEÑA", type="password", placeholder="Escribe tu contraseña")
            submit         = st.form_submit_button("INGRESAR", use_container_width=True)

            ...
        
        st.markdown('<div class="login-footer">WebShield AI · Herramientas de Ciberseguridad</div>', unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

    return False


def cerrar_sesion():
    for key in ["session_token", "usuario_actual", "nombre_actual",
                "scan_json", "resultado_ia", "url_analizada", "chat_messages"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()