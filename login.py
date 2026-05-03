"""
login.py — Sistema de autenticación seguro
Proyecto Final: Asistente de Seguridad Web con IA
Materia: Herramientas de Ciberseguridad | Prof. Pablo Náchez
Universidad Iberoamericana León — 2026

Características de seguridad:
- Contraseñas hasheadas con bcrypt (no se guardan en texto plano)
- Bloqueo temporal tras 3 intentos fallidos
- Token de sesión firmado con HMAC-SHA256
- Tiempo de sesión limitado a 2 horas
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
#  USUARIOS AUTORIZADOS
#  Las contraseñas están hasheadas con bcrypt
#  Para generar un nuevo hash: bcrypt.hashpw(b"tupassword", bcrypt.gensalt())
# ────────────────────────────────────────────

# Para generar hashes nuevos corre: python generar_hashes.py

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
        "nombre": "Francisco Emiliano Guillén",
        "hash": "$2b$12$8e6jPLNiYfNssol/yhZ5DuANa1xl7nQploYLg5d1yq5LpOkt2jPCu"
    }
}

# ────────────────────────────────────────────
#  CONFIGURACIÓN DE SEGURIDAD
# ────────────────────────────────────────────
MAX_INTENTOS      = 3          # intentos antes de bloqueo
BLOQUEO_SEGUNDOS  = 300        # 5 minutos de bloqueo
SESION_SEGUNDOS   = 7200       # 2 horas de sesión
SECRET_KEY        = os.environ.get("SESSION_SECRET", "webshield-ibero-2026-secret-key")


# ────────────────────────────────────────────
#  FUNCIONES DE SEGURIDAD
# ────────────────────────────────────────────

def _generar_token(usuario: str) -> str:
    """Genera un token de sesión firmado con HMAC-SHA256."""
    timestamp = str(int(time.time()))
    mensaje   = f"{usuario}:{timestamp}"
    firma     = hmac.new(
        SECRET_KEY.encode(),
        mensaje.encode(),
        hashlib.sha256
    ).hexdigest()
    return f"{mensaje}:{firma}"


def _validar_token(token: str) -> str | None:
    """
    Valida el token de sesión.
    Devuelve el nombre de usuario si es válido, None si no.
    """
    try:
        partes = token.split(":")
        if len(partes) != 3:
            return None

        usuario, timestamp, firma_recibida = partes

        # Verificar firma
        mensaje      = f"{usuario}:{timestamp}"
        firma_esperada = hmac.new(
            SECRET_KEY.encode(),
            mensaje.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(firma_recibida, firma_esperada):
            return None

        # Verificar expiración
        if time.time() - int(timestamp) > SESION_SEGUNDOS:
            return None

        return usuario

    except Exception:
        return None


def _esta_bloqueado(usuario: str) -> tuple[bool, int]:
    """
    Verifica si un usuario está bloqueado por intentos fallidos.
    Devuelve (bloqueado, segundos_restantes).
    """
    clave_intentos = f"intentos_{usuario}"
    clave_tiempo   = f"bloqueo_tiempo_{usuario}"

    intentos      = st.session_state.get(clave_intentos, 0)
    tiempo_bloqueo = st.session_state.get(clave_tiempo, 0)

    if intentos >= MAX_INTENTOS and tiempo_bloqueo > 0:
        restante = int(tiempo_bloqueo - time.time())
        if restante > 0:
            return True, restante
        else:
            # Bloqueo expiró, resetear
            st.session_state[clave_intentos] = 0
            st.session_state[clave_tiempo]   = 0

    return False, 0


def _registrar_intento_fallido(usuario: str):
    """Registra un intento fallido y bloquea si se superó el límite."""
    clave_intentos = f"intentos_{usuario}"
    clave_tiempo   = f"bloqueo_tiempo_{usuario}"

    intentos = st.session_state.get(clave_intentos, 0) + 1
    st.session_state[clave_intentos] = intentos

    if intentos >= MAX_INTENTOS:
        st.session_state[clave_tiempo] = time.time() + BLOQUEO_SEGUNDOS


def _resetear_intentos(usuario: str):
    """Resetea los intentos fallidos tras login exitoso."""
    st.session_state[f"intentos_{usuario}"] = 0
    st.session_state[f"bloqueo_tiempo_{usuario}"] = 0


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
#  FUNCIÓN PRINCIPAL — Mostrar pantalla de login
# ────────────────────────────────────────────

def mostrar_login() -> bool:
    """
    Muestra la pantalla de login.
    Devuelve True si el usuario está autenticado, False si no.
    """

    # ── Verificar sesión activa ──
    token = st.session_state.get("session_token")
    if token:
        usuario = _validar_token(token)
        if usuario:
            st.session_state["usuario_actual"] = usuario
            st.session_state["nombre_actual"]  = USUARIOS[usuario]["nombre"]
            return True
        else:
            # Token expirado
            del st.session_state["session_token"]

    # ── CSS del login ──
    st.markdown("""
    <style>
    .login-wrapper {
        max-width: 420px;
        margin: 6rem auto 0;
        padding: 2.5rem;
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.08);
        border-radius: 16px;
        backdrop-filter: blur(10px);
    }
    .login-logo {
        text-align: center;
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
    }
    .login-title {
        text-align: center;
        font-size: 1.4rem;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 0.2rem;
    }
    .login-sub {
        text-align: center;
        font-size: 0.75rem;
        color: #475569;
        margin-bottom: 2rem;
        letter-spacing: 0.1em;
        text-transform: uppercase;
        font-family: 'Space Mono', monospace;
    }
    .security-badge {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        background: rgba(0,255,170,0.05);
        border: 1px solid rgba(0,255,170,0.15);
        border-radius: 8px;
        padding: 0.6rem 1rem;
        margin-bottom: 1.5rem;
        font-size: 0.72rem;
        color: #94a3b8;
        font-family: 'Space Mono', monospace;
    }
    .security-dot {
        width: 8px; height: 8px;
        border-radius: 50%;
        background: #00ffaa;
        box-shadow: 0 0 6px #00ffaa;
        flex-shrink: 0;
    }
    </style>
    """, unsafe_allow_html=True)

    # ── UI del login ──
    st.markdown("""
    <div class="login-wrapper">
        <div class="login-logo">🛡️</div>
        <div class="login-title">WebShield AI</div>
        <div class="login-sub">Acceso restringido · Solo equipo autorizado</div>
        <div class="security-badge">
            <div class="security-dot"></div>
            Conexión segura · Sesión cifrada · Acceso auditado
        </div>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        with st.form("login_form", clear_on_submit=False):
            usuario_input  = st.text_input("👤 Usuario", placeholder="tu usuario")
            password_input = st.text_input("🔒 Contraseña", type="password", placeholder="••••••••••")
            submit         = st.form_submit_button("INGRESAR →", use_container_width=True, type="primary")

            if submit:
                usuario_lower = usuario_input.lower().strip()

                # Verificar bloqueo
                bloqueado, restante = _esta_bloqueado(usuario_lower)
                if bloqueado:
                    minutos = restante // 60
                    segundos = restante % 60
                    st.error(f"🔒 Cuenta bloqueada. Intenta en {minutos}m {segundos}s")
                    return False

                # Verificar credenciales
                if verificar_credenciales(usuario_lower, password_input):
                    _resetear_intentos(usuario_lower)
                    token = _generar_token(usuario_lower)
                    st.session_state["session_token"]   = token
                    st.session_state["usuario_actual"]  = usuario_lower
                    st.session_state["nombre_actual"]   = USUARIOS[usuario_lower]["nombre"]
                    st.rerun()
                else:
                    _registrar_intento_fallido(usuario_lower)
                    intentos_restantes = MAX_INTENTOS - st.session_state.get(f"intentos_{usuario_lower}", 0)
                    if intentos_restantes > 0:
                        st.error(f"❌ Usuario o contraseña incorrectos. Intentos restantes: {intentos_restantes}")
                    else:
                        st.error(f"🔒 Cuenta bloqueada por {BLOQUEO_SEGUNDOS // 60} minutos.")

        st.markdown("""
        <div style="text-align:center; margin-top:1rem; font-size:0.65rem; 
                    color:#334155; font-family:'Space Mono',monospace; letter-spacing:0.1em;">
            ACCESO SOLO PARA MIEMBROS DEL EQUIPO<br>
            UNIVERSIDAD IBEROAMERICANA LEÓN · 2026
        </div>
        """, unsafe_allow_html=True)

    return False


def cerrar_sesion():
    """Cierra la sesión del usuario actual."""
    for key in ["session_token", "usuario_actual", "nombre_actual",
                "scan_json", "resultado_ia", "url_analizada", "chat_messages"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()