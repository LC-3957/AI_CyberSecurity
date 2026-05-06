"""
ai_analista.py
Módulo de integración de IA — Proyecto Final: Asistente de Seguridad Web
Materia: Herramientas de Ciberseguridad | Prof. Pablo Náchez
Universidad Iberoamericana León — 2026
"""

import os, json
import anthropic
from dotenv import load_dotenv
load_dotenv()

cliente = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
MODELO  = "claude-sonnet-4-6"

NO_EMOJIS = (
    "IMPORTANTE: No uses emojis, íconos ni símbolos especiales en tu respuesta. "
    "Usa solo texto plano, formato Markdown (negritas, listas, encabezados) pero sin emojis. "
)


def _llamar_ia(system_prompt: str, user_prompt: str) -> str:
    respuesta = cliente.messages.create(
        model=MODELO,
        max_tokens=1024,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )
    return respuesta.content[0].text.strip()


def resumir_hallazgos(scan_json: dict) -> str:
    system = (
        "Eres un analista de ciberseguridad experto. "
        "Tu tarea es leer un reporte de escaneo de seguridad web en formato JSON "
        "y generar un resumen claro, conciso y en español de los hallazgos encontrados. "
        "El resumen debe ser comprensible para cualquier persona, técnica o no. "
        "No repitas el JSON. Organiza el resumen en 3-5 puntos clave. "
        + NO_EMOJIS
    )
    user = (
        f"Aquí está el reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Por favor genera el resumen de hallazgos."
    )
    return _llamar_ia(system, user)


def clasificar_riesgos(scan_json: dict) -> str:
    system = (
        "Eres un experto en ciberseguridad. "
        "Analiza el reporte de escaneo y clasifica cada hallazgo con un nivel de riesgo: "
        "ALTO, MEDIO o BAJO. "
        "Devuelve una lista ordenada de mayor a menor riesgo. "
        "Para cada hallazgo indica: nombre del hallazgo, nivel de riesgo y una razón breve en una línea. "
        "Responde en español. "
        + NO_EMOJIS
    )
    user = (
        f"Reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Clasifica y prioriza todos los riesgos encontrados."
    )
    return _llamar_ia(system, user)


def explicar_impacto(scan_json: dict) -> str:
    system = (
        "Eres un consultor de seguridad web. "
        "Para cada hallazgo del reporte, explica en términos simples qué impacto real "
        "podría tener si un atacante lo aprovechara. "
        "Sé específico: menciona qué tipo de ataque habilitaría y qué información o sistema podría verse afectado. "
        "El objetivo es que el equipo dueño del sitio entienda el riesgo real. "
        "Responde en español. "
        + NO_EMOJIS
    )
    user = (
        f"Reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Explica el impacto potencial de cada hallazgo."
    )
    return _llamar_ia(system, user)


def sugerir_mitigaciones(scan_json: dict) -> str:
    system = (
        "Eres un ingeniero de seguridad web. "
        "Para cada hallazgo del reporte, proporciona una recomendación técnica concreta y aplicable "
        "para corregirlo o mitigarlo. "
        "Incluye ejemplos de configuración o comandos cuando sea posible. "
        "Prioriza las acciones de mayor impacto. "
        "Responde en español. "
        + NO_EMOJIS
    )
    user = (
        f"Reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Proporciona mitigaciones técnicas para cada hallazgo."
    )
    return _llamar_ia(system, user)


def traducir_ejecutivo(scan_json: dict) -> str:
    system = (
        "Eres un consultor de ciberseguridad que presenta resultados a directivos de una empresa. "
        "Transforma el reporte técnico en un resumen ejecutivo breve (máximo 200 palabras). "
        "Usa lenguaje de negocio, sin tecnicismos. "
        "Menciona: el estado general de seguridad del sitio, los 2-3 riesgos más importantes "
        "en términos de impacto al negocio, y una recomendación de acción inmediata. "
        "Responde en español. "
        + NO_EMOJIS
    )
    user = (
        f"Reporte técnico del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Genera el resumen ejecutivo."
    )
    return _llamar_ia(system, user)


def analizar_completo(scan_json: dict) -> dict:
    print(f"[IA] Analizando resultados de: {scan_json.get('url_analizada', '?')}")
    analisis = {
        "url_analizada":     scan_json.get("url_analizada"),
        "resumen":           resumir_hallazgos(scan_json),
        "riesgos":           clasificar_riesgos(scan_json),
        "impacto":           explicar_impacto(scan_json),
        "mitigaciones":      sugerir_mitigaciones(scan_json),
        "resumen_ejecutivo": traducir_ejecutivo(scan_json),
    }
    print("[IA] Análisis completo.")
    return analisis