"""
ai_analyzer.py
Módulo de integración de IA — Proyecto Final: Asistente de Seguridad Web
Materia: Herramientas de Ciberseguridad | Prof. Pablo Náchez
Alumnos: Lyzzet Valenzuela Cabello
Francisco Emiliano Guillen Calderon
Diego Flores Prudente
Universidad Iberoamericana León — 2026

Este módulo recibe el JSON de hallazgos generado por main.py (Diego)
y lo procesa con la API de Claude para cumplir las 5 funciones de IA requeridas.
"""

import os
import json
import anthropic

from dotenv import load_dotenv
load_dotenv()


cliente = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
MODELO = "claude-sonnet-4-6"   # modelo gratuito con free tier



#  UTILIDAD INTERNA

def _llamar_ia(system_prompt: str, user_prompt: str) -> str:
    """
    Función auxiliar que realiza la llamada a la API de Claude
    y devuelve el texto de respuesta limpio.
    """
    respuesta = cliente.messages.create(
        model=MODELO,
        max_tokens=1024,
        system=system_prompt,
        messages=[
            {"role": "user", "content": user_prompt}
        ]
    )
    return respuesta.content[0].text.strip()



#  FUNCIÓN 1 — Resumir hallazgos

def resumir_hallazgos(scan_json: dict) -> str:
    """
    Toma el JSON del escaneo y devuelve un resumen claro
    de los hallazgos más importantes.
    """
    system = (
        "Eres un analista de ciberseguridad experto. "
        "Tu tarea es leer un reporte de escaneo de seguridad web en formato JSON "
        "y generar un resumen claro, conciso y en español de los hallazgos encontrados. "
        "El resumen debe ser comprensible para cualquier persona, técnica o no. "
        "No repitas el JSON. Organiza el resumen en 3-5 puntos clave."
    )
    user = (
        f"Aquí está el reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Por favor genera el resumen de hallazgos."
    )
    return _llamar_ia(system, user)



#  FUNCIÓN 2 — Clasificar y priorizar riesgos

def clasificar_riesgos(scan_json: dict) -> str:
    """
    Clasifica cada hallazgo con un nivel de riesgo (Alto / Medio / Bajo)
    y los prioriza de mayor a menor urgencia.
    """
    system = (
        "Eres un experto en ciberseguridad. "
        "Analiza el reporte de escaneo y clasifica cada hallazgo con un nivel de riesgo: "
        "ALTO, MEDIO o BAJO. "
        "Devuelve una lista ordenada de mayor a menor riesgo. "
        "Para cada hallazgo indica: nombre del hallazgo, nivel de riesgo y una razón breve en una línea. "
        "Responde en español."
    )
    user = (
        f"Reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Clasifica y prioriza todos los riesgos encontrados."
    )
    return _llamar_ia(system, user)



#  FUNCIÓN 3 — Explicar impacto de hallazgos

def explicar_impacto(scan_json: dict) -> str:
    """
    Explica qué puede pasar si cada hallazgo es explotado por un atacante.
    El enfoque es educativo y orientado a concientización.
    """
    system = (
        "Eres un consultor de seguridad web. "
        "Para cada hallazgo del reporte, explica en términos simples qué impacto real "
        "podría tener si un atacante lo aprovechara. "
        "Sé específico: menciona qué tipo de ataque habilitaría y qué información o sistema podría verse afectado. "
        "El objetivo es que el equipo dueño del sitio entienda el riesgo real. "
        "Responde en español."
    )
    user = (
        f"Reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Explica el impacto potencial de cada hallazgo."
    )
    return _llamar_ia(system, user)



#  FUNCIÓN 4 — Sugerir mitigaciones

def sugerir_mitigaciones(scan_json: dict) -> str:
    """
    Proporciona recomendaciones técnicas concretas para corregir
    cada hallazgo identificado en el escaneo.
    """
    system = (
        "Eres un ingeniero de seguridad web. "
        "Para cada hallazgo del reporte, proporciona una recomendación técnica concreta y aplicable "
        "para corregirlo o mitigarlo. "
        "Incluye ejemplos de configuración o comandos cuando sea posible. "
        "Prioriza las acciones de mayor impacto. "
        "Responde en español."
    )
    user = (
        f"Reporte de seguridad del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Proporciona mitigaciones técnicas para cada hallazgo."
    )
    return _llamar_ia(system, user)



#  FUNCIÓN 5 — Traducir a lenguaje ejecutivo

def traducir_ejecutivo(scan_json: dict) -> str:
    """
    Genera un reporte ejecutivo en lenguaje no técnico,
    dirigido a directivos o personas sin conocimientos de seguridad.
    """
    system = (
        "Eres un consultor de ciberseguridad que presenta resultados a directivos de una empresa. "
        "Transforma el reporte técnico en un resumen ejecutivo breve (máximo 200 palabras). "
        "Usa lenguaje de negocio, sin tecnicismos. "
        "Menciona: el estado general de seguridad del sitio, los 2-3 riesgos más importantes "
        "en términos de impacto al negocio, y una recomendación de acción inmediata. "
        "Responde en español."
    )
    user = (
        f"Reporte técnico del sitio '{scan_json.get('url_analizada', 'desconocido')}':\n\n"
        f"{json.dumps(scan_json, ensure_ascii=False, indent=2)}\n\n"
        "Genera el resumen ejecutivo."
    )
    return _llamar_ia(system, user)


#  FUNCIÓN PRINCIPAL — Análisis completo

def analizar_completo(scan_json: dict) -> dict:
    """
    Ejecuta las 5 funciones de IA sobre el JSON del escaneo
    y devuelve un diccionario con todos los resultados.

    Uso desde main.py o el bot:
        from ai_analyzer import analizar_completo
        resultados_ia = analizar_completo(scan_json)
    """
    print(f"[IA] Analizando resultados de: {scan_json.get('url_analizada', '?')}")

    analisis = {
        "url_analizada": scan_json.get("url_analizada"),
        "resumen":         resumir_hallazgos(scan_json),
        "riesgos":         clasificar_riesgos(scan_json),
        "impacto":         explicar_impacto(scan_json),
        "mitigaciones":    sugerir_mitigaciones(scan_json),
        "resumen_ejecutivo": traducir_ejecutivo(scan_json),
    }

    print("[IA] Análisis completo.")
    return analisis


#  MODO PRUEBA — ejecuta con el JSON de ejemplo de Diego
if __name__ == "__main__":
    # JSON de prueba enviado por Diego
    scan_ejemplo = {
        "url_analizada": "https://wordpress.org",
        "headers_seguridad": {
            "Strict-Transport-Security": {"presente": True,  "valor": "max-age=3600"},
            "Content-Security-Policy":   {"presente": False, "valor": "Faltante"},
            "X-Frame-Options":           {"presente": True,  "valor": "SAMEORIGIN"},
            "X-Content-Type-Options":    {"presente": False, "valor": "Faltante"},
            "X-XSS-Protection":          {"presente": False, "valor": "Faltante"},
        },
        "ssl_valido": True,
        "tecnologias": [
            "CMS/Generador: WordPress 7.1-alpha-62259",
            "Servidor: nginx"
        ],
        "puertos_abiertos": [
            "Puerto 80 abierto (HTTP)",
            "Puerto 443 abierto (HTTPS)"
        ],
        "formularios": 1,
        "rutas_expuestas": [
            "Ruta detectada: /robots.txt (Status: 200)",
            "Ruta detectada: /sitemap.xml (Status: 200)"
        ]
    }

    resultado = analizar_completo(scan_ejemplo)

    print("\n" + "="*60)
    print("📋  RESUMEN DE HALLAZGOS")
    print("="*60)
    print(resultado["resumen"])

    print("\n" + "="*60)
    print("⚠️  CLASIFICACIÓN DE RIESGOS")
    print("="*60)
    print(resultado["riesgos"])

    print("\n" + "="*60)
    print("💥  IMPACTO POTENCIAL")
    print("="*60)
    print(resultado["impacto"])

    print("\n" + "="*60)
    print("🛠️  MITIGACIONES SUGERIDAS")
    print("="*60)
    print(resultado["mitigaciones"])

    print("\n" + "="*60)
    print("📊  RESUMEN EJECUTIVO")
    print("="*60)
    print(resultado["resumen_ejecutivo"])