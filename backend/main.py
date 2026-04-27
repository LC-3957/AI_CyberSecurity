from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
import ssl
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

app = FastAPI(title="API de Análisis de Seguridad Web", version="1.0")

class ScanRequest(BaseModel):
    url: str

class ScanResult(BaseModel):
    url_analizada: str
    headers_seguridad: dict | None = None
    ssl_valido: bool | None = None
    tecnologias: list | None = None
    puertos_abiertos: list | None = None
    formularios: int | None = None
    rutas_expuestas: list | None = None

# --- FUNCIONES DE VALIDACIÓN ---

def revisar_headers(url: str) -> dict:
    """Valida la presencia de encabezados de seguridad HTTP."""
    headers_criticos = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection"
    ]
    
    resultados = {}
    try:
        # Hacemos la petición con un timeout corto para no bloquear la API
        respuesta = requests.get(url, timeout=5)
        headers_sitio = respuesta.headers
        
        # Revisamos cuáles encabezados críticos están presentes
        for header in headers_criticos:
            if header in headers_sitio:
                resultados[header] = {"presente": True, "valor": headers_sitio[header]}
            else:
                resultados[header] = {"presente": False, "valor": "Faltante"}
                
        return resultados
        
    except requests.RequestException as e:
        # Si la URL no existe o rechaza la conexión, lo atrapamos aquí
        return {"error": f"No se pudo conectar al sitio: {str(e)}"}
    
def validar_ssl(url: str) -> bool:
    """Valida si el sitio tiene un certificado SSL/TLS válido."""
    try:

        hostname = urlparse(url).netloc
        if not hostname:
            return False
            
        contexto = ssl.create_default_context()
        # Nos conectamos al puerto 443 (HTTPS) con un timeout de 5 segundos
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with contexto.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Si logramos envolver el socket sin que salte una excepción, el certificado es válido
                return True
    except Exception:
        # Si falla (ej. certificado expirado, no coincide el dominio, o puerto cerrado)
        return False

def detectar_tecnologias(url: str) -> list:
    """Detecta tecnologías visibles en cabeceras y código HTML."""
    tecnologias = []
    try:
        # Hacemos la petición
        respuesta = requests.get(url, timeout=5)
        
        # 1. Buscar en los Headers HTTP (Servidor y Backend)
        headers = respuesta.headers
        if 'Server' in headers:
            tecnologias.append(f"Servidor: {headers['Server']}")
        if 'X-Powered-By' in headers:
            tecnologias.append(f"Backend: {headers['X-Powered-By']}")
            
        # 2. Buscar en el código fuente HTML (CMS o Generadores)
        soup = BeautifulSoup(respuesta.text, 'html.parser')
        
        # Buscamos la etiqueta meta generator (muy común en WordPress, Drupal, etc.)
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator and generator.get('content'):
            tecnologias.append(f"CMS/Generador: {generator.get('content')}")
            
        # Buscamos indicios de frameworks frontend en los scripts
        scripts = [script.get('src', '') for script in soup.find_all('script')]
        for src in scripts:
            if 'react' in src.lower():
                tecnologias.append("Frontend: React")
                break
            if 'vue' in src.lower():
                tecnologias.append("Frontend: Vue.js")
                break
                
    except Exception:
        # Si algo falla en el scraping, simplemente devolvemos la lista como esté
        pass
        
    return list(set(tecnologias)) # Usamos set() para borrar duplicados si los hubiera

def escanear_puertos(url: str) -> list:
    """Escanea puertos comunes usando sockets nativos para evitar dependencias de OS."""
    hostname = urlparse(url).netloc
    if not hostname:
        return []
    
    # Quitamos el puerto si viene en la URL (ej. localhost:8000)
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    puertos_comunes = {
        21: "FTP",
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP-Alt"
    }
    
    puertos_abiertos = []
    for puerto, servicio in puertos_comunes.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5) # Timeout súper corto para que el escaneo vuele
                resultado = s.connect_ex((hostname, puerto))
                if resultado == 0:
                    puertos_abiertos.append(f"Puerto {puerto} abierto ({servicio})")
        except Exception:
            pass
            
    return puertos_abiertos

def detectar_formularios(url: str) -> int:
    """Cuenta los formularios presentes en la página principal."""
    try:
        respuesta = requests.get(url, timeout=5)
        soup = BeautifulSoup(respuesta.text, 'html.parser')
        # Buscamos todas las etiquetas de formulario
        formularios = soup.find_all('form')
        return len(formularios)
    except Exception:
        return 0

def buscar_rutas(url: str) -> list:
    """Busca rutas y archivos públicos comunes de forma no destructiva."""
    rutas_comunes = ['/robots.txt', '/sitemap.xml', '/admin', '/login']
    rutas_encontradas = []
    
    base_url = url.rstrip('/') # Quitamos la diagonal final si la tiene
    
    for ruta in rutas_comunes:
        try:
            # No queremos descargar la página entera, solo ver si existe (HEAD es más rápido que GET)
            respuesta = requests.head(f"{base_url}{ruta}", timeout=3)
            # Si responde 200 (OK) o 401/403 (Existe pero pide clave), la contamos
            if respuesta.status_code in [200, 401, 403]:
                rutas_encontradas.append(f"Ruta detectada: {ruta} (Status: {respuesta.status_code})")
        except Exception:
            pass
            
    return rutas_encontradas

# --- ENDPOINTS ---

@app.get("/")
def home():
    return {"mensaje": "API de Ciberseguridad Activa. Usa el endpoint /scan para analizar."}

@app.post("/scan", response_model=ScanResult)
def run_scan(request: ScanRequest):
    target_url = request.url
    
    if not target_url.startswith("http"):
        raise HTTPException(status_code=400, detail="La URL debe comenzar con http:// o https://")

    # --- EJECUCIÓN DE LAS 6 VALIDACIONES ---
    resultados_headers = revisar_headers(target_url)
    estado_ssl = validar_ssl(target_url)
    tec_detectadas = detectar_tecnologias(target_url)
    puertos = escanear_puertos(target_url)
    num_forms = detectar_formularios(target_url)
    rutas = buscar_rutas(target_url)
    
    # --- ENSAMBLE DEL JSON FINAL ---
    resultados = ScanResult(
        url_analizada=target_url,
        headers_seguridad=resultados_headers,
        ssl_valido=estado_ssl,
        tecnologias=tec_detectadas,
        puertos_abiertos=puertos,
        formularios=num_forms,
        rutas_expuestas=rutas
    )
    
    return resultados