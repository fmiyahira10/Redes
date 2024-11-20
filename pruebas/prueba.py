import requests

def obtener_ip_publica():
    try:
        response = requests.get('https://ifconfig.me')
        return response.text
    except requests.RequestException:
        return "No se pudo determinar la IP pública"

ip_usuario = obtener_ip_publica()
print("IP pública:", ip_usuario)
