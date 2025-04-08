from scapy.all import sniff, ICMP, Raw
from colorama import Fore, Style, init
import string

# Inicializa colorama
init(autoreset=True)

mensaje = []

# Lista básica de palabras comunes (puedes ampliarla)
PALABRAS_COMUNES = {
    'hola', 'mundo', 'mensaje', 'este', 'es', 'una', 'prueba',
    'texto', 'final', 'de', 'la', 'el', 'en', 'con'
}

def cesar(texto, desplazamiento):
    resultado = ''
    for c in texto:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            resultado += chr((ord(c) - base - desplazamiento) % 26 + base)
        else:
            resultado += c
    return resultado

def puntuacion_texto(texto):
    palabras = texto.lower().split()
    return sum(1 for p in palabras if p in PALABRAS_COMUNES)

def aplicar_cesar_todos_desplazamientos(texto):
    candidatos = []
    for desplazamiento in range(26):
        descifrado = cesar(texto, desplazamiento)
        score = puntuacion_texto(descifrado)
        candidatos.append((desplazamiento, descifrado, score))
    
    # Obtener el desplazamiento con más coincidencias de palabras comunes
    mejor = max(candidatos, key=lambda x: x[2])
    return candidatos, mejor[0]

def procesar_paquete(packet):
    if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw):
        char = packet[Raw].load.decode(errors='ignore')
        if char in string.printable:
            mensaje.append(char)

def main():
    print("Escuchando paquetes ICMP tipo 8 (Echo Request) por 30 segundos...")
    sniff(filter="icmp", prn=procesar_paquete, store=0, timeout=30)

    texto = ''.join(mensaje)
    print(f"\nMensaje crudo recibido: {texto}")

    candidatos, mejor_desplazamiento = aplicar_cesar_todos_desplazamientos(texto)

    print("\n--- Posibles mensajes con cifrado César ---")
    for desplazamiento, resultado, _ in candidatos:
        if desplazamiento == mejor_desplazamiento:
            print(Fore.GREEN + f"Desplazamiento {desplazamiento:2}: {resultado}")
        else:
            print(f"Desplazamiento {desplazamiento:2}: {resultado}")
    print("-" * 40)

if __name__ == "__main__":
    main()
