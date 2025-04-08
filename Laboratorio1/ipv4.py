from scapy.all import IP, ICMP, Raw, send
import time

def send_icmp_to_google(message, delay=0.2):
    target_ip = "8.8.8.8"
    print(f"Enviando mensaje a {target_ip} carácter por carácter...")
    
    for char in message:
        packet = IP(dst=target_ip) / ICMP(type=8) / Raw(load=char.encode())
        send(packet, verbose=False)
        print(f"Enviado: {char}")
        time.sleep(delay)
    
    print("Mensaje enviado completamente.")

if __name__ == "__main__":
    mensaje = input("Ingrese el mensaje a enviar: ")
    send_icmp_to_google(mensaje)