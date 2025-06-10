from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import base64
import hashlib
import random
import string
#Tamaños de las llaves
# DES       ---> Key = 64bits (8 bytes), 56 (7 bytes) de la llave y 8 de paridad (1 byte0) IV = 64 bits 
# DES3      ---> Key = 112 bits o 168 bits 
# AES-256   ---> Key = 256 bits 



############### DES ###############
# https://anycript.com/crypto/des

def cifrarDES(input_key, input_data,input_iv):
    print("--- Cifrado DES ---")
    print("\nLlave original:", input_key)
    print("IV original:", input_iv)
    print("-----------")

    # Asegúrate de que la llave sea tipo bytes
#procesar llave
    key_bytes = input_key.encode('utf-8')

    if len(key_bytes) > 8:
        key_for_des = key_bytes[:8]
        print("Llave truncada para DES (8 bytes):", key_for_des)
    else:
        padding_needed = 8 - len(input_key)
        random_padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_needed))
        key_for_des_str = input_key + random_padding
        print("Llave con padding aleatorio para DES (8 bytes):", key_for_des_str)
        key_for_des = key_for_des_str.encode('utf-8')
#procesar iv
    iv_bytes = input_iv.encode('utf-8')
    if len(iv_bytes) > 8:
        iv_for_des = iv_bytes[:8]
        print("IV truncado para DES (8 bytes):", iv_for_des)
    else:
        padding_needed = 8 - len(iv_bytes)
        random_padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_needed))
        iv_for_des_str = input_iv + random_padding
        print("IV con padding aleatorio para DES (8 bytes):", iv_for_des_str)
        iv_for_des = iv_for_des_str.encode('utf-8')

    # Preparamos los datos
    print("-----------")
    data = input_data.encode('utf-8') 

    # Cifrado DES en modo CBC
    cipher = DES.new(key_for_des, DES.MODE_CBC, iv_for_des)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))

    print("Data cifrada con DES:", ciphertext)

    ciphertext_b64 = base64.b64encode(ciphertext)

# Si necesitas texto (string), decodifica a UTF-8
    ciphertext_b64_str = ciphertext_b64.decode('utf-8')
    print("--")
    print("Data cifrada a base64:", ciphertext_b64_str)
    print("-----------")
    return ciphertext, key_for_des, iv_for_des


def descifrarDES(key_for_des: bytes, ciphertext: bytes, iv_for_des: bytes):
    cipher = DES.new(key_for_des, DES.MODE_CBC, iv_for_des)
    decrypted_padded = cipher.decrypt(ciphertext)
    # Quitar el padding
    try:
        decrypted = unpad(decrypted_padded, DES.block_size)
    except ValueError:
        print("Padding incorrecto. ¿Quizás usaste la llave equivocada?")
        return

    print("Mensaje descifrado DES:", decrypted.decode('utf-8'))
    print("\n====================\n")



############### 3DES ###############
#https://en.metools.info/enencrypt/tripledes277.html


def cifrar3DES(input_key, input_data,input_iv):
    print("--- Cifrado 3DES ---")
    print("\nLlave original:", input_key)
    print("IV original:", input_iv)
    print("-----------")
    # Asegúrate de que la llave sea tipo bytes
#procesar llave
    key_bytes = input_key.encode('utf-8')
    if len(key_bytes) >= 24:
        key_for_3des = key_bytes[:24]
        print("Llave truncada para 3DES (24 bytes):", key_for_3des)

    elif len(key_bytes) >= 16:
        key_for_3des_16 = key_bytes[:16]
        aux = key_for_3des_16[:8]
        key_for_3des = key_for_3des_16 + aux
        print("Llave truncada (16 bytes) para 3DES y concatenada K1 - K2 - K1 (24 bytes): \n", key_for_3des)
    
    else:
        padding_needed = 24 - len(key_bytes)
        random_padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_needed))
        key_for_3des_str = input_key + random_padding
        print("Llave con padding aleatorio para 3DES (24 bytes):", key_for_3des_str)
        key_for_3des = key_for_3des_str.encode('utf-8')

#procesar iv
    iv_bytes = input_iv.encode('utf-8')
    if len(iv_bytes) > 8:
        iv_for_3des = iv_bytes[:8]
        print("IV truncado para 3DES (8 bytes):", iv_for_3des)
    else:
        padding_needed = 8 - len(iv_bytes)
        random_padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_needed))
        iv_for_3des_str = input_iv + random_padding
        print("IV con padding aleatorio para 3DES (8 bytes):", iv_for_3des_str)
        iv_for_3des = iv_for_3des_str.encode('utf-8')
    # Preparamos los datos
    print("-----------")
    data = input_data.encode('utf-8') 

    # Cifrado DES en modo CBC
    cipher = DES3.new(key_for_3des, DES3.MODE_CBC, iv_for_3des)
    ciphertext = cipher.encrypt(pad(data, DES3.block_size))

    print("Data cifrada con 3DES:", ciphertext)

    ciphertext_b64 = base64.b64encode(ciphertext)

    ciphertext_b64_str = ciphertext_b64.decode('utf-8')
    print("--")
    print("Data cifrada a base64:", ciphertext_b64_str)
    print("-----------")
    return ciphertext, key_for_3des, iv_for_3des


def descifrar3DES(key_for_3des: bytes, ciphertext: bytes, iv_for_3des: bytes):
    cipher = DES3.new(key_for_3des, DES3.MODE_CBC, iv_for_3des)
    decrypted_padded = cipher.decrypt(ciphertext)
    # Quitar el padding
    try:
        decrypted = unpad(decrypted_padded, DES3.block_size)
    except ValueError:
        print("Padding incorrecto. ¿Quizás usaste la llave equivocada?")
        return

    print("Mensaje descifrado 3DES:", decrypted.decode('utf-8'))
    print("\n====================\n")


################ AES ################

def cifrarAES(input_key, input_data,input_iv):
    print("--- Cifrado AES ---")
    print("\nLlave original:", input_key)
    print("IV original:", input_iv)
    print("-----------")

    # Asegúrate de que la llave sea tipo bytes
#procesar llave
    key_bytes = input_key.encode('utf-8')
    if len(key_bytes) >= 32:
        key_for_aes = key_bytes[:32]
        print("Llave truncada para AES (32 bytes):", key_for_aes)

    else:
        padding_needed = 32 - len(key_bytes)
        random_padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_needed))
        key_for_aes_str = input_key + random_padding
        print("Llave con padding aleatorio para AES (32 bytes):", key_for_aes_str)
        key_for_aes = key_for_aes_str.encode('utf-8')

#procesar iv
    iv_bytes = input_iv.encode('utf-8')
    if len(iv_bytes) >= 16:
        iv_for_aes = iv_bytes[:16]
        print("IV truncado para AES (16 bytes):", iv_for_aes)
    else:
        padding_needed = 16 - len(iv_bytes)
        random_padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_needed))
        iv_for_aes_str = input_iv + random_padding
        print("IV con padding aleatorio para aes (16 bytes):", iv_for_aes_str)
        iv_for_aes = iv_for_aes_str.encode('utf-8')
    # Preparamos los datos
    print("-----------")
    data = input_data.encode('utf-8') 

    # Cifrado AES en modo CBC
    cipher = AES.new(key_for_aes, AES.MODE_CBC, iv_for_aes)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))

    print("Data cifrada con AES:", ciphertext)

    ciphertext_b64 = base64.b64encode(ciphertext)

# Si necesitas texto (string), decodifica a UTF-8
    ciphertext_b64_str = ciphertext_b64.decode('utf-8')
    print("--")
    print("Data cifrada a base64:", ciphertext_b64_str)
    print("-----------")
    return ciphertext, key_for_aes, iv_for_aes


def descifrarAES(key_for_aes: bytes, ciphertext: bytes, iv_for_aes: bytes):
    cipher = AES.new(key_for_aes, AES.MODE_CBC, iv_for_aes)
    decrypted_padded = cipher.decrypt(ciphertext)
    # Quitar el padding
    try:
        decrypted = unpad(decrypted_padded, AES.block_size)
    except ValueError:
        print("Padding incorrecto. ¿Quizás usaste la llave equivocada?")
        return
        
    print("Mensaje descifrado AES:", decrypted.decode('utf-8'))
    print("\n====================\n")



################ Main ###################
print("\n==============================\n")


#verificar que la llave al dividirse no degenera el 3DES a un DES simple
flag = True
while (flag == True):
    print("Ingrese la llave :")
    input_key = input()
    print("------")

    if(len(input_key) >= 24):
        ver_key = input_key[:24]
        k1 = ver_key[:8]
        k2 = ver_key[8:16]
        k3 = ver_key[16:24]
        if(k1 == k2 == k3):
            print("La llave hace que 3DES se degenere: K1 = K2 = K3. Esto reduce la seguridad a DES simple.")
            print("\nIngrese una llave válida.")
            print("------")
        else:
            flag = False

    elif(len(input_key) >= 16):
        ver_key = input_key[:16]
        k1 = ver_key[:8]
        k2 = ver_key[8:16]
        if(k1 == k2):
            print("La llave hace que 3DES se degenere: K1 = K2. Esto reduce la seguridad a DES simple.")
            print("\nIngrese una llave válida.")
            print("------")
        else:
            flag = False

    else:
        flag = False


    



print("Ingrese la data a cifrar:")
input_data= input()
print("------")

print("Ingrese el IV:")
input_iv= input()
print("\n==============================\n")

#Cifrado y Descifrado DES
ciphertext, key_usada, iv_usado =cifrarDES(input_key, input_data, input_iv)
descifrarDES(key_usada, ciphertext, iv_usado)

#Cifrado y Descifrado 3DES
ciphertext, key_usada, iv_usado =cifrar3DES(input_key, input_data, input_iv)
descifrar3DES(key_usada, ciphertext, iv_usado)

#Cifrado y Descifrado AES-256
ciphertext, key_usada, iv_usado =cifrarAES(input_key, input_data, input_iv)
descifrarAES(key_usada, ciphertext, iv_usado)
