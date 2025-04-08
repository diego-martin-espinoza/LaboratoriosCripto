


def cifrar_cesar(texto, desplazamiento):
    texto_cifrado = ""
    for letra in texto:
        if letra.isalpha():
            inicio = ord('A') if letra.isupper() else ord('a')
            texto_cifrado += chr((ord(letra) - inicio + desplazamiento) % 26 + inicio)
        else:
            texto_cifrado += letra
    return texto_cifrado

texto_a_cifrar = input("Ingrese el texto a cifrar: \n")
print("--")
desplazamiento_cesar = int(input("Ingrese el desplazamiento Cesar: \n"))
print("________________\n")
print("El texto cifrado es : " + cifrar_cesar(texto_a_cifrar, desplazamiento_cesar))