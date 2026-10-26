# forger_truncate.py
import sys

# Usaremos la firma válida que generaste en el paso 1
archivo_valido = "prueba1_valida.csig"
archivo_roto = "prueba5_malformada.csig"

try:
    with open(archivo_valido, 'rb') as f:
        datos = f.read()
        
    # Le cortamos los últimos 200 bytes para romper la estructura del fichero
    datos_rotos = datos[:-200] 
    
    with open(archivo_roto, 'wb') as f:
        f.write(datos_rotos)
        
    print(f"[+] Archivo malformado generado con éxito: {archivo_roto}")
except FileNotFoundError:
    print(f"[-] Error: No se encuentra el archivo {archivo_valido}. Asegúrate de haberlo creado antes.")