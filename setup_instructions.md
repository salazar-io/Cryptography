# Instrucciones de Preparación del proyecto

Este documento explica cómo configurar automáticamente el entorno necesario para ejecutar el vault contanier.

## Requisitos Previos

Asegúrate de estar en el directorio raíz del proyecto:
```bash
cd /home/crypto/Cryptography/
```

Es recomendable activar tu entorno virtual si tienes uno configurado. Puedes instalar las dependencias manualmente usando `pip install -r requirements.txt`, o simplemente dejar que el script `setup_demo.py` lo haga por ti automáticamente.

## Ejecutar el Setup

Para evitar crear las carpetas, instalar dependencias y generar claves manualmente, hemos provisto un script automatizado que preparará todos los elementos necesarios para la demo.

Ejecuta el siguiente comando en tu terminal:

```bash
python setup_demo.py
```

### ¿Qué hace este script?

1. **Instalación de Dependencias**: Verifica si las librerías requeridas (`cryptography`, `pytest`) están instaladas en tu entorno. Si no lo están, las descarga e instala automáticamente vía `pip`.
2. **Estructura de Directorios**: Crea las carpetas `vault_container/plaintext`, `vault_container/encrypted_vault` y `vault_container/decrypted_files`.
3. **Archivos de Prueba**: 
   - Genera el archivo original de la demo en `vault_container/plaintext/poema.txt`.
   - Genera un archivo extra de prueba en `vault_container/plaintext/documento_prueba.txt` por si deseas realizar pruebas adicionales de cifrado.
4. **Generación de Claves (Edgar)**: Genera las claves ECC y Ed25519 para Edgar y crea un *Keystore* cifrado. 
   - **Contraseña de Edgar**: `edgar123`
5. **Generación de Claves (Laysha)**: Genera las claves ECC y Ed25519 para Laysha y crea un *Keystore* cifrado.
   - **Contraseña de Laysha**: `laysha123`
