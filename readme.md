# Secure Digital Document Vault

## Integrantes

- Salazar Serrano Edgar
- Mendoza González Mario
- Victoria Correa Laysha Daniela
- Rojas Jiménez Claudia Alin

## 1. Descripción General del Sistema

### 1.1 Problema que resuelve

La bóveda digital protege, comparte y verifica documentos digitales en entornos donde la confidencialidad, integridad y autenticidad son esenciales. El sistema está diseñado para evitar exposición de información sensible, manipulación de archivos, uso inseguro de claves privadas y compartición no controlada con múltiples destinatarios.

### 1.2 Funciones principales

El proyecto combina primitivas criptográficas modernas con una arquitectura basada en línea de comandos (CLI).

Sus funciones principales son:

- Cifrado autenticado (AEAD) para garantizar confidencialidad e integridad.
- Cifrado híbrido para proteger la clave del archivo con las llaves públicas de los destinatarios.
- Firmas digitales para autenticar el origen del archivo y proteger el contenedor.
- Separación de llaves por propósito criptográfico: cifrado y firma.
- Gestión segura de claves privadas protegidas con contraseña y KDF.
- Compartición segura con múltiples receptores.
- Verificación obligatoria de firma antes del descifrado.

El flujo general del sistema es: **Generación de llaves -> Cifrado -> Firma -> Encapsulamiento -> Verificación -> Descifrado**.

### 1.3 Alcance y límites

El sistema no incluye gestión manual de claves simétricas, no permite el uso de algoritmos débiles, no acepta generadores pseudoaleatorios no criptográficos, no almacena llaves privadas en texto plano y prohíbe la reutilización de nonces.

---

## 2. Diagrama de Arquitectura

![Arquitectura](./diagram.png)

---

## 3. Requerimientos de Seguridad

- **Confidencialidad:** un atacante con acceso al contenedor no debe obtener el contenido sin las llaves adecuadas.
- **Integridad:** cualquier modificación del archivo debe detectarse.
- **Autenticidad del remitente:** el destinatario debe validar quién firmó el archivo.
- **Protección de llaves privadas:** las llaves deben estar cifradas en disco.
- **Protección de metadatos y cabeceras:** la información del contenedor también debe estar protegida.
- **No repudio:** una firma válida queda ligada al emisor legítimo.

---

## 4. Modelo de Amenaza

### 4.1 Activos

- Contenido del archivo.
- Metadatos del archivo.
- Llaves privadas.
- Contraseñas.
- Validez de la firma.

### 4.2 Adversarios

El sistema considera atacantes externos con acceso a contenedores almacenados, destinatarios maliciosos, atacantes que alteran metadatos y atacantes con acceso temporal al dispositivo. Ninguno de ellos debe poder descifrar, falsificar firmas o modificar información protegida sin ser detectado.

---

## 5. Suposiciones de confianza

El sistema asume que el dispositivo no está comprometido por malware, que existe un generador de números aleatorios seguro, que el usuario protege su contraseña y que se emplean algoritmos criptográficos estándar sin puertas traseras.

---

## 6. Análisis de la superficie de ataque

| Punto de entrada                    | Riesgo                                           | Propiedad afectada        |
| ----------------------------------- | ------------------------------------------------ | ------------------------- |
| Entrada de archivos                 | Archivos malformados o grandes pueden causar DoS | Disponibilidad            |
| Metadatos                           | Manipulación de cabeceras o identificadores      | Integridad / Autenticidad |
| Importación y exportación de llaves | Llaves expuestas en disco                        | Confidencialidad          |
| Entrada de contraseña               | Fuerza bruta o exposición en historial           | Confidencialidad          |
| Flujo de compartición               | Inclusión de destinatarios no autorizados        | Confidencialidad          |
| Verificación de firmas              | Procesar antes de validar                        | Autenticidad / Integridad |
| Argumentos de CLI                   | Filtrado insuficiente de datos sensibles         | Confidencialidad          |

---

## 7. Restricciones de diseño derivadas de los requisitos

| Requerimiento                         | Restricción de diseño                                    |
| ------------------------------------- | -------------------------------------------------------- |
| Integridad garantizada                | Uso obligatorio de AEAD como AES-GCM o ChaCha20-Poly1305 |
| Autenticidad requerida                | Uso de firmas digitales como Ed25519                     |
| Protección de llaves privadas         | Cifrado con KDF robusto antes de guardar en disco        |
| Confidencialidad en almacenamiento    | Cifrado híbrido para múltiples destinatarios             |
| Prevención de reutilización de llaves | Uso obligatorio de CSPRNG para llaves y nonces           |

### Conclusión de diseño

La arquitectura queda orientada a resistir tanto ataques externos como errores de implementación, manteniendo cifrado, autenticación e integridad aun si el almacenamiento es comprometido.

---

## 8. Arquitectura de cifrado híbrido

El sistema usa un esquema híbrido basado en criptografía simétrica para el contenido y criptografía asimétrica para proteger la clave del archivo por destinatario.

### 8.1 Diseño híbrido

- El cifrado simétrico se usa para proteger el contenido porque es eficiente con archivos grandes.
- AES-256-GCM se utiliza para cifrar el archivo y validar su integridad.
- La clave simétrica del archivo se cifra individualmente para cada destinatario usando su clave pública.

### 8.2 Firmas digitales y autenticación de origen

El sistema incorpora Ed25519 para autenticar al emisor y proteger el contenedor `.vault`.

- Se generan pares de llaves separados para cifrado y firma.
- La firma cubre el `AAD`, el `ciphertext` y el `authentication tag`.
- La verificación de la firma ocurre antes del descifrado.
- Si los metadatos cambian, la firma deja de ser válida.

### 8.3 Efecto de la verificación

Si se altera el archivo, los metadatos o la lista de destinatarios, el proceso debe fallar antes de revelar contenido. Esto evita tanto manipulación como procesamiento innecesario de archivos no confiables.

---

## 9. Estructura del código criptográfico

La estructura del proyecto separa los scripts de uso del usuario de la lógica criptográfica.

```text
vault_container/
├── encrypted_vault/       # Archivos .vault cifrados
├── decrypted_files/       # Archivos descifrados
├── plaintext/             # Archivos originales
├── user_keys/             # Llaves de usuario
│
├── encrypt_file.py        # Cifra un archivo y lo firma
├── decrypt_file.py        # Descifra un vault tras validar firma
├── share_vault.py         # Añade nuevos destinatarios
├── generate_user_keys.py  # Genera llaves de cifrado y firma
├── test_security.py       # Pruebas de cifrado híbrido
└── test_signatures.py     # Pruebas de firmas digitales

src/crypto_vault/
├── vault.py               # Lógica principal de cifrado/descifrado híbrido
├── key_manager.py         # Gestión y derivación de llaves
└── container.py           # Empaquetado en JSON y Base64
```

### Flujo de cifrado híbrido

1. Se genera una clave simétrica única para el archivo.
2. El contenido se cifra con AES-GCM.
3. La clave del archivo se cifra para cada destinatario.
4. Se firman el AAD, el ciphertext y el tag.
5. El archivo se guarda como `.vault`.

---

## 10. Manual de uso

### 10.1 Generar llaves de usuario

```bash
python generate_user_keys.py
```

El sistema solicita el ID del usuario y una contraseña para proteger la clave privada. Ahora se generan dos pares de llaves: uno para cifrado y otro para firma.

### 10.2 Cifrar un archivo

```bash
python encrypt_file.py
```

El sistema solicita la ruta del archivo, permite agregar destinatarios y después pide la identidad del firmante, la ruta de su clave privada de firma y su contraseña. Al finalizar, se guarda el archivo cifrado en `encrypted_vault/`.

### 10.3 Compartir un vault existente

```bash
python share_vault.py
```

Este comando permite agregar nuevos destinatarios a un archivo ya cifrado. El usuario debe autenticarse para modificar el contenedor de forma segura.

### 10.4 Descifrar un archivo

```bash
python decrypt_file.py
```

El sistema solicita el archivo `.vault`, el ID del destinatario, la clave privada de cifrado y la contraseña. Después muestra quién afirma haber firmado el contenedor y pide la clave pública de firma correspondiente antes de descifrar.

---

## 11. Pruebas unitarias de seguridad

El proyecto incluye pruebas para validar el comportamiento del sistema frente a accesos no autorizados, alteraciones del contenedor y verificación estricta de firmas digitales.

### 11.1 Pruebas de seguridad del contenedor

Las pruebas de seguridad del contenedor verifican lo siguiente:

1. Múltiples destinatarios pueden descifrar de forma independiente.
2. Usuarios no autorizados son rechazados.
3. Cambios en el AAD o en la estructura JSON invalidan el descifrado.
4. Una clave privada incorrecta falla de forma segura.
5. La revocación de un destinatario rompe su acceso.

### 11.2 Pruebas de firmas digitales

Las pruebas de firmas digitales validan estos escenarios:

- **Valid signature:** el archivo se acepta cuando la firma coincide con el contenido y los metadatos.
- **Modified ciphertext:** el archivo se rechaza si el contenido cifrado fue alterado.
- **Modified metadata:** el archivo se rechaza si se modifica cualquier metadato protegido.
- **Wrong public key:** el archivo se rechaza si se intenta verificar con una clave pública incorrecta.
- **Signature removed:** el archivo se rechaza si la firma fue eliminada del contenedor.

Estas validaciones demuestran que la autenticidad del emisor y la integridad del `.vault` se revisan antes de permitir el descifrado del contenido.

**Comandos de prueba:**

```bash
python test_security.py
python test_signatures.py
```
