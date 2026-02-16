# Este es el repositorio para el curso de Criptografía 2026-2  
## Integrantes:  
- Salazar Serrano Edgar   

## 2. Diagrama de Arquitectura  
![Arquitectura](./diagrama.png)
## 3. Requerimientos de Seguridad  
- Confidencialidad: Si un atacante obtiene acceso al contenedor de archivos, ya sea en almacenamiento local o remoto, no debe ser capaz de extaer ninguna informacion del contenido de los archivos sin tener una de las llaves privadas vinculadas al contenedor.  
- Integridad de los archivos: Si se realiza alguna modificación de un arhivo del contenedor, debe ser detectada por el sistema. En caso de alteración se debe cancelar el proceso para evitar que se procesen datos corruptos.  
- Autenticidad del remitente del archivo: El destinatario debe tener la certeza de que el archivo fue generado por el dueño de la llave pública. Así un atacante no debe ser capaz de falsificar un archivo que aparentemente proviene de un usuario autorizado.
- Confidencialidad de las llaves privadas: Las llaves privadas guardadas en el Key Store no deben estar accesibles en texto plano, deben estar protegidas con un cifrado derivado de la contraseña del usuario, de modo que si un atacante se roba el archivo, no pueda realizar ataques de fuerza bruta.
- Protección contra manipulación (Metadatos y Cabeceras): La protección del sistema debe ir más allá de los datos del archivo. No basta con cifrar el documento, el sistema también debe proteger la información que explica cómo descifrarlo. Así un atacante no debe ser capaz de cambiar los nombres de los destinatarios, ni intercambiar las llaves cifradas por otras, sin que el sistema lo detecte.
- No repudio: Una vez que un archivo ha sido firmado y compartido, el emisor no podrá negar haber creado dicho contenido, puesto que la firma digital es única y está ligada exclusivamente a su llave privada.
