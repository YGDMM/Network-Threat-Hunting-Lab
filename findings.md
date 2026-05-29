## Análisis de comportamiento por IP

# 5.252.153.241 → “fase inicial / establecedor”

* Empieza primero (20:45)
* Mayor volumen (1376 conexiones)
* Incluye HTTP claro + TCP
* Interacción bidireccional intensa

Interpretación:

Es el nodo que parece actuar como entry point o beacon inicial

Probablemente:

* descarga inicial
* check-in
* o handshake de C2

⸻

# 45.125.66.32 → “fase de actividad fuerte posterior”

* Empieza después (20:59)
* MUCHÍSIMO volumen (3737)
* TLSv1.2 + TCP
* comunicación continua

Interpretación:

Este es el nodo más “activo operativo”

Esto suele encajar con:

* C2 principal
* servidor de comandos
* o infraestructura de respuesta

⸻

# 45.125.66.252 → “nodo paralelo / redundancia”

* Empieza 21:00 (casi junto al anterior)
* Menor volumen (465)
* TLS + TCP
* mismo patrón estructural

Interpretación:

nodo secundario o fallback

Posible:

* balanceo
* backup C2
* servidor de staging

-------
# CLAVE

* TLSv1.2 aparece en TODOS
* HTTP aparece solo en el primero
* tráfico es bidireccional en todos
* timestamps se solapan

Esto elimina:

* navegación web normal 
* tráfico pasivo 

y refuerza:  comunicación automatizada tipo agente
