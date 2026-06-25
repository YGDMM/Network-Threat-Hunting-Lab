# FASES DEL PROYECTO

## FASE 1 – LOAD PCAP FILE (TShark + Pandas)

* La primera fase del análisis se centró en la adquisición y normalización del tráfico de red a partir del archivo PCAP mediante TShark. El objetivo principal fue transformar un conjunto de datos binarios de red en un dataset estructurado que permitiera su análisis con Python y técnicas de data analysis.
* Para ello se extrajeron campos de diferentes capas del modelo OSI, incluyendo información de enlace (MAC addresses), red (IP origen y destino), transporte (puertos TCP/UDP y flags) y metadatos de los paquetes como timestamp, longitud y protocolo.
* Como resultado se obtuvo un dataset completo y consistente que sirvió como base para todas las fases posteriores del análisis. Esta estructura permitió reconstruir sesiones de comunicación e identificar patrones temporales y relaciones entre hosts, sin realizar aún inferencias de comportamiento malicioso.

⸻

## FASE 2 – BASELINE TRAFFIC ANALYSIS

* Esta fase tuvo como objetivo establecer una línea base del comportamiento de la red, identificando protocolos predominantes, hosts más activos y relaciones entre sistemas internos y externos.
* El análisis reveló un entorno claramente asociado a Active Directory, con presencia de Kerberos (KRB5), LDAP, SMB2 y DCE/RPC.
* El host víctima (10.1.17.215) destaca como principal generador y receptor de tráfico, interactuando tanto con el domain controller (10.1.17.2) como con múltiples IPs externas relevantes para fases posteriores del análisis.

⸻

## FASE 3 – DNS TRAFFIC ANALYSIS (EARLY INDICATORS)

* Esta fase se centró en el análisis del tráfico DNS para identificar posibles indicadores de compromiso asociados a la fase inicial del ataque.
* Se observó una actividad DNS intensiva entre la víctima y el controlador de dominio interno, coherente con un entorno Windows AD.
* Destaca la resolución recurrente de ping3.dyngate.com, sugiriendo posible automatización o comunicación externa sospechosa.
* También se observan dominios legítimos de Microsoft, lo que indica coexistencia de tráfico benigno y potencialmente malicioso.

⸻

## FASE 3.1 – ADVANCED DNS ANALYSIS

* Se profundizó en la detección de patrones anómalos en DNS mediante heurísticas de filtrado.
* Se confirma la persistencia de consultas hacia ping3.dyngate.com, intercaladas con tráfico legítimo del sistema operativo.
* Este patrón es compatible con actividad post-compromise o beaconing inicial, aunque no concluyente por sí solo.

⸻

## FASE 4 – LATERAL MOVEMENT ANALYSIS

* El objetivo fue identificar posible movimiento lateral dentro del entorno Windows.
* Se analizaron protocolos como LDAP, SMB, Kerberos y DCE/RPC.
* Se confirma comunicación constante entre el host víctima y el controlador de dominio, compatible con un entorno AD activo.
* Este tráfico puede representar tanto actividad legítima como comportamiento post-compromise.

⸻

## FASE 4.1 – LATERAL ANALYSIS DEEP DIVE

* Se profundiza en la interacción interna del dominio.
* Se identifican patrones consistentes de autenticación Kerberos, acceso SMB y consultas LDAP.
* Se extrae información relevante del entorno de la víctima (usuario, MAC, contexto de dominio).

⸻

## FASE 5 – TIMELINE ANALYSIS

* Se reconstruye la actividad temporal de la red mediante agregación por minutos.
* Se detecta una ventana de actividad de ~54 minutos (20:44–21:38).
* Se identifican picos relevantes en:
    * 20:45
    * 20:47 (máximo: 6317 pkt/min)
    * 20:59
    * 21:25
    * 21:28
* Estos picos actúan como puntos de correlación para fases posteriores del análisis.

⸻

## FASE 6 – PEAK ACTIVITY DATASET CREATION

* Se crea un dataset específico centrado únicamente en los periodos de mayor actividad.
* Esto permite aislar tráfico relevante del ruido general de la red.
* Este dataset se convierte en la base para el análisis de infraestructura sospechosa y correlación de IOC.

⸻

## FASE 6.1 – PEAK ACTIVITY ANALYSIS

* Se analizan protocolos e IPs durante los picos de actividad.
* La víctima (10.1.17.215) concentra el tráfico principal.
* IPs externas relevantes:
    * 45.125.66.32
    * 45.125.66.252
    * 5.252.153.241
    * 82.221.136.26
* Predominan TCP y TLS, junto con DNS y HTTP.
* Se refuerza la hipótesis de actividad post-compromise durante estos intervalos.

⸻

## FASE 7 – IOC CORRELATION

* Se correlacionan los IOC principales para determinar aparición temporal y comportamiento.
* 82.221.136.26 aparece primero (fase inicial de acceso).
* 5.252.153.241 permanece activa durante gran parte de la captura.
* 45.125.66.32 y 45.125.66.252 aparecen en fase posterior como infraestructura de control.
* El tráfico está dominado por TCP/TLS.

⸻

## FASE 7.1 – IOC TIMELINE

* Se visualiza la actividad temporal de cada IOC.
* Se observa una secuencia progresiva de activación de infraestructura.
* Los nodos no operan de forma aislada, sino coordinada.
* El patrón sugiere infraestructura distribuida tipo C2.

⸻

## FASE 7.2 – C2 BEHAVIOUR ANALYSIS

* Se analiza el comportamiento de las conexiones sospechosas.
* Se detectan sesiones completas TCP (SYN → FIN → RST).
* 82.221.136.26 muestra conexiones cortas tipo initial access.
* El resto de IPs presentan sesiones más prolongadas, compatibles con persistencia.

⸻

## FASE 7.3 – C2 COMMUNICATION CLASSIFICATION

* Se analizan métricas avanzadas: jitter, burstiness, intervalos y duración.
* No se detecta beaconing perfectamente periódico.
* Sin embargo, la correlación temporal con picos de tráfico sugiere comportamiento coordinado.
* El modelo clasifica el tráfico como “ruidoso”, pero no descarta C2.

⸻

## FASE 8 – VICTIM IDENTIFICATION

* Se identifica el host principal: 10.1.17.215.
* Es el sistema con mayor volumen de tráfico (~39.000+ paquetes).
* Interactúa tanto con infraestructura interna como externa.
* Se confirma como nodo principal del incidente.

⸻

## FASE 8.1 – VICTIM PROFILING

* Se analiza el comportamiento completo del host comprometido.
* Se detectan consultas DNS sospechosas y tráfico hacia infraestructura externa.
* IPs externas coinciden con IOC previamente identificados.
* El comportamiento es consistente con post-compromise activity en entorno AD.

⸻

## FASE 9 – VICTIM ENVIRONMENT PROFILING

* Se reconstruye el contexto del sistema víctima.
* Se identifica dominio: bluemoontuesday.com.
* Se confirma entorno Active Directory.
* Se detecta coexistencia de tráfico legítimo y actividad sospechosa.
* Se integran resultados de fases 4 y 8.

⸻

## FASE 9.1 – IOC TIMELINE (FINAL CONSOLIDATION)

* Se consolidan todos los IOC en una línea temporal única.
* Se observa secuencia clara:
    * acceso inicial
    * bootstrap
    * activación C2
    * persistencia

⸻

## FASE 9.2 – IOC ENRICHMENT

* Se enriquecen IOC con datos externos (WHOIS, ASN, DNS).
* Se confirma uso de infraestructura de hosting comercial.
* Se refuerza hipótesis de infraestructura alquilada para C2/staging.

⸻

## FASE 9.3 – WHOIS CLEAN

* Se filtra información relevante de WHOIS.
* Se eliminan datos irrelevantes.
* Se conservan únicamente campos útiles para análisis forense.

⸻

## FASE 9.4 – IOC TABLE

* Se consolida toda la inteligencia en una tabla estructurada.
* Se clasifican IOC por:
    * C2 infrastructure
    * staging
    * internal AD
    * suspicious hosting

⸻

## FASE 10 – ATTACK RECONSTRUCTION

* Se reconstruye toda la cadena de ataque de forma narrativa.
* Se integran:
    * DNS analysis
    * timeline
    * C2 behaviour
    * IOC enrichment
    * victim profiling
* Se identifica un ataque multi-etapa:
    * initial access (phishing/fake site)
    * bootstrap communication
    * multi-node C2 infrastructure
    * sustained post-compromise activity
* Infraestructura asociada a AS133398 (HostBaltic) refuerza hipótesis de C2 distribuido.
