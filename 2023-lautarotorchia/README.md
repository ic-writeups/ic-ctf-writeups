# Trabajo Final - Introducción a la Ciberseguridad

**Alumno:** Lautaro Torchia (17824/4)

**Nick CTFs:** lautarotorchia

## Introducción

Este repositorio contiene la resolución del trabajo final para la materia "Introducción a la Ciberseguridad". El objetivo del trabajo fue participar en dos competencias internacionales de Capture The Flag (CTF) para aplicar de manera práctica los conocimientos teóricos adquiridos durante la cursada.

A continuación, se detallan las competencias en las que participé, los desafíos resueltos y una reflexión sobre el proceso de aprendizaje, las herramientas utilizadas y las dificultades encontradas.

---
LOS Writeups particulares, se encuentran dentro de las carpetas, cybergames/ y us-cybergames/

## CTF 1: CyberGames CTF

* **Fecha de participación:** Mayo de 2025 
* **Writeup Completo:** [Ver Writeup Completo de CyberGames CTF](./CyberGames_CTF/writeup_cybergames.pdf)
* **Link CTFTime** https://ctftime.org/event/2774

### Desafíos Resueltos (Selección)

Durante esta competencia resolví más de 10 desafíos, empece resolviendo para el final y me cope con algunos de este challenge, resolvi mas de 3 ya que algunos de los primeros resueltos eran muy sencillos e introductorios. A continuación, se destacan algunos de los más representativos de cada categoría:

* **PWN/Web Exploitation:** JAILE - Calculator 
* **Reverse Engineering:** ConnectionChecker (Tool & Lies) [cite: 43, 78], SanityChecker (Sleepy Python, Bash Dropper, Password Protected) 
* **Cryptography:** Adversary (Almost Classic & 3AES) [cite: 156, 165], Advanced Decryption Standard (Codebook, Blockchain, easy like counting up to three) 

### Reflexiones sobre CyberGames CTF

Esta competencia fue una excelente oportunidad para poner a prueba los fundamentos.

* En **Reversing**, los retos como `ConnectionChecker` y `SanityChecker`: empezar con análisis estático (`strings`, `jadx` para decompilar JARs [cite: 61]) y, si era necesario, pasar a un análisis dinámico (`ltrace` para observar llamadas a librerías en binarios ). El reto "ConnectionChecker - Lies" fue interesante, ya que la flag no estaba oculta de forma simple, sino que se generaba a través de una serie de operaciones bitwise que tuve que replicar en Python para revelar su propósito real, Reversing fue un tema que tuve que repasar antes de comenzar a realizar ejercicios. 

* En **Cryptography**, los desafíos me permitieron aplicar directamente la teoría de la materia."Almost Classic" La serie "Advanced Decryption Standard" fue una introduccion sencilla que me recordo a usar "CyberChef" como herramienta y a recordar la teoria de cifrado Simetrico y asimetrico

* El reto de **PWN**, "JAILE - Calculator", fue un caso de estudio sobre cómo sortear filtros en inyecciones de código Python. La solución no era trivial y requirió evadir una lista negra de palabras (`open`, `read`, etc.). La clave fue el uso de `__builtins__` para acceder a funciones nativas y `bytes().decode()` para construir los nombres de esas funciones sin usar comillas. 

---

## CTF 2: US Cybergames CTF

* **Fecha de participación:** Junio de 2025 
* **Writeup Completo:** [Ver Writeup Completo de US Cybergames CTF](./US_Cybergames_CTF/writeup_uscybergames.pdf)
* **Link CTFTime** https://ctftime.org/event/2717

### Desafíos Resueltos

* **PWN:** Donut (Pwn) 
* **Reverse Engineering:** CTF Cafe (RE) 
* **Cryptography:** Gotta Go Low (Crypto) 
* **Cryptography:** Prime Suspects 

### Reflexiones sobre US Cybergames CTF

Esta competencia presentó desafíos con vulnerabilidades muy clásicas y conocidas, lo que sirvió para reforzar conceptos fundamentales. Empece haciendo la competencia Beginners Room y me cope y resolvi algunos ejercicios del competitive CTF(Ambos challenge tenian duracion de 1 semana)

* El reto de **PWN**, "Donut", fue un ejemplo de cómo encadenar dos vulnerabilidades. Primero, un **buffer overflow** a través de la función `gets()` para sobrescribir una variable de control en la sección `.bss`. Segundo, una vez superada la verificación, explotar una **inyección de comandos** en una llamada a `system()`.  Este reto demostró la importancia de analizar no solo el flujo del código, sino también la disposición de las variables en memoria.

* En **Reversing**, "CTF Cafe" fue una lección sobre la eficacia de herramientas como Ghidra. Al ser un binario no "stripped", pude localizar rápidamente la variable `secret_sauce`. Usando las referencias cruzadas (Xrefs), encontré el bucle que la procesaba y vi que se trataba de un simple cifrado XOR cíclico.  La combinación de la decompilación en Ghidra para entender el algoritmo y GDB para extraer los bytes de la memoria y aplicar el XOR fue clave para la solución. 

* Los retos de **Cryptography** fueron directamente sacados del manual de "malas prácticas en RSA". "Gotta Go Low" explotaba el uso de un **exponente público bajo (e=3)** con un mensaje corto, lo que permitía recuperar el texto plano simplemente calculando la raíz cúbica del texto cifrado[cite: 278, 283, 290]. Por otro lado, "Prime Suspects" se basaba en un **módulo `n` demasiado pequeño (256 bits)** [cite: 309, 310], lo que lo hacía factorizable de forma trivial con herramientas online como Factordb.  Ambos retos fueron un recordatorio contundente de que la seguridad de RSA depende críticamente de la correcta elección de sus parámetros.

## Metodología y Uso de Herramientas

Mi enfoque para resolver los desafíos se basó en una combinación de las técnicas y herramientas presentadas en la cátedra y el uso de la inteligencia artificial como asistente de aprendizaje.

* **Fundamentos de la Cátedra**: Los conocimientos sobre vulnerabilidades comunes (Buffer Overflow, Command Injection), algoritmos criptográficos (AES, RSA, cifrados clásicos) y técnicas de reversing (análisis estático vs. dinámico) fueron la base indispensable. Sin esta base, no habria entendido de que se trataban muchos ejercicioos ni como arrancar a resolverlos.

* **Uso de IA (Gemini/GPT)**: Utilicé modelos de IA como un compañero de debugging. No los usé para obtener la solución directa, sino para acelerar el aprendizaje y desatascarme en puntos específicos. Por ejemplo, podía preguntar:
    * *"¿Me puedes dar un ejemplo de cómo usar la librería PyCryptodome para desencriptar con AES en modo CBC?"*
    * *"No entiendo esta línea de código ensamblador en Ghidra, ¿qué hace esta instrucción?"*
    * *"¿Cuál es la forma más eficiente de calcular una raíz cúbica entera en Python para un número muy grande?"*
    
    Esta interacción me permitió enfocarme en la lógica del desafío en lugar de perder tiempo en detalles de sintaxis o implementación, haciendo el proceso de resolución mucho más eficiente y didáctico.

En mi experiencia usando IA para CTFs, el modelo Gemini PRO 2.5, resulta el mas astuto a la hora de encontrar las soluciones o entender porque camino se debe abordar para resolver los ejercicios, tambien use ChatGPT 4, con peores resultados.

## Conclusión General

La experiencia de participar en estas competencias fue buena y me dio ganas de seguir participando en algunas otras competencias, asi que estare atento en CTF time cuando aparezcan.