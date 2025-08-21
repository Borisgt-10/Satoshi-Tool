# Satoshi-Tool
Herramienta en Python para trabajar con seeds BIP-39. Incluye: modo automático (generar semillas y consultar saldo), modo manual (introducir seed y consultar saldo), probar passphrases frente a una dirección, y recuperar seeds por fuerza bruta si falta alguna palabra.

---

## 🌍 Descripción  

### 🇪🇸 Español  
**Satoshi's Tool** es una utilidad diseñada para:  
- 🔹 **Modo Automático**: generar semillas válidas y consultar saldo en direcciones derivadas.  
- 🔹 **Modo Manual**: introducir una semilla existente y comprobar saldo y transacciones.  
- 🔹 **Passphrase Hunter**: probar diferentes passphrases y verificar si coinciden con una dirección conocida.  
- 🔹 **Seed Hunter**: recuperar semillas por fuerza bruta si se han perdido una o varias palabras, usando búsqueda inteligente con prefijos o incógnitas.  

Su objetivo principal es servir como herramienta **educativa** y de **recuperación personal**, nunca para fines maliciosos.  

---

### 🇬🇧 English  
**Satoshi's Tool** is a Python utility designed for:  
- 🔹 **Automatic Mode**: generate valid seeds and check balances on derived addresses.  
- 🔹 **Manual Mode**: input an existing seed and check balance and transactions.  
- 🔹 **Passphrase Hunter**: test multiple passphrases and verify if they match a known address.  
- 🔹 **Seed Hunter**: recover seeds via brute force if one or more words are missing, using smart search with prefixes or unknown placeholders.  

The main goal is to provide an **educational** and **personal recovery** tool, never for malicious purposes.  

---

## ⚡ Instalación / Installation  

Clona el repositorio y accede a la carpeta:  
```bash
git clone https://github.com/tuusuario/satoshis-tool.git
cd satoshis-tool
```

Instala las dependencias:  
```bash
pip install -r requirements.txt
```

---

## ▶️ Uso / Usage  

Ejecutar el programa principal:  
```bash
python3 satoshis_tool.py
```

Aparecerá un menú interactivo con los distintos modos disponibles:  

```
========================================
   Satoshi's Tool — Modo de Ejecución
========================================
[1] Automático
[2] Manual
[3] Passphrase Hunter
[4] Seed Hunter
[5] Generador de Semillas → (pendiente de implementar)
[Q] Salir
```

Selecciona el modo deseado y sigue las instrucciones en pantalla.  

---

## 📌 Ejemplos  

### 🇪🇸 Español  
- Probar passphrases con una dirección conocida:  
  ```
  Selecciona [3] → Passphrase Hunter
  Introduce la semilla base
  Introduce la dirección objetivo
  Introduce lista de passphrases a probar
  ```
- Recuperar una semilla con palabras perdidas:  
  ```
  Selecciona [4] → Seed Hunter
  Escribe la máscara de la semilla (ejemplo: abandon abandon ? pre* about ...)
  La herramienta probará las combinaciones válidas hasta encontrar coincidencias
  ```

### 🇬🇧 English  
- Test passphrases with a known address:  
  ```
  Select [3] → Passphrase Hunter
  Enter the base seed
  Enter the target address
  Enter a list of passphrases to test
  ```
- Recover a seed with missing words:  
  ```
  Select [4] → Seed Hunter
  Write the seed mask (example: abandon abandon ? pre* about ...)
  The tool will test valid combinations until a match is found
  ```

---

## ⚠️ Disclaimer  

🇪🇸 **Aviso**: Esta herramienta es únicamente para **uso educativo y de recuperación personal**.  
No debe usarse con fines ilegales ni para acceder a fondos de terceros.  
El autor no se hace responsable del uso indebido que se haga del software.  

🇬🇧 **Disclaimer**: This tool is intended for **educational and personal recovery purposes only**.  
It must not be used for illegal activities or to access third-party funds.  
The author is not responsible for any misuse of this software.  
