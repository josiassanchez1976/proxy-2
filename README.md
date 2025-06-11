# Proxy Quality Checker

Esta aplicación permite analizar listas de proxies para determinar su calidad.
Incluye una interfaz gráfica opcional y un modo de consola para entornos sin
display. Los proxies se verifican en paralelo y solo se muestran los que están
activos y no aparecen en listas negras.

## Requisitos

Instala las dependencias con:

```bash
pip install -r requirements.txt
```

## Uso en modo consola

```bash
python proxy_quality_checker.py --file lista.txt
```

Donde `lista.txt` es un archivo con proxies en formato `IP:PUERTO[:tipo]`.

## Uso de la interfaz gráfica

Si cuentas con un entorno con pantalla puedes ejecutar simplemente:

```bash
python proxy_quality_checker.py
```
