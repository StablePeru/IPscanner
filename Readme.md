# IP Scanner Profesional

Este proyecto es una aplicación gráfica profesional para escanear direcciones IP y rangos de red, utilizando `nmap` para detectar hosts, puertos abiertos y servicios. La aplicación también permite exportar los resultados a CSV o Excel y tiene una interfaz elegante y fácil de usar.

## Características

- Escaneo de IPs y rangos de IPs utilizando `nmap`.
- Escaneo de puertos específicos (por defecto, del 22 al 443).
- Detección de sistemas operativos y servicios abiertos en los hosts.
- Exportación de resultados en formato CSV o Excel.
- Filtros de búsqueda en los resultados escaneados.
- Detalles de cada host en una ventana emergente.

## Requisitos

- Python 3.x
- `nmap` debe estar instalado y accesible en el sistema.
- Las dependencias de Python se pueden instalar usando el archivo `requirements.txt`.

## Instalación

1. Clona este repositorio:
   ```bash
   git clone https://github.com/stableperu/ip-scanner-profesional.git
   cd ip-scanner-profesional
   ```

2. Instala las dependencias:
   ```bash
   pip install -r requirements.txt
   ```

3. Asegúrate de que `nmap` esté instalado y disponible en el `PATH` de tu sistema.

## Uso

Ejecuta el archivo `main.py` para iniciar la aplicación:

```bash
python main.py
```

## Personalización

Puedes modificar los estilos de la interfaz editando el archivo `style.qss`. Si no está presente, se usarán los estilos predeterminados.

## Estructura del Proyecto

- `main.py`: Archivo principal que inicia la aplicación.
- `gui.py`: Implementación de la interfaz gráfica.
- `scanner.py`: Clase que maneja las funcionalidades de escaneo utilizando `nmap`.
- `path.py`: Archivo que imprime la variable de entorno `PATH`.
- `style.qss`: Archivo opcional que define los estilos visuales de la aplicación.

## Exportación de Resultados

Después de un escaneo exitoso, puedes exportar los resultados en formato CSV o Excel para analizar la información en otras herramientas.

## Licencia

Este proyecto está bajo la Licencia MIT. Puedes ver más detalles en el archivo `LICENSE`.
