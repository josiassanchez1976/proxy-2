"""Proxy Quality Checker

This script provides a GUI application for loading proxy lists, analyzing
quality metrics, and applying selected proxies on Windows systems.

Features include:
- Loading proxies from a text file in multiple formats
- Configuration of API keys for ProxyCheck.io and IPQualityScore
- Concurrent proxy analysis including connectivity, geolocation, blacklist
  checks, performance metrics, and external API detection
- Quality scoring and colored results table
- Ability to apply a selected proxy to the Windows system
- Exporting valid proxies to text or CSV files

The implementation focuses on clarity and modularity. Many complex network
operations are simplified to keep the example concise.
"""

import argparse
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import dns.resolver
except ImportError:  # pragma: no cover - optional dependency
    dns = None

CONFIG_FILE = "config.json"
APP_INSTANCE = None

# ------------------------------ Data Models ------------------------------ #

@dataclass
class ProxyInfo:
    address: str
    proxy_type: str
    country: str = ""
    region: str = ""
    city: str = ""
    isp: str = ""
    latency: float = 0.0
    speed: float = 0.0
    success: int = 0
    blacklisted: bool = False
    detected: bool = False
    score: int = 0
    raw: str = field(default="")

# ------------------------------ Utility Functions ------------------------------ #

def load_config() -> Dict[str, str]:
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_config(config: Dict[str, str]) -> None:
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f)


def parse_proxy_line(line: str, default_type: str = "http") -> Optional[ProxyInfo]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split(":")
    if len(parts) < 2:
        return None
    ip, port = parts[0], parts[1]
    ptype = parts[2].lower() if len(parts) > 2 else default_type
    if ptype not in {"http", "https", "socks4", "socks5"}:
        ptype = default_type
    return ProxyInfo(address=f"{ip}:{port}", proxy_type=ptype, raw=line)


def load_proxies(path: str) -> List[ProxyInfo]:
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                lines.append(line.strip())

    default_type = detectar_tipo_de_proxies(lines)
    proxies: List[ProxyInfo] = []
    for line in lines:
        info = parse_proxy_line(line, default_type)
        if info:
            proxies.append(info)
    return proxies



def detectar_tipo_de_proxies(lista: List[str]) -> str:
    if any(":socks5" in p.lower() for p in lista):
        return "socks5"
    return "http"


def proxy_is_alive(ip: str, port: int, tipo: str) -> bool:
    try:
        socket.create_connection((ip, port), timeout=3)
        return True
    except Exception:
        return False


def is_blacklisted(ip: str) -> bool:
    if dns is None:
        return False
    reversed_ip = ".".join(reversed(ip.split(".")))
    lists = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"]
    for bl in lists:
        try:
            dns.resolver.resolve(f"{reversed_ip}.{bl}", "A")
            return True
        except Exception:
            continue
    return False


def analyze_proxy(proxy: ProxyInfo) -> Optional[ProxyInfo]:
    ip, port = proxy.address.split(":")
    if not proxy_is_alive(ip, int(port), proxy.proxy_type):
        return None
    if is_blacklisted(ip):
        return None
    return proxy


def mostrar_en_tabla(resultado: ProxyInfo) -> None:
    if APP_INSTANCE is None:
        return
    APP_INSTANCE.results.append(resultado)
    APP_INSTANCE._update_tree(resultado)


def verificar_lista_de_proxies_concurrente(
    proxies: List[ProxyInfo], max_workers: int = 20
) -> List[ProxyInfo]:
    """Verifica en paralelo y devuelve solo los proxies válidos."""
    valid: List[ProxyInfo] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(analyze_proxy, p) for p in proxies]
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                valid.append(resultado)
                if APP_INSTANCE is not None:
                    mostrar_en_tabla(resultado)
    if APP_INSTANCE is not None:
        APP_INSTANCE.proxies = valid
    return valid

# ------------------------------ Network Checks ------------------------------ #

def check_connectivity(proxy: ProxyInfo) -> bool:
    try:
        host, port = proxy.address.split(":")
        socket.create_connection((host, int(port)), timeout=3)
        return True
    except Exception:
        return False


def fetch_geolocation(proxy: ProxyInfo) -> None:
    try:
        ip = proxy.address.split(":")[0]
        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = resp.json()
        proxy.country = data.get("country", "")
        proxy.region = data.get("regionName", "")
        proxy.city = data.get("city", "")
        proxy.isp = data.get("isp", "")
    except Exception:
        pass


def check_dnsbl(proxy: ProxyInfo) -> None:
    if dns is None:
        return
    ip = proxy.address.split(":")[0]
    reversed_ip = ".".join(reversed(ip.split(".")))
    lists = ["zen.spamhaus.org", "bl.spamcop.net", "dnsbl.sorbs.net"]
    hits = 0
    for bl in lists:
        try:
            query = f"{reversed_ip}.{bl}"
            dns.resolver.resolve(query, "A")
            hits += 1
        except Exception:
            continue
    proxy.blacklisted = hits > 0


def external_detection(proxy: ProxyInfo, config: Dict[str, str]) -> None:
    detected = False
    try:
        key = config.get("proxycheck")
        if key:
            resp = requests.get(
                f"https://proxycheck.io/v2/{proxy.address.split(':')[0]}",
                params={"key": key, "vpn": 1, "risk": 1},
                timeout=5,
            )
            data = resp.json().get("status", "")
            if data != "ok":
                detected = True
        key = config.get("ipqualityscore")
        if key:
            resp = requests.get(
                f"https://ipqualityscore.com/api/json/ip/{key}/{proxy.address.split(':')[0]}",
                timeout=5,
            )
            if resp.json().get("proxy"):
                detected = True
    except Exception:
        pass
    proxy.detected = detected


def measure_performance(proxy: ProxyInfo) -> None:
    proxies = {
        "http": f"{proxy.proxy_type}://{proxy.address}",
        "https": f"{proxy.proxy_type}://{proxy.address}",
    }
    latencies = []
    success = 0
    start = time.time()
    for _ in range(3):
        try:
            t0 = time.time()
            r = requests.get("https://www.google.com/robots.txt", proxies=proxies, timeout=5)
            r.raise_for_status()
            latencies.append((time.time() - t0) * 1000)
            if _ == 0:
                speed = len(r.content) / (time.time() - t0)
                proxy.speed = speed / 1024
            success += 1
        except Exception:
            pass
    if latencies:
        proxy.latency = sum(latencies) / len(latencies)
    proxy.success = success
    proxy.speed = round(proxy.speed, 2)


def calculate_score(proxy: ProxyInfo) -> None:
    score = 0
    if proxy.success > 0:
        score += 30
    if proxy.country == "United States":
        score += 10
    if proxy.region and proxy.city:
        score += 5
    if not proxy.blacklisted:
        score += 30
    if not proxy.detected:
        score += 15
    if any(word in proxy.isp.lower() for word in ["datacenter", "llc", "cloud"]):
        score -= 20
    if proxy.blacklisted:
        score -= 30
    if proxy.speed > 200:
        score += 5
    if proxy.speed < 50:
        score -= 10
    if proxy.success == 3:
        score += 5
    proxy.score = max(0, min(100, score))

# ------------------------------ Windows Proxy ------------------------------ #

def apply_proxy_to_windows(proxy: ProxyInfo) -> bool:
    try:
        import winreg  # type: ignore

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy.address)
        winreg.CloseKey(key)
        proxies = {
            "http": f"{proxy.proxy_type}://{proxy.address}",
            "https": f"{proxy.proxy_type}://{proxy.address}",
        }
        r = requests.get("https://www.google.com", proxies=proxies, timeout=5)
        r.raise_for_status()
        return True
    except Exception:
        return False

# ------------------------------ GUI ------------------------------ #

class ProxyCheckerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Proxy Quality Checker")
        self.config = load_config()
        self.proxies: List[ProxyInfo] = []
        self.results: List[ProxyInfo] = []
        self._setup_ui()

    # UI Setup
    def _setup_ui(self) -> None:
        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        btn_load = ttk.Button(frame, text="Cargar archivo de proxies", command=self.load_file)
        btn_load.grid(row=0, column=0, padx=5, pady=5)

        btn_conf = ttk.Button(frame, text="Configurar APIs", command=self.configure_apis)
        btn_conf.grid(row=0, column=1, padx=5, pady=5)

        btn_analyze = ttk.Button(frame, text="Analizar proxies", command=self.start_analysis)
        btn_analyze.grid(row=0, column=2, padx=5, pady=5)

        btn_export = ttk.Button(frame, text="Exportar proxies válidos", command=self.export_results)
        btn_export.grid(row=0, column=3, padx=5, pady=5)

        self.tree = ttk.Treeview(
            frame,
            columns=(
                "addr",
                "type",
                "country",
                "region",
                "city",
                "isp",
                "latency",
                "speed",
                "success",
                "blacklist",
                "detected",
                "score",
            ),
            show="headings",
        )
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col.capitalize())
        self.tree.grid(row=1, column=0, columnspan=4, sticky="nsew")

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.grid(row=1, column=4, sticky="ns")

        btn_apply = ttk.Button(frame, text="Aplicar proxy seleccionado", command=self.apply_selected)
        btn_apply.grid(row=2, column=0, padx=5, pady=5)

        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(3, weight=1)

        self.progress = ttk.Label(frame, text="")
        self.progress.grid(row=2, column=1, columnspan=3)

    # Button Callbacks
    def load_file(self) -> None:
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if not file_path:
            return
        proxies = load_proxies(file_path)
        self.tree.delete(*self.tree.get_children())
        self.results.clear()
        self.proxies = []
        threading.Thread(
            target=verificar_lista_de_proxies_concurrente,
            args=(proxies,),
            daemon=True,
        ).start()

    def configure_apis(self) -> None:
        top = tk.Toplevel(self.root)
        top.title("Configurar APIs")

        tk.Label(top, text="ProxyCheck.io key:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        entry_pc = tk.Entry(top, width=40)
        entry_pc.grid(row=0, column=1, padx=5, pady=5)
        entry_pc.insert(0, self.config.get("proxycheck", ""))

        tk.Label(top, text="IPQualityScore key:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        entry_ipq = tk.Entry(top, width=40)
        entry_ipq.grid(row=1, column=1, padx=5, pady=5)
        entry_ipq.insert(0, self.config.get("ipqualityscore", ""))

        def save() -> None:
            self.config["proxycheck"] = entry_pc.get().strip()
            self.config["ipqualityscore"] = entry_ipq.get().strip()
            save_config(self.config)
            top.destroy()
            messagebox.showinfo("Config", "Claves guardadas")

        btn_save = ttk.Button(top, text="Guardar", command=save)
        btn_save.grid(row=2, column=0, columnspan=2, pady=10)

    def start_analysis(self) -> None:
        if not self.proxies:
            messagebox.showwarning("Advertencia", "Carga un archivo de proxies primero")
            return
        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        threading.Thread(target=self._analyze_all, daemon=True).start()

    def _analyze_all(self) -> None:
        self.progress.config(text="Analizando...")
        for proxy in self.proxies:
            self.progress.config(text=f"Analizando {proxy.address}")
            if not check_connectivity(proxy):
                continue
            fetch_geolocation(proxy)
            check_dnsbl(proxy)
            external_detection(proxy, self.config)
            measure_performance(proxy)
            calculate_score(proxy)
            self.results.append(proxy)
            self._update_tree(proxy)
        self.progress.config(text="Listo")

    def _update_tree(self, proxy: ProxyInfo) -> None:
        color = "red"
        if proxy.score >= 80:
            color = "green"
        elif proxy.score >= 50:
            color = "yellow"
        self.tree.insert(
            "",
            "end",
            values=(
                proxy.address,
                proxy.proxy_type,
                proxy.country,
                proxy.region,
                proxy.city,
                proxy.isp,
                f"{proxy.latency:.0f}ms",
                f"{proxy.speed:.0f}KB/s",
                f"{proxy.success}/3",
                "Sí" if proxy.blacklisted else "No",
                "Sí" if proxy.detected else "No",
                proxy.score,
            ),
            tags=(color,),
        )
        self.tree.tag_configure("green", background="#d4f4dd")
        self.tree.tag_configure("yellow", background="#fff7d5")
        self.tree.tag_configure("red", background="#f4d4d4")

    def apply_selected(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        proxy = self.results[idx]
        if apply_proxy_to_windows(proxy):
            messagebox.showinfo("Proxy", "✅ Proxy aplicado correctamente y con acceso a Internet.")
        else:
            messagebox.showerror("Proxy", "❌ El proxy no tiene conexión. No se aplicará.")

    def export_results(self) -> None:
        if not self.results:
            messagebox.showwarning("Advertencia", "No hay resultados para exportar")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("CSV", "*.csv")])
        if not path:
            return
        valid = [p for p in self.results if p.score >= 70]
        if path.endswith(".csv"):
            import csv

            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "IP:PORT",
                    "Type",
                    "Country",
                    "Region",
                    "City",
                    "ISP",
                    "Latency",
                    "Speed",
                    "Success",
                    "Blacklist",
                    "Detected",
                    "Score",
                ])
                for p in self.results:
                    writer.writerow([
                        p.address,
                        p.proxy_type,
                        p.country,
                        p.region,
                        p.city,
                        p.isp,
                        f"{p.latency:.0f}",
                        f"{p.speed:.0f}",
                        p.success,
                        p.blacklisted,
                        p.detected,
                        p.score,
                    ])
        else:
            with open(path, "w", encoding="utf-8") as f:
                for p in valid:
                    f.write(f"{p.address}:{p.proxy_type}\n")
        messagebox.showinfo("Exportar", f"Se exportaron {len(valid)} proxies válidos")

# ------------------------------ CLI ------------------------------ #

def analyze_file_cli(path: str) -> None:
    """Analiza un archivo de proxies en modo consola."""
    proxies = load_proxies(path)
    valid = verificar_lista_de_proxies_concurrente(proxies)

    if not valid:
        print("No se encontraron proxies válidos.")
        return

    print("Proxies válidos:")
    for p in valid:
        print(f"{p.address} ({p.proxy_type})")

# ------------------------------ Main ------------------------------ #

def main() -> None:
    parser = argparse.ArgumentParser(description="Proxy Quality Checker")
    parser.add_argument(
        "--file",
        help="Archivo de proxies para análisis en modo consola",
    )
    args = parser.parse_args()

    if args.file:
        analyze_file_cli(args.file)
        return

    root = tk.Tk()
    global APP_INSTANCE
    app = ProxyCheckerApp(root)
    APP_INSTANCE = app
    root.mainloop()


if __name__ == "__main__":
    main()
