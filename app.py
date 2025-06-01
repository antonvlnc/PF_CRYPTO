import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simulación de Protocolo Seguro")
        self.root.geometry("1200x600")
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, font=('Helvetica', 10))
        self.style.configure("TFrame", background="#f0f0f0")

        self.server_process = None
        self.client_process = None

        self.create_layout()

    def create_layout(self):
        self.frame = ttk.Frame(self.root, padding="10")
        self.frame.pack(fill="both", expand=True)

        # Dividir en 2 paneles
        self.server_frame = ttk.LabelFrame(self.frame, text="Servidor", padding="10")
        self.server_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.device_frame = ttk.LabelFrame(self.frame, text="Dispositivo", padding="10")
        self.device_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        self.frame.columnconfigure(0, weight=1)
        self.frame.columnconfigure(1, weight=1)
        self.frame.rowconfigure(0, weight=1)

        # Área de logs del servidor
        self.server_logs = self.create_log_area(self.server_frame)
        # Área de logs del cliente
        self.device_logs = self.create_log_area(self.device_frame)

        # Botones
        self.button_frame = ttk.Frame(self.frame)
        self.button_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky="ew")

        self.start_server_btn = ttk.Button(self.button_frame, text="🖥 Iniciar Servidor", command=self.start_server)
        self.start_server_btn.pack(side="left", padx=5)

        self.run_client_btn = ttk.Button(self.button_frame, text="📱 Ejecutar Cliente", command=self.run_client)
        self.run_client_btn.pack(side="left", padx=5)

        self.clear_btn = ttk.Button(self.button_frame, text="🧹 Limpiar Logs", command=self.clear_logs)
        self.clear_btn.pack(side="left", padx=5)

    def create_log_area(self, parent):
        logs = tk.Text(parent, height=25, width=80, bg="#ffffff", fg="#333333", font=('Consolas', 9))
        logs.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=logs.yview)
        scrollbar.pack(side="right", fill="y")
        logs.config(yscrollcommand=scrollbar.set, state="disabled")
        return logs

    def start_server(self):
        if self.server_process is None or self.server_process.poll() is not None:
            self.append_log(self.server_logs, "[Sistema] Iniciando servidor...")
            self.server_process = subprocess.Popen(
                ["python", "server_host.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            threading.Thread(target=self.read_output, args=(self.server_process, self.server_logs), daemon=True).start()
            self.start_server_btn.config(text="Detener Servidor", command=self.stop_server)
        else:
            messagebox.showinfo("Servidor activo", "El servidor ya está en ejecución.")

    def run_client(self):
        if self.client_process is None or self.client_process.poll() is not None:
            self.append_log(self.device_logs, "[Sistema] Iniciando cliente...")
            self.client_process = subprocess.Popen(
                ["python", "device_client.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            threading.Thread(target=self.read_output, args=(self.client_process, self.device_logs), daemon=True).start()
        else:
            messagebox.showinfo("Cliente activo", "El cliente ya está en ejecución.")

    def stop_server(self):
        if self.server_process:
            self.server_process.terminate()
            self.server_process = None
            self.append_log(self.server_logs, "[Sistema] Servidor detenido.")
            self.start_server_btn.config(text="Iniciar Servidor", command=self.start_server)

    def read_output(self, process, log_area):
        for line in iter(process.stdout.readline, ''):
            self.append_log(log_area, line.strip())

    def append_log(self, area, message):
        area.config(state="normal")
        area.insert("end", message + "\n")
        area.see("end")
        area.config(state="disabled")

    def clear_logs(self):
        for area in [self.server_logs, self.device_logs]:
            area.config(state="normal")
            area.delete("1.0", "end")
            area.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
