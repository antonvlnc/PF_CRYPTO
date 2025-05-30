import tkinter as tk
import subprocess
import threading
from tkinter import ttk, messagebox

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Communication Protocol")
        
        # Configuración de estilo
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, font=('Helvetica', 10))
        self.style.configure("TFrame", background="#f0f0f0")
        
        # Frame principal
        self.frame = ttk.Frame(root, padding="20")
        self.frame.grid(row=0, column=0, sticky="nsew")
        
        # Título
        self.title_label = ttk.Label(
            self.frame,
            text="Protocolo de Comunicación Segura",
            font=('Helvetica', 12, 'bold')
        )
        self.title_label.grid(row=0, column=0, pady=(0, 15))
        
        # Botón de conexión para protocolo
        self.connect_btn = ttk.Button(
            self.frame,
            text="🔒 Iniciar Protocolo Seguro",
            command=self.run_secure_protocol,
            style="Accent.TButton"
        )
        self.connect_btn.grid(row=1, column=0, pady=5, sticky="ew")
        
        # Barra de progreso
        self.progress = ttk.Progressbar(
            self.frame,
            orient="horizontal",
            length=300,
            mode="determinate"
        )
        self.progress.grid(row=2, column=0, pady=10, sticky="ew")
        
        # Área de logs
        self.logs = tk.Text(
            self.frame,
            height=15,
            width=70,
            state="disabled",
            bg="#ffffff",
            fg="#333333",
            font=('Consolas', 9)
        )
        self.logs.grid(row=3, column=0, pady=5)
        
        # Scrollbar para logs
        self.scrollbar = ttk.Scrollbar(
            self.frame,
            orient="vertical",
            command=self.logs.yview
        )
        self.scrollbar.grid(row=3, column=1, sticky="ns")
        self.logs.config(yscrollcommand=self.scrollbar.set)
        
        # Botón de limpiar logs
        self.clear_btn = ttk.Button(
            self.frame,
            text="🧹 Limpiar Logs",
            command=self.clear_logs
        )
        self.clear_btn.grid(row=4, column=0, pady=(5, 0), sticky="ew")
        
        # Botón para iniciar el servidor
        self.server_btn = ttk.Button(
            self.frame,
            text="🖥 Iniciar Servidor",
            command=self.start_server,
            style="Accent.TButton"
        )
        self.server_btn.grid(row=5, column=0, pady=(5, 0), sticky="ew")

        # Configuración de grid responsivo
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.frame.columnconfigure(0, weight=1)

        # Atributo para controlar el servidor
        self.server_process = None

    def run_secure_protocol(self):
        """Ejecuta el protocolo real con sockets y actualiza la interfaz"""
        self.clear_logs()
        self.connect_btn.config(state="disabled")
        self.progress["value"] = 0

        def ejecutar_cliente():
            try:
                self.log("=== Iniciando cliente (device_client.py) ===")
                self.update_progress(20)

                proceso = subprocess.Popen(
                    ["python", "device_client.py"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                for line in proceso.stdout:
                    self.log(line.strip())

                stderr = proceso.stderr.read()
                if stderr:
                    self.log("❌ Error:")
                    self.log(stderr.strip())

                self.update_progress(100)
                messagebox.showinfo("Éxito", "¡Protocolo ejecutado correctamente!")

            except Exception as e:
                self.log(f"❌ ERROR: {str(e)}")
                messagebox.showerror("Error", f"Falló la ejecución: {str(e)}")

            finally:
                self.connect_btn.config(state="normal")

        threading.Thread(target=ejecutar_cliente).start()

    def start_server(self):
        """Inicia el servidor en un proceso independiente"""
        if self.server_process is None or self.server_process.poll() is not None:
            self.server_process = subprocess.Popen(
                ["python", "server_host.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Cambiar texto del botón
            self.server_btn.config(text="🖥 Detener Servidor", command=self.stop_server)

            # Esperar a que el servidor inicie
            self.log("Iniciando el servidor...")
        else:
            messagebox.showinfo("Servidor en ejecución", "El servidor ya está en ejecución.")

    def stop_server(self):
        """Detiene el servidor"""
        if self.server_process:
            self.server_process.terminate()  # Termina el proceso del servidor
            self.server_process = None
            self.server_btn.config(text="🖥 Iniciar Servidor", command=self.start_server)
            self.log("Servidor detenido.")

    def update_progress(self, value):
        """Actualiza la barra de progreso"""
        self.progress["value"] = value
        self.root.update_idletasks()

    def log(self, message):
        """Añade mensajes al área de logs"""
        self.logs.config(state="normal")
        self.logs.insert("end", message + "\n")
        self.logs.see("end")
        self.logs.config(state="disabled")

    def clear_logs(self):
        """Limpia el área de logs"""
        self.logs.config(state="normal")
        self.logs.delete(1.0, "end")
        self.logs.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
