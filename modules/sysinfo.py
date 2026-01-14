"""
Reiatsu System Info Module - Comprehensive system reconnaissance.
"""
import os
import io
import sys
import platform
import socket
import subprocess
import json

class SysInfo:
    """System Info: Comprehensive system information gathering."""
    
    @staticmethod
    def _get_basic_info():
        """Gather basic system information."""
        info = {}
        try:
            info['hostname'] = socket.gethostname()
            info['platform'] = platform.system()
            info['platform_release'] = platform.release()
            info['platform_version'] = platform.version()
            info['architecture'] = platform.machine()
            info['processor'] = platform.processor()
            info['python_version'] = platform.python_version()
        except Exception as e:
            info['error'] = str(e)
        return info
    
    @staticmethod
    def _get_user_info():
        """Gather user information."""
        info = {}
        try:
            try:
                info['username'] = os.getlogin()
            except:
                info['username'] = os.getenv("USER") or os.getenv("USERNAME") or "unknown"
            
            info['home_dir'] = os.path.expanduser('~')
            info['current_dir'] = os.getcwd()
            info['uid'] = os.getuid() if hasattr(os, 'getuid') else 'N/A'
            info['gid'] = os.getgid() if hasattr(os, 'getgid') else 'N/A'
            
            # Check if running as admin/root
            if platform.system() == "Windows":
                try:
                    import ctypes
                    info['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin() != 0
                except:
                    info['is_admin'] = 'Unknown'
            else:
                info['is_admin'] = os.getuid() == 0 if hasattr(os, 'getuid') else 'Unknown'
                
        except Exception as e:
            info['error'] = str(e)
        return info
    
    @staticmethod
    def _get_network_info():
        """Gather network information."""
        info = {}
        try:
            info['hostname'] = socket.gethostname()
            info['fqdn'] = socket.getfqdn()
            
            # Get all IPs
            try:
                info['local_ip'] = socket.gethostbyname(socket.gethostname())
            except:
                info['local_ip'] = 'Unable to determine'
            
            # Get all network interfaces
            if platform.system() == "Windows":
                try:
                    result = subprocess.check_output('ipconfig', text=True, errors='ignore', timeout=10)
                    info['interfaces'] = result[:1500]  # Truncate
                except:
                    pass
            else:
                try:
                    result = subprocess.check_output(['ip', 'addr'], text=True, errors='ignore', timeout=10)
                    info['interfaces'] = result[:1500]
                except:
                    try:
                        result = subprocess.check_output(['ifconfig'], text=True, errors='ignore', timeout=10)
                        info['interfaces'] = result[:1500]
                    except:
                        pass
            
            # Get routing info
            if platform.system() == "Windows":
                try:
                    result = subprocess.check_output('route print', shell=True, text=True, errors='ignore', timeout=10)
                    # Extract just the gateway
                    for line in result.split('\n'):
                        if '0.0.0.0' in line and 'On-link' not in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                info['default_gateway'] = parts[2]
                                break
                except:
                    pass
            else:
                try:
                    result = subprocess.check_output(['ip', 'route'], text=True, errors='ignore', timeout=10)
                    for line in result.split('\n'):
                        if line.startswith('default'):
                            parts = line.split()
                            if len(parts) >= 3:
                                info['default_gateway'] = parts[2]
                                break
                except:
                    pass
                    
        except Exception as e:
            info['error'] = str(e)
        return info
    
    @staticmethod
    def _get_disk_info():
        """Gather disk information."""
        info = {}
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    'wmic logicaldisk get caption,description,freespace,size',
                    shell=True, text=True, errors='ignore', timeout=10
                )
                info['disks'] = result.strip()
            else:
                result = subprocess.check_output(
                    ['df', '-h'],
                    text=True, errors='ignore', timeout=10
                )
                info['disks'] = result.strip()
        except Exception as e:
            info['error'] = str(e)
        return info
    
    @staticmethod
    def _get_process_info():
        """Get running processes count and key processes."""
        info = {}
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(
                    'tasklist /FO CSV',
                    shell=True, text=True, errors='ignore', timeout=15
                )
                processes = result.strip().split('\n')[1:]  # Skip header
                info['process_count'] = len(processes)
                
                # Find security products
                security_keywords = ['defender', 'antivirus', 'security', 'norton', 'mcafee', 'kaspersky', 'avg', 'avast', 'eset', 'malware']
                security_procs = []
                for proc in processes:
                    proc_lower = proc.lower()
                    for keyword in security_keywords:
                        if keyword in proc_lower:
                            security_procs.append(proc.split(',')[0].strip('"'))
                            break
                info['security_products'] = list(set(security_procs))
            else:
                result = subprocess.check_output(['ps', 'aux'], text=True, errors='ignore', timeout=10)
                processes = result.strip().split('\n')[1:]
                info['process_count'] = len(processes)
                
                # Find security products
                security_keywords = ['clamd', 'freshclam', 'snort', 'suricata', 'ossec', 'aide', 'tripwire', 'rkhunter']
                security_procs = []
                for proc in processes:
                    proc_lower = proc.lower()
                    for keyword in security_keywords:
                        if keyword in proc_lower:
                            parts = proc.split()
                            if len(parts) >= 11:
                                security_procs.append(parts[10])
                            break
                info['security_products'] = list(set(security_procs))
                
        except Exception as e:
            info['error'] = str(e)
        return info
    
    @staticmethod
    def _get_env_info():
        """Get important environment variables."""
        important_vars = ['PATH', 'HOME', 'USER', 'SHELL', 'TERM', 'LANG', 
                         'TEMP', 'TMP', 'USERPROFILE', 'COMPUTERNAME', 'USERDOMAIN']
        info = {}
        for var in important_vars:
            val = os.getenv(var)
            if val:
                if len(val) > 200:
                    val = val[:200] + "..."
                info[var] = val
        return info

    @staticmethod
    def run_remote(args):
        """Main entry point for system info module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] System Information Module")
            print(f"[+] Target: {platform.system()} {platform.release()}")
            print("=" * 60)
            
            # Basic Info
            print(f"\n{'='*20} BASIC INFO {'='*20}")
            basic = SysInfo._get_basic_info()
            for key, value in basic.items():
                print(f"  {key:<20}: {value}")
            
            # User Info
            print(f"\n{'='*20} USER INFO {'='*20}")
            user = SysInfo._get_user_info()
            for key, value in user.items():
                print(f"  {key:<20}: {value}")
            
            # Network Info
            print(f"\n{'='*20} NETWORK INFO {'='*20}")
            network = SysInfo._get_network_info()
            for key, value in network.items():
                if key == 'interfaces':
                    print(f"  {key}:\n{value}")
                else:
                    print(f"  {key:<20}: {value}")
            
            # Disk Info
            print(f"\n{'='*20} DISK INFO {'='*20}")
            disk = SysInfo._get_disk_info()
            for key, value in disk.items():
                print(f"  {value}")
            
            # Process Info
            print(f"\n{'='*20} PROCESS INFO {'='*20}")
            procs = SysInfo._get_process_info()
            print(f"  {'Process Count':<20}: {procs.get('process_count', 'N/A')}")
            security = procs.get('security_products', [])
            if security:
                print(f"  {'Security Products':<20}: {', '.join(security)}")
            else:
                print(f"  {'Security Products':<20}: None detected")
            
            # Environment
            print(f"\n{'='*20} ENVIRONMENT {'='*20}")
            env = SysInfo._get_env_info()
            for key, value in env.items():
                print(f"  {key:<20}: {value}")
                
        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
