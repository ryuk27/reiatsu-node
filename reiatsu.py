#!/usr/bin/env python3

import argparse
import sys
import os
import ssl
import ipaddress
from datetime import datetime, timedelta, timezone
from core.c2_server import C2Server

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'core'))

def generate_ssl_cert_python(cert_file, key_file):
    """Generate self-signed SSL certificate using Python cryptography library."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "None"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "None"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Reiatsu"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1"))
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        
        # Write private key
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return True
    except Exception as e:
        print(f"[-] Python SSL generation failed: {e}")
        return False

def generate_ssl_cert_openssl(cert_file, key_file):
    """Generate self-signed SSL certificate using OpenSSL command."""
    subj = "/C=US/ST=None/L=None/O=Reiatsu/CN=localhost"
    redirect = "2>nul" if os.name == 'nt' else "2>/dev/null"
    openssl_cmd = (
        f'openssl req -new -x509 -days 365 -nodes -out "{cert_file}" '
        f'-keyout "{key_file}" -subj "{subj}" {redirect}'
    )
    result = os.system(openssl_cmd)
    return result == 0 and os.path.exists(cert_file) and os.path.exists(key_file)

def main():
    """Main entry point for the Reiatsu C2 server."""
    parser = argparse.ArgumentParser(
        description="Reiatsu Node C2 Framework - Encrypted, cross-platform Command & Control.",
        epilog="Example: python3 reiatsu.py --host 0.0.0.0 --port 443"
    )
    parser.add_argument("--host", help="C2 server IP/host to bind to.", default="0.0.0.0")
    parser.add_argument("--port", type=int, help="C2 server port.", default=443)
    args = parser.parse_args()

    cert_file = os.path.join(os.path.dirname(__file__), "cert.pem")
    key_file = os.path.join(os.path.dirname(__file__), "key.pem")

    # Generate SSL certificate if not found
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        print(f"[!] SSL certificate or key not found.")
        print(f"[*] Generating SSL certificates...")
        
        # Try OpenSSL method first (more compatible)
        if generate_ssl_cert_openssl(cert_file, key_file):
            print(f"[+] SSL certificate and key generated successfully (OpenSSL).")
        # Then try Python method
        elif generate_ssl_cert_python(cert_file, key_file):
            print(f"[+] SSL certificate and key generated successfully (Python).")
        else:
            print(f"[-] FATAL: Failed to generate SSL certificate or key.")
            print(f"    Install cryptography: pip install cryptography")
            print(f"    Or install OpenSSL and add to PATH.")
            sys.exit(1)

    try:
        server = C2Server(args.host, args.port, ssl_cert=cert_file, ssl_key=key_file)
        server.run()
    except Exception as e:
        print(f"[-] A fatal error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()