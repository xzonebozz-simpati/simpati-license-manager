"""Utility script to generate an Ed25519 digital signature keypair for SIMPATI."""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.security.crypto import generate_ed25519_keypair


def main():
    print("===============================================================")
    print("SIMPATI LICENSE MANAGER - GENERATOR KUNCI ED25519")
    print("===============================================================")
    
    priv_pem, pub_pem = generate_ed25519_keypair()
    
    output_dir = Path(__file__).resolve().parent.parent / "secrets" / "keys"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    priv_file = output_dir / "simpati_ed25519_root.key"
    pub_file = output_dir / "simpati_ed25519_root.pub"
    
    with open(priv_file, "w", encoding="utf-8") as f:
        f.write(priv_pem)
    
    with open(pub_file, "w", encoding="utf-8") as f:
        f.write(pub_pem)
        
    print(f"[OK] Kunci privat disimpan ke: {priv_file}")
    print(f"[OK] Kunci publik disimpan ke: {pub_file}")
    print("\n--- PUBLIC KEY PEM ---")
    print(pub_pem)
    print("PENTING: Jangan pernah membagikan atau mengunggah file kunci privat (.key)!")


if __name__ == "__main__":
    main()
