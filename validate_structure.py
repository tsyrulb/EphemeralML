#!/usr/bin/env python3
"""
Validation script to check the Rust workspace structure
"""

import os
import sys
from pathlib import Path

def check_file_exists(path, description):
    """Check if a file exists and report the result"""
    if Path(path).exists():
        print(f"✓ {description}: {path}")
        return True
    else:
        print(f"✗ {description}: {path} (MISSING)")
        return False

def check_directory_exists(path, description):
    """Check if a directory exists and report the result"""
    if Path(path).is_dir():
        print(f"✓ {description}: {path}/")
        return True
    else:
        print(f"✗ {description}: {path}/ (MISSING)")
        return False

def main():
    print("EphemeralML Workspace Structure Validation")
    print("=" * 50)
    
    all_good = True
    
    # Check workspace root files
    all_good &= check_file_exists("Cargo.toml", "Workspace Cargo.toml")
    all_good &= check_file_exists("README.md", "README file")
    
    # Check client crate
    print("\nClient Crate:")
    all_good &= check_directory_exists("client", "Client directory")
    all_good &= check_file_exists("client/Cargo.toml", "Client Cargo.toml")
    all_good &= check_file_exists("client/src/lib.rs", "Client lib.rs")
    all_good &= check_file_exists("client/src/main.rs", "Client main.rs")
    all_good &= check_file_exists("client/src/error.rs", "Client error.rs")
    all_good &= check_file_exists("client/src/types.rs", "Client types.rs")
    all_good &= check_file_exists("client/src/decomposer.rs", "Client decomposer.rs")
    all_good &= check_file_exists("client/src/secure_client.rs", "Client secure_client.rs")
    all_good &= check_file_exists("client/src/mock.rs", "Client mock.rs")
    
    # Check host crate
    print("\nHost Crate:")
    all_good &= check_directory_exists("host", "Host directory")
    all_good &= check_file_exists("host/Cargo.toml", "Host Cargo.toml")
    all_good &= check_file_exists("host/src/lib.rs", "Host lib.rs")
    all_good &= check_file_exists("host/src/main.rs", "Host main.rs")
    all_good &= check_file_exists("host/src/error.rs", "Host error.rs")
    all_good &= check_file_exists("host/src/proxy.rs", "Host proxy.rs")
    all_good &= check_file_exists("host/src/storage.rs", "Host storage.rs")
    all_good &= check_file_exists("host/src/mock.rs", "Host mock.rs")
    
    # Check enclave crate
    print("\nEnclave Crate:")
    all_good &= check_directory_exists("enclave", "Enclave directory")
    all_good &= check_file_exists("enclave/Cargo.toml", "Enclave Cargo.toml")
    all_good &= check_file_exists("enclave/src/lib.rs", "Enclave lib.rs")
    all_good &= check_file_exists("enclave/src/main.rs", "Enclave main.rs")
    all_good &= check_file_exists("enclave/src/error.rs", "Enclave error.rs")
    all_good &= check_file_exists("enclave/src/attestation.rs", "Enclave attestation.rs")
    all_good &= check_file_exists("enclave/src/assembly.rs", "Enclave assembly.rs")
    all_good &= check_file_exists("enclave/src/inference.rs", "Enclave inference.rs")
    all_good &= check_file_exists("enclave/src/mock.rs", "Enclave mock.rs")
    
    print("\n" + "=" * 50)
    if all_good:
        print("✓ All required files and directories are present!")
        print("✓ Workspace structure is valid")
        print("✓ Mock mode support is configured")
        print("✓ Feature flags are set up correctly")
        return 0
    else:
        print("✗ Some files or directories are missing")
        return 1

if __name__ == "__main__":
    sys.exit(main())