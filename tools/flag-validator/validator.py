#!/usr/bin/env python3
"""
CyberLab Flag Validator
Validates CTF flags for lab challenges
"""

import hashlib
import json
import sys
from pathlib import Path

# Flag database (hashed for security)
# Format: { "lab_id": "sha256_hash_of_flag" }
FLAGS = {
    # Web Security
    "sql-injection-basic": hashlib.sha256(b"FLAG{sql_1nj3ct10n_m4st3r}").hexdigest(),
    "sql-injection-union": hashlib.sha256(b"FLAG{un10n_b4s3d_pwn3d}").hexdigest(),
    "sql-injection-blind": hashlib.sha256(b"FLAG{bl1nd_sql1_t1m3_b4s3d}").hexdigest(),
    "xss-reflected": hashlib.sha256(b"FLAG{r3fl3ct3d_xss_pwn3d}").hexdigest(),
    "command-injection": hashlib.sha256(b"FLAG{c0mm4nd_1nj3ct10n_pwn3d}").hexdigest(),

    # Network Analysis
    "network-forensics-1": hashlib.sha256(b"FLAG{p4ssw0rd_3xf1ltr4t10n_d3t3ct3d}").hexdigest(),
    "network-forensics-2": hashlib.sha256(b"FLAG{c2_b34c0n_1d3nt1f13d_443}").hexdigest(),
    "network-forensics-3": hashlib.sha256(b"FLAG{ftp_f1l3_r3c0v3r3d_s3cr3t}").hexdigest(),
    "network-forensics-4": hashlib.sha256(b"FLAG{dns_tunn3l_d4t4_3xtr4ct3d}").hexdigest(),
    "network-forensics-5": hashlib.sha256(b"FLAG{http_s3ss10n_r3c0nstruct3d}").hexdigest(),

    # System Exploitation
    "buffer-overflow": hashlib.sha256(b"FLAG{buff3r_0v3rfl0w_m4st3r}").hexdigest(),
    "stack-smash": hashlib.sha256(b"FLAG{st4ck_sm4sh1ng_succ3ss}").hexdigest(),
    "format-string": hashlib.sha256(b"FLAG{f0rm4t_str1ng_m4st3r}").hexdigest(),
    "reverse-shell": hashlib.sha256(b"FLAG{r3v3rs3_sh3ll_pwn3d}").hexdigest(),
    "shell-stabilization": hashlib.sha256(b"FLAG{st4bl3_tty_sh3ll}").hexdigest(),

    # Database
    "mysql-basic": hashlib.sha256(b"FLAG{sql_1nj3ct10n_m4st3r}").hexdigest(),
    "postgres-injection": hashlib.sha256(b"FLAG{p0stgr3s_pwn3d}").hexdigest(),
    "data-exfiltration": hashlib.sha256(b"FLAG{s3ns1t1v3_d4t4_3xp0s3d}").hexdigest(),

    # Services
    "ssh-weak-creds": hashlib.sha256(b"FLAG{ssh_w34k_cr3ds_pwn3d}").hexdigest(),
    "ftp-anonymous": hashlib.sha256(b"FLAG{ftp_4n0nym0us_4cc3ss}").hexdigest(),
}


def validate_flag(lab_id: str, submitted_flag: str) -> bool:
    """Validate a submitted flag against the stored hash."""
    if lab_id not in FLAGS:
        return False

    submitted_hash = hashlib.sha256(submitted_flag.encode()).hexdigest()
    return submitted_hash == FLAGS[lab_id]


def get_hint(lab_id: str) -> str:
    """Get a hint for a specific lab."""
    hints = {
        "sql-injection-basic": "Try a basic OR 1=1 payload",
        "buffer-overflow": "Buffer size is 64 bytes. Find the offset to RIP.",
        "network-forensics-1": "Look for HTTP POST data in the capture",
    }
    return hints.get(lab_id, "No hint available")


def main():
    if len(sys.argv) < 3:
        print("Usage: python validator.py <lab_id> <flag>")
        print("Example: python validator.py sql-injection-basic 'FLAG{...}'")
        print("\nAvailable labs:")
        for lab_id in sorted(FLAGS.keys()):
            print(f"  - {lab_id}")
        sys.exit(1)

    lab_id = sys.argv[1]
    flag = sys.argv[2]

    if validate_flag(lab_id, flag):
        print("\n" + "=" * 50)
        print("  CORRECT! Flag validated successfully!")
        print("=" * 50 + "\n")
        sys.exit(0)
    else:
        print("\n" + "=" * 50)
        print("  INCORRECT. Try again!")
        print(f"  Hint: {get_hint(lab_id)}")
        print("=" * 50 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
