"""
Generic Qiling Malware Emulation Template
Use this as a starting point for new malware analysis modules.
"""

import os
import argparse
from qiling import Qiling
from qiling.const import QL_VERBOSE

def hook_example_api(ql: Qiling, arg1: int, arg2: int) -> int:
    """
    Example API hook.
    """
    print(f"[*] Example API hooked. Arg1: 0x{arg1:x}, Arg2: 0x{arg2:x}")
    return 0

def run_emulation(sample_path: str, rootfs_path: str, verbose: bool = False) -> None:
    """
    Configures and runs the Qiling environment.
    """
    if not os.path.exists(sample_path):
        print(f"[-] Error: Sample file not found at {sample_path}")
        return
    if not os.path.exists(rootfs_path):
        print(f"[-] Error: Rootfs not found at {rootfs_path}")
        return

    log_level = QL_VERBOSE.DEBUG if verbose else QL_VERBOSE.DEFAULT

    print(f"[*] Loading sample: {sample_path}")
    print(f"[*] Using rootfs: {rootfs_path}")

    # Initialize the Qiling instance
    # Adjust architecture and OS as needed for the target
    ql = Qiling(
        [sample_path],
        rootfs_path,
        console=False,
        verbose=log_level
    )

    # === Setup Hooks ===
    # ql.os.set_api("LoadLibraryA", hook_example_api)
    
    # === Memory Modifications (if needed) ===
    # ql.mem.write(0x1000000, b"\\x90\\x90")

    print("[*] Starting emulation engine...")
    try:
        ql.run()
    except Exception as e:
        print(f"[-] Emulation halted due to exception: {e}")
    finally:
        print("[*] Emulation run completed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Targeted Malware Emulation Harness (Template)")
    parser.add_argument("-s", "--sample", required=True, help="Path to the malware sample")
    parser.add_argument("-r", "--rootfs", required=True, help="Path to the Qiling rootfs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debug logging")
    
    args = parser.parse_args()
    
    run_emulation(args.sample, args.rootfs, args.verbose)
