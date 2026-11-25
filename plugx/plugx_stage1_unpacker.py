"""
PlugX Stage-1 In-Memory Unpacker
Leverages Qiling for targeted emulation to extract the decompressed payload.
Execution is safely halted immediately after the payload dump to prevent unstable state.
"""
# -*- coding: utf-8 -*-
import os
import sys
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# ==========================================
# MINIMAL ANTI-EVASION (To bypass initial checks)
# ==========================================
@winsdkapi(cc=STDCALL, params={'dwMilliseconds': DWORD})
def hook_Sleep(ql, address, params):
    # Fast-forward delays to speed up analysis
    return 0

@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    # Simulate basic uptime
    return 0x5000 

@winsdkapi(cc=STDCALL, params={'nIndex': DWORD})
def hook_GetSystemMetrics(ql, address, params):
    # Simulate a standard resolution screen
    index = params['nIndex']
    if index == 0: return 1920 
    elif index == 1: return 1080 
    return 1

# ==========================================
# THE SWEET SPOT: TARGETED DUMP & STOP
# ==========================================
@winsdkapi(cc=STDCALL, params={
    'hProcess': HANDLE, 'lpBaseAddress': LPVOID, 'lpBuffer': POINTER, 
    'nSize': SIZE_T, 'lpNumberOfBytesWritten': POINTER
})
def hook_WriteProcessMemory(ql, address, params):
    size = params['nSize']
    dest_addr = params['lpBaseAddress']
    
    if size > 0:
        print("\n" + "="*70)
        print("🎯 [SWEET SPOT] Injection routine intercepted (WriteProcessMemory)")
        print(f" [*] Target Address : {hex(dest_addr)}")
        print(f" [*] Payload Size   : {size} bytes")
        
        try:
            # Read the decrypted/unpacked buffer
            data = ql.mem.read(params['lpBuffer'], size)
            
            # Identify if it's a valid PE file
            if data.startswith(b'MZ'):
                print(" [+] Valid PE header (MZ) detected in the extracted buffer.")
            else:
                print(" [*] Extracted raw shellcode/payload (No MZ header).")

            # Dump to disk
            dump_name = "plugx_stage1_unpacked.bin"
            with open(dump_name, "wb") as f:
                f.write(data)
                
            print(f" [+] DUMP SUCCESSFUL: Saved to '{dump_name}'")
            
        except Exception as e:
            print(f" [-] ERROR reading memory during dump: {e}")
            
        print(" [+] Safely halting emulation to prevent unstable execution...")
        print("="*70 + "\n")
        
        # THIS IS THE CORE OF TARGETED EMULATION
        ql.stop() 
        
    return 1 

# ==========================================
# SETUP & EXECUTION
# ==========================================
def setup_unpacker_hooks(ql):
    # Basic Evasion Bypasses
    ql.os.set_api("Sleep", hook_Sleep)
    ql.os.set_api("GetTickCount", hook_GetTickCount)
    ql.os.set_api("GetSystemMetrics", hook_GetSystemMetrics)
    
    # Injection / Unpacking interception
    ql.os.set_api("WriteProcessMemory", hook_WriteProcessMemory)

def run_unpacker(pe_path, rootfs_path):
    print(f"[*] Starting Targeted Emulation for: {os.path.basename(pe_path)}")
    print("[*] Goal: Intercept memory injection, dump payload, and exit.")
    
    try:
        # Initialize Qiling with lower verbosity to keep output clean
        ql = Qiling([pe_path], rootfs_path, verbose=QL_VERBOSE.DEFAULT)
        setup_unpacker_hooks(ql)
        
        print("[*] Emulation engine running. Waiting for unpacking routine...\n")
        ql.run() 
        
    except Exception as e:
        print(f"\n[!] Emulation exception (often expected after ql.stop): {e}")

if __name__ == "__main__":
    # Setup paths relative to the repository structure
    rootfs = os.path.join(os.getcwd(), "..", "..") # Adjust based on your rootfs location
    malware_path = os.path.join(os.getcwd(), "sample.dat") # Use the dummy or the public sample
    
    if not os.path.exists(malware_path):
        print(f"\n[-] ERROR: Target file not found: {malware_path}")
        print("    Please provide the encrypted sample or dummy file.")
        sys.exit(1)
        
    run_unpacker(malware_path, rootfs)