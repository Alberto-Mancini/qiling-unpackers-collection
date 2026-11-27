# -*- coding: utf-8 -*-
"""
Astaroth (Guildma) - UPX In-Memory Unpacker & Dynamic Behavioral Analyzer
=========================================================================
Harness di emulazione dinamica basato su Qiling Framework per il superamento
delle difese Anti-Analysis / Anti-Sandbox, il decompattamento automatico UPX
in memoria e l'estrazione telemetrica degli IoC del campione Astaroth.

Metadati del Campione Target (per riproducibilita'):
  - Famiglia  : Astaroth / Guildma
  - SHA-256   : 9b0d5e40ea39bcdb7f21c195750b010d7ebe343eefd691b27e572e6bbd740c33
  - Fonte     : MalwareBazaar
  - Formato   : PE32 (x86 32-bit), MinGW GCC 13-win32, compresso con UPX 4.22
  - Ambiente  : Qiling Framework (testato su v1.4.6) con rootfs Windows x86 (32-bit)

Fasi gestite dallo script:
  1. Decompattamento automatico dello stub UPX (EP 0x00413360) e dump della
     memoria PE ricostruita all'ingresso di main() (0x00401A18).
  2. Emulazione del sottosistema Microsoft CryptoAPI (ADVAPI32) assente in Qiling
     ed estrazione in chiaro della stringa segreta decifrata via XOR ("Molon Labe")
     prima della ricifratura AES-256.
  3. Bypass del rilevamento debugger (IsDebuggerPresent) e della richiesta di
     elevazione privilegi UAC (ShellExecuteA).
  4. Tracciamento dell'occultamento su filesystem (5kidRoot.exe, HIDDEN | SYSTEM)
     e della doppia persistenza nel Registro (HKCU e HKLM Run).
  5. Costruzione in RAM della struttura hostent (192.168.1.100) e intercettazione
     della scansione ICMP Ping Sweep sull'intera sottorete locale (/24, 254 host).
  6. Neutralizzazione controllata dell'attacco DoS finale (Fork-Bomb tramite
     CreateProcessA + allocazione da 400 MB e ciclo da 100 milioni di scritture).

Utilizzo:
  python astaroth_upx_unpacker_analyzer.py -s <percorso_sample> -r <percorso_rootfs_x86_windows>
"""

import argparse
import json
import os
import socket as py_socket
import struct
import sys

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.api import DWORD, HANDLE, INT, LPCSTR, POINTER, UINT
from qiling.os.windows.fncc import CDECL, STDCALL, winsdkapi

# ==============================================================================
# COSTANTI DEL CAMPIONE TARGET (SHA-256: 9b0d5e40...bbd740c33)
# ==============================================================================
SAMPLE_SHA256 = "9b0d5e40ea39bcdb7f21c195750b010d7ebe343eefd691b27e572e6bbd740c33"

IMAGE_BASE = 0x00400000
UNPACKED_DUMP_SIZE = 0x15000
UPX_STUB_EP = 0x00413360

ADDR_UNPACKED_MAIN = 0x00401A18
ADDR_MINGW_SPRINTF = 0x004014E0
ADDR_MINGW_SPRINTF_RET = 0x0040150C
ADDR_RAM_FILL_LOOP = 0x004019D2
ADDR_RAM_FILL_LOOP_END = 0x004019FC

DEFAULT_TIMEOUT_US = 30_000_000  # 30 secondi espressi in microsecondi

# ==============================================================================
# STATO GLOBALE E TELEMETRIA DELL'ANALISI
# ==============================================================================
telemetry = {}
create_process_count = 0
reg_handles = {}
next_reg_handle = 0x9000
_output_dir = os.path.dirname(os.path.abspath(__file__))


def _reset_analysis_state(output_dir=None):
    """Inizializza/ripristina lo stato globale per garantire esecuzioni ripetibili."""
    global telemetry, create_process_count, reg_handles, next_reg_handle, _output_dir

    if output_dir is not None:
        _output_dir = output_dir

    telemetry = {
        "sample": "Astaroth.exe",
        "packer": "UPX 4.22 (PE32 i386)",
        "unpacked_oep": "0x004014c0 / main @ 0x00401a18",
        "decrypted_strings": [],
        "crypto_operations": [],
        "anti_debug": [],
        "privilege_escalation": [],
        "filesystem_actions": [],
        "registry_persistence": [],
        "network_discovery": {
            "hostname": "",
            "local_ip": "",
            "socket_type": "",
            "icmp_sweep_targets": [],
            "total_icmp_packets": 0,
        },
        "dos_activity": [],
    }
    create_process_count = 0
    reg_handles = {
        0x80000001: "HKEY_CURRENT_USER",
        0x80000002: "HKEY_LOCAL_MACHINE",
    }
    next_reg_handle = 0x9000


# Inizializza lo stato di default al caricamento del modulo
_reset_analysis_state()


# ==============================================================================
# HOOKS CRYPTOAPI (Non implementate nativamente in Qiling -> Crash in cryptsp.dll)
# ==============================================================================

@winsdkapi(cc=STDCALL, params={
    "phProv": POINTER,
    "szContainer": LPCSTR,
    "szProvider": LPCSTR,
    "dwProvType": DWORD,
    "dwFlags": DWORD,
})
def hook_CryptAcquireContextA(ql, address, params):
    phProv = params["phProv"]
    dwProvType = params["dwProvType"]
    dwFlags = params["dwFlags"]
    fake_prov = 0xCAFE0001
    if phProv:
        ql.mem.write(phProv, struct.pack("<I", fake_prov))
    msg = (
        f"CryptAcquireContextA(dwProvType=0x{dwProvType:x} [PROV_RSA_AES], "
        f"dwFlags=0x{dwFlags:x}) -> hProv=0x{fake_prov:x}"
    )
    print(f"[CRYPTO] {msg}")
    telemetry["crypto_operations"].append(msg)
    return 1


@winsdkapi(cc=STDCALL, params={
    "hProv": HANDLE,
    "Algid": UINT,
    "dwFlags": DWORD,
    "phKey": POINTER,
})
def hook_CryptGenKey(ql, address, params):
    algid = params["Algid"]
    dwFlags = params["dwFlags"]
    phKey = params["phKey"]
    fake_key = 0xCAFE0002
    if phKey:
        ql.mem.write(phKey, struct.pack("<I", fake_key))
    alg_name = "CALG_AES_256" if algid == 0x6610 else f"0x{algid:x}"
    msg = (
        f"CryptGenKey(Algid=0x{algid:x} [{alg_name}], "
        f"dwFlags=0x{dwFlags:x}) -> hKey=0x{fake_key:x}"
    )
    print(f"[CRYPTO] {msg}")
    telemetry["crypto_operations"].append(msg)
    return 1


@winsdkapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "hHash": HANDLE,
    "Final": INT,
    "dwFlags": DWORD,
    "pbData": POINTER,
    "pdwDataLen": POINTER,
    "dwBufLen": DWORD,
})
def hook_CryptEncrypt(ql, address, params):
    pbData = params["pbData"]
    pdwDataLen = params["pdwDataLen"]
    dwBufLen = params["dwBufLen"]

    data_len = 0
    plaintext_str = ""
    if pdwDataLen:
        data_len = struct.unpack("<I", ql.mem.read(pdwDataLen, 4))[0]
    if pbData and data_len > 0:
        raw = bytes(ql.mem.read(pbData, data_len))
        plaintext_str = raw.split(b"\x00")[0].decode("utf-8", errors="replace")
        # Simuliamo la cifratura in-place nel buffer
        enc = bytes((b ^ 0xA5) for b in raw)
        ql.mem.write(pbData, enc)

    msg = (
        f"CryptEncrypt(pbData=0x{pbData:x}, len={data_len}, "
        f"bufLen={dwBufLen}, plaintext='{plaintext_str}')"
    )
    print(f"[CRYPTO] {msg}")
    telemetry["crypto_operations"].append(msg)
    if plaintext_str and plaintext_str not in telemetry["decrypted_strings"]:
        telemetry["decrypted_strings"].append(plaintext_str)
    return 1


@winsdkapi(cc=STDCALL, params={"hKey": HANDLE})
def hook_CryptDestroyKey(ql, address, params):
    msg = f"CryptDestroyKey(hKey=0x{params['hKey']:x})"
    print(f"[CRYPTO] {msg}")
    telemetry["crypto_operations"].append(msg)
    return 1


@winsdkapi(cc=STDCALL, params={"hProv": HANDLE, "dwFlags": DWORD})
def hook_CryptReleaseContext(ql, address, params):
    msg = f"CryptReleaseContext(hProv=0x{params['hProv']:x})"
    print(f"[CRYPTO] {msg}")
    telemetry["crypto_operations"].append(msg)
    return 1


# ==============================================================================
# HOOKS ANTI-DEBUG, PRIVILEGE ESCALATION, FILESYSTEM E REGISTRO
# ==============================================================================

@winsdkapi(cc=STDCALL, params={})
def hook_IsDebuggerPresent(ql, address, params):
    print("[ANTI-DEBUG] IsDebuggerPresent() intercettata -> Restituito 0 (Bypass)")
    telemetry["anti_debug"].append("IsDebuggerPresent() -> 0")
    return 0


@winsdkapi(cc=STDCALL, params={
    "hwnd": HANDLE,
    "lpOperation": LPCSTR,
    "lpFile": LPCSTR,
    "lpParameters": LPCSTR,
    "lpDirectory": LPCSTR,
    "nShowCmd": INT,
})
def hook_ShellExecuteA(ql, address, params):
    op = params["lpOperation"]
    f_name = params["lpFile"]
    show = params["nShowCmd"]
    msg = (
        f"ShellExecuteA(op='{op}', file='{f_name}', nShowCmd={show}) "
        f"[Tentativo di elevazione privilegi UAC]"
    )
    print(f"[PRIV-ESC] {msg}")
    telemetry["privilege_escalation"].append(msg)
    return 42  # Valore > 32 indica successo in ShellExecuteA


@winsdkapi(cc=STDCALL, params={
    "hModule": HANDLE,
    "lpFilename": POINTER,
    "nSize": DWORD,
})
def hook_GetModuleFileNameA(ql, address, params):
    buf = params["lpFilename"]
    size = params["nSize"]
    fake_self = b"C:\\Users\\Public\\Astaroth.exe\x00"
    if buf and size > 0:
        ql.mem.write(buf, fake_self[:size])
    return len(fake_self) - 1


@winsdkapi(cc=STDCALL, params={
    "hwnd": HANDLE,
    "csidl": INT,
    "hToken": HANDLE,
    "dwFlags": DWORD,
    "pszPath": POINTER,
})
def hook_SHGetFolderPathA(ql, address, params):
    csidl = params["csidl"]
    pszPath = params["pszPath"]
    appdata_path = b"C:\\Users\\Victim\\AppData\\Roaming\x00"
    if pszPath:
        ql.mem.write(pszPath, appdata_path)
    print(
        f"[FILESYSTEM] SHGetFolderPathA(csidl=0x{csidl:x} [CSIDL_APPDATA]) "
        f"-> 'C:\\Users\\Victim\\AppData\\Roaming'"
    )
    return 0  # S_OK


@winsdkapi(cc=STDCALL, params={
    "lpExistingFileName": LPCSTR,
    "lpNewFileName": LPCSTR,
    "bFailIfExists": INT,
})
def hook_CopyFileA(ql, address, params):
    src = params["lpExistingFileName"]
    dst = params["lpNewFileName"]
    msg = f"CopyFileA(src='{src}', dst='{dst}', bFailIfExists={params['bFailIfExists']})"
    print(f"[FILESYSTEM] {msg}")
    telemetry["filesystem_actions"].append(msg)
    return 1


@winsdkapi(cc=STDCALL, params={
    "lpFileName": LPCSTR,
    "dwFileAttributes": DWORD,
})
def hook_SetFileAttributesA(ql, address, params):
    fn = params["lpFileName"]
    attr = params["dwFileAttributes"]
    msg = f"SetFileAttributesA(file='{fn}', attr=0x{attr:x} [HIDDEN | SYSTEM])"
    print(f"[FILESYSTEM] {msg}")
    telemetry["filesystem_actions"].append(msg)
    return 1


@winsdkapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpSubKey": LPCSTR,
    "ulOptions": DWORD,
    "samDesired": DWORD,
    "phkResult": POINTER,
})
def hook_RegOpenKeyExA(ql, address, params):
    global next_reg_handle
    hKey = params["hKey"]
    subkey = params["lpSubKey"]
    phkResult = params["phkResult"]

    root_name = reg_handles.get(hKey, f"0x{hKey:x}")
    next_reg_handle += 1
    new_h = next_reg_handle
    reg_handles[new_h] = f"{root_name}\\{subkey}"

    if phkResult:
        ql.mem.write(phkResult, struct.pack("<I", new_h))
    print(f"[REGISTRY] RegOpenKeyExA({root_name}, '{subkey}') -> hKey=0x{new_h:x}")
    return 0  # ERROR_SUCCESS


@winsdkapi(cc=STDCALL, params={
    "hKey": HANDLE,
    "lpValueName": LPCSTR,
    "Reserved": DWORD,
    "dwType": DWORD,
    "lpData": POINTER,
    "cbData": DWORD,
})
def hook_RegSetValueExA(ql, address, params):
    hKey = params["hKey"]
    val_name = params["lpValueName"]
    lpData = params["lpData"]
    cbData = params["cbData"]

    key_path = reg_handles.get(hKey, f"0x{hKey:x}")
    val_str = ""
    if lpData and cbData > 0:
        raw = bytes(ql.mem.read(lpData, cbData))
        val_str = raw.split(b"\x00")[0].decode("utf-8", errors="replace")

    msg = f"RegSetValueExA({key_path}, value='{val_name}', data='{val_str}')"
    print(f"[PERSISTENCE] {msg}")
    telemetry["registry_persistence"].append(msg)
    return 0


@winsdkapi(cc=STDCALL, params={"hKey": HANDLE})
def hook_RegCloseKey(ql, address, params):
    return 0


# ==============================================================================
# HOOKS RETE / WINSOCK (Scansione ICMP Ping Sweep della sottorete /24)
# ==============================================================================

@winsdkapi(cc=STDCALL, params={"wVersionRequested": DWORD, "lpWSAData": POINTER})
def hook_WSAStartup(ql, address, params):
    print(f"[NETWORK] WSAStartup(version=0x{params['wVersionRequested']:x})")
    return 0


@winsdkapi(cc=STDCALL, params={"name": POINTER, "namelen": INT})
def hook_gethostname(ql, address, params):
    buf = params["name"]
    host = b"DESKTOP-SANDBOX\x00"
    if buf:
        ql.mem.write(buf, host)
    telemetry["network_discovery"]["hostname"] = "DESKTOP-SANDBOX"
    print("[NETWORK] gethostname() -> 'DESKTOP-SANDBOX'")
    return 0


@winsdkapi(cc=STDCALL, params={"name": LPCSTR})
def hook_gethostbyname(ql, address, params):
    name = params["name"]
    # Allochiamo una struttura hostent a 32-bit valida in memoria per evitare NULL dereference:
    #   +0x00 h_name      (ptr)
    #   +0x04 h_aliases   (ptr)
    #   +0x08 h_addrtype  (short = 2 AF_INET)
    #   +0x0a h_length    (short = 4)
    #   +0x0c h_addr_list (ptr -> array terminato da NULL di ptr a in_addr)
    base = ql.os.heap.alloc(0x80)
    h_name_ptr = base + 0x20
    h_addr_list_ptr = base + 0x40
    in_addr_ptr = base + 0x50

    ip_bytes = py_socket.inet_aton("192.168.1.100")
    ql.mem.write(h_name_ptr, b"DESKTOP-SANDBOX\x00")
    ql.mem.write(in_addr_ptr, ip_bytes)
    ql.mem.write(h_addr_list_ptr, struct.pack("<II", in_addr_ptr, 0))

    hostent_struct = struct.pack("<IIhhI", h_name_ptr, 0, 2, 4, h_addr_list_ptr)
    ql.mem.write(base, hostent_struct)

    telemetry["network_discovery"]["local_ip"] = "192.168.1.100"
    print(f"[NETWORK] gethostbyname('{name}') -> 192.168.1.100 (struct hostent @ 0x{base:x})")
    return base


@winsdkapi(cc=STDCALL, params={"netlong": DWORD})
def hook_ntohl(ql, address, params):
    val = params["netlong"]
    return py_socket.ntohl(val)


@winsdkapi(cc=STDCALL, params={"af": INT, "type": INT, "protocol": INT})
def hook_socket(ql, address, params):
    af = params["af"]
    stype = params["type"]
    proto = params["protocol"]
    desc = f"socket(af={af} [AF_INET], type={stype} [SOCK_RAW], protocol={proto} [IPPROTO_ICMP])"
    print(f"[NETWORK] {desc} -> handle=0x1337")
    telemetry["network_discovery"]["socket_type"] = desc
    return 0x1337


@winsdkapi(cc=STDCALL, params={"Family": INT, "pszAddrString": LPCSTR, "pAddrBuf": POINTER})
def hook_inet_pton(ql, address, params):
    ip_str = params["pszAddrString"]
    pAddrBuf = params["pAddrBuf"]
    try:
        packed = py_socket.inet_aton(ip_str)
        if pAddrBuf:
            ql.mem.write(pAddrBuf, packed)
    except Exception:
        pass
    return 1


@winsdkapi(cc=STDCALL, params={
    "s": HANDLE,
    "buf": POINTER,
    "len": INT,
    "flags": INT,
    "to": POINTER,
    "tolen": INT,
})
def hook_sendto(ql, address, params):
    to_ptr = params["to"]
    pkt_len = params["len"]
    target_ip = "unknown"
    if to_ptr:
        sockaddr = bytes(ql.mem.read(to_ptr, 8))
        target_ip = py_socket.inet_ntoa(sockaddr[4:8])

    telemetry["network_discovery"]["total_icmp_packets"] += 1
    count = telemetry["network_discovery"]["total_icmp_packets"]

    if count <= 3 or count == 254:
        print(
            f"[NETWORK] sendto(sock=0x{params['s']:x}, len={pkt_len} "
            f"[ICMP Echo Request], target={target_ip}) (#{count}/254)"
        )
        if count == 3:
            print("[NETWORK] ... (scansione ICMP ping sweep in corso su 192.168.1.4 .. 192.168.1.253) ...")

    if len(telemetry["network_discovery"]["icmp_sweep_targets"]) < 5 or count == 254:
        telemetry["network_discovery"]["icmp_sweep_targets"].append(target_ip)

    return pkt_len


@winsdkapi(cc=STDCALL, params={"s": HANDLE})
def hook_closesocket(ql, address, params):
    print(f"[NETWORK] closesocket(0x{params['s']:x})")
    return 0


@winsdkapi(cc=STDCALL, params={})
def hook_WSACleanup(ql, address, params):
    print("[NETWORK] WSACleanup()")
    return 0


# ==============================================================================
# HOOKS PROCESSO E ANTI-STALLO (Fork-Bomb & Memory Exhaustion in sub_401912)
# ==============================================================================

@winsdkapi(cc=STDCALL, params={"dwMilliseconds": DWORD})
def hook_Sleep(ql, address, params):
    ms = params["dwMilliseconds"]
    if ms >= 500:
        print(f"[ANTI-DELAY] Sleep({ms} ms) intercettato e azzerato")
    return 0


@winsdkapi(cc=STDCALL, params={
    "lpApplicationName": LPCSTR,
    "lpCommandLine": LPCSTR,
    "lpProcessAttributes": POINTER,
    "lpThreadAttributes": POINTER,
    "bInheritHandles": INT,
    "dwCreationFlags": DWORD,
    "lpEnvironment": POINTER,
    "lpCurrentDirectory": LPCSTR,
    "lpStartupInfo": POINTER,
    "lpProcessInformation": POINTER,
})
def hook_CreateProcessA(ql, address, params):
    global create_process_count
    create_process_count += 1
    app = params["lpApplicationName"]

    if create_process_count <= 2:
        msg = (
            f"CreateProcessA(app='{app}') [Iterazione Fork-Bomb #{create_process_count}] "
            f"-> Consentito (Simulato)"
        )
        print(f"[DOS / FORK-BOMB] {msg}")
        telemetry["dos_activity"].append(msg)
        return 1  # TRUE: entra nel blocco di allocazione 400 MB
    else:
        msg = (
            f"CreateProcessA(app='{app}') [Iterazione #{create_process_count}] "
            f"-> Interrotto (Restituito 0 per uscire dal loop infinito)"
        )
        print(f"[DOS / FORK-BOMB] {msg}")
        telemetry["dos_activity"].append(msg)
        return 0  # FALSE: permette l'uscita pulita da sub_401912


@winsdkapi(cc=CDECL, params={"size": DWORD})
def hook_malloc(ql, address, params):
    size = params["size"]
    if size >= 0x10000000:  # Richiesta di 0x17d78400 byte (400 MB) in sub_401912
        msg = (
            f"malloc(0x{size:x} [{size // (1024 * 1024)} MB]) intercettato! "
            f"Allocato buffer ridotto di sicurezza per prevenire OOM."
        )
        print(f"[DOS / RAM-EXHAUSTION] {msg}")
        telemetry["dos_activity"].append(msg)
        return ql.os.heap.alloc(0x1000)
    return ql.os.heap.alloc(size if size > 0 else 16)


# ==============================================================================
# HOOKS SU INDIRIZZI SPECIFICI (Post-UPX Unpacking)
# ==============================================================================

def hook_unpacked_main(ql):
    """
    Eseguito quando il sample raggiunge main() (0x00401A18) dopo il decompattamento UPX.
    Salva il dump del binario PE decompattato su disco.
    """
    print(f"\n[+] Decompattamento UPX completato! Raggiunto main() a 0x{ADDR_UNPACKED_MAIN:08x}.")
    dump_path = os.path.join(_output_dir, "astaroth_unpacked_dump.bin")
    try:
        mem = ql.mem.read(IMAGE_BASE, UNPACKED_DUMP_SIZE)
        with open(dump_path, "wb") as f:
            f.write(mem)
        print(f"[+] Dump della memoria PE decompattata salvato in: {dump_path}")
    except Exception as e:
        print(f"[-] Impossibile salvare il dump: {e}")


def hook_mingw_sprintf(ql):
    """
    Intercetta il wrapper sprintf di MinGW a 0x004014E0 (chiamato in sub_401701 con formato
    '%d.%d.%d.%d'), evitando che __mingw_pformat invochi API non implementate di locale/DBCS
    in msvcrt.dll.
    """
    esp = ql.arch.regs.esp
    buf_ptr = struct.unpack("<I", ql.mem.read(esp + 4, 4))[0]
    o1 = struct.unpack("<I", ql.mem.read(esp + 12, 4))[0] & 0xFF
    o2 = struct.unpack("<I", ql.mem.read(esp + 16, 4))[0] & 0xFF
    o3 = struct.unpack("<I", ql.mem.read(esp + 20, 4))[0] & 0xFF
    o4 = struct.unpack("<I", ql.mem.read(esp + 24, 4))[0] & 0xFF

    ip_str = f"{o1}.{o2}.{o3}.{o4}".encode("ascii") + b"\x00"
    if buf_ptr:
        ql.mem.write(buf_ptr, ip_str)
    ql.arch.regs.eax = len(ip_str) - 1
    ql.arch.regs.eip = ADDR_MINGW_SPRINTF_RET  # Salta direttamente all'istruzione 'ret'


def hook_bypass_ram_fill_loop(ql):
    """
    All'indirizzo 0x004019D2 (dentro sub_401912), il malware esegue un ciclo di
    100.000.000 di iterazioni (cmpl $0x5f5e0ff, -0xc(%ebp)) scrivendo interi nel buffer
    da 400 MB per saturare la RAM fisica. Saltiamo direttamente a 0x004019FC (dopo il loop).
    """
    msg = (
        f"Rilevato ciclo di saturazione RAM a 0x{ADDR_RAM_FILL_LOOP:x} "
        f"(100.000.000 scritture int32 = 400 MB). Bypass a 0x{ADDR_RAM_FILL_LOOP_END:x}!"
    )
    print(f"[DOS / RAM-EXHAUSTION] {msg}")
    telemetry["dos_activity"].append(msg)
    ql.arch.regs.eip = ADDR_RAM_FILL_LOOP_END


# ==============================================================================
# MOTORE PRINCIPALE DI EMULAZIONE
# ==============================================================================

def setup_astaroth_hooks(ql):
    """Registra tutti gli hook API e gli hook su indirizzo nell'istanza Qiling."""
    # Hook API Crypto (ADVAPI32)
    ql.os.set_api("CryptAcquireContextA", hook_CryptAcquireContextA)
    ql.os.set_api("CryptGenKey", hook_CryptGenKey)
    ql.os.set_api("CryptEncrypt", hook_CryptEncrypt)
    ql.os.set_api("CryptDestroyKey", hook_CryptDestroyKey)
    ql.os.set_api("CryptReleaseContext", hook_CryptReleaseContext)

    # Hook Sistema, Persistenza e FileSystem
    ql.os.set_api("IsDebuggerPresent", hook_IsDebuggerPresent)
    ql.os.set_api("ShellExecuteA", hook_ShellExecuteA)
    ql.os.set_api("GetModuleFileNameA", hook_GetModuleFileNameA)
    ql.os.set_api("SHGetFolderPathA", hook_SHGetFolderPathA)
    ql.os.set_api("CopyFileA", hook_CopyFileA)
    ql.os.set_api("SetFileAttributesA", hook_SetFileAttributesA)
    ql.os.set_api("RegOpenKeyExA", hook_RegOpenKeyExA)
    ql.os.set_api("RegSetValueExA", hook_RegSetValueExA)
    ql.os.set_api("RegCloseKey", hook_RegCloseKey)

    # Hook Rete (WS2_32)
    ql.os.set_api("WSAStartup", hook_WSAStartup)
    ql.os.set_api("gethostname", hook_gethostname)
    ql.os.set_api("gethostbyname", hook_gethostbyname)
    ql.os.set_api("ntohl", hook_ntohl)
    ql.os.set_api("socket", hook_socket)
    ql.os.set_api("inet_pton", hook_inet_pton)
    ql.os.set_api("sendto", hook_sendto)
    ql.os.set_api("closesocket", hook_closesocket)
    ql.os.set_api("WSACleanup", hook_WSACleanup)

    # Hook Processi, Memoria e Tempo
    ql.os.set_api("Sleep", hook_Sleep)
    ql.os.set_api("CreateProcessA", hook_CreateProcessA)
    ql.os.set_api("malloc", hook_malloc)

    # Hook su indirizzi specifici (post-UPX unpacking)
    ql.hook_address(hook_unpacked_main, ADDR_UNPACKED_MAIN)
    ql.hook_address(hook_mingw_sprintf, ADDR_MINGW_SPRINTF)
    ql.hook_address(hook_bypass_ram_fill_loop, ADDR_RAM_FILL_LOOP)


def avvia_emulazione_astaroth(pe_path, rootfs_path, output_dir=None, verbose=False):
    """Configura Qiling, esegue l'emulazione completa di Astaroth ed esporta la telemetria."""
    pe_path = os.path.abspath(pe_path)
    rootfs_path = os.path.abspath(rootfs_path)
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))
    else:
        output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    _reset_analysis_state(output_dir=output_dir)

    print("=" * 75)
    print(f"[*] Avvio Analisi Dinamica in Qiling: {os.path.basename(pe_path)}")
    print(f"[*] Target SHA-256 atteso: {SAMPLE_SHA256}")
    print(f"[*] Rootfs Qiling        : {rootfs_path}")
    print("=" * 75)

    log_level = QL_VERBOSE.DEFAULT if verbose else QL_VERBOSE.DISABLED
    ql = Qiling([pe_path], rootfs_path, verbose=log_level)
    setup_astaroth_hooks(ql)

    print(f"[*] Esecuzione avviata dallo stub UPX (Entry Point: 0x{UPX_STUB_EP:08x})...")
    try:
        ql.run(timeout=DEFAULT_TIMEOUT_US)
        print("\n" + "=" * 75)
        print("[+] EMULAZIONE COMPLETATA CON SUCCESSO FINO ALLA TERMINAZIONE DEL PROCESSO!")
        print("=" * 75)
    except Exception as e:
        print(f"\n[!] Errore durante l'emulazione a EIP={hex(ql.arch.regs.eip)}: {e}")

    report_path = os.path.join(output_dir, "astaroth_report.json")
    with open(report_path, "w", encoding="utf-8") as rf:
        json.dump(telemetry, rf, indent=4, ensure_ascii=False)
    print(f"[+] Report telemetrico JSON salvato in: {report_path}")


def _resolve_default_sample(base_dir):
    """Ricerca il sample nei percorsi predefiniti per compatibilita' immediata."""
    candidates = [
        os.path.join(base_dir, "Source", "Astaroth", "Astaroth.exe"),
        os.path.join(os.getcwd(), "Source", "Astaroth", "Astaroth.exe"),
        os.path.join(base_dir, "Astaroth.exe"),
        os.path.join(base_dir, f"{SAMPLE_SHA256}.exe"),
        os.path.join(base_dir, "sample.exe"),
        os.path.join(base_dir, "sample.dat"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return candidates[0]


def _parse_args():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    default_sample = _resolve_default_sample(base_dir)
    default_rootfs = os.path.abspath(os.path.join(base_dir, "..", ".."))

    parser = argparse.ArgumentParser(
        description=(
            "Astaroth (Guildma) Qiling Unpacker & Behavioral Analyzer "
            f"[Target SHA-256: {SAMPLE_SHA256}]"
        )
    )
    parser.add_argument(
        "-s", "--sample",
        default=default_sample,
        help="Percorso al sample Astaroth compresso con UPX (PE32 x86)",
    )
    parser.add_argument(
        "-r", "--rootfs",
        default=default_rootfs,
        help="Percorso al rootfs Windows x86 (32-bit) di Qiling (es. examples/rootfs/x86_windows)",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=base_dir,
        help="Cartella di destinazione per il dump PE e il report JSON (default: cartella dello script)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Abilita i log interni di Qiling (default: disabilitati per output pulito)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if not os.path.isfile(args.sample):
        print(f"[-] Errore: File malware non trovato in: {args.sample}")
        print(f"    Fornisci il campione (SHA-256: {SAMPLE_SHA256}) tramite:")
        print(f"    python {os.path.basename(__file__)} -s <percorso_sample> -r <percorso_rootfs_x86_windows>")
        sys.exit(1)

    if not os.path.isdir(args.rootfs):
        print(f"[-] Errore: Directory rootfs di Qiling non trovata in: {args.rootfs}")
        print(f"    Specifica il rootfs x86_windows con: -r <percorso_rootfs_x86_windows>")
        sys.exit(1)

    try:
        entries_lower = [entry.lower() for entry in os.listdir(args.rootfs)]
        if "windows" not in entries_lower:
            print(
                f"[!] Avviso: La cartella 'Windows' non sembra presente in '{args.rootfs}'. "
                f"Se Qiling fallisce l'avvio, passa il percorso esplicito con -r <rootfs/x86_windows>."
            )
    except OSError:
        pass

    avvia_emulazione_astaroth(
        pe_path=args.sample,
        rootfs_path=args.rootfs,
        output_dir=args.output_dir,
        verbose=args.verbose,
    )
