# -*- coding: utf-8 -*-
"""
TrickBot (Go Loader / RAT) - Multi-Stage Anti-VM & WebSocket C2 Analyzer
========================================================================
Harness di emulazione dinamica completa basato su Qiling Framework per
l'analisi multi-stadio del campione Go a 64 bit etichettato come TrickBot,
il superamento delle verifiche Anti-VM / Anti-Sandbox e l'interazione
completa con il protocollo C2 WebSocket + Protocol Buffers.

Metadati del Campione Target (per riproducibilita'):
  - Famiglia  : TrickBot / Go RAT Loader (attribuzione MalwareBazaar)
  - SHA-256   : 818a48e399389a23fc73994dc4331314374a7097fe831b4ee617b9315487d804
  - Fonte     : MalwareBazaar
  - Formato   : PE32+ (x86_64 64-bit), compilato in Go 1.23.4
  - Ambiente  : Qiling Framework (testato su v1.4.6) con rootfs Windows x86_64 (64-bit)

Fasi gestite dallo script:
  1. Adattamento del runtime Go 1.23 a 64 bit in modalita' single-thread
     (gestione memoria VirtualAlloc/VirtualQuery, bypass gcenable e signal_recv,
     avanzamento dell'orologio condiviso KUSER_SHARED_DATA su attese IOCP).
  2. Superamento dell'evasione tramite processo figlio nascosto (_HIDDEN_CHILD):
     intercettazione di CreateProcessW e forzatura di RAX=0 a 0x77dd94 per
     proseguire in-process nello Stadio 2 evitando os.Exit(0).
  3. Simulazione completa COM / OLE / WMI (IDispatch + IEnumVARIANT) per
     presentare una CPU desktop Intel Core i7-9700K (8 core fisici/logici, 3600 MHz).
  4. Falsificazione coerente delle risorse hardware e di sistema (uptime > 1 ora,
     carico CPU realistico ~24.69%, 16 GB RAM, disco NTFS da 500 GB, NIC Gigabit
     Intel 82574L con traffico pregresso di 154 MB RX / 48 MB TX su Windows 10 Pro).
  5. Simulazione DNS/HTTP per IP pubblico (api.ipify.org) e geolocalizzazione
     (ip-api.com -> New York, US), scansione porte locali e server C2 WebSocket
     RFC 6455 (ws://54.233.190.22:8080/ws) con decodifica/iniezione di messaggi
     Protocol Buffers ed esportazione del report trickbot_c2_full_report.json.

Utilizzo:
  python trickbot_multistage_c2_analyzer.py -s <percorso_sample> -r <percorso_rootfs_x8664_windows>
"""

import argparse
import base64
import hashlib
import json
import os
import struct
import sys

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.api import (
    BOOL,
    BYTE,
    DWORD,
    HANDLE,
    INT,
    LONG,
    POINTER,
    SIZE_T,
    STRING,
    UINT,
    ULONG,
    ULONGLONG,
    WORD,
    WSTRING,
)
from qiling.os.windows.fncc import STDCALL, winsdkapi

SAMPLE_SHA256 = "818a48e399389a23fc73994dc4331314374a7097fe831b4ee617b9315487d804"

# ==============================================================================
# WRAPPER HANDLE PER COMPATIBILITA' QILING (CloseHandle / Permissions Fix)
# ==============================================================================
handle_auto_counter = 0xa0001000

class QlVirtualFileHandle:
    """
    Incapsula oggetti file Python (es. os.devnull o file reali) consentendo all'HandleManager
    e a CloseHandle di Qiling di accedere agli attributi .id, .permissions, .inherit senza errori.
    Inoltra inoltre in modo trasparente tutte le operazioni di I/O (seek, tell, read, write).
    """
    def __init__(self, obj, name="file"):
        self.obj = obj
        self.name = name
        self.id = 0
        self.permissions = 0
        self.inherit = False

    def fileno(self):
        try:
            return self.obj.fileno()
        except Exception:
            return -1

    def seek(self, *args, **kwargs):
        return self.obj.seek(*args, **kwargs)

    def tell(self):
        return self.obj.tell()

    def read(self, *args, **kwargs):
        return self.obj.read(*args, **kwargs)

    def write(self, *args, **kwargs):
        return self.obj.write(*args, **kwargs)

    def close(self):
        try:
            return self.obj.close()
        except Exception:
            pass

    def __getattr__(self, item):
        if hasattr(self.obj, item):
            return getattr(self.obj, item)
        return None

def get_or_create_file_handle(ql, file_obj, name="file"):
    """
    Registra in sicurezza uno stream aperto nell'HandleManager di Qiling,
    garantendo la restituzione di un identificatore intero positivo valido.
    """
    global handle_auto_counter
    handle_auto_counter += 4
    h_id = handle_auto_counter

    h_wrap = QlVirtualFileHandle(file_obj, name)
    h_wrap.id = h_id

    try:
        res = ql.os.handle_manager.append(h_wrap)
        if isinstance(res, int) and res > 0:
            h_id = res
        elif hasattr(h_wrap, 'id') and isinstance(h_wrap.id, int) and h_wrap.id > 0:
            h_id = h_wrap.id
    except Exception as e:
        print(f"[-] Errore append handle_manager: {e}")

    try:
        if hasattr(ql.os.handle_manager, 'handles') and isinstance(ql.os.handle_manager.handles, dict):
            ql.os.handle_manager.handles[h_id] = h_wrap
    except Exception:
        pass

    return h_id

def set_last_error(ql, error_code):
    """
    Imposta LastError nell'ambiente Qiling e scrive fisicamente nel TEB a 64 bit (offset 0x68),
    in modo che le interrogazioni native Go tramite GS:[0x68] o GetLastError() ricevano
    esattamente il codice desiderato (es. WAIT_TIMEOUT = 258, ERROR_INSUFFICIENT_BUFFER = 122).
    """
    try:
        ql.os.last_error = error_code
    except Exception:
        pass
    try:
        teb_addr = 0x6000000
        if hasattr(ql.os, 'teb') and ql.os.teb and hasattr(ql.os.teb, 'address'):
            teb_addr = ql.os.teb.address
        ql.mem.write(teb_addr + 0x68, struct.pack('<I', error_code))
    except Exception:
        pass

def read_wstring(ql, address, max_chars=256):
    """Legge una stringa Unicode UTF-16LE terminata da zero dalla memoria virtuale."""
    if not address or address == 0:
        return ""
    try:
        raw = ql.mem.read(address, max_chars * 2)
        chars = []
        for i in range(0, len(raw), 2):
            val = struct.unpack('<H', raw[i:i+2])[0]
            if val == 0:
                break
            chars.append(chr(val))
        return "".join(chars)
    except Exception:
        return ""

# ==============================================================================
# GESTIONE TEMPO (Anti-Evasion & Monotonic Clock)
# ==============================================================================
tempo_simulato = 0x1000
simulated_qpc = 10000000

def update_kuser_time(ql, increment_ms=1000):
    try:
        curr_time = struct.unpack('<Q', ql.mem.read(0x7ffe0008, 8))[0]
        curr_time += int(increment_ms) * 10000  # +increment_ms in unità da 100ns
        ql.mem.write(0x7ffe0008, struct.pack('<Q', curr_time))
        ql.mem.write(0x7ffe0014, struct.pack('<Q', curr_time))
        ql.mem.write(0x7ffe0320, struct.pack('<I', int(curr_time // 10000) & 0xFFFFFFFF))
    except Exception:
        pass

@winsdkapi(cc=STDCALL, params={'dwMilliseconds': DWORD})
def hook_Sleep(ql, address, params):
    global tempo_simulato
    ms = params['dwMilliseconds']
    tempo_simulato += ms
    update_kuser_time(ql, max(ms, 100))
    print(f"\n⏱ [ANTI-VM] Sleep bypassato: {ms} ms salvati.")
    return 0

@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    global tempo_simulato
    tempo_simulato += 50
    update_kuser_time(ql, 50)
    set_last_error(ql, 0)
    return tempo_simulato

@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount64(ql, address, params):
    global tempo_simulato
    tempo_simulato += 250
    update_kuser_time(ql, 250)
    set_last_error(ql, 0)
    uptime_ms = 3600000 + tempo_simulato  # ~1 ora di uptime simulato
    print(f"\n[DEBUG/SYSINFO] ⏱ GetTickCount64 chiamato -> Restituito uptime={uptime_ms} ms ({uptime_ms // 1000} s)")
    return uptime_ms

@winsdkapi(cc=STDCALL, params={'lpPerformanceCount': POINTER})
def hook_QueryPerformanceCounter(ql, address, params):
    global simulated_qpc
    lpPerf = params['lpPerformanceCount']
    simulated_qpc += 10000
    if lpPerf and lpPerf != 0:
        try:
            ql.mem.write(lpPerf, struct.pack('<Q', simulated_qpc))
        except Exception:
            pass
    update_kuser_time(ql)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'lpFrequency': POINTER})
def hook_QueryPerformanceFrequency(ql, address, params):
    lpFreq = params['lpFrequency']
    if lpFreq and lpFreq != 0:
        try:
            ql.mem.write(lpFreq, struct.pack('<Q', 10000000))  # 10 MHz
        except Exception:
            pass
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'uPeriod': UINT})
def hook_timeBeginPeriod(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={'uPeriod': UINT})
def hook_timeEndPeriod(ql, address, params):
    return 0

# ==============================================================================
# FIX API DI SISTEMA, PRIVILEGI ED ECCEZIONI
# ==============================================================================
@winsdkapi(cc=STDCALL, params={})
def hook_GetErrorMode(ql, address, params):
    return 0x0002  # SEM_NOGPFAULTERRORBOX

@winsdkapi(cc=STDCALL, params={})
def hook_WerGetFlagsWorker(ql, address, params):
    return 0x0001  # WER_FAULT_REPORTING_FLAG_NOHEAP

@winsdkapi(cc=STDCALL, params={'dwFlags': DWORD})
def hook_WerSetFlagsWorker(ql, address, params):
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={})
def hook_AddVectoredContinueHandler(ql, address, params):
    return 0x12345678

@winsdkapi(cc=STDCALL, params={
    'lpTimerAttributes': POINTER,
    'lpTimerName': WSTRING,
    'dwFlags': DWORD,
    'dwDesiredAccess': DWORD
})
def hook_CreateWaitableTimerExW(ql, address, params):
    return 0x40001

@winsdkapi(cc=STDCALL, params={
    'hTimer': HANDLE,
    'lpDueTime': POINTER,
    'lPeriod': LONG,
    'pfnCompletionRoutine': POINTER,
    'lpArgToCompletionRoutine': POINTER,
    'fResume': BOOL
})
def hook_SetWaitableTimer(ql, address, params):
    return 1

@winsdkapi(cc=STDCALL, params={'hTimer': HANDLE})
def hook_CancelWaitableTimer(ql, address, params):
    return 1

@winsdkapi(cc=STDCALL, params={
    'hProcess': HANDLE,
    'lpProcessAffinityMask': POINTER,
    'lpSystemAffinityMask': POINTER
})
def hook_GetProcessAffinityMask(ql, address, params):
    pMask = params['lpProcessAffinityMask']
    sMask = params['lpSystemAffinityMask']
    fake_mask = struct.pack('<Q', 0x04)  # 4 CPU cores
    if pMask and pMask != 0:
        try:
            ql.mem.write(pMask, fake_mask)
        except Exception:
            pass
    if sMask and sMask != 0:
        try:
            ql.mem.write(sMask, fake_mask)
        except Exception:
            pass
    return 1

@winsdkapi(cc=STDCALL, params={'hProcess': HANDLE, 'bDisablePriorityBoost': BOOL})
def hook_SetProcessPriorityBoost(ql, address, params):
    return 1

@winsdkapi(cc=STDCALL, params={'HandlerRoutine': POINTER, 'Add': BOOL})
def hook_SetConsoleCtrlHandler(ql, address, params):
    return 1

@winsdkapi(cc=STDCALL, params={'WaitCompletionPacketHandle': POINTER})
def hook_NtCreateWaitCompletionPacket(ql, address, params):
    pHandle = params['WaitCompletionPacketHandle']
    if pHandle and pHandle != 0:
        try:
            ql.mem.write(pHandle, struct.pack('<Q', 0x90001))
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={
    'lpIdleTime': POINTER,
    'lpKernelTime': POINTER,
    'lpUserTime': POINTER
})
def hook_GetSystemTimes(ql, address, params):
    p_idle = params['lpIdleTime']
    p_kernel = params['lpKernelTime']
    p_user = params['lpUserTime']
    base_time = 133000000000000000
    idle_val = base_time + 700000000    # ~70% idle
    kernel_val = base_time + 900000000  # ~20% kernel
    user_val = base_time + 100000000    # ~10% user
    if p_idle and p_idle != 0:
        try:
            ql.mem.write(p_idle, struct.pack('<Q', idle_val))
        except Exception:
            pass
    if p_kernel and p_kernel != 0:
        try:
            ql.mem.write(p_kernel, struct.pack('<Q', kernel_val))
        except Exception:
            pass
    if p_user and p_user != 0:
        try:
            ql.mem.write(p_user, struct.pack('<Q', user_val))
        except Exception:
            pass
    set_last_error(ql, 0)
    return 1  # TRUE

# ==============================================================================
# SUITE HARDWARE & OS RECONNAISSANCE (gopsutil / ntdll / kernel32 / advapi32)
# ==============================================================================
nt_cpu_call_count = 0

@winsdkapi(cc=STDCALL, params={
    'SystemInformationClass': ULONG,
    'SystemInformation': POINTER,
    'SystemInformationLength': ULONG,
    'ReturnLength': POINTER
})
def hook_NtQuerySystemInformation(ql, address, params):
    global nt_cpu_call_count
    info_class = params['SystemInformationClass']
    buf = params['SystemInformation']
    buf_len = params['SystemInformationLength']
    ret_len_ptr = params['ReturnLength']

    # Class 8: SystemProcessorPerformanceInformation (48 bytes per core)
    if info_class == 8:
        nt_cpu_call_count += 1
        num_cores = 8
        entry_size = 48
        total_size = num_cores * entry_size
        # Incrementiamo i contatori ad ogni chiamata per permettere il calcolo delta CPU Usage (~24.5%)
        step = nt_cpu_call_count
        idle_ticks = 100000000 + step * 7550000
        kernel_ticks = 150000000 + step * 9000000  # KernelTime include IdleTime su Windows
        user_ticks = 30000000 + step * 1000000
        dpc_ticks = 2000000 + step * 50000
        irq_ticks = 1000000 + step * 25000
        irq_count = 5000 + step * 100

        if buf and buf != 0 and buf_len >= total_size:
            entry = struct.pack('<qqqqqQ', idle_ticks, kernel_ticks, user_ticks, dpc_ticks, irq_ticks, irq_count)
            try:
                ql.mem.write(buf, entry * num_cores)
            except Exception:
                pass
        if ret_len_ptr and ret_len_ptr != 0:
            try:
                ql.mem.write(ret_len_ptr, struct.pack('<I', total_size))
            except Exception:
                pass
        print(f"\n[DEBUG/SYSINFO] 🖥️ NtQuerySystemInformation(SystemProcessorPerformanceInformation): Popolati {num_cores} core (campione #{nt_cpu_call_count})")
        set_last_error(ql, 0)
        return 0  # STATUS_SUCCESS

    if ret_len_ptr and ret_len_ptr != 0:
        try:
            ql.mem.write(ret_len_ptr, struct.pack('<I', 0))
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'lpBuffer': POINTER})
def hook_GlobalMemoryStatusEx(ql, address, params):
    buf = params['lpBuffer']
    total_phys = 16 * 1024 * 1024 * 1024  # 16 GB RAM
    avail_phys = 10 * 1024 * 1024 * 1024  # 10 GB Free (6 GB Used = 37.5%)
    total_page = 32 * 1024 * 1024 * 1024
    avail_page = 24 * 1024 * 1024 * 1024
    total_virt = 0x7FFFFFFE0000
    avail_virt = 0x7FFFFFF00000
    if buf and buf != 0:
        data = struct.pack('<IIQQQQQQQ', 64, 37, total_phys, avail_phys, total_page, avail_page, total_virt, avail_virt, 0)
        try:
            ql.mem.write(buf, data)
            print(f"\n[DEBUG/SYSINFO] 🧠 GlobalMemoryStatusEx: Total=16 GB, Used=6 GB, Free=10 GB")
        except Exception:
            pass
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'nBufferLength': DWORD, 'lpBuffer': POINTER})
def hook_GetLogicalDriveStringsW(ql, address, params):
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    drives = "C:\\\x00\x00".encode('utf-16le')
    if buf and buf != 0 and n_len >= 4:
        try:
            ql.mem.write(buf, drives)
            print("\n[DEBUG/SYSINFO] 💽 GetLogicalDriveStringsW: Restituito volume 'C:\\'")
        except Exception:
            pass
    set_last_error(ql, 0)
    return 4

@winsdkapi(cc=STDCALL, params={'lpRootPathName': WSTRING})
def hook_GetDriveTypeW(ql, address, params):
    set_last_error(ql, 0)
    return 3  # DRIVE_FIXED

@winsdkapi(cc=STDCALL, params={
    'lpRootPathName': WSTRING,
    'lpVolumeNameBuffer': POINTER,
    'nVolumeNameSize': DWORD,
    'lpVolumeSerialNumber': POINTER,
    'lpMaximumComponentLength': POINTER,
    'lpFileSystemFlags': POINTER,
    'lpFileSystemNameBuffer': POINTER,
    'nFileSystemNameSize': DWORD
})
def hook_GetVolumeInformationW(ql, address, params):
    vol_buf = params['lpVolumeNameBuffer']
    ser_ptr = params['lpVolumeSerialNumber']
    max_comp_ptr = params['lpMaximumComponentLength']
    flags_ptr = params['lpFileSystemFlags']
    fs_buf = params['lpFileSystemNameBuffer']
    if vol_buf and vol_buf != 0:
        try:
            ql.mem.write(vol_buf, "Windows\x00".encode('utf-16le'))
        except Exception:
            pass
    if ser_ptr and ser_ptr != 0:
        try:
            ql.mem.write(ser_ptr, struct.pack('<I', 0x12345678))
        except Exception:
            pass
    if max_comp_ptr and max_comp_ptr != 0:
        try:
            ql.mem.write(max_comp_ptr, struct.pack('<I', 255))
        except Exception:
            pass
    if flags_ptr and flags_ptr != 0:
        try:
            ql.mem.write(flags_ptr, struct.pack('<I', 0))
        except Exception:
            pass
    if fs_buf and fs_buf != 0:
        try:
            ql.mem.write(fs_buf, "NTFS\x00".encode('utf-16le'))
        except Exception:
            pass
    print("\n[DEBUG/SYSINFO] 💽 GetVolumeInformationW: Volume='Windows', FileSystem='NTFS'")
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    'lpDirectoryName': WSTRING,
    'lpFreeBytesAvailableToCaller': POINTER,
    'lpTotalNumberOfBytes': POINTER,
    'lpTotalNumberOfFreeBytes': POINTER
})
def hook_GetDiskFreeSpaceExW(ql, address, params):
    p_free_caller = params['lpFreeBytesAvailableToCaller']
    p_total = params['lpTotalNumberOfBytes']
    p_free = params['lpTotalNumberOfFreeBytes']
    total_space = 500 * 1024 * 1024 * 1024  # 500 GB
    free_space = 320 * 1024 * 1024 * 1024   # 320 GB
    if p_free_caller and p_free_caller != 0:
        try:
            ql.mem.write(p_free_caller, struct.pack('<Q', free_space))
        except Exception:
            pass
    if p_total and p_total != 0:
        try:
            ql.mem.write(p_total, struct.pack('<Q', total_space))
        except Exception:
            pass
    if p_free and p_free != 0:
        try:
            ql.mem.write(p_free, struct.pack('<Q', free_space))
        except Exception:
            pass
    print("\n[DEBUG/SYSINFO] 💽 GetDiskFreeSpaceExW: Total=500 GB, Used=180 GB, Free=320 GB")
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'lpVersionInformation': POINTER})
def hook_RtlGetVersion(ql, address, params):
    buf = params['lpVersionInformation']
    if buf and buf != 0:
        try:
            ver_struct = bytearray(284)
            struct.pack_into('<IIIII', ver_struct, 0, 284, 10, 0, 19045, 2)  # Win 10.0 Build 19045
            struct.pack_into('<B', ver_struct, 0x11a, 1)  # VER_NT_WORKSTATION
            ql.mem.write(buf, bytes(ver_struct))
            print("\n[DEBUG/SYSINFO] 🪟 RtlGetVersion: Windows 10.0 Build 19045 (Workstation)")
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0  # STATUS_SUCCESS

@winsdkapi(cc=STDCALL, params={
    'hKey': HANDLE,
    'lpSubKey': WSTRING,
    'ulOptions': DWORD,
    'samDesired': DWORD,
    'phkResult': POINTER
})
def hook_RegOpenKeyExW(ql, address, params):
    subkey = params['lpSubKey'] or ""
    phk = params['phkResult']
    h_out = 0x77001
    if "Cryptography" in subkey:
        h_out = 0x77002
    if phk and phk != 0:
        try:
            ql.mem.write(phk, struct.pack('<Q', h_out))
        except Exception:
            pass
    print(f"\n[DEBUG/REG] 🔑 RegOpenKeyExW: '{subkey}' -> Handle={hex(h_out)}")
    set_last_error(ql, 0)
    return 0  # ERROR_SUCCESS

@winsdkapi(cc=STDCALL, params={
    'hKey': HANDLE,
    'lpValueName': WSTRING,
    'lpReserved': POINTER,
    'lpType': POINTER,
    'lpData': POINTER,
    'lpcbData': POINTER
})
def hook_RegQueryValueExW(ql, address, params):
    val_name = params['lpValueName'] or ""
    p_type = params['lpType']
    p_data = params['lpData']
    p_cb = params['lpcbData']

    reg_values = {
        "ProductName": (1, "Windows 10 Pro\x00".encode('utf-16le')),
        "CurrentBuildNumber": (1, "19045\x00".encode('utf-16le')),
        "CurrentBuild": (1, "19045\x00".encode('utf-16le')),
        "ReleaseId": (1, "22H2\x00".encode('utf-16le')),
        "DisplayVersion": (1, "22H2\x00".encode('utf-16le')),
        "CSDVersion": (1, "\x00".encode('utf-16le')),
        "UBR": (4, struct.pack('<I', 3803)),
        "MachineGuid": (1, "d1a2b3c4-e5f6-4789-8012-3456789abcde\x00".encode('utf-16le')),
    }

    if val_name not in reg_values:
        set_last_error(ql, 2)  # ERROR_FILE_NOT_FOUND
        return 2

    reg_type, raw_bytes = reg_values[val_name]
    if p_type and p_type != 0:
        try:
            ql.mem.write(p_type, struct.pack('<I', reg_type))
        except Exception:
            pass

    avail_len = 0
    if p_cb and p_cb != 0:
        try:
            avail_len = struct.unpack('<I', ql.mem.read(p_cb, 4))[0]
            ql.mem.write(p_cb, struct.pack('<I', len(raw_bytes)))
        except Exception:
            pass

    if p_data and p_data != 0:
        if avail_len < len(raw_bytes):
            set_last_error(ql, 234)  # ERROR_MORE_DATA
            return 234
        try:
            ql.mem.write(p_data, raw_bytes)
            print(f"[+] 🔑 RegQueryValueExW: '{val_name}' -> Restituiti {len(raw_bytes)} bytes")
        except Exception:
            pass

    set_last_error(ql, 0)
    return 0  # ERROR_SUCCESS

@winsdkapi(cc=STDCALL, params={'hKey': HANDLE})
def hook_RegCloseKey(ql, address, params):
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    'hKey': HANDLE,
    'lpSubKey': WSTRING,
    'Reserved': DWORD,
    'lpClass': WSTRING,
    'dwOptions': DWORD,
    'samDesired': DWORD,
    'lpSecurityAttributes': POINTER,
    'phkResult': POINTER,
    'lpdwDisposition': POINTER
})
def hook_RegCreateKeyExW(ql, address, params):
    subkey = params['lpSubKey'] or ""
    phk = params['phkResult']
    p_disp = params['lpdwDisposition']
    h_out = 0x77003
    if phk and phk != 0:
        try:
            ql.mem.write(phk, struct.pack('<Q', h_out))
        except Exception:
            pass
    if p_disp and p_disp != 0:
        try:
            ql.mem.write(p_disp, struct.pack('<I', 1))  # REG_CREATED_NEW_KEY
        except Exception:
            pass
    print(f"\n[DEBUG/REG] 🔑 RegCreateKeyExW: '{subkey}' -> Handle={hex(h_out)}")
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    'hKey': HANDLE,
    'lpValueName': WSTRING,
    'Reserved': DWORD,
    'dwType': DWORD,
    'lpData': POINTER,
    'cbData': DWORD
})
def hook_RegSetValueExW(ql, address, params):
    val_name = params['lpValueName'] or ""
    dw_type = params['dwType']
    p_data = params['lpData']
    cb_data = params['cbData']
    val_preview = ""
    if p_data and p_data != 0 and cb_data > 0:
        try:
            raw = bytes(ql.mem.read(p_data, min(cb_data, 512)))
            if dw_type in (1, 2):  # REG_SZ, REG_EXPAND_SZ
                val_preview = raw.decode('utf-16le', errors='replace').rstrip('\x00')
            elif dw_type == 4 and cb_data >= 4:  # REG_DWORD
                val_preview = str(struct.unpack('<I', raw[:4])[0])
            else:
                val_preview = raw.hex()
        except Exception:
            pass
    print(f"\n[DEBUG/REG] 📝 RegSetValueExW: Name='{val_name}', Type={dw_type}, Value='{val_preview}'")
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    'hKey': HANDLE,
    'lpValueName': WSTRING
})
def hook_RegDeleteValueW(ql, address, params):
    val_name = params['lpValueName'] or ""
    print(f"\n[DEBUG/REG] 🗑️ RegDeleteValueW: Name='{val_name}'")
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'lpSystemInfo': POINTER})
def hook_GetNativeSystemInfo(ql, address, params):
    buf = params['lpSystemInfo']
    if buf and buf != 0:
        try:
            sys_info = struct.pack('<HHIIQQIIIHH',
                9,                   # wProcessorArchitecture = PROCESSOR_ARCHITECTURE_AMD64 (9)
                0,                   # wReserved
                4096,                # dwPageSize
                0x10000,             # lpMinimumApplicationAddress
                0x7FFFFFFEFFFF,      # lpMaximumApplicationAddress
                0xFF,                # dwActiveProcessorMask (8 cores)
                8,                   # dwNumberOfProcessors = 8
                8664,                # dwProcessorType
                65536,               # dwAllocationGranularity
                6,                   # wProcessorLevel
                0x9e0d               # wProcessorRevision
            )
            ql.mem.write(buf, sys_info)
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    'lpidProcess': POINTER,
    'cb': DWORD,
    'lpcbNeeded': POINTER
})
def hook_EnumProcesses(ql, address, params):
    p_pids = params['lpidProcess']
    cb = params['cb']
    p_needed = params['lpcbNeeded']
    pids = struct.pack('<4I', 4, 412, 884, 1337)
    if p_pids and p_pids != 0 and cb >= 16:
        try:
            ql.mem.write(p_pids, pids)
        except Exception:
            pass
    if p_needed and p_needed != 0:
        try:
            ql.mem.write(p_needed, struct.pack('<I', 16))
        except Exception:
            pass
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={})
def hook_RtlGetCurrentPeb(ql, address, params):
    # Restituisce l'indirizzo del PEB a 64 bit (evita di eseguire il codice a 32-bit in ntdll.dll)
    return 0x60001f0

# ==============================================================================
# GESTIONE NLS & LOCALE (kernel32.dll) — Supporto go-ole & IDispatch
# ==============================================================================
@winsdkapi(cc=STDCALL, params={})
def hook_GetUserDefaultLCID(ql, address, params):
    set_last_error(ql, 0)
    return 0x0409  # en-US (1033)

@winsdkapi(cc=STDCALL, params={})
def hook_GetSystemDefaultLCID(ql, address, params):
    set_last_error(ql, 0)
    return 0x0409

@winsdkapi(cc=STDCALL, params={})
def hook_GetUserDefaultLangID(ql, address, params):
    set_last_error(ql, 0)
    return 0x0409

@winsdkapi(cc=STDCALL, params={})
def hook_GetSystemDefaultLangID(ql, address, params):
    set_last_error(ql, 0)
    return 0x0409

@winsdkapi(cc=STDCALL, params={})
def hook_GetUserDefaultUILanguage(ql, address, params):
    set_last_error(ql, 0)
    return 0x0409

@winsdkapi(cc=STDCALL, params={})
def hook_GetSystemDefaultUILanguage(ql, address, params):
    set_last_error(ql, 0)
    return 0x0409

@winsdkapi(cc=STDCALL, params={})
def hook_GetThreadLocale(ql, address, params):
    return 0x0409

@winsdkapi(cc=STDCALL, params={'Locale': DWORD})
def hook_SetThreadLocale(ql, address, params):
    set_last_error(ql, 0)
    return 1

@winsdkapi(cc=STDCALL, params={'Locale': DWORD, 'dwFlags': DWORD})
def hook_IsValidLocale(ql, address, params):
    return 1

@winsdkapi(cc=STDCALL, params={
    'lpLocaleName': POINTER,
    'cchLocaleName': INT
})
def hook_GetUserDefaultLocaleName(ql, address, params):
    buf = params['lpLocaleName']
    cch = params['cchLocaleName']
    loc_str = "en-US\x00".encode('utf-16le')
    req_chars = 6
    if buf and buf != 0 and cch >= req_chars:
        try:
            ql.mem.write(buf, loc_str)
        except Exception:
            pass
    set_last_error(ql, 0)
    return req_chars

@winsdkapi(cc=STDCALL, params={
    'lpLocaleName': POINTER,
    'cchLocaleName': INT
})
def hook_GetSystemDefaultLocaleName(ql, address, params):
    buf = params['lpLocaleName']
    cch = params['cchLocaleName']
    loc_str = "en-US\x00".encode('utf-16le')
    req_chars = 6
    if buf and buf != 0 and cch >= req_chars:
        try:
            ql.mem.write(buf, loc_str)
        except Exception:
            pass
    set_last_error(ql, 0)
    return req_chars

@winsdkapi(cc=STDCALL, params={
    'Locale': DWORD,
    'LCType': DWORD,
    'lpLCData': POINTER,
    'cchData': INT
})
def hook_GetLocaleInfoW(ql, address, params):
    lctype = params['LCType'] & 0xFFFF
    buf = params['lpLCData']
    cch = params['cchData']
    val = "0409"
    if lctype in (0x59, 0x2):
        val = "en-US"
    elif lctype == 0x1:
        val = "0409"
    data = (val + "\x00").encode('utf-16le')
    req_chars = len(val) + 1
    if buf and buf != 0 and cch >= req_chars:
        try:
            ql.mem.write(buf, data)
        except Exception:
            pass
    set_last_error(ql, 0)
    return req_chars

@winsdkapi(cc=STDCALL, params={
    'Locale': DWORD,
    'LCType': DWORD,
    'lpLCData': POINTER,
    'cchData': INT
})
def hook_GetLocaleInfoA(ql, address, params):
    lctype = params['LCType'] & 0xFFFF
    buf = params['lpLCData']
    cch = params['cchData']
    val = "0409"
    if lctype in (0x59, 0x2):
        val = "en-US"
    elif lctype == 0x1:
        val = "0409"
    data = (val + "\x00").encode('latin1')
    req_chars = len(val) + 1
    if buf and buf != 0 and cch >= req_chars:
        try:
            ql.mem.write(buf, data)
        except Exception:
            pass
    set_last_error(ql, 0)
    return req_chars

@winsdkapi(cc=STDCALL, params={'GeoClass': DWORD})
def hook_GetUserGeoID(ql, address, params):
    return 244  # GeoID United States

@winsdkapi(cc=STDCALL, params={
    'Location': DWORD,
    'GeoType': DWORD,
    'lpGeoData': POINTER,
    'cchData': INT,
    'LangId': DWORD
})
def hook_GetGeoInfoW(ql, address, params):
    buf = params['lpGeoData']
    cch = params['cchData']
    val = "US\x00".encode('utf-16le')
    if buf and buf != 0 and cch >= 3:
        try:
            ql.mem.write(buf, val)
        except Exception:
            pass
    return 3

# ==============================================================================
# HOST FINGERPRINTING: COMPUTER NAME
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'NameType': DWORD,
    'lpBuffer': POINTER,
    'nSize': POINTER
})
def hook_GetComputerNameExW(ql, address, params):
    buf = params['lpBuffer']
    size_ptr = params['nSize']
    comp_name = "DESKTOP-TRICKBOT"
    name_len = len(comp_name)

    if size_ptr and size_ptr != 0:
        try:
            buf_len = struct.unpack('<I', ql.mem.read(size_ptr, 4))[0]
            if buf == 0 or buf_len < name_len + 1:
                ql.mem.write(size_ptr, struct.pack('<I', name_len + 1))
                set_last_error(ql, 234)  # ERROR_MORE_DATA
                return 0
            ql.mem.write(buf, (comp_name + "\x00").encode('utf-16le'))
            ql.mem.write(size_ptr, struct.pack('<I', name_len))
            print(f"[+] GetComputerNameExW: Restituito '{comp_name}' ({name_len} chars).")
            return 1
        except Exception as e:
            print(f"[-] Errore GetComputerNameExW: {e}")
    return 1

@winsdkapi(cc=STDCALL, params={'lpBuffer': POINTER, 'nSize': POINTER})
def hook_GetComputerNameW(ql, address, params):
    buf = params['lpBuffer']
    size_ptr = params['nSize']
    comp_name = "DESKTOP-TRICKBOT"
    name_len = len(comp_name)
    if buf and buf != 0:
        try:
            ql.mem.write(buf, (comp_name + "\x00").encode('utf-16le'))
        except Exception:
            pass
    if size_ptr and size_ptr != 0:
        try:
            ql.mem.write(size_ptr, struct.pack('<I', name_len))
        except Exception:
            pass
    return 1

@winsdkapi(cc=STDCALL, params={'lpBuffer': POINTER, 'nSize': POINTER})
def hook_GetComputerNameA(ql, address, params):
    buf = params['lpBuffer']
    size_ptr = params['nSize']
    comp_name = "DESKTOP-TRICKBOT"
    name_len = len(comp_name)
    if buf and buf != 0:
        try:
            ql.mem.write(buf, (comp_name + "\x00").encode('latin1'))
        except Exception:
            pass
    if size_ptr and size_ptr != 0:
        try:
            ql.mem.write(size_ptr, struct.pack('<I', name_len))
        except Exception:
            pass
    return 1

# ==============================================================================
# PRIVILEGE ESCALATION & SECURITY TOKENS
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'lpSystemName': WSTRING,
    'lpName': WSTRING,
    'lpLuid': POINTER
})
def hook_LookupPrivilegeValueW(ql, address, params):
    priv_name = params['lpName']
    p_luid = params['lpLuid']
    print(f"\n[DEBUG/FIX] 🔑 LookupPrivilegeValueW chiamato: Privilegio='{priv_name}', OutLUID={hex(p_luid)}")

    luid_low = 20  # SeDebugPrivilege ha LUID = 20 (0x14)
    if priv_name == "SeShutdownPrivilege":
        luid_low = 19

    if p_luid and p_luid != 0:
        try:
            ql.mem.write(p_luid, struct.pack('<II', luid_low, 0))
            print(f"[+] LookupPrivilegeValueW: Assegnato LUID={luid_low} per '{priv_name}'.")
        except Exception as e:
            print(f"[-] Errore scrittura LUID: {e}")

    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    'TokenHandle': HANDLE,
    'DisableAllPrivileges': BOOL,
    'NewState': POINTER,
    'BufferLength': DWORD,
    'PreviousState': POINTER,
    'ReturnLength': POINTER
})
def hook_AdjustTokenPrivileges(ql, address, params):
    hToken = params['TokenHandle']
    new_state = params['NewState']
    ret_len = params['ReturnLength']
    print(f"\n[DEBUG/FIX] 🔑 AdjustTokenPrivileges chiamato: Token={hex(hToken)}, NewState={hex(new_state)}")
    if ret_len and ret_len != 0:
        try:
            ql.mem.write(ret_len, struct.pack('<I', 0))
        except Exception:
            pass
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    'TokenHandle': HANDLE,
    'TokenInformationClass': DWORD,
    'TokenInformation': POINTER,
    'TokenInformationLength': DWORD,
    'ReturnLength': POINTER
})
def hook_GetTokenInformation(ql, address, params):
    buf = params['TokenInformation']
    buf_len = params['TokenInformationLength']
    ret_len = params['ReturnLength']
    if ret_len and ret_len != 0:
        try:
            ql.mem.write(ret_len, struct.pack('<I', min(buf_len, 32)))
        except Exception:
            pass
    return 1

# ==============================================================================
# GESTIONE MEMORIA & ALLOCATORE A 64 BIT (512 MB Page Summary)
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'lpAddress': POINTER,
    'dwSize': SIZE_T,
    'flAllocationType': DWORD,
    'flProtect': DWORD
})
def hook_VirtualAlloc(ql, address, params):
    lpAddress = params['lpAddress']
    size = params['dwSize']
    aligned_size = (size + 0xFFF) & ~0xFFF

    if lpAddress == 0:
        if not hasattr(ql, 'custom_valloc_base'):
            ql.custom_valloc_base = 0x6000000000
        addr = ql.custom_valloc_base
        ql.custom_valloc_base += aligned_size + 0x10000
        try:
            ql.mem.map(addr, aligned_size)
            if size >= 0x1000000:
                print(f"\n[DEBUG/FIX] 🛠️ VirtualAlloc (GO Runtime): Mappati {size/1024/1024:.2f} MB all'indirizzo {hex(addr)}.")
            return addr
        except Exception as e:
            print(f"[-] Errore map in VirtualAlloc (lpAddress=0): {e}")
            return 0
    else:
        addr = lpAddress
        try:
            ql.mem.map(addr, aligned_size)
        except Exception:
            pass
        return addr

@winsdkapi(cc=STDCALL, params={
    'lpAddress': POINTER,
    'lpBuffer': POINTER,
    'dwLength': SIZE_T
})
def hook_VirtualQuery(ql, address, params):
    addr = params['lpAddress']
    buf = params['lpBuffer']
    dwLength = params['dwLength']

    if 0x7ffffff00000 <= addr <= 0x800000100000:
        base_addr = 0x7ffffffde000
        alloc_base = 0x7ffffffde000
        region_size = 0x80000001e000 - 0x7ffffffde000
    elif 0x500000000 <= addr <= 0x500020000:
        base_addr = 0x500000000
        alloc_base = 0x500000000
        region_size = 0x20000
    elif addr >= 0x6000000000:
        base_addr = addr & ~0xFFF
        alloc_base = base_addr
        region_size = 0x20000000
    else:
        base_addr = addr & ~0xFFF
        alloc_base = base_addr
        region_size = 0x10000

    mbi = struct.pack('<QQIIQQII',
        base_addr,
        alloc_base,
        0x40,    # PAGE_EXECUTE_READWRITE
        0,       # PartitionId
        region_size,
        0x1000,  # MEM_COMMIT
        0x40,    # PAGE_EXECUTE_READWRITE
        0x20000  # MEM_PRIVATE
    )

    if buf and buf != 0 and dwLength >= len(mbi):
        try:
            ql.mem.write(buf, mbi)
        except Exception as e:
            print(f"[-] Errore scrittura mbi in VirtualQuery: {e}")
    return 48

# ==============================================================================
# FIX DISPATCHER A 0x0 & MULTITHREADING
# ==============================================================================
custom_event_counter = 0x4000

def hook_zero_address(ql):
    global custom_event_counter
    rcx = ql.arch.regs.rcx
    rdx = ql.arch.regs.rdx
    if rcx == 0 and rdx == 0:
        custom_event_counter += 8
        if custom_event_counter > 0x5ff0:
            custom_event_counter = 0x4000
        ql.arch.regs.rax = custom_event_counter
    elif rdx in (0xffffffff, 0xfffffffffffffffe):
        ql.arch.regs.rax = 0
    elif rcx != 0 and rdx == 32:
        try:
            ql.mem.write(rcx, os.urandom(32))
            ql.arch.regs.rax = 1
        except Exception:
            ql.arch.regs.rax = 1
    else:
        ql.arch.regs.rax = 1

def hook_stack_switch(ql):
    if ql.arch.regs.rsp > 0x8000000000000000 or ql.arch.regs.rsp < 0x10000:
        ql.arch.regs.rsp = 0x500004fe0
    rdi = ql.arch.regs.rdi
    try:
        cur_hi = struct.unpack('<Q', ql.mem.read(rdi + 8, 8))[0]
        if cur_hi == 0:
            ql.mem.write(rdi + 8, struct.pack('<Q', 0x500010000))
    except Exception:
        pass

def hook_tstart(ql):
    if ql.arch.regs.rsp > 0x8000000000000000 or ql.arch.regs.rsp < 0x10000:
        ql.arch.regs.rsp = 0x500004fe0

def hook_gcenable(ql):
    print("\n[DEBUG/FIX] 🚀 runtime.gcenable intercettato a 0x417560! Bypass pulito per ambiente single-thread.")
    ret_addr = struct.unpack('<Q', ql.mem.read(ql.arch.regs.rsp, 8))[0]
    ql.arch.regs.rsp += 8
    ql.arch.regs.rip = ret_addr

@winsdkapi(cc=STDCALL, params={
    'lpThreadAttributes': POINTER,
    'dwStackSize': SIZE_T,
    'lpStartAddress': POINTER,
    'lpParameter': POINTER,
    'dwCreationFlags': DWORD,
    'lpThreadId': POINTER
})
def hook_CreateThread(ql, address, params):
    lpParam = params['lpParameter']
    if lpParam and lpParam != 0:
        try:
            g0_ptr = struct.unpack('<Q', ql.mem.read(lpParam, 8))[0]
            if g0_ptr and g0_ptr != 0:
                ql.mem.write(g0_ptr + 0x10, struct.pack('<Q', 0x500000000))
                ql.mem.write(g0_ptr + 0x18, struct.pack('<Q', 0x500010000))
        except Exception:
            pass
    return 0x6001

@winsdkapi(cc=STDCALL, params={'hThread': HANDLE})
def hook_SuspendThread(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={'hThread': HANDLE, 'nPriority': INT})
def hook_SetThreadPriority(ql, address, params):
    return 1

@winsdkapi(cc=STDCALL, params={})
def hook_SwitchToThread(ql, address, params):
    return 1

# ==============================================================================
# GESTIONE FILE I/O & SEEKING (TrickBot Loader)
# ==============================================================================
malware_exe_path = ""
_output_dir = os.path.dirname(os.path.abspath(__file__))

@winsdkapi(cc=STDCALL, params={
    'hFile': HANDLE,
    'lpFileInformation': POINTER
})
def hook_GetFileInformationByHandle(ql, address, params):
    h = params['hFile']
    out_ptr = params['lpFileInformation']
    print(f"\n[DEBUG/FIX] 📂 GetFileInformationByHandle chiamato: Handle={hex(h)}, OutPtr={hex(out_ptr)}")

    size = None
    try:
        h_obj = ql.os.handle_manager.get(h)
        if h_obj:
            target_obj = getattr(h_obj, 'obj', h_obj)
            if hasattr(target_obj, 'fileno') and target_obj.fileno() >= 0:
                size = os.fstat(target_obj.fileno()).st_size
    except Exception:
        pass

    if size is None:
        try:
            size = os.path.getsize(malware_exe_path)
        except Exception:
            size = 0x800000

    size_low = size & 0xFFFFFFFF
    size_high = (size >> 32) & 0xFFFFFFFF

    file_info = struct.pack('<IQQQIIIIII',
        0x20,                # dwFileAttributes (FILE_ATTRIBUTE_ARCHIVE)
        133000000000000000,  # ftCreationTime
        133000000000000000,  # ftLastAccessTime
        133000000000000000,  # ftLastWriteTime
        0x12345678,          # dwVolumeSerialNumber
        size_high,           # nFileSizeHigh
        size_low,            # nFileSizeLow
        1,                   # nNumberOfLinks
        0,                   # nFileIndexHigh
        1                    # nFileIndexLow
    )

    if out_ptr and out_ptr != 0:
        try:
            ql.mem.write(out_ptr, file_info)
            print(f"[+] GetFileInformationByHandle: Popolata struttura (Dimensione={hex(size)} bytes).")
        except Exception as e:
            print(f"[-] Errore scrittura BY_HANDLE_FILE_INFORMATION: {e}")

    set_last_error(ql, 0)
    return 1

@winsdkapi(cc=STDCALL, params={
    'hFile': HANDLE,
    'FileInformationClass': DWORD,
    'lpFileInformation': POINTER,
    'dwBufferSize': DWORD
})
def hook_GetFileInformationByHandleEx(ql, address, params):
    info_class = params['FileInformationClass']
    out_ptr = params['lpFileInformation']
    buf_size = params['dwBufferSize']

    size = 0
    try:
        size = os.path.getsize(malware_exe_path)
    except Exception:
        size = 0x800000

    if info_class == 1 and out_ptr and buf_size >= 24:
        try:
            data = struct.pack('<QQIBB', size, size, 1, 0, 0)
            ql.mem.write(out_ptr, data.ljust(buf_size, b'\x00'))
        except Exception:
            pass
    elif info_class == 0 and out_ptr and buf_size >= 40:
        try:
            time_val = 133000000000000000
            data = struct.pack('<QQQQI', time_val, time_val, time_val, time_val, 0x20)
            ql.mem.write(out_ptr, data.ljust(buf_size, b'\x00'))
        except Exception:
            pass

    set_last_error(ql, 0)
    return 1

@winsdkapi(cc=STDCALL, params={'lpFileName': WSTRING})
def hook_GetFileAttributesW(ql, address, params):
    fname = params['lpFileName'] or ""
    real_path = fname
    try:
        real_path = ql.os.path.transform_to_real_path(fname)
    except Exception:
        pass
    if os.path.isdir(real_path) or fname.rstrip('\\/').lower().endswith(('remoteadmin', 'roaming', 'appdata', 'qiling', 'users', 'temp', 'windows', 'trickbot', 'c:')):
        set_last_error(ql, 0)
        return 0x10  # FILE_ATTRIBUTE_DIRECTORY
    if "client_id" in fname.lower() and not os.path.exists(real_path):
        set_last_error(ql, 2)  # ERROR_FILE_NOT_FOUND
        return 0xFFFFFFFF
    set_last_error(ql, 0)
    return 0x20

@winsdkapi(cc=STDCALL, params={
    'lpFileName': WSTRING,
    'fInfoLevelId': DWORD,
    'lpFileInformation': POINTER
})
def hook_GetFileAttributesExW(ql, address, params):
    fname = params['lpFileName'] or ""
    out_ptr = params['lpFileInformation']
    real_path = fname
    try:
        real_path = ql.os.path.transform_to_real_path(fname)
    except Exception:
        pass

    if "client_id" in fname.lower() and not os.path.exists(real_path):
        set_last_error(ql, 2)  # ERROR_FILE_NOT_FOUND
        return 0

    is_dir = os.path.isdir(real_path) or fname.rstrip('\\/').lower().endswith(('remoteadmin', 'roaming', 'appdata', 'qiling', 'users', 'temp', 'windows', 'trickbot', 'c:'))
    attr = 0x10 if is_dir else 0x20
    size = 0
    if not is_dir:
        if os.path.exists(real_path):
            try:
                size = os.path.getsize(real_path)
            except Exception:
                size = 64
        else:
            try:
                size = os.path.getsize(malware_exe_path)
            except Exception:
                size = 0x800000
    if out_ptr and out_ptr != 0:
        try:
            data = struct.pack('<IQQQII', attr, 133000000000000000, 133000000000000000, 133000000000000000, (size >> 32) & 0xFFFFFFFF, size & 0xFFFFFFFF)
            ql.mem.write(out_ptr, data)
        except Exception:
            pass
    set_last_error(ql, 0)
    return 1

@winsdkapi(cc=STDCALL, params={
    'hFile': HANDLE,
    'liDistanceToMove': ULONGLONG,
    'lpNewFilePointer': POINTER,
    'dwMoveMethod': DWORD
})
def hook_SetFilePointerEx(ql, address, params):
    h = params['hFile']
    dist = params['liDistanceToMove']
    if dist >= (1 << 63):
        dist -= (1 << 64)
    method = params['dwMoveMethod']
    out_ptr = params['lpNewFilePointer']

    print(f"\n[DEBUG/FIX] 📂 SetFilePointerEx: Handle={hex(h)}, Distanza={dist}, Metodo={method}")
    new_pos = 0
    success = False
    try:
        h_obj = ql.os.handle_manager.get(h)
        if h_obj:
            target_obj = getattr(h_obj, 'obj', h_obj)
            if hasattr(target_obj, 'seek'):
                target_obj.seek(dist, method)
                new_pos = target_obj.tell()
                success = True
            elif hasattr(target_obj, 'fileno'):
                new_pos = os.lseek(target_obj.fileno(), dist, method)
                success = True
    except Exception as e:
        print(f"[-] Errore seek su handle {hex(h)}: {e}")

    if not success:
        new_pos = max(0, dist)

    if out_ptr and out_ptr != 0:
        try:
            ql.mem.write(out_ptr, struct.pack('<q', new_pos))
            print(f"[+] SetFilePointerEx: Nuova posizione salvata a {hex(out_ptr)}: {hex(new_pos)} ({new_pos} bytes)")
        except Exception as e:
            print(f"[-] Errore scrittura lpNewFilePointer: {e}")

    return 1

@winsdkapi(cc=STDCALL, params={
    'hFile': HANDLE,
    'lDistanceToMove': LONG,
    'lpDistanceToMoveHigh': POINTER,
    'dwMoveMethod': DWORD
})
def hook_SetFilePointer(ql, address, params):
    h = params['hFile']
    dist_low = params['lDistanceToMove']
    high_ptr = params['lpDistanceToMoveHigh']
    dist_high = 0
    if high_ptr and high_ptr != 0:
        try:
            dist_high = struct.unpack('<i', ql.mem.read(high_ptr, 4))[0]
        except Exception:
            dist_high = 0
    dist = (dist_high << 32) | (dist_low & 0xFFFFFFFF)
    if dist >= (1 << 63):
        dist -= (1 << 64)
    method = params['dwMoveMethod']

    new_pos = 0
    try:
        h_obj = ql.os.handle_manager.get(h)
        if h_obj:
            target_obj = getattr(h_obj, 'obj', h_obj)
            if hasattr(target_obj, 'seek'):
                target_obj.seek(dist, method)
                new_pos = target_obj.tell()
    except Exception as e:
        print(f"[-] Errore seek in SetFilePointer: {e}")
        new_pos = max(0, dist)

    if high_ptr and high_ptr != 0:
        try:
            ql.mem.write(high_ptr, struct.pack('<I', (new_pos >> 32) & 0xFFFFFFFF))
        except Exception:
            pass

    return new_pos & 0xFFFFFFFF

@winsdkapi(cc=STDCALL, params={'hFile': HANDLE, 'lpFileSize': POINTER})
def hook_GetFileSizeEx(ql, address, params):
    h = params['hFile']
    out_ptr = params['lpFileSize']
    size = 0
    try:
        h_obj = ql.os.handle_manager.get(h)
        if h_obj:
            target_obj = getattr(h_obj, 'obj', h_obj)
            if hasattr(target_obj, 'fileno'):
                size = os.fstat(target_obj.fileno()).st_size
    except Exception:
        pass

    if size == 0:
        try:
            size = os.path.getsize(malware_exe_path)
        except Exception:
            size = 0x800000

    if out_ptr and out_ptr != 0:
        try:
            ql.mem.write(out_ptr, struct.pack('<q', size))
        except Exception:
            pass
    return 1

@winsdkapi(cc=STDCALL, params={'hFile': HANDLE, 'lpFileSizeHigh': POINTER})
def hook_GetFileSize(ql, address, params):
    size = 0
    try:
        size = os.path.getsize(malware_exe_path)
    except Exception:
        size = 0x800000
    high_ptr = params['lpFileSizeHigh']
    if high_ptr and high_ptr != 0:
        try:
            ql.mem.write(high_ptr, struct.pack('<I', (size >> 32) & 0xFFFFFFFF))
        except Exception:
            pass
    return size & 0xFFFFFFFF

@winsdkapi(cc=STDCALL, params={
    'lpFileName': WSTRING,
    'dwDesiredAccess': DWORD,
    'dwShareMode': DWORD,
    'lpSecurityAttributes': POINTER,
    'dwCreationDisposition': DWORD,
    'dwFlagsAndAttributes': DWORD,
    'hTemplateFile': HANDLE
})
def hook_CreateFileW(ql, address, params):
    fname = params['lpFileName'] or ""
    disp = params['dwCreationDisposition']
    clean = fname.strip().strip('\x00').strip('\\.').strip('/').upper()
    print(f"\n[DEBUG/FIX] 📁 CreateFileW chiamato per: '{fname}' (Disposition={disp}, clean: '{clean}')")

    if clean in ("NUL", "DEV/NULL", "CON", "CONOUT$", "CONIN$"):
        try:
            devnull = open(os.devnull, 'r+b')
            h = get_or_create_file_handle(ql, devnull, clean)
            if not hasattr(ql, 'nul_handles'):
                ql.nul_handles = set()
            ql.nul_handles.add(h)
            print(f"[+] 📁 CreateFileW: Virtualizzazione dispositivo DOS '{clean}' riuscita -> Assegnato Handle {hex(h)}")
            set_last_error(ql, 0)
            return h
        except Exception as e:
            print(f"[-] Errore apertura os.devnull per '{clean}': {e}")
            return 0xa0001004

    try:
        real_path = fname
        try:
            real_path = ql.os.path.transform_to_real_path(fname)
        except Exception:
            pass

        # Se il binario si trova fuori dal rootfs, risolve l'auto-apertura dell'eseguibile verso malware_exe_path
        if (
            not os.path.exists(real_path)
            and malware_exe_path
            and os.path.isfile(malware_exe_path)
            and os.path.basename(fname.replace("\\", "/")).lower() == os.path.basename(malware_exe_path).lower()
        ):
            f = open(malware_exe_path, 'rb')
            h = get_or_create_file_handle(ql, f, os.path.basename(malware_exe_path))
            print(f"[+] 📁 CreateFileW: Reindirizzata auto-lettura sample a '{malware_exe_path}' -> Handle {hex(h)}")
            set_last_error(ql, 0)
            return h

        # Se OPEN_EXISTING (3) e il file non esiste (es. primo controllo client_id), ritorna INVALID_HANDLE_VALUE
        if disp == 3 and not os.path.exists(real_path):
            print(f"[*] 📁 CreateFileW: File '{real_path}' non esistente (OPEN_EXISTING) -> Ritorno ERROR_FILE_NOT_FOUND")
            set_last_error(ql, 2)  # ERROR_FILE_NOT_FOUND
            return 0xFFFFFFFFFFFFFFFF

        parent_dir = os.path.dirname(real_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        if disp in (2, 5):  # CREATE_ALWAYS / TRUNCATE_EXISTING
            mode = 'w+b'
        else:
            mode = 'r+b' if os.path.exists(real_path) else 'w+b'
        f = open(real_path, mode)
        h = get_or_create_file_handle(ql, f, os.path.basename(real_path))
        print(f"[+] 📁 CreateFileW: Aperto file reale '{real_path}' -> Assegnato Handle {hex(h)}")
        set_last_error(ql, 0)
        return h
    except Exception as e:
        print(f"[-] Errore apertura file reale per '{fname}': {e}")

    set_last_error(ql, 2)
    return 0xFFFFFFFFFFFFFFFF

@winsdkapi(cc=STDCALL, params={
    'lpFileName': STRING,
    'dwDesiredAccess': DWORD,
    'dwShareMode': DWORD,
    'lpSecurityAttributes': POINTER,
    'dwCreationDisposition': DWORD,
    'dwFlagsAndAttributes': DWORD,
    'hTemplateFile': HANDLE
})
def hook_CreateFileA(ql, address, params):
    fname = params['lpFileName'] or ""
    disp = params['dwCreationDisposition']
    clean = fname.strip().strip('\x00').strip('\\.').strip('/').upper()
    print(f"\n[DEBUG/FIX] 📁 CreateFileA chiamato per: '{fname}' (Disposition={disp}, clean: '{clean}')")

    if clean in ("NUL", "DEV/NULL", "CON", "CONOUT$", "CONIN$"):
        try:
            devnull = open(os.devnull, 'r+b')
            h = get_or_create_file_handle(ql, devnull, clean)
            if not hasattr(ql, 'nul_handles'):
                ql.nul_handles = set()
            ql.nul_handles.add(h)
            print(f"[+] 📁 CreateFileA: Virtualizzazione dispositivo DOS '{clean}' riuscita -> Assegnato Handle {hex(h)}")
            set_last_error(ql, 0)
            return h
        except Exception as e:
            print(f"[-] Errore apertura os.devnull per '{clean}': {e}")
            return 0xa0001004

    try:
        real_path = fname
        try:
            real_path = ql.os.path.transform_to_real_path(fname)
        except Exception:
            pass

        if (
            not os.path.exists(real_path)
            and malware_exe_path
            and os.path.isfile(malware_exe_path)
            and os.path.basename(fname.replace("\\", "/")).lower() == os.path.basename(malware_exe_path).lower()
        ):
            f = open(malware_exe_path, 'rb')
            h = get_or_create_file_handle(ql, f, os.path.basename(malware_exe_path))
            set_last_error(ql, 0)
            return h

        if disp == 3 and not os.path.exists(real_path):
            set_last_error(ql, 2)
            return 0xFFFFFFFFFFFFFFFF

        parent_dir = os.path.dirname(real_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)

        mode = 'r+b' if os.path.exists(real_path) else 'w+b'
        f = open(real_path, mode)
        h = get_or_create_file_handle(ql, f, os.path.basename(real_path))
        print(f"[+] 📁 CreateFileA: Aperto file reale '{real_path}' -> Assegnato Handle {hex(h)}")
        set_last_error(ql, 0)
        return h
    except Exception as e:
        print(f"[-] Errore apertura file reale per '{fname}': {e}")

    set_last_error(ql, 2)
    return 0xFFFFFFFFFFFFFFFF

@winsdkapi(cc=STDCALL, params={
    'hFile': HANDLE,
    'lpBuffer': POINTER,
    'nNumberOfBytesToRead': DWORD,
    'lpNumberOfBytesRead': POINTER,
    'lpOverlapped': POINTER
})
def hook_ReadFile(ql, address, params):
    h = params['hFile']
    buf = params['lpBuffer']
    n_bytes = params['nNumberOfBytesToRead']
    out_read = params['lpNumberOfBytesRead']

    data = b""
    try:
        h_obj = ql.os.handle_manager.get(h)
        if h_obj:
            target_obj = getattr(h_obj, 'obj', h_obj)
            if hasattr(target_obj, 'read'):
                data = target_obj.read(n_bytes)
                if isinstance(data, str):
                    data = data.encode('utf-8')
    except Exception as e:
        print(f"[-] Errore ReadFile su handle {hex(h)}: {e}")

    read_len = len(data)
    if buf and buf != 0 and read_len > 0:
        try:
            ql.mem.write(buf, data)
            print(f"\n[DEBUG/FILE_READ] 📖 ReadFile (Handle={hex(h)}, BytesRead={read_len}/{n_bytes})")
        except Exception as e:
            print(f"[-] Errore scrittura buffer ReadFile: {e}")

    if out_read and out_read != 0:
        try:
            ql.mem.write(out_read, struct.pack('<I', read_len))
        except Exception:
            pass

    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    'hFile': HANDLE,
    'lpBuffer': POINTER,
    'nNumberOfBytesToWrite': DWORD,
    'lpNumberOfBytesWritten': POINTER,
    'lpOverlapped': POINTER
})
def hook_WriteFile(ql, address, params):
    h = params['hFile']
    buf = params['lpBuffer']
    n_bytes = params['nNumberOfBytesToWrite']
    out_written = params['lpNumberOfBytesWritten']

    if buf and buf != 0 and n_bytes > 0:
        try:
            data = bytes(ql.mem.read(buf, min(n_bytes, 4096)))
            if data.startswith(b"MZ"):
                dump_payload(data, "WriteFile_DroppedModule")
            try:
                text = data.decode('utf-8', errors='replace')
            except Exception:
                text = str(data)
            print(f"\n[DEBUG/FILE_WRITE] 📝 WriteFile (Handle={hex(h)}, Bytes={n_bytes}):\n>>> {text.strip()} <<<")
        except Exception as e:
            print(f"[-] Errore lettura buffer WriteFile: {e}")

    written = n_bytes
    try:
        h_obj = ql.os.handle_manager.get(h)
        if h_obj:
            target_obj = getattr(h_obj, 'obj', h_obj)
            if hasattr(target_obj, 'write'):
                data = ql.mem.read(buf, n_bytes)
                target_obj.write(bytes(data))
                if hasattr(target_obj, 'flush'):
                    target_obj.flush()
    except Exception as e:
        print(f"[-] Errore scrittura effettiva WriteFile: {e}")

    if out_written and out_written != 0:
        try:
            ql.mem.write(out_written, struct.pack('<I', written))
        except Exception:
            pass
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'lpPathName': WSTRING, 'lpSecurityAttributes': POINTER})
def hook_CreateDirectoryW(ql, address, params):
    path = params['lpPathName'] or ""
    try:
        real_path = ql.os.path.transform_to_real_path(path)
        os.makedirs(real_path, exist_ok=True)
    except Exception:
        pass
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'lpFileName': WSTRING})
def hook_DeleteFileW(ql, address, params):
    fname = params['lpFileName'] or ""
    print(f"\n[DEBUG/FILE] 🗑️ DeleteFileW chiamato per: '{fname}'")
    try:
        real_path = ql.os.path.transform_to_real_path(fname)
        if os.path.exists(real_path) and os.path.isfile(real_path):
            os.remove(real_path)
    except Exception:
        pass
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'lpPathName': WSTRING})
def hook_RemoveDirectoryW(ql, address, params):
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'hConsoleHandle': HANDLE, 'lpMode': POINTER})
def hook_GetConsoleMode(ql, address, params):
    h = params['hConsoleHandle']
    p_mode = params['lpMode']
    if h in (0xfffffff6, 0xfffffff5, 0xfffffff4):
        if p_mode and p_mode != 0:
            try:
                ql.mem.write(p_mode, struct.pack('<I', 3))
            except Exception:
                pass
        set_last_error(ql, 0)
        return 1  # TRUE solo per handle console standard
    set_last_error(ql, 6)  # ERROR_INVALID_HANDLE per file su disco (così Go usa ReadFile/WriteFile invece di ReadConsoleW/WriteConsoleW)
    return 0  # FALSE

@winsdkapi(cc=STDCALL, params={'hFile': HANDLE})
def hook_GetFileType(ql, address, params):
    h = params['hFile']
    if hasattr(ql, 'nul_handles') and h in ql.nul_handles:
        return 2  # FILE_TYPE_CHAR
    if h in (0xfffffff6, 0xfffffff5, 0xfffffff4):
        return 2  # FILE_TYPE_CHAR
    return 1      # FILE_TYPE_DISK

@winsdkapi(cc=STDCALL, params={'hObject': HANDLE})
def hook_CloseHandle(ql, address, params):
    h = params['hObject']
    print(f"\n[DEBUG/FIX] 🔒 CloseHandle chiamato per handle: {hex(h)}")
    try:
        h_obj = ql.os.handle_manager.get(h)
        if h_obj:
            if hasattr(h_obj, 'close'):
                try:
                    h_obj.close()
                except Exception:
                    pass
            elif hasattr(h_obj, 'obj') and hasattr(h_obj.obj, 'close'):
                try:
                    h_obj.obj.close()
                except Exception:
                    pass
    except Exception:
        pass
    return 1  # TRUE

# ==============================================================================
# GESTIONE I/O COMPLETION PORTS (kernel32.dll / Go Runtime Netpoll)
# ==============================================================================
iocp_port_counter = 0x50000

@winsdkapi(cc=STDCALL, params={
    'FileHandle': HANDLE,
    'ExistingCompletionPort': HANDLE,
    'CompletionKey': POINTER,
    'NumberOfConcurrentThreads': DWORD
})
def hook_CreateIoCompletionPort(ql, address, params):
    global iocp_port_counter
    f_handle = params['FileHandle']
    existing = params['ExistingCompletionPort']
    key = params['CompletionKey']
    threads = params['NumberOfConcurrentThreads']
    print(f"\n[DEBUG/IOCP] 🌐 CreateIoCompletionPort: File={hex(f_handle)}, Existing={hex(existing)}, Key={hex(key)}, Threads={threads}")

    if key and key != 0:
        ql.last_iocp_key = key
        if not hasattr(ql, 'socket_iocp_keys'):
            ql.socket_iocp_keys = {}
        ql.socket_iocp_keys[f_handle] = key
        print(f"[+] CreateIoCompletionPort: Registrata chiave IOCP per socket {hex(f_handle)}: {hex(key)}")

    if existing and existing != 0:
        ql.last_iocp_port = existing
        return existing

    iocp_port_counter += 1
    new_h = iocp_port_counter
    ql.last_iocp_port = new_h
    print(f"[+] CreateIoCompletionPort: Inizializzato nuovo IOCP Handle: {hex(new_h)} per Go Netpoll.")
    set_last_error(ql, 0)
    return new_h

@winsdkapi(cc=STDCALL, params={
    'CompletionPort': HANDLE,
    'lpNumberOfBytesTransferred': POINTER,
    'lpCompletionKey': POINTER,
    'lpOverlapped': POINTER,
    'dwMilliseconds': DWORD
})
def hook_GetQueuedCompletionStatus(ql, address, params):
    h = params['CompletionPort']
    p_bytes = params['lpNumberOfBytesTransferred']
    p_key = params['lpCompletionKey']
    p_ov = params['lpOverlapped']
    ms = params['dwMilliseconds']

    adv_ms = max(ms if ms != 0xFFFFFFFF else 1000, 1000)
    update_kuser_time(ql, adv_ms)

    ev = None
    if hasattr(ql, 'iocp_events') and ql.iocp_events:
        ev = ql.iocp_events.pop(0)

    if ev:
        b_trans = ev.get('bytes', getattr(ql, 'last_transferred_bytes', 0))
        if p_bytes and p_bytes != 0:
            try:
                ql.mem.write(p_bytes, struct.pack('<I', b_trans))
            except Exception:
                pass
        if p_key and p_key != 0:
            try:
                ql.mem.write(p_key, struct.pack('<Q', ev.get('key', 0)))
            except Exception:
                pass
        if p_ov and p_ov != 0:
            try:
                ql.mem.write(p_ov, struct.pack('<Q', ev.get('overlapped', 0)))
            except Exception:
                pass
        set_last_error(ql, 0)
        print(f"[+] 🌐 GetQueuedCompletionStatus: Consegnato evento IOCP (Key={hex(ev.get('key', 0))}, Bytes={b_trans})")
        return 1  # TRUE

    if p_bytes and p_bytes != 0:
        try:
            ql.mem.write(p_bytes, struct.pack('<I', 0))
        except Exception:
            pass
    set_last_error(ql, 258)  # WAIT_TIMEOUT
    return 0  # FALSE

@winsdkapi(cc=STDCALL, params={
    'CompletionPort': HANDLE,
    'lpCompletionPortEntries': POINTER,
    'ulCount': ULONG,
    'ulNumEntriesRemoved': POINTER,
    'dwMilliseconds': DWORD,
    'fAlertable': BOOL
})
def hook_GetQueuedCompletionStatusEx(ql, address, params):
    h = params['CompletionPort']
    entries_ptr = params['lpCompletionPortEntries']
    max_count = params['ulCount']
    p_removed = params['ulNumEntriesRemoved']
    ms = params['dwMilliseconds']

    # Avanza l'orologio monotono KUSER_SHARED_DATA così i timer Go (es. time.Sleep(1s)) scadono istantaneamente
    adv_ms = max(ms if ms != 0xFFFFFFFF else 1000, 1000)
    update_kuser_time(ql, adv_ms)

    events_to_deliver = []
    if hasattr(ql, 'iocp_events') and ql.iocp_events:
        while ql.iocp_events and len(events_to_deliver) < max_count:
            ev = ql.iocp_events.pop(0)
            events_to_deliver.append(ev)

    if events_to_deliver:
        num_removed = len(events_to_deliver)
        for i, ev in enumerate(events_to_deliver):
            entry_bytes = struct.pack('<QQQI4x',
                ev.get('key', 0),
                ev.get('overlapped', 0),
                ev.get('internal', 0),
                ev.get('bytes', 0)
            )
            if entries_ptr and entries_ptr != 0:
                try:
                    ql.mem.write(entries_ptr + i * 32, entry_bytes)
                except Exception as e:
                    print(f"[-] Errore scrittura OVERLAPPED_ENTRY: {e}")

        if p_removed and p_removed != 0:
            try:
                ql.mem.write(p_removed, struct.pack('<I', num_removed))
            except Exception:
                pass

        set_last_error(ql, 0)
        print(f"\n[DEBUG/IOCP] 🌐 GetQueuedCompletionStatusEx: Port={hex(h)}, Timeout={ms}ms -> Consegnati {num_removed} eventi IOCP con successo a Go Netpoll!")
        return 1  # TRUE

    if p_removed and p_removed != 0:
        try:
            ql.mem.write(p_removed, struct.pack('<I', 0))
        except Exception:
            pass
    print(f"\n[DEBUG/IOCP] ⏱ GetQueuedCompletionStatusEx: Nessun evento IOCP pendente -> WAIT_TIMEOUT (Avanzato KUSER_SHARED_DATA di +{adv_ms}ms)")
    set_last_error(ql, 258)  # WAIT_TIMEOUT
    return 0  # FALSE

@winsdkapi(cc=STDCALL, params={
    'CompletionPort': HANDLE,
    'dwNumberOfBytesTransferred': DWORD,
    'dwCompletionKey': POINTER,
    'lpOverlapped': POINTER
})
def hook_PostQueuedCompletionStatus(ql, address, params):
    h = params['CompletionPort']
    bytes_trans = params['dwNumberOfBytesTransferred']
    key = params['dwCompletionKey']
    ov = params['lpOverlapped']
    print(f"\n[DEBUG/IOCP] 🌐 PostQueuedCompletionStatus: Port={hex(h)}, Bytes={bytes_trans}, Key={hex(key)}, Overlapped={hex(ov)}")
    if not hasattr(ql, 'iocp_events'):
        ql.iocp_events = []
    ql.iocp_events.append({
        'port': h,
        'key': key,
        'overlapped': ov,
        'internal': 0,
        'bytes': bytes_trans
    })
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'hFile': HANDLE})
def hook_CancelIo(ql, address, params):
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'hFile': HANDLE, 'lpOverlapped': POINTER})
def hook_CancelIoEx(ql, address, params):
    set_last_error(ql, 0)
    return 1  # TRUE

# ==============================================================================
# GESTIONE DIRECTORY & PERCORSI (kernel32.dll)
# ==============================================================================
current_working_dir = r"C:\Windows\Documenti\Source\TrickBot"

@winsdkapi(cc=STDCALL, params={
    'nBufferLength': DWORD,
    'lpBuffer': POINTER
})
def hook_GetCurrentDirectoryW(ql, address, params):
    global current_working_dir
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    print(f"\n[DEBUG/FIX] 📁 GetCurrentDirectoryW chiamato: BufLen={n_len}, Buf={hex(buf)}")
    cur_dir = current_working_dir
    chars_count = len(cur_dir)
    data = (cur_dir + "\x00").encode('utf-16le')
    if buf and buf != 0 and n_len >= chars_count + 1:
        try:
            ql.mem.write(buf, data)
            print(f"[+] GetCurrentDirectoryW: Restituito '{cur_dir}' ({chars_count} chars).")
        except Exception as e:
            print(f"[-] Errore scrittura GetCurrentDirectoryW: {e}")
    return chars_count

@winsdkapi(cc=STDCALL, params={
    'nBufferLength': DWORD,
    'lpBuffer': POINTER
})
def hook_GetCurrentDirectoryA(ql, address, params):
    global current_working_dir
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    print(f"\n[DEBUG/FIX] 📁 GetCurrentDirectoryA chiamato: BufLen={n_len}, Buf={hex(buf)}")
    cur_dir = current_working_dir
    chars_count = len(cur_dir)
    data = (cur_dir + "\x00").encode('latin1')
    if buf and buf != 0 and n_len >= chars_count + 1:
        try:
            ql.mem.write(buf, data)
            print(f"[+] GetCurrentDirectoryA: Restituito '{cur_dir}' ({chars_count} chars).")
        except Exception as e:
            print(f"[-] Errore scrittura GetCurrentDirectoryA: {e}")
    return chars_count

@winsdkapi(cc=STDCALL, params={'lpPathName': WSTRING})
def hook_SetCurrentDirectoryW(ql, address, params):
    global current_working_dir
    path = params['lpPathName']
    if path:
        current_working_dir = path
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'lpPathName': STRING})
def hook_SetCurrentDirectoryA(ql, address, params):
    global current_working_dir
    path = params['lpPathName']
    if path:
        current_working_dir = path
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    'lpFileName': WSTRING,
    'nBufferLength': DWORD,
    'lpBuffer': POINTER,
    'lpFilePart': POINTER
})
def hook_GetFullPathNameW(ql, address, params):
    fname = params['lpFileName'] or ""
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    full_path = fname
    if not (len(fname) >= 3 and fname[1] == ':' and fname[2] == '\\'):
        full_path = current_working_dir + "\\" + fname.lstrip('\\')
    chars_count = len(full_path)
    data = (full_path + "\x00").encode('utf-16le')
    if buf and buf != 0 and n_len >= chars_count + 1:
        try:
            ql.mem.write(buf, data)
        except Exception:
            pass
    return chars_count

# ==============================================================================
# GESTIONE FILE E PERCORSI TEMPORANEI (kernel32.dll)
# ==============================================================================
temp_file_counter = 1000

@winsdkapi(cc=STDCALL, params={
    'nBufferLength': DWORD,
    'lpBuffer': POINTER
})
def hook_GetTempPath2W(ql, address, params):
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    temp_dir = r"C:\Windows\Temp\\"
    chars_count = len(temp_dir)
    data = (temp_dir + "\x00").encode('utf-16le')
    if buf and buf != 0 and n_len >= chars_count + 1:
        try:
            ql.mem.write(buf, data)
            print(f"[+] GetTempPath2W: Restituito '{temp_dir}' ({chars_count} chars).")
        except Exception as e:
            print(f"[-] Errore scrittura GetTempPath2W: {e}")
    return chars_count

@winsdkapi(cc=STDCALL, params={
    'nBufferLength': DWORD,
    'lpBuffer': POINTER
})
def hook_GetTempPath2A(ql, address, params):
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    temp_dir = r"C:\Windows\Temp\\"
    chars_count = len(temp_dir)
    data = (temp_dir + "\x00").encode('latin-1')
    if buf and buf != 0 and n_len >= chars_count + 1:
        try:
            ql.mem.write(buf, data)
            print(f"[+] GetTempPath2A: Restituito '{temp_dir}' ({chars_count} chars).")
        except Exception as e:
            print(f"[-] Errore scrittura GetTempPath2A: {e}")
    return chars_count

@winsdkapi(cc=STDCALL, params={
    'nBufferLength': DWORD,
    'lpBuffer': POINTER
})
def hook_GetTempPathW(ql, address, params):
    return hook_GetTempPath2W(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'nBufferLength': DWORD,
    'lpBuffer': POINTER
})
def hook_GetTempPathA(ql, address, params):
    return hook_GetTempPath2A(ql, address, params)

@winsdkapi(cc=STDCALL, params={
    'lpPathName': WSTRING,
    'lpPrefixString': WSTRING,
    'uUnique': UINT,
    'lpTempFileName': POINTER
})
def hook_GetTempFileNameW(ql, address, params):
    global temp_file_counter
    path = (params['lpPathName'] or r"C:\Windows\Temp").rstrip('\\')
    pfx = (params['lpPrefixString'] or "tmp")[:3]
    u = params['uUnique']
    if u == 0:
        temp_file_counter += 1
        u = temp_file_counter
    out_buf = params['lpTempFileName']
    fname = f"{path}\\{pfx}{u:x}.tmp"
    if out_buf and out_buf != 0:
        try:
            ql.mem.write(out_buf, (fname + "\x00").encode('utf-16le'))
        except Exception:
            pass
    return u

@winsdkapi(cc=STDCALL, params={
    'lpPathName': STRING,
    'lpPrefixString': STRING,
    'uUnique': UINT,
    'lpTempFileName': POINTER
})
def hook_GetTempFileNameA(ql, address, params):
    global temp_file_counter
    path = (params['lpPathName'] or r"C:\Windows\Temp").rstrip('\\')
    pfx = (params['lpPrefixString'] or "tmp")[:3]
    u = params['uUnique']
    if u == 0:
        temp_file_counter += 1
        u = temp_file_counter
    out_buf = params['lpTempFileName']
    fname = f"{path}\\{pfx}{u:x}.tmp"
    if out_buf and out_buf != 0:
        try:
            ql.mem.write(out_buf, (fname + "\x00").encode('latin-1'))
        except Exception:
            pass
    return u

@winsdkapi(cc=STDCALL, params={
    'lpPath': WSTRING,
    'lpFileName': WSTRING,
    'lpExtension': WSTRING,
    'nBufferLength': DWORD,
    'lpBuffer': POINTER,
    'lpFilePart': POINTER
})
def hook_SearchPathW(ql, address, params):
    fname = params['lpFileName'] or ""
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    full_found = f"C:\\Windows\\System32\\{fname}"
    if not full_found.lower().endswith(".exe"):
        full_found += ".exe"
    chars_count = len(full_found)
    data = (full_found + "\x00").encode('utf-16le')
    if buf and buf != 0 and n_len >= chars_count + 1:
        try:
            ql.mem.write(buf, data)
        except Exception:
            pass
    return chars_count

@winsdkapi(cc=STDCALL, params={
    'lpPath': STRING,
    'lpFileName': STRING,
    'lpExtension': STRING,
    'nBufferLength': DWORD,
    'lpBuffer': POINTER,
    'lpFilePart': POINTER
})
def hook_SearchPathA(ql, address, params):
    fname = params['lpFileName'] or ""
    n_len = params['nBufferLength']
    buf = params['lpBuffer']
    full_found = f"C:\\Windows\\System32\\{fname}"
    if not full_found.lower().endswith(".exe"):
        full_found += ".exe"
    chars_count = len(full_found)
    data = (full_found + "\x00").encode('latin-1')
    if buf and buf != 0 and n_len >= chars_count + 1:
        try:
            ql.mem.write(buf, data)
        except Exception:
            pass
    return chars_count

# ==============================================================================
# VARIABILI D'AMBIENTE (kernel32.dll) — GESTIONE DUAL-STAGE (_HIDDEN_CHILD)
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'lpName': WSTRING,
    'lpBuffer': POINTER,
    'nSize': DWORD
})
def hook_GetEnvironmentVariableW(ql, address, params):
    name = params['lpName'] or ""
    buf = params['lpBuffer']
    n_size = params['nSize']

    env_map = {
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "USERPROFILE": r"C:\Users\Qiling",
        "APPDATA": r"C:\Users\Qiling\AppData\Roaming",
        "LOCALAPPDATA": r"C:\Users\Qiling\AppData\Local",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
        "TEMP": r"C:\Windows\Temp",
        "TMP": r"C:\Windows\Temp",
        "DEV_MODE": "0",
    }

    # Allo Stage 1 (Dropper), _HIDDEN_CHILD non è impostato così il malware esegue setupHiddenProcess -> CreateProcessW.
    # Dopo CreateProcessW (Stage 2), _HIDDEN_CHILD diventa "1".
    if name == "_HIDDEN_CHILD":
        if getattr(ql, 'hidden_child_spawned', False):
            env_map["_HIDDEN_CHILD"] = "1"
        else:
            print("\n[DEBUG/ENV] 🔍 GetEnvironmentVariableW('_HIDDEN_CHILD') -> Non impostato (Attivazione Stage 1 Dropper: setupHiddenProcess!)")
            set_last_error(ql, 203)  # ERROR_ENVVAR_NOT_FOUND
            return 0

    if name in env_map:
        val = env_map[name]
        val_len = len(val)
        if name == "_HIDDEN_CHILD":
            print(f"\n[DEBUG/ENV] 🌟 GetEnvironmentVariableW intercettato: '_HIDDEN_CHILD' -> Restituito '{val}' (Processo Figlio Attivo!)")
        if buf and buf != 0 and n_size >= val_len + 1:
            try:
                ql.mem.write(buf, (val + "\x00").encode('utf-16le'))
                set_last_error(ql, 0)
                return val_len
            except Exception:
                pass
        set_last_error(ql, 0)
        return val_len + 1

    set_last_error(ql, 203)  # ERROR_ENVVAR_NOT_FOUND
    return 0

@winsdkapi(cc=STDCALL, params={
    'lpName': STRING,
    'lpBuffer': POINTER,
    'nSize': DWORD
})
def hook_GetEnvironmentVariableA(ql, address, params):
    name = params['lpName'] or ""
    buf = params['lpBuffer']
    n_size = params['nSize']

    if name == "_HIDDEN_CHILD" and getattr(ql, 'hidden_child_spawned', False):
        val = b"1\x00"
        print(f"\n[DEBUG/ENV] 🌟 GetEnvironmentVariableA intercettato: '_HIDDEN_CHILD' -> Restituito '1'")
        if buf and buf != 0 and n_size >= 2:
            try:
                ql.mem.write(buf, val)
            except Exception:
                pass
            set_last_error(ql, 0)
            return 1
        return 2

    set_last_error(ql, 203)
    return 0

@winsdkapi(cc=STDCALL, params={'lpName': WSTRING, 'lpValue': WSTRING})
def hook_SetEnvironmentVariableW(ql, address, params):
    set_last_error(ql, 0)
    return 1

@winsdkapi(cc=STDCALL, params={'lpName': STRING, 'lpValue': STRING})
def hook_SetEnvironmentVariableA(ql, address, params):
    set_last_error(ql, 0)
    return 1

# ==============================================================================
# GESTIONE STARTUPINFOEX & ATTRIBUTE LIST (Win32 Extended Process Creation)
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'lpAttributeList': POINTER,
    'dwAttributeCount': DWORD,
    'dwFlags': DWORD,
    'lpSize': POINTER
})
def hook_InitializeProcThreadAttributeList(ql, address, params):
    attr_list = params['lpAttributeList']
    count = params['dwAttributeCount']
    flags = params['dwFlags']
    lp_size = params['lpSize']

    required_size = 32 + (count * 32)
    print(f"\n[DEBUG/FIX] ⚙️ InitializeProcThreadAttributeList: ListPtr={hex(attr_list)}, Count={count}, Flags={hex(flags)}, SizePtr={hex(lp_size)}")

    if attr_list == 0:
        if lp_size and lp_size != 0:
            try:
                ql.mem.write(lp_size, struct.pack('<Q', required_size))
                print(f"[+] InitializeProcThreadAttributeList [Stadio 1]: Fornita dimensione necessaria: {required_size} bytes.")
            except Exception as e:
                print(f"[-] Errore scrittura lpSize: {e}")
        set_last_error(ql, 122)  # ERROR_INSUFFICIENT_BUFFER (0x7a)
        return 0  # FALSE

    try:
        header = struct.pack('<IIQQ', 0x1, count, 0, 0)
        ql.mem.write(attr_list, header.ljust(required_size, b'\x00'))
        if lp_size and lp_size != 0:
            ql.mem.write(lp_size, struct.pack('<Q', required_size))
        print(f"[+] InitializeProcThreadAttributeList [Stadio 2]: Buffer attributi inizializzato a {hex(attr_list)} ({required_size} bytes).")
    except Exception as e:
        print(f"[-] Errore inizializzazione buffer attributi: {e}")
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    'lpAttributeList': POINTER,
    'dwFlags': DWORD,
    'Attribute': SIZE_T,
    'lpValue': POINTER,
    'cbSize': SIZE_T,
    'lpPreviousValue': POINTER,
    'lpReturnSize': POINTER
})
def hook_UpdateProcThreadAttribute(ql, address, params):
    attr_list = params['lpAttributeList']
    attr = params['Attribute']
    val_ptr = params['lpValue']
    cb_size = params['cbSize']
    print(f"\n[DEBUG/FIX] ⚙️ UpdateProcThreadAttribute: List={hex(attr_list)}, Attr={hex(attr)}, Size={cb_size}")
    if attr == 0x20002:  # PROC_THREAD_ATTRIBUTE_HANDLE_LIST
        try:
            num_handles = cb_size // 8
            raw = ql.mem.read(val_ptr, cb_size)
            handles = struct.unpack(f'<{num_handles}Q', raw)
            hex_handles = [hex(h) for h in handles]
            print(f"[+] UpdateProcThreadAttribute: Whitelist Handle Ereditati -> {hex_handles}")
        except Exception as e:
            print(f"[-] Errore lettura whitelist handle: {e}")
    elif attr == 0x20000:  # PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
        print(f"[+] UpdateProcThreadAttribute: Spoofing Parent Process rilevato!")
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={'lpAttributeList': POINTER})
def hook_DeleteProcThreadAttributeList(ql, address, params):
    return

# ==============================================================================
# GESTIONE ADATTATORI E RETE (iphlpapi.dll) — Go net.Interfaces()
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'Family': ULONG,
    'Flags': ULONG,
    'Reserved': POINTER,
    'AdapterAddresses': POINTER,
    'SizePointer': POINTER
})
def hook_GetAdaptersAddresses(ql, address, params):
    family = params['Family']
    flags = params['Flags']
    buf_ptr = params['AdapterAddresses']
    size_ptr = params['SizePointer']
    print(f"\n[DEBUG/NET] 🌐 GetAdaptersAddresses chiamato: Family={family}, Flags={hex(flags)}, BufPtr={hex(buf_ptr)}, SizePtr={hex(size_ptr)}")

    required_size = 600

    if buf_ptr == 0:
        if size_ptr and size_ptr != 0:
            try:
                ql.mem.write(size_ptr, struct.pack('<I', required_size))
            except Exception:
                pass
        return 111  # ERROR_BUFFER_OVERFLOW

    try:
        unicast_addr_ptr = buf_ptr + 256
        sockaddr_ptr = buf_ptr + 256 + 64
        adapter_name_ptr = buf_ptr + 350
        friendly_name_ptr = buf_ptr + 420
        desc_ptr = buf_ptr + 500

        adapter_name = b"{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}\x00"
        friendly_name = "Ethernet0\x00".encode('utf-16le')
        desc_name = "Intel(R) 82574L Gigabit Network Connection\x00".encode('utf-16le')

        # sockaddr_in: AF_INET (2), port 0, IP 192.168.1.100, zero pad
        sockaddr = struct.pack('<HH4s8s', 2, 0, bytes([192, 168, 1, 100]), b'\x00' * 8)

        # IP_ADAPTER_UNICAST_ADDRESS_LH (64-bit, 48 bytes)
        unicast_struct = struct.pack('<IIQQIIIIIIII',
            48,                 # Length
            0,                  # Flags
            0,                  # Next = NULL
            sockaddr_ptr,       # Address.lpSockaddr
            16,                 # Address.iSockaddrLength
            0,                  # Padding
            3,                  # PrefixOrigin = IpPrefixOriginDhcp
            3,                  # SuffixOrigin = IpSuffixOriginDhcp
            4,                  # DadState = IpDadStatePreferred
            0xffffffff,         # ValidLifetime
            0xffffffff,         # PreferredLifetime
            0xffffffff          # LeaseLifetime
        )

        mac_bytes = bytes([0x00, 0x0c, 0x29, 0x12, 0x34, 0x56, 0x00, 0x00])

        adapter_struct = bytearray(256)
        struct.pack_into('<II', adapter_struct, 0, 144, 1)           # Length=144, IfIndex=1
        struct.pack_into('<Q', adapter_struct, 8, 0)                 # Next = 0
        struct.pack_into('<Q', adapter_struct, 16, adapter_name_ptr) # AdapterName
        struct.pack_into('<Q', adapter_struct, 24, unicast_addr_ptr) # FirstUnicastAddress
        struct.pack_into('<Q', adapter_struct, 64, desc_ptr)         # Description
        struct.pack_into('<Q', adapter_struct, 72, friendly_name_ptr)# FriendlyName
        adapter_struct[80:88] = mac_bytes                            # PhysicalAddress
        struct.pack_into('<I', adapter_struct, 88, 6)                # PhysicalAddressLength = 6
        struct.pack_into('<I', adapter_struct, 92, 0x04)             # Flags = IP_ADAPTER_DHCP_ENABLED
        struct.pack_into('<I', adapter_struct, 96, 1500)             # Mtu = 1500
        struct.pack_into('<I', adapter_struct, 100, 6)               # IfType = IF_TYPE_ETHERNET_CSMACD (6)
        struct.pack_into('<I', adapter_struct, 104, 1)               # OperStatus = IfOperStatusUp (1)
        struct.pack_into('<I', adapter_struct, 108, 1)               # Ipv6IfIndex = 1
        struct.pack_into('<Q', adapter_struct, 184, 1000000000)      # TransmitLinkSpeed = 1 Gbps
        struct.pack_into('<Q', adapter_struct, 192, 1000000000)      # ReceiveLinkSpeed = 1 Gbps

        ql.mem.write(buf_ptr, bytes(adapter_struct))
        ql.mem.write(unicast_addr_ptr, unicast_struct)
        ql.mem.write(sockaddr_ptr, sockaddr)
        ql.mem.write(adapter_name_ptr, adapter_name)
        ql.mem.write(friendly_name_ptr, friendly_name)
        ql.mem.write(desc_ptr, desc_name)

        if size_ptr and size_ptr != 0:
            ql.mem.write(size_ptr, struct.pack('<I', required_size))

        print(f"[+] GetAdaptersAddresses: Popolato adattatore virtuale 'Ethernet0' (IP: 192.168.1.100, MAC: 00:0C:29:12:34:56)")
        set_last_error(ql, 0)
        return 0  # ERROR_SUCCESS
    except Exception as e:
        print(f"[-] Errore GetAdaptersAddresses: {e}")
        return 0

@winsdkapi(cc=STDCALL, params={'pAdapterInfo': POINTER, 'pOutBufLen': POINTER})
def hook_GetAdaptersInfo(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={'pIfRow': POINTER})
def hook_GetIfEntry(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={'pIfRow': POINTER})
def hook_GetIfEntry2(ql, address, params):
    p_row = params['pIfRow']
    if p_row and p_row != 0:
        try:
            # MIB_IF_ROW2: InOctets (+0x4b8) e OutOctets (+0x500)
            ql.mem.write(p_row + 0x4b8, struct.pack('<Q', 154829104))  # ~154 MB ricevuti
            ql.mem.write(p_row + 0x500, struct.pack('<Q', 48291042))   # ~48 MB inviati
            print("\n[DEBUG/SYSINFO] 🌐 GetIfEntry2: Popolati contatori traffico MIB_IF_ROW2 (InOctets=154.8 MB, OutOctets=48.2 MB)")
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'dwDestAddr': DWORD, 'pdwBestIfIndex': POINTER})
def hook_GetBestInterface(ql, address, params):
    out_ptr = params['pdwBestIfIndex']
    if out_ptr and out_ptr != 0:
        try:
            ql.mem.write(out_ptr, struct.pack('<I', 1))
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={'pFixedInfo': POINTER, 'pOutBufLen': POINTER})
def hook_GetNetworkParams(ql, address, params):
    return 0

# ==============================================================================
# GESTIONE RETE WINSOCK, DNS, BIND & CONNECTEX (ws2_32.dll)
# ==============================================================================
dns_mapped = False
def map_dns_memory(ql):
    global dns_mapped
    if not dns_mapped:
        try:
            ql.mem.map(0x70000000, 0x40000)  # Mappa 256 KB (copre DNS, COM, Enum, BSTR)
            # Salvaguardia globale anti-slide: riempimento preventivo con istruzioni RET (0xC3)
            ql.mem.write(0x70000000, b'\xC3' * 0x40000)
            dns_mapped = True
        except Exception:
            dns_mapped = True

@winsdkapi(cc=STDCALL, params={'wVersionRequired': WORD, 'lpWSAData': POINTER})
def hook_WSAStartup(ql, address, params):
    lpData = params['lpWSAData']
    if lpData and lpData != 0:
        try:
            wsadata = struct.pack('<HH', 0x0202, 0x0202) + (b'WINSOCK\x00' * 10)[:404]
            ql.mem.write(lpData, wsadata)
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={})
def hook_WSACleanup(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={
    'lpiProtocols': POINTER,
    'lpProtocolBuffer': POINTER,
    'lpdwBufferLength': POINTER
})
def hook_WSAEnumProtocolsW(ql, address, params):
    buf_ptr = params['lpProtocolBuffer']
    len_ptr = params['lpdwBufferLength']
    proto_size = 628
    total_size = proto_size * 2

    if buf_ptr == 0:
        if len_ptr and len_ptr != 0:
            try:
                ql.mem.write(len_ptr, struct.pack('<I', total_size))
            except Exception:
                pass
        set_last_error(ql, 10040)
        return 0xFFFFFFFF
    else:
        try:
            proto1 = bytearray(proto_size)
            struct.pack_into('<I', proto1, 0, 0x20066)  # dwServiceFlags1 = XP1_IFS_HANDLES (0x20000) | TCP flags
            struct.pack_into('<I', proto1, 76, 2)
            struct.pack_into('<I', proto1, 88, 1)
            struct.pack_into('<I', proto1, 92, 6)
            proto1_name = "MSAFD Tcpip [TCP/IP]\x00".encode('utf-16le')
            proto1[116:116+len(proto1_name)] = proto1_name

            proto2 = bytearray(proto_size)
            struct.pack_into('<I', proto2, 0, 0x20009)  # dwServiceFlags1 = XP1_IFS_HANDLES (0x20000) | UDP flags
            struct.pack_into('<I', proto2, 76, 2)
            struct.pack_into('<I', proto2, 88, 2)
            struct.pack_into('<I', proto2, 92, 17)
            proto2_name = "MSAFD Tcpip [UDP/IP]\x00".encode('utf-16le')
            proto2[116:116+len(proto2_name)] = proto2_name

            combined = bytes(proto1 + proto2)
            ql.mem.write(buf_ptr, combined)
            if len_ptr and len_ptr != 0:
                ql.mem.write(len_ptr, struct.pack('<I', total_size))
            return 2
        except Exception as e:
            print(f"[-] Errore popolamento WSAEnumProtocolsW: {e}")
            return 0

@winsdkapi(cc=STDCALL, params={'FileHandle': HANDLE, 'Flags': BYTE})
def hook_SetFileCompletionNotificationModes(ql, address, params):
    return 1

# Trampoline per ConnectEx (chiamata via puntatore salvato da WSAIoctl a 0x70003000)
def hook_ConnectEx_trampoline(ql):
    s = ql.arch.regs.rcx
    name_ptr = ql.arch.regs.rdx
    namelen = ql.arch.regs.r8
    ip = ""
    port = 0
    if name_ptr and name_ptr != 0 and namelen >= 8:
        try:
            raw = ql.mem.read(name_ptr, min(namelen, 16))
            family, port = struct.unpack('<H', raw[:2])[0], struct.unpack('>H', raw[2:4])[0]
            ip = ".".join(str(b) for b in raw[4:8])
            if ip == "127.0.0.1":
                print(f"[DEBUG/RECON] 🔍 Scansione porta locale (sysinfo.isPortOpen): {ip}:{port}")
            elif ip == "54.233.190.22":
                print("\n" + "=" * 75)
                print(f"[!] 🚨 CONNESSIONE AL SERVER C2 RILEVATA (ConnectEx): ws://{ip}:{port}/ws")
                print("=" * 75)
            else:
                print(f"\n[DEBUG/NET] 🌐 ConnectEx() verso servizio esterno: {ip}:{port} (Socket={hex(s)})")
        except Exception:
            pass

    lp_ov = 0
    try:
        lp_ov = struct.unpack('<Q', ql.mem.read(ql.arch.regs.rsp + 0x38, 8))[0]
        if lp_ov != 0:
            ql.last_overlapped = lp_ov
            if not hasattr(ql, 'overlapped_transferred'):
                ql.overlapped_transferred = {}
            ql.overlapped_transferred[lp_ov] = 0
    except Exception:
        pass

    # Per la scansione porte locali (127.0.0.1), rendiamo aperte le porte tipiche (80, 443, 3389, 8080) e chiuse le altre
    if ip == "127.0.0.1" and port not in (80, 443, 3389, 8080):
        set_last_error(ql, 10061)  # WSAECONNREFUSED (errore sincrono immediato, evita attese)
        ql.arch.regs.rax = 0
        return

    set_last_error(ql, 0)
    ql.arch.regs.rax = 1  # TRUE: Connessione sincrona riuscita con successo

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'name': POINTER,
    'namelen': INT,
    'lpSendBuffer': POINTER,
    'dwSendDataLength': DWORD,
    'lpdwBytesSent': POINTER,
    'lpOverlapped': POINTER
})
def hook_ConnectEx_api(ql, address, params):
    lp_ov = params['lpOverlapped']
    if lp_ov and lp_ov != 0:
        ql.last_overlapped = lp_ov
        if not hasattr(ql, 'overlapped_transferred'):
            ql.overlapped_transferred = {}
        ql.overlapped_transferred[lp_ov] = 0
    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'dwIoControlCode': DWORD,
    'lpvInBuffer': POINTER,
    'cbInBuffer': DWORD,
    'lpvOutBuffer': POINTER,
    'cbOutBuffer': DWORD,
    'lpcbBytesReturned': POINTER,
    'lpOverlapped': POINTER,
    'lpCompletionRoutine': POINTER
})
def hook_WSAIoctl(ql, address, params):
    code = params['dwIoControlCode']
    out_buf = params['lpvOutBuffer']
    out_len = params['cbOutBuffer']
    ret_ptr = params['lpcbBytesReturned']
    p_ov = params['lpOverlapped']
    print(f"\n[DEBUG/FIX] 🌐 WSAIoctl: Code={hex(code)}, OutLen={out_len}")

    if p_ov and p_ov != 0:
        ql.last_overlapped = p_ov

    # SIO_GET_EXTENSION_FUNCTION_POINTER (0xC8000006) per recuperare ConnectEx
    if code in (0xC8000006, 0x98000006, 3355443206, -939524090):
        map_dns_memory(ql)
        connectex_ptr = 0x70003000
        if out_buf and out_buf != 0 and out_len >= 8:
            try:
                ql.mem.write(out_buf, struct.pack('<Q', connectex_ptr))
                if ret_ptr and ret_ptr != 0:
                    ql.mem.write(ret_ptr, struct.pack('<I', 8))
                print(f"[+] WSAIoctl: Fornito puntatore ConnectEx -> {hex(connectex_ptr)}")
                set_last_error(ql, 0)
                return 0  # Successo
            except Exception as e:
                print(f"[-] Errore fornitura ConnectEx in WSAIoctl: {e}")

    if ret_ptr and ret_ptr != 0:
        try:
            ql.mem.write(ret_ptr, struct.pack('<I', 0))
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0

socket_counter = 0x8000

@winsdkapi(cc=STDCALL, params={
    'af': INT,
    'type': INT,
    'protocol': INT,
    'lpProtocolInfo': POINTER,
    'g': DWORD,
    'dwFlags': DWORD
})
def hook_WSASocketW(ql, address, params):
    global socket_counter
    socket_counter += 1
    set_last_error(ql, 0)
    return socket_counter

@winsdkapi(cc=STDCALL, params={
    'af': INT,
    'type': INT,
    'protocol': INT,
    'lpProtocolInfo': POINTER,
    'g': DWORD,
    'dwFlags': DWORD
})
def hook_WSASocketA(ql, address, params):
    global socket_counter
    socket_counter += 1
    set_last_error(ql, 0)
    return socket_counter

@winsdkapi(cc=STDCALL, params={'af': INT, 'type': INT, 'protocol': INT})
def hook_socket(ql, address, params):
    global socket_counter
    socket_counter += 1
    set_last_error(ql, 0)
    return socket_counter

@winsdkapi(cc=STDCALL, params={'s': HANDLE})
def hook_closesocket(ql, address, params):
    if hasattr(ql, 'iocp_events'):
        ql.iocp_events.clear()
    if getattr(ql, 'c2_closing', False):
        print("\n" + "=" * 75)
        print("[+] 🏁 SESSIONE C2 COMPLETATA E SOCKET CHIUSO DAL MALWARE (closesocket)!")
        print("[+] Tutti gli stadi (Dropper, SysInfo, WebSocket Handshake, Esfiltrazione Protobuf")
        print("[+] e Ciclo Comandi Remoti C2) sono stati eseguiti ed estratti con successo.")
        print("=" * 75 + "\n")
        ql.emu_stop()
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'name': POINTER, 'namelen': INT})
def hook_bind(ql, address, params):
    s = params['s']
    name_ptr = params['name']
    namelen = params['namelen']
    if name_ptr and name_ptr != 0 and namelen >= 8:
        try:
            raw = ql.mem.read(name_ptr, min(namelen, 16))
            family, port = struct.unpack('>HH', raw[:4])
            ip = ".".join(str(b) for b in raw[4:8])
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'backlog': INT})
def hook_listen(ql, address, params):
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'addr': POINTER, 'addrlen': POINTER})
def hook_accept(ql, address, params):
    set_last_error(ql, 0)
    return 0x8002

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'addr': POINTER,
    'addrlen': POINTER,
    'lpfnCondition': POINTER,
    'dwCallbackData': DWORD
})
def hook_WSAAccept(ql, address, params):
    set_last_error(ql, 0)
    return 0x8002

@winsdkapi(cc=STDCALL, params={
    'pNodeName': WSTRING,
    'pServiceName': WSTRING,
    'pHints': POINTER,
    'ppResult': POINTER
})
def hook_GetAddrInfoW(ql, address, params):
    node = params['pNodeName'] or ""
    service = params['pServiceName'] or ""
    result_ptr = params['ppResult']

    map_dns_memory(ql)
    addrinfo_ptr = 0x70001000
    sockaddr_ptr = 0x70001030

    port = 80
    if service:
        try:
            port = int(service)
        except Exception:
            if "443" in str(service) or "https" in str(service):
                port = 443
            else:
                port = 80

    if node.lower() in ("localhost", "127.0.0.1"):
        ip_tuple = (127, 0, 0, 1)
    elif "ip-api.com" in node.lower():
        ip_tuple = (208, 95, 112, 1)
    else:
        ip_tuple = (104, 26, 12, 159)

    sin_port = struct.pack('>H', port)
    ip_bytes = bytes(ip_tuple)
    sockaddr = struct.pack('<H', 2) + sin_port + ip_bytes + (b'\x00' * 8)
    addrinfo_struct = struct.pack('<iiiiQQQQ', 0, 2, 1, 6, 16, 0, sockaddr_ptr, 0)

    try:
        ql.mem.write(addrinfo_ptr, addrinfo_struct)
        ql.mem.write(sockaddr_ptr, sockaddr)
        if result_ptr and result_ptr != 0:
            ql.mem.write(result_ptr, struct.pack('<Q', addrinfo_ptr))
            if node.lower() not in ("localhost", "127.0.0.1"):
                ip_str = ".".join(str(x) for x in ip_tuple)
                print(f"\n[DEBUG/DNS] 🌐 GetAddrInfoW: Risolto '{node}' -> {ip_str}:{port}")
    except Exception as e:
        print(f"[-] Errore scrittura strutture DNS: {e}")

    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    'pNodeName': STRING,
    'pServiceName': STRING,
    'pHints': POINTER,
    'ppResult': POINTER
})
def hook_GetAddrInfoA(ql, address, params):
    node = params['pNodeName'] or ""
    service = params['pServiceName'] or ""
    result_ptr = params['ppResult']

    map_dns_memory(ql)
    addrinfo_ptr = 0x70001000
    sockaddr_ptr = 0x70001030

    port = 80
    if service:
        try:
            port = int(service)
        except Exception:
            port = 80

    sin_port = struct.pack('>H', port)
    ip_bytes = bytes([104, 26, 12, 159])
    sockaddr = struct.pack('<H', 2) + sin_port + ip_bytes + (b'\x00' * 8)

    addrinfo_struct = struct.pack('<iiiiQQQQ', 0, 2, 1, 6, 16, 0, sockaddr_ptr, 0)

    try:
        ql.mem.write(addrinfo_ptr, addrinfo_struct)
        ql.mem.write(sockaddr_ptr, sockaddr)
        if result_ptr and result_ptr != 0:
            ql.mem.write(result_ptr, struct.pack('<Q', addrinfo_ptr))
    except Exception:
        pass

    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'pAddrInfo': POINTER})
def hook_FreeAddrInfoW(ql, address, params):
    set_last_error(ql, 0)
    return

@winsdkapi(cc=STDCALL, params={'ai': POINTER})
def hook_freeaddrinfo(ql, address, params):
    set_last_error(ql, 0)
    return

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'name': POINTER, 'namelen': INT})
def hook_connect(ql, address, params):
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'name': POINTER,
    'namelen': INT,
    'lpCallerData': POINTER,
    'lpCalleeData': POINTER,
    'lpSQOS': POINTER,
    'lpGQOS': POINTER
})
def hook_WSAConnect(ql, address, params):
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'buf': POINTER, 'len': INT, 'flags': INT})
def hook_send(ql, address, params):
    n_len = params['len']
    ql.last_transferred_bytes = n_len
    set_last_error(ql, 0)
    return n_len

# ==============================================================================
# PROTOBUF & WEBSOCKET C2 ENGINE (Decodifica & Forging Comandi C2)
# ==============================================================================
def encode_varint(val):
    out = bytearray()
    while val > 0x7F:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val & 0x7F)
    return bytes(out)

def encode_proto_bytes(field_num, data_bytes):
    if not data_bytes:
        return b""
    tag = (field_num << 3) | 2
    return bytes([tag]) + encode_varint(len(data_bytes)) + data_bytes

def encode_proto_command(cmd_id, command, args=None, file_data=None, working_dir=None):
    """Serializza un messaggio proto.Command conforme a pkg/proto/messages.proto."""
    buf = bytearray()
    buf.extend(encode_proto_bytes(1, cmd_id.encode('utf-8')))
    buf.extend(encode_proto_bytes(2, command.encode('utf-8')))
    if args:
        for a in args:
            buf.extend(encode_proto_bytes(3, a.encode('utf-8')))
    if file_data:
        buf.extend(encode_proto_bytes(4, file_data))
    if working_dir:
        buf.extend(encode_proto_bytes(5, working_dir.encode('utf-8')))
    return bytes(buf)

def build_ws_server_frame(payload_bytes, opcode=2):
    """Costruisce un frame WebSocket RFC 6455 Server-to-Client (non mascherato)."""
    header = bytearray([0x80 | (opcode & 0x0F)])
    n = len(payload_bytes)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header.extend(struct.pack('>H', n))
    else:
        header.append(127)
        header.extend(struct.pack('>Q', n))
    return bytes(header) + payload_bytes

def decode_protobuf_raw(data):
    """Decodificatore generico wire-format Protobuf -> dict {field_num: [values]}."""
    fields = {}
    idx = 0
    n = len(data)
    while idx < n:
        tag = 0
        shift = 0
        while idx < n:
            b = data[idx]
            idx += 1
            tag |= (b & 0x7F) << shift
            if not (b & 0x80):
                break
            shift += 7
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # Varint
            val = 0
            shift = 0
            while idx < n:
                b = data[idx]
                idx += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            fields.setdefault(field_num, []).append(val)
        elif wire_type == 1:  # 64-bit (double / fixed64)
            val_bytes = data[idx:idx+8]
            idx += 8
            fields.setdefault(field_num, []).append(val_bytes)
        elif wire_type == 2:  # Length-delimited
            length = 0
            shift = 0
            while idx < n:
                b = data[idx]
                idx += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            val_bytes = data[idx:idx+length]
            idx += length
            fields.setdefault(field_num, []).append(val_bytes)
        elif wire_type == 5:  # 32-bit
            val_bytes = data[idx:idx+4]
            idx += 4
            fields.setdefault(field_num, []).append(val_bytes)
        else:
            break
    return fields

def parse_client_info_proto(raw_bytes):
    """Decodifica proto.ClientInfo e il sotto-messaggio proto.SystemInfo."""
    f = decode_protobuf_raw(raw_bytes)
    def get_str(d, k):
        val = d.get(k, [b""])[0]
        return val.decode('utf-8', errors='replace') if isinstance(val, (bytes, bytearray)) else str(val)
    def get_int(d, k):
        val = d.get(k, [0])[0]
        if isinstance(val, int):
            return val
        if isinstance(val, (bytes, bytearray)) and len(val) == 8:
            return int(struct.unpack('<d', val)[0])
        return 0

    info = {
        "id": get_str(f, 1),
        "hostname": get_str(f, 2),
        "os": get_str(f, 3),
        "ip_address": get_str(f, 4),
        "country": get_str(f, 5),
        "city": get_str(f, 6),
        "system_info": {}
    }

    if 7 in f and f[7]:
        sf = decode_protobuf_raw(f[7][0])
        cpu_usage = 0.0
        if 2 in sf and sf[2]:
            raw_u = sf[2][0]
            if isinstance(raw_u, (bytes, bytearray)):
                if len(raw_u) == 8:
                    cpu_usage = struct.unpack('<d', raw_u)[0]
                elif len(raw_u) >= 4 and len(raw_u) % 4 == 0:
                    floats = struct.unpack(f'<{len(raw_u)//4}f', raw_u)
                    cpu_usage = sum(floats) / len(floats)

        disks = []
        for d_raw in sf.get(7, []):
            df = decode_protobuf_raw(d_raw)
            disks.append({
                "device": get_str(df, 1),
                "mount_point": get_str(df, 2),
                "total_space_gb": round(get_int(df, 3) / (1024**3), 2),
                "used_space_gb": round(get_int(df, 4) / (1024**3), 2),
                "free_space_gb": round(get_int(df, 5) / (1024**3), 2),
                "filesystem_type": get_str(df, 6),
            })

        net_ifaces = []
        for n_raw in sf.get(8, []):
            nf = decode_protobuf_raw(n_raw)
            net_ifaces.append({
                "name": get_str(nf, 1),
                "ip_addresses": [x.decode('utf-8', errors='replace') for x in nf.get(2, [])],
                "mac_address": get_str(nf, 3),
                "bytes_sent": get_int(nf, 4),
                "bytes_received": get_int(nf, 5),
            })

        open_ports = []
        for p_val in sf.get(12, []):
            if isinstance(p_val, int):
                open_ports.append(p_val)
            elif isinstance(p_val, bytes):
                # Packed repeated int32
                idx = 0
                while idx < len(p_val):
                    v = 0
                    sh = 0
                    while idx < len(p_val):
                        b = p_val[idx]
                        idx += 1
                        v |= (b & 0x7F) << sh
                        if not (b & 0x80):
                            break
                        sh += 7
                    open_ports.append(v)

        info["system_info"] = {
            "cpu_cores": get_int(sf, 1),
            "cpu_usage_percent": round(cpu_usage, 2),
            "cpu_model": get_str(sf, 3),
            "total_memory_gb": round(get_int(sf, 4) / (1024**3), 2),
            "used_memory_gb": round(get_int(sf, 5) / (1024**3), 2),
            "free_memory_gb": round(get_int(sf, 6) / (1024**3), 2),
            "disks": disks,
            "network_interfaces": net_ifaces,
            "os_version": get_str(sf, 9),
            "kernel_version": get_str(sf, 10),
            "uptime_seconds": get_int(sf, 11),
            "open_ports": open_ports,
        }
    return info

def parse_response_proto(raw_bytes):
    """Decodifica proto.Response inviato dal malware al C2."""
    f = decode_protobuf_raw(raw_bytes)
    def get_str(d, k):
        val = d.get(k, [b""])[0]
        return val.decode('utf-8', errors='replace') if isinstance(val, (bytes, bytearray)) else str(val)
    def get_int(d, k):
        val = d.get(k, [0])[0]
        return val if isinstance(val, int) else 0
    file_data = f.get(6, [b""])[0]
    if not isinstance(file_data, (bytes, bytearray)):
        file_data = b""
    return {
        "id": get_str(f, 1),
        "output": get_str(f, 2),
        "exit_code": get_int(f, 3),
        "completed": bool(get_int(f, 4)),
        "file_data_len": len(file_data),
        "file_data_preview": file_data.decode('utf-8', errors='replace') if file_data else "",
        "error": get_str(f, 7),
        "working_dir": get_str(f, 8),
    }

def _json_safe(obj):
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    return str(obj)

simulated_wan_ip = b'{"ip":"198.51.100.42"}'
simulated_ipify_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: cloudflare\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(simulated_wan_ip)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n" +
    simulated_wan_ip
)

simulated_ipapi_body = b'{"status":"success","country":"United States","city":"New York","query":"198.51.100.42"}'
simulated_ipapi_response = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: " + str(len(simulated_ipapi_body)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"\r\n" +
    simulated_ipapi_body
)

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'lpBuffers': POINTER,
    'dwBufferCount': DWORD,
    'lpNumberOfBytesSent': POINTER,
    'dwFlags': DWORD,
    'lpOverlapped': POINTER,
    'lpCompletionRoutine': POINTER
})
def hook_WSASend(ql, address, params):
    s = params['s']
    p_bufs = params['lpBuffers']
    count = params['dwBufferCount']
    p_sent = params['lpNumberOfBytesSent']
    p_ov = params['lpOverlapped']
    if p_ov and p_ov != 0:
        ql.last_overlapped = p_ov

    total_bytes = 0
    full_payload = bytearray()
    if p_bufs and p_bufs != 0 and count > 0:
        try:
            for i in range(min(count, 16)):
                buf_desc = ql.mem.read(p_bufs + i * 16, 16)
                b_len = struct.unpack('<I', buf_desc[:4])[0]
                b_ptr = struct.unpack('<Q', buf_desc[8:16])[0]
                total_bytes += b_len
                if b_ptr != 0 and b_len > 0:
                    chunk = bytes(ql.mem.read(b_ptr, b_len))
                    full_payload.extend(chunk)
        except Exception as e:
            print(f"[-] Errore lettura buffer WSASend: {e}")

    payload_bytes = bytes(full_payload)
    if not hasattr(ql, 'recv_stream_buf'):
        ql.recv_stream_buf = bytearray()
    if not hasattr(ql, 'eof_after_drain'):
        ql.eof_after_drain = set()
    if not hasattr(ql, 'eof_sockets'):
        ql.eof_sockets = set()

    # 1. Rilevamento richiesta HTTP WAN IP (api.ipify.org)
    if b"Host: api.ipify.org" in payload_bytes:
        print(f"\n[DEBUG/HTTP] 🌐 WSASend -> Richiesta HTTP GET a api.ipify.org ({total_bytes} bytes)")
        ql.recv_stream_buf = bytearray(simulated_ipify_response)
        ql.eof_after_drain.add(s)

    # 2. Rilevamento richiesta HTTP Geolocalizzazione (ip-api.com)
    elif b"Host: ip-api.com" in payload_bytes:
        print(f"\n[DEBUG/HTTP] 🌍 WSASend -> Richiesta HTTP GET Geolocalizzazione a ip-api.com ({total_bytes} bytes)")
        ql.recv_stream_buf = bytearray(simulated_ipapi_response)
        ql.eof_after_drain.add(s)

    # 3. Rilevamento Handshake WebSocket C2 (ws://54.233.190.22:8080/ws)
    elif b"Upgrade: websocket" in payload_bytes or b"Sec-WebSocket-Key:" in payload_bytes:
        req_text = payload_bytes.decode('utf-8', errors='replace')
        print("\n" + "=" * 75)
        print(f"[!] 🌐 HANDSHAKE WEBSOCKET C2 INVIATO DAL MALWARE ({total_bytes} bytes):")
        print(req_text.strip())
        ws_key = ""
        for line in req_text.splitlines():
            if line.lower().startswith("sec-websocket-key:"):
                ws_key = line.split(":", 1)[1].strip()
                break
        accept_raw = hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode('ascii')).digest()
        accept_key = base64.b64encode(accept_raw).decode('ascii')
        ws_resp = (
            f"HTTP/1.1 101 Switching Protocols\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key}\r\n\r\n"
        ).encode('ascii')
        ql.recv_stream_buf = bytearray(ws_resp)
        ql.ws_connected = True
        ql.ws_binary_msg_count = 0
        print(f"[+] Handshake WebSocket RFC 6455 calcolato: Sec-WebSocket-Accept = {accept_key}")
        print("=" * 75)

    # 4. Intercettazione e Decodifica Frame WebSocket RFC 6455 inviati dal Malware al C2
    elif getattr(ql, 'ws_connected', False) and len(payload_bytes) >= 6:
        opcode = payload_bytes[0] & 0x0F
        masked = (payload_bytes[1] & 0x80) != 0
        plen = payload_bytes[1] & 0x7F
        idx = 2
        if plen == 126:
            plen = struct.unpack('>H', payload_bytes[2:4])[0]
            idx = 4
        elif plen == 127:
            plen = struct.unpack('>Q', payload_bytes[2:10])[0]
            idx = 10
        if masked:
            mask_key = payload_bytes[idx:idx+4]
            idx += 4
            enc_body = payload_bytes[idx:idx+plen]
            unmasked_body = bytes(b ^ mask_key[i % 4] for i, b in enumerate(enc_body))
        else:
            unmasked_body = payload_bytes[idx:idx+plen]

        if opcode == 2:  # Binary Message (Protobuf)
            ql.ws_binary_msg_count = getattr(ql, 'ws_binary_msg_count', 0) + 1
            msg_num = ql.ws_binary_msg_count

            if msg_num == 1:
                print("\n" + "🔥" * 38)
                print("[!] 🎯 PAYLOAD C2 #1 ESTRATTO: Registrazione iniziale proto.ClientInfo!")
                dump_payload(unmasked_body, "WSASend_C2_ClientInfo_Protobuf")
                parsed_info = parse_client_info_proto(unmasked_body)
                print("[+] 📋 DATI ESFILTRATI DAL MALWARE AL SERVER C2 (54.233.190.22:8080):")
                print(json.dumps(parsed_info, indent=2, default=_json_safe))
                print("🔥" * 38 + "\n")

                if not hasattr(ql, 'c2_extracted_log'):
                    ql.c2_extracted_log = {"client_info": parsed_info, "c2_commands_responses": []}

                # Invia Comando C2 #1: 'pwd' (Verifica working directory remota)
                cmd1_proto = encode_proto_command("cmd-001-pwd", "pwd")
                ql.recv_stream_buf.extend(build_ws_server_frame(cmd1_proto, opcode=2))
                print("[+] 📡 [C2 -> MALWARE] Iniettato Comando Protobuf #1: id='cmd-001-pwd', command='pwd'")

            elif msg_num == 2:
                dump_payload(unmasked_body, "WSASend_C2_Response_pwd")
                resp = parse_response_proto(unmasked_body)
                ql.c2_extracted_log["c2_commands_responses"].append(resp)
                print("\n" + "=" * 75)
                print(f"[+] 📥 [MALWARE -> C2] Ricevuto proto.Response #1 ('pwd'):")
                print(json.dumps(resp, indent=2, default=_json_safe))
                print("=" * 75)

                # Invia Comando C2 #2: 'upload_file' (Drop di un modulo binario dal C2 su disco)
                dropped_pe_stub = b"MZ\x90\x00\x03\x00\x00\x00[TRICKBOT_C2_REMOTE_UPLOADED_MODULE_PAYLOAD]"
                cmd2_proto = encode_proto_command(
                    "cmd-002-upload",
                    "upload_file",
                    args=[r"C:\Windows\Temp\c2_dropped_module.bin"],
                    file_data=dropped_pe_stub
                )
                ql.recv_stream_buf.extend(build_ws_server_frame(cmd2_proto, opcode=2))
                print("[+] 📡 [C2 -> MALWARE] Iniettato Comando Protobuf #2: id='cmd-002-upload', command='upload_file' -> 'C:\\Windows\\Temp\\c2_dropped_module.bin'")

            elif msg_num == 3:
                dump_payload(unmasked_body, "WSASend_C2_Response_upload_file")
                resp = parse_response_proto(unmasked_body)
                ql.c2_extracted_log["c2_commands_responses"].append(resp)
                print("\n" + "=" * 75)
                print(f"[+] 📥 [MALWARE -> C2] Ricevuto proto.Response #2 ('upload_file'):")
                print(json.dumps(resp, indent=2, default=_json_safe))
                print("=" * 75)

                # Invia Comando C2 #3: 'download_file' (Esfiltrazione file client_id dalla vittima)
                cmd3_proto = encode_proto_command(
                    "cmd-003-download",
                    "download_file",
                    args=[r"C:\Users\Qiling\AppData\Roaming\RemoteAdmin\client_id"]
                )
                ql.recv_stream_buf.extend(build_ws_server_frame(cmd3_proto, opcode=2))
                print("[+] 📡 [C2 -> MALWARE] Iniettato Comando Protobuf #3: id='cmd-003-download', command='download_file' -> '%APPDATA%\\RemoteAdmin\\client_id'")

            elif msg_num == 4:
                dump_payload(unmasked_body, "WSASend_C2_Response_download_file")
                resp = parse_response_proto(unmasked_body)
                ql.c2_extracted_log["c2_commands_responses"].append(resp)
                print("\n" + "=" * 75)
                print(f"[+] 📥 [MALWARE -> C2] Ricevuto proto.Response #3 ('download_file' - File Esfiltrato!):")
                print(json.dumps(resp, indent=2, default=_json_safe))
                print("=" * 75)

                # Invia Comando C2 #4: 'delete_file' (Rimozione tracce modulo caricato)
                cmd4_proto = encode_proto_command(
                    "cmd-004-delete",
                    "delete_file",
                    args=[r"C:\Windows\Temp\c2_dropped_module.bin"]
                )
                ql.recv_stream_buf.extend(build_ws_server_frame(cmd4_proto, opcode=2))
                print("[+] 📡 [C2 -> MALWARE] Iniettato Comando Protobuf #4: id='cmd-004-delete', command='delete_file' -> 'C:\\Windows\\Temp\\c2_dropped_module.bin'")

            elif msg_num == 5:
                dump_payload(unmasked_body, "WSASend_C2_Response_delete_file")
                resp = parse_response_proto(unmasked_body)
                ql.c2_extracted_log["c2_commands_responses"].append(resp)
                print("\n" + "=" * 75)
                print(f"[+] 📥 [MALWARE -> C2] Ricevuto proto.Response #4 ('delete_file'):")
                print(json.dumps(resp, indent=2, default=_json_safe))
                print("=" * 75)

                # Salva il report JSON completo della sessione C2
                report_path = os.path.join(_output_dir, "trickbot_c2_full_report.json")
                with open(report_path, "w", encoding="utf-8") as rf:
                    json.dump(ql.c2_extracted_log, rf, indent=2, default=_json_safe)
                print(f"\n[+] 💾 Report JSON completo della sessione C2 salvato in: {os.path.abspath(report_path)}")

                # Invia frame di chiusura WebSocket (Opcode 8, codice 1001 Going Away) per terminare pulitamente readPump
                ql.c2_closing = True
                ql.recv_stream_buf.extend(b"\x88\x02\x03\xe9")
                ql.eof_after_drain.add(s)
                print("[+] 📡 [C2 -> MALWARE] Inviato WebSocket Close Frame (1001 Going Away) per chiusura pulita.")

        elif opcode == 8:
            print("\n[+] 🔒 [MALWARE -> C2] Ricevuto WebSocket Close ACK Frame dal malware!")

    if p_sent and p_sent != 0:
        try:
            ql.mem.write(p_sent, struct.pack('<I', total_bytes))
        except Exception:
            pass

    if not hasattr(ql, 'overlapped_transferred'):
        ql.overlapped_transferred = {}

    if p_ov and p_ov != 0:
        ql.overlapped_transferred[p_ov] = total_bytes
        ql.last_transferred_bytes = total_bytes

    # Se c'era una WSARecv asincrona in attesa su questo socket (es. net/http readLoop o WebSocket readPump),
    # popoliamo subito il suo buffer e accodiamo l'evento di completamento IOCP!
    if len(ql.recv_stream_buf) > 0 and hasattr(ql, 'pending_wsarecv') and s in ql.pending_wsarecv:
        r_b_ptr, r_b_len, r_p_recvd, r_p_ov = ql.pending_wsarecv.pop(s)
        to_write = min(len(ql.recv_stream_buf), r_b_len)
        chunk = bytes(ql.recv_stream_buf[:to_write])
        del ql.recv_stream_buf[:to_write]
        if len(ql.recv_stream_buf) == 0 and s in ql.eof_after_drain:
            ql.eof_sockets.add(s)
        try:
            ql.mem.write(r_b_ptr, chunk)
            if r_p_recvd and r_p_recvd != 0:
                ql.mem.write(r_p_recvd, struct.pack('<I', to_write))
            if r_p_ov and r_p_ov != 0:
                ql.mem.write(r_p_ov, struct.pack('<QQ', 0, to_write))
                ql.mem.write(r_p_ov + 0xac, struct.pack('<I', to_write))
                ql.overlapped_transferred[r_p_ov] = to_write
                ql.last_transferred_bytes = to_write
                iocp_key = getattr(ql, 'socket_iocp_keys', {}).get(s, ql.last_iocp_key)
                if not hasattr(ql, 'iocp_events'):
                    ql.iocp_events = []
                ql.iocp_events.append({
                    'key': iocp_key,
                    'overlapped': r_p_ov,
                    'internal': 0,
                    'bytes': to_write
                })
        except Exception as e:
            print(f"[-] Errore completamento WSARecv pendente: {e}")

    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'buf': POINTER, 'len': INT, 'flags': INT})
def hook_recv(ql, address, params):
    buf = params['buf']
    n_len = params['len']
    if not hasattr(ql, 'recv_stream_buf'):
        ql.recv_stream_buf = bytearray(simulated_ipify_response)
    if buf and buf != 0 and n_len > 0 and len(ql.recv_stream_buf) > 0:
        to_write = min(len(ql.recv_stream_buf), n_len)
        chunk = bytes(ql.recv_stream_buf[:to_write])
        del ql.recv_stream_buf[:to_write]
        ql.mem.write(buf, chunk)
        ql.last_transferred_bytes = to_write
        set_last_error(ql, 0)
        return to_write
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'lpBuffers': POINTER,
    'dwBufferCount': DWORD,
    'lpNumberOfBytesRecvd': POINTER,
    'lpFlags': POINTER,
    'lpOverlapped': POINTER,
    'lpCompletionRoutine': POINTER
})
def hook_WSARecv(ql, address, params):
    s = params['s']
    p_bufs = params['lpBuffers']
    count = params['dwBufferCount']
    p_recvd = params['lpNumberOfBytesRecvd']
    p_flags = params['lpFlags']
    p_ov = params['lpOverlapped']

    if p_ov and p_ov != 0:
        ql.last_overlapped = p_ov

    if not hasattr(ql, 'recv_stream_buf'):
        ql.recv_stream_buf = bytearray()
    if not hasattr(ql, 'eof_after_drain'):
        ql.eof_after_drain = set()
    if not hasattr(ql, 'eof_sockets'):
        ql.eof_sockets = set()
    if not hasattr(ql, 'pending_wsarecv'):
        ql.pending_wsarecv = {}

    if p_flags and p_flags != 0:
        try:
            ql.mem.write(p_flags, struct.pack('<I', 0))
        except Exception:
            pass

    b_len = 0
    b_ptr = 0
    if p_bufs and p_bufs != 0 and count > 0:
        try:
            buf_desc = ql.mem.read(p_bufs, 16)
            b_len = struct.unpack('<I', buf_desc[:4])[0]
            b_ptr = struct.unpack('<Q', buf_desc[8:16])[0]
        except Exception:
            pass

    if len(ql.recv_stream_buf) > 0 and b_ptr != 0 and b_len > 0:
        to_write = min(len(ql.recv_stream_buf), b_len)
        chunk = bytes(ql.recv_stream_buf[:to_write])
        del ql.recv_stream_buf[:to_write]
        if len(ql.recv_stream_buf) == 0 and s in ql.eof_after_drain:
            ql.eof_sockets.add(s)
        try:
            ql.mem.write(b_ptr, chunk)
            if p_recvd and p_recvd != 0:
                ql.mem.write(p_recvd, struct.pack('<I', to_write))
        except Exception as e:
            print(f"[-] Errore in WSARecv: {e}")

        if not hasattr(ql, 'overlapped_transferred'):
            ql.overlapped_transferred = {}
        if p_ov and p_ov != 0:
            ql.overlapped_transferred[p_ov] = to_write
            ql.last_transferred_bytes = to_write
        set_last_error(ql, 0)
        return 0

    # Se il socket ha terminato lo stream (es. dopo risposta HTTP Connection: close), restituisce 0 bytes (EOF)
    if s in ql.eof_sockets:
        if p_recvd and p_recvd != 0:
            try:
                ql.mem.write(p_recvd, struct.pack('<I', 0))
            except Exception:
                pass
        if not hasattr(ql, 'overlapped_transferred'):
            ql.overlapped_transferred = {}
        if p_ov and p_ov != 0:
            ql.overlapped_transferred[p_ov] = 0
            ql.last_transferred_bytes = 0
        set_last_error(ql, 0)
        return 0

    # Altrimenti i dati non sono ancora pronti (es. readLoop/readPump chiamato prima di WSASend):
    # registriamo la WSARecv come asincrona pendente (WSA_IO_PENDING = 997)
    ql.pending_wsarecv[s] = (b_ptr, b_len, p_recvd, p_ov)
    set_last_error(ql, 997)  # WSA_IO_PENDING
    return 0xFFFFFFFF  # SOCKET_ERROR

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'name': POINTER, 'namelen': POINTER})
def hook_getsockname(ql, address, params):
    name_ptr = params['name']
    len_ptr = params['namelen']
    if name_ptr and name_ptr != 0 and len_ptr and len_ptr != 0:
        try:
            sockaddr = struct.pack('<H', 2) + struct.pack('>H', 49152) + bytes([192, 168, 1, 100]) + (b'\x00' * 8)
            ql.mem.write(name_ptr, sockaddr)
            ql.mem.write(len_ptr, struct.pack('<i', 16))
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'name': POINTER, 'namelen': POINTER})
def hook_getpeername(ql, address, params):
    name_ptr = params['name']
    len_ptr = params['namelen']
    if name_ptr and name_ptr != 0 and len_ptr and len_ptr != 0:
        try:
            sockaddr = struct.pack('<H', 2) + struct.pack('>H', 80) + bytes([104, 26, 12, 159]) + (b'\x00' * 8)
            ql.mem.write(name_ptr, sockaddr)
            ql.mem.write(len_ptr, struct.pack('<i', 16))
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'cmd': LONG, 'argp': POINTER})
def hook_ioctlsocket(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'level': INT, 'optname': INT, 'optval': POINTER, 'optlen': INT})
def hook_setsockopt(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'level': INT, 'optname': INT, 'optval': POINTER, 'optlen': POINTER})
def hook_getsockopt(ql, address, params):
    val = params['optval']
    out_len = params['optlen']
    if val and val != 0:
        try:
            ql.mem.write(val, struct.pack('<I', 0))
        except Exception:
            pass
    if out_len and out_len != 0:
        try:
            ql.mem.write(out_len, struct.pack('<I', 4))
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'hEventObject': HANDLE, 'lNetworkEvents': LONG})
def hook_WSAEventSelect(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={})
def hook_WSAGetLastError(ql, address, params):
    try:
        return ql.os.last_error
    except Exception:
        return 0

@winsdkapi(cc=STDCALL, params={'iError': INT})
def hook_WSASetLastError(ql, address, params):
    set_last_error(ql, params['iError'])
    return

@winsdkapi(cc=STDCALL, params={'s': HANDLE, 'how': INT})
def hook_shutdown(ql, address, params):
    return 0

@winsdkapi(cc=STDCALL, params={'name': STRING})
def hook_gethostbyname(ql, address, params):
    map_dns_memory(ql)
    hostent_ptr = 0x70002000
    ip_ptr = 0x70002050
    ip_list_ptr = 0x70002040
    try:
        ip_bytes = bytes([104, 26, 12, 159])
        ql.mem.write(ip_ptr, ip_bytes)
        ql.mem.write(ip_list_ptr, struct.pack('<QQ', ip_ptr, 0))
        hostent = struct.pack('<QQHHIQ', 0, 0, 2, 4, 0, ip_list_ptr)
        ql.mem.write(hostent_ptr, hostent)
        return hostent_ptr
    except Exception:
        return 0

@winsdkapi(cc=STDCALL, params={'name': POINTER, 'namelen': INT})
def hook_gethostname(ql, address, params):
    buf = params['name']
    n_len = params['namelen']
    hname = "DESKTOP-TRICKBOT\x00".encode('latin1')
    if buf and buf != 0 and n_len >= len(hname):
        try:
            ql.mem.write(buf, hname)
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'lpOverlapped': POINTER,
    'lpcbTransfer': POINTER,
    'fWait': BOOL,
    'lpdwFlags': POINTER
})
def hook_WSAGetOverlappedResult(ql, address, params):
    s = params['s']
    lp_ov = params['lpOverlapped']
    transfer_ptr = params['lpcbTransfer']
    flags_ptr = params['lpdwFlags']

    bytes_trans = 0
    if hasattr(ql, 'overlapped_transferred') and lp_ov in ql.overlapped_transferred:
        bytes_trans = ql.overlapped_transferred[lp_ov]
    else:
        bytes_trans = getattr(ql, 'last_transferred_bytes', 0)

    print(f"\n[DEBUG/NET] 🌐 WSAGetOverlappedResult: Socket={hex(s)}, Overlapped={hex(lp_ov)}, BytesTransferred={bytes_trans}")

    if transfer_ptr and transfer_ptr != 0:
        try:
            ql.mem.write(transfer_ptr, struct.pack('<I', bytes_trans))
        except Exception as e:
            print(f"[-] Errore scrittura lpcbTransfer: {e}")

    if flags_ptr and flags_ptr != 0:
        try:
            ql.mem.write(flags_ptr, struct.pack('<I', 0))
        except Exception:
            pass

    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={
    'hFile': HANDLE,
    'lpOverlapped': POINTER,
    'lpNumberOfBytesTransferred': POINTER,
    'bWait': BOOL
})
def hook_GetOverlappedResult(ql, address, params):
    h = params['hFile']
    lp_ov = params['lpOverlapped']
    transfer_ptr = params['lpNumberOfBytesTransferred']

    bytes_trans = 0
    if hasattr(ql, 'overlapped_transferred') and lp_ov in ql.overlapped_transferred:
        bytes_trans = ql.overlapped_transferred[lp_ov]
    else:
        bytes_trans = getattr(ql, 'last_transferred_bytes', 0)

    if transfer_ptr and transfer_ptr != 0:
        try:
            ql.mem.write(transfer_ptr, struct.pack('<I', bytes_trans))
        except Exception:
            pass

    set_last_error(ql, 0)
    return 1  # TRUE

@winsdkapi(cc=STDCALL, params={})
def hook_WSACreateEvent(ql, address, params):
    return 0x60001

@winsdkapi(cc=STDCALL, params={'hEvent': HANDLE})
def hook_WSACloseEvent(ql, address, params):
    return 1

@winsdkapi(cc=STDCALL, params={
    'cEvents': DWORD,
    'lphEvents': POINTER,
    'fWaitAll': BOOL,
    'dwTimeout': DWORD,
    'fAlertable': BOOL
})
def hook_WSAWaitForMultipleEvents(ql, address, params):
    return 0  # WSA_WAIT_EVENT_0

@winsdkapi(cc=STDCALL, params={
    's': HANDLE,
    'hEventObject': HANDLE,
    'lpNetworkEvents': POINTER
})
def hook_WSAEnumNetworkEvents(ql, address, params):
    net_events_ptr = params['lpNetworkEvents']
    if net_events_ptr and net_events_ptr != 0:
        try:
            ev_data = struct.pack('<I', 0x33) + (b'\x00' * 40)
            ql.mem.write(net_events_ptr, ev_data)
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0

# ==============================================================================
# GESTIONE COM, BSTR & OLEAUT32 (ole32.dll & oleaut32.dll)
# ==============================================================================
bstr_pool_base = 0x70010000

def alloc_bstr(ql, text):
    """Alloca una BSTR conforme OLE con prefisso DWORD di lunghezza byte."""
    global bstr_pool_base
    data = (text + "\x00").encode('utf-16le')
    byte_len = len(text) * 2
    alloc_addr = bstr_pool_base
    bstr_pool_base += ((byte_len + 16) + 0x1F) & ~0x1F
    try:
        ql.mem.write(alloc_addr, struct.pack('<I', byte_len))
        bstr_ptr = alloc_addr + 4
        ql.mem.write(bstr_ptr, data)
        return bstr_ptr
    except Exception:
        return 0

@winsdkapi(cc=STDCALL, params={})
def hook_CoInitialize(ql, address, params):
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'pvReserved': POINTER, 'dwCoInit': DWORD})
def hook_CoInitializeEx(ql, address, params):
    print(f"\n[DEBUG/COM] 🧩 CoInitializeEx chiamato (dwCoInit={params['dwCoInit']}) -> S_OK")
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={})
def hook_CoUninitialize(ql, address, params):
    return

@winsdkapi(cc=STDCALL, params={
    'lpszProgID': POINTER,
    'lpclsid': POINTER
})
def hook_CLSIDFromProgID(ql, address, params):
    p_progid = params['lpszProgID']
    p_clsid = params['lpclsid']
    progid = read_wstring(ql, p_progid)
    print(f"\n[DEBUG/COM] 🧩 CLSIDFromProgID chiamato per ProgID: '{progid}' (lpclsid={hex(p_clsid)})")

    if p_clsid != 0:
        if "Wbem" in progid or "SWbem" in progid:
            # SWbemLocator: {76A64158-CB41-11D1-8B02-00600806D9B6}
            guid = bytes.fromhex("5841a67641cb11d18b0200600806d9b6")
        elif "WScript.Shell" in progid:
            # WScript.Shell: {72C24DD5-D70A-438B-8A42-98424B88AFB8}
            guid = bytes.fromhex("d54dc2720ad78b438a4298424b88afb8")
        else:
            guid = hashlib.md5(progid.encode('utf-8')).digest()

        try:
            ql.mem.write(p_clsid, guid)
            print(f"[+] CLSIDFromProgID: Scritto CLSID ({guid.hex()}) per '{progid}'.")
        except Exception as e:
            print(f"[-] Errore scrittura CLSID: {e}")

    set_last_error(ql, 0)
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={
    'lpsz': POINTER,
    'pclsid': POINTER
})
def hook_CLSIDFromString(ql, address, params):
    p_str = params['lpsz']
    p_clsid = params['pclsid']
    guid_str = read_wstring(ql, p_str)
    if p_clsid != 0:
        guid = hashlib.md5(guid_str.encode('utf-8')).digest()
        try:
            ql.mem.write(p_clsid, guid)
        except Exception:
            pass
    set_last_error(ql, 0)
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'pclsid': POINTER, 'lplpszProgID': POINTER})
def hook_ProgIDFromCLSID(ql, address, params):
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={
    'rclsid': POINTER,
    'pUnkOuter': POINTER,
    'dwClsContext': DWORD,
    'riid': POINTER,
    'ppv': POINTER
})
def hook_CoCreateInstance(ql, address, params):
    p_rclsid = params['rclsid']
    p_riid = params['riid']
    p_ppv = params['ppv']

    clsid_hex = ""
    if p_rclsid != 0:
        try:
            clsid_hex = bytes(ql.mem.read(p_rclsid, 16)).hex()
        except Exception:
            pass

    riid_hex = ""
    if p_riid != 0:
        try:
            riid_hex = bytes(ql.mem.read(p_riid, 16)).hex()
        except Exception:
            pass

    print(f"\n[DEBUG/COM] 🧩 CoCreateInstance chiamato: CLSID={clsid_hex}, RIID={riid_hex}, OutPPV={hex(p_ppv)}")

    if p_ppv != 0:
        mock_obj_addr = 0x70005000
        try:
            ql.mem.write(p_ppv, struct.pack('<Q', mock_obj_addr))
            print(f"[+] CoCreateInstance: Assegnato Mock COM Object a {hex(mock_obj_addr)}")
        except Exception as e:
            print(f"[-] Errore scrittura Mock COM pointer: {e}")

    set_last_error(ql, 0)
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={
    'Clsid': POINTER,
    'punkOuter': POINTER,
    'dwClsCtx': DWORD,
    'pServerInfo': POINTER,
    'dwCount': DWORD,
    'pResults': POINTER
})
def hook_CoCreateInstanceEx(ql, address, params):
    dwCount = params['dwCount']
    pResults = params['pResults']
    if pResults != 0 and dwCount > 0:
        for i in range(dwCount):
            offset = i * 24
            try:
                ql.mem.write(pResults + offset + 8, struct.pack('<Q', 0x70005000))
                ql.mem.write(pResults + offset + 16, struct.pack('<I', 0))
            except Exception:
                pass
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={
    'pProxy': POINTER,
    'dwAuthnSvc': DWORD,
    'dwAuthzSvc': DWORD,
    'pServerPrincName': POINTER,
    'dwAuthnLevel': DWORD,
    'dwImpLevel': DWORD,
    'pAuthInfo': POINTER,
    'dwCapabilities': DWORD
})
def hook_CoSetProxyBlanket(ql, address, params):
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'rclsid': POINTER, 'lplpsz': POINTER})
def hook_StringFromCLSID(ql, address, params):
    p_str = params['lplpsz']
    if p_str and p_str != 0:
        guid_str = "{76A64158-CB41-11D1-8B02-00600806D9B6}\x00".encode('utf-16le')
        try:
            ql.mem.write(0x70001800, guid_str)
            ql.mem.write(p_str, struct.pack('<Q', 0x70001800))
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={'rguid': POINTER, 'lpsz': POINTER, 'cchMax': INT})
def hook_StringFromGUID2(ql, address, params):
    buf = params['lpsz']
    cch = params['cchMax']
    guid_str = "{76A64158-CB41-11D1-8B02-00600806D9B6}\x00".encode('utf-16le')
    if buf and buf != 0 and cch >= 39:
        try:
            ql.mem.write(buf, guid_str[:39*2])
            return 39
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={'cb': SIZE_T})
def hook_CoTaskMemAlloc(ql, address, params):
    cb = params['cb']
    if not hasattr(ql, 'cotask_base'):
        ql.cotask_base = 0x70008000
    addr = ql.cotask_base
    ql.cotask_base += (cb + 0x1f) & ~0x1f
    return addr

@winsdkapi(cc=STDCALL, params={'pv': POINTER})
def hook_CoTaskMemFree(ql, address, params):
    return

# ==============================================================================
# SUITE BSTR & OLE AUTOMATION (Override del bug interno di Qiling)
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'strIn': POINTER,
    'ui': UINT
})
def hook_SysAllocStringLen(ql, address, params):
    global bstr_pool_base
    p_str = params['strIn']
    ui = params['ui']

    text = ""
    byte_len = ui * 2
    raw_chars = b"\x00" * byte_len

    if p_str and p_str != 0 and ui > 0:
        try:
            raw_chars = ql.mem.read(p_str, byte_len)
            text = raw_chars.decode('utf-16le', errors='replace')
        except Exception:
            pass

    print(f"\n[DEBUG/COM] 🧩 SysAllocStringLen chiamato: strIn={hex(p_str)}, ui={ui} chars")
    if text:
        print(f"[+] 🔍 Stringa BSTR allocata: \"{text}\"")

    alloc_addr = bstr_pool_base
    bstr_pool_base += ((byte_len + 16) + 0x1F) & ~0x1F

    try:
        ql.mem.write(alloc_addr, struct.pack('<I', byte_len))
        bstr_ptr = alloc_addr + 4
        ql.mem.write(bstr_ptr, bytes(raw_chars) + b"\x00\x00")
        print(f"[+] SysAllocStringLen: BSTR creato a {hex(bstr_ptr)} (Prefisso DWORD={byte_len} a {hex(alloc_addr)})")
        return bstr_ptr
    except Exception as e:
        print(f"[-] Errore creazione BSTR in SysAllocStringLen: {e}")
        return 0

@winsdkapi(cc=STDCALL, params={'psz': POINTER})
def hook_SysAllocString(ql, address, params):
    p_str = params['psz']
    if not p_str or p_str == 0:
        return 0
    text = read_wstring(ql, p_str)
    return alloc_bstr(ql, text)

@winsdkapi(cc=STDCALL, params={'psz': POINTER, 'len': UINT})
def hook_SysAllocStringByteLen(ql, address, params):
    global bstr_pool_base
    p_str = params['psz']
    n_bytes = params['len']
    raw_data = b"\x00" * n_bytes
    if p_str and p_str != 0 and n_bytes > 0:
        try:
            raw_data = ql.mem.read(p_str, n_bytes)
        except Exception:
            pass
    alloc_addr = bstr_pool_base
    bstr_pool_base += ((n_bytes + 16) + 0x1F) & ~0x1F
    try:
        ql.mem.write(alloc_addr, struct.pack('<I', n_bytes))
        bstr_ptr = alloc_addr + 4
        ql.mem.write(bstr_ptr, bytes(raw_data) + b"\x00\x00")
        return bstr_ptr
    except Exception:
        return 0

@winsdkapi(cc=STDCALL, params={'bstrString': POINTER})
def hook_SysFreeString(ql, address, params):
    return

@winsdkapi(cc=STDCALL, params={'bstrString': POINTER})
def hook_SysStringLen(ql, address, params):
    p = params['bstrString']
    if not p or p == 0:
        return 0
    try:
        byte_len = struct.unpack('<I', ql.mem.read(p - 4, 4))[0]
        if byte_len < 0x10000:
            return byte_len // 2
    except Exception:
        pass
    try:
        s = read_wstring(ql, p)
        return len(s)
    except Exception:
        return 0

@winsdkapi(cc=STDCALL, params={'bstr': POINTER})
def hook_SysStringByteLen(ql, address, params):
    p = params['bstr']
    if not p or p == 0:
        return 0
    try:
        return struct.unpack('<I', ql.mem.read(p - 4, 4))[0]
    except Exception:
        return 0

@winsdkapi(cc=STDCALL, params={'pvarg': POINTER})
def hook_VariantInit(ql, address, params):
    p = params['pvarg']
    if p and p != 0:
        try:
            ql.mem.write(p, b'\x00' * 24)
        except Exception:
            pass
    return

@winsdkapi(cc=STDCALL, params={'pvarg': POINTER})
def hook_VariantClear(ql, address, params):
    p = params['pvarg']
    if p and p != 0:
        try:
            ql.mem.write(p, b'\x00' * 24)
        except Exception:
            pass
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'pvargDest': POINTER, 'pvargSrc': POINTER})
def hook_VariantCopy(ql, address, params):
    dst = params['pvargDest']
    src = params['pvargSrc']
    if dst and src and dst != 0 and src != 0:
        try:
            data = ql.mem.read(src, 24)
            ql.mem.write(dst, data)
        except Exception:
            pass
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={
    'pvargDest': POINTER,
    'pvarSrc': POINTER,
    'wFlags': WORD,
    'vt': WORD
})
def hook_VariantChangeType(ql, address, params):
    dst = params['pvargDest']
    src = params['pvarSrc']
    if dst and src and dst != 0 and src != 0:
        try:
            data = ql.mem.read(src, 24)
            ql.mem.write(dst, data)
        except Exception:
            pass
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'vt': WORD, 'cDims': UINT, 'rgsabound': POINTER})
def hook_SafeArrayCreate(ql, address, params):
    return 0x70009000

@winsdkapi(cc=STDCALL, params={'psa': POINTER})
def hook_SafeArrayDestroy(ql, address, params):
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'psa': POINTER, 'nDim': UINT, 'plUbound': POINTER})
def hook_SafeArrayGetUBound(ql, address, params):
    p = params['plUbound']
    if p and p != 0:
        try:
            ql.mem.write(p, struct.pack('<i', -1))
        except Exception:
            pass
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'psa': POINTER, 'nDim': UINT, 'plLbound': POINTER})
def hook_SafeArrayGetLBound(ql, address, params):
    p = params['plLbound']
    if p and p != 0:
        try:
            ql.mem.write(p, struct.pack('<i', 0))
        except Exception:
            pass
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'psa': POINTER, 'ppvData': POINTER})
def hook_SafeArrayAccessData(ql, address, params):
    p = params['ppvData']
    if p and p != 0:
        try:
            ql.mem.write(p, struct.pack('<Q', 0x70009100))
        except Exception:
            pass
    return 0  # S_OK

@winsdkapi(cc=STDCALL, params={'psa': POINTER})
def hook_SafeArrayUnaccessData(ql, address, params):
    return 0  # S_OK

# ==============================================================================
# TRAMPOLINES MOCK COM & INTERFACCE IDISPATCH / IENUMVARIANT
# ==============================================================================
enum_query_count = 0

def hook_QueryInterface_trampoline(ql):
    this_ptr = ql.arch.regs.rcx
    riid_ptr = ql.arch.regs.rdx
    ppv_ptr = ql.arch.regs.r8

    guid_hex = ""
    if riid_ptr != 0:
        try:
            guid_hex = bytes(ql.mem.read(riid_ptr, 16)).hex()
        except Exception:
            pass

    print(f"\n[DEBUG/COM] 🧩 Mock COM QueryInterface: this={hex(this_ptr)}, RIID={guid_hex}, OutPPV={hex(ppv_ptr)}")

    # Se il chiamante è 0x70006000 o richiede IEnumVARIANT ({00020404-0000-0000-C000-000000000046}):
    if this_ptr == 0x70006000 or "04040200" in guid_hex:
        out_obj = 0x70006000
    elif this_ptr == 0x70007000:
        out_obj = 0x70007000
    else:
        out_obj = 0x70005000

    if ppv_ptr != 0:
        try:
            ql.mem.write(ppv_ptr, struct.pack('<Q', out_obj))
            print(f"[+] QueryInterface: Assegnato oggetto {hex(out_obj)} a {hex(ppv_ptr)}")
        except Exception as e:
            print(f"[-] Errore scrittura QueryInterface: {e}")

    ql.arch.regs.rax = 0  # S_OK

def hook_AddRef_trampoline(ql):
    ql.arch.regs.rax = 1

def hook_Release_trampoline(ql):
    ql.arch.regs.rax = 0

def hook_GenericCOM_trampoline(ql):
    print(f"\n[DEBUG/COM] 🧩 Mock COM Method generico chiamato -> Ritorno S_OK")
    ql.arch.regs.rax = 0  # S_OK

def hook_GetIDsOfNames_trampoline(ql):
    c_names = ql.arch.regs.r9
    p_names = ql.arch.regs.r8
    name_str = ""
    dispid_to_assign = 1
    if p_names != 0 and c_names > 0:
        try:
            p_first_name = struct.unpack('<Q', ql.mem.read(p_names, 8))[0]
            name_str = read_wstring(ql, p_first_name)
        except Exception:
            pass

    print(f"\n[DEBUG/COM] 🧩 Mock IDispatch::GetIDsOfNames: Richiesto membro '{name_str}' (cNames={c_names})")

    lower_name = name_str.lower()
    if lower_name in ("count", "length"):
        dispid_to_assign = 1001
    elif lower_name in ("item", "itemindex"):
        dispid_to_assign = 1002
    elif lower_name in ("connectserver",):
        dispid_to_assign = 1003
    elif lower_name in ("execquery",):
        dispid_to_assign = 1004
    elif lower_name in ("_newenum",):
        dispid_to_assign = -4  # DISPID_NEWENUM (-4)
    elif lower_name == "family":
        dispid_to_assign = 2001
    elif lower_name == "manufacturer":
        dispid_to_assign = 2002
    elif lower_name in ("name", "caption", "description"):
        dispid_to_assign = 2003
    elif lower_name in ("numberoflogicalprocessors", "logicalprocessors"):
        dispid_to_assign = 2004
    elif lower_name in ("numberofcores", "cores"):
        dispid_to_assign = 2005
    elif lower_name == "processorid":
        dispid_to_assign = 2006
    elif lower_name == "stepping":
        dispid_to_assign = 2007
    elif lower_name in ("maxclockspeed", "clockspeed"):
        dispid_to_assign = 2008
    else:
        dispid_to_assign = 3000

    try:
        rg_dispid = struct.unpack('<Q', ql.mem.read(ql.arch.regs.rsp + 0x30, 8))[0]
        if rg_dispid != 0:
            ql.mem.write(rg_dispid, struct.pack('<i', dispid_to_assign))
            print(f"[+] GetIDsOfNames: Assegnato DISPID={dispid_to_assign} per '{name_str}' a {hex(rg_dispid)}")
    except Exception as e:
        print(f"[-] Errore scrittura DISPID in GetIDsOfNames: {e}")

    ql.arch.regs.rax = 0  # S_OK

def hook_Invoke_trampoline(ql):
    global enum_query_count
    # Normalizzazione rigorosa DISPID su 32-bit signed
    dispid_raw = ql.arch.regs.rdx & 0xFFFFFFFF
    if dispid_raw >= 0x80000000:
        dispid = dispid_raw - 0x100000000
    else:
        dispid = dispid_raw

    print(f"\n[DEBUG/COM] 🧩 Mock IDispatch::Invoke chiamato (DISPID={dispid})!")

    # Ispezione query WMI
    if dispid == 1004:
        enum_query_count = 0  # Resetta il cursore enumerazione per la nuova query
        try:
            p_params = struct.unpack('<Q', ql.mem.read(ql.arch.regs.rsp + 0x30, 8))[0]
            if p_params != 0:
                c_args = struct.unpack('<I', ql.mem.read(p_params + 16, 4))[0]
                rgvarg = struct.unpack('<Q', ql.mem.read(p_params, 8))[0]
                if c_args > 0 and rgvarg != 0:
                    for arg_idx in range(c_args):
                        vt = struct.unpack('<H', ql.mem.read(rgvarg + arg_idx * 24, 2))[0]
                        if vt == 8:  # VT_BSTR
                            bstr = struct.unpack('<Q', ql.mem.read(rgvarg + arg_idx * 24 + 8, 8))[0]
                            q_text = read_wstring(ql, bstr)
                            print(f"[+] 🎯 WMI ExecQuery Argomento [{arg_idx}]: \"{q_text}\"")
        except Exception as e:
            print(f"[-] Errore lettura parametri ExecQuery: {e}")

    try:
        p_var = struct.unpack('<Q', ql.mem.read(ql.arch.regs.rsp + 0x38, 8))[0]
        if p_var != 0:
            if dispid == 1001:  # Count
                var_bytes = struct.pack('<H6xi12x', 3, 0)  # VT_I4 = 3, lVal = 0
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito Count = 0 (VT_I4)")
            elif dispid == -4:  # _NewEnum: VT_UNKNOWN (13) puntato a IEnumVARIANT
                var_bytes = struct.pack('<H6xQ8x', 13, 0x70006000)  # VT_UNKNOWN = 13
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito _NewEnum come VT_UNKNOWN (0x70006000) [UNBLOCK GO REFLECT!]")
            elif dispid == 2001:  # Family
                var_bytes = struct.pack('<H6xi12x', 3, 206)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito Family = 206 (VT_I4)")
            elif dispid == 2002:  # Manufacturer
                bstr = alloc_bstr(ql, "GenuineIntel")
                var_bytes = struct.pack('<H6xQ8x', 8, bstr)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito Manufacturer = 'GenuineIntel' (VT_BSTR)")
            elif dispid == 2003:  # Name
                bstr = alloc_bstr(ql, "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz")
                var_bytes = struct.pack('<H6xQ8x', 8, bstr)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito Name = 'Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz' (VT_BSTR)")
            elif dispid == 2004:  # NumberOfLogicalProcessors
                var_bytes = struct.pack('<H6xi12x', 3, 8)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito NumberOfLogicalProcessors = 8 (VT_I4)")
            elif dispid == 2005:  # NumberOfCores
                var_bytes = struct.pack('<H6xi12x', 3, 8)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito NumberOfCores = 8 (VT_I4)")
            elif dispid == 2006:  # ProcessorID
                bstr = alloc_bstr(ql, "BFEBFBFF000906ED")
                var_bytes = struct.pack('<H6xQ8x', 8, bstr)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito ProcessorID = 'BFEBFBFF000906ED' (VT_BSTR)")
            elif dispid == 2007:  # Stepping
                bstr = alloc_bstr(ql, "9")
                var_bytes = struct.pack('<H6xQ8x', 8, bstr)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito Stepping = '9' (VT_BSTR)")
            elif dispid == 2008:  # MaxClockSpeed
                var_bytes = struct.pack('<H6xi12x', 3, 3600)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito MaxClockSpeed = 3600 (VT_I4)")
            elif dispid == 1004:  # ExecQuery -> SWbemObjectSet
                var_bytes = struct.pack('<H6xQ8x', 9, 0x70005000)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito SWbemObjectSet per ExecQuery (0x70005000)")
            else:
                var_bytes = struct.pack('<H6xQ8x', 9, 0x70005000)
                ql.mem.write(p_var, var_bytes)
                print(f"[+] IDispatch::Invoke: Restituito pVarResult come VT_DISPATCH (0x70005000)")
    except Exception as e:
        print(f"[-] Errore in Invoke trampoline: {e}")

    ql.arch.regs.rax = 0  # S_OK

def hook_EnumVARIANT_Next_trampoline(ql):
    global enum_query_count
    # HRESULT Next(ULONG celt, VARIANT *rgVar, ULONG *pCeltFetched)
    celt = ql.arch.regs.rdx
    rg_var = ql.arch.regs.r8
    p_fetched = ql.arch.regs.r9

    print(f"\n[DEBUG/COM] 🧩 Mock IEnumVARIANT::Next: celt={celt}, rgVar={hex(rg_var)}, pFetched={hex(p_fetched)}, count={enum_query_count}")

    if enum_query_count == 0:
        enum_query_count += 1
        if rg_var != 0:
            var_bytes = struct.pack('<H6xQ8x', 9, 0x70007000)  # VT_DISPATCH a SWbemObject (win32_Processor)
            ql.mem.write(rg_var, var_bytes)
        if p_fetched != 0:
            ql.mem.write(p_fetched, struct.pack('<I', 1))
        print("[+] IEnumVARIANT::Next: Restituito 1 record win32_Processor (VT_DISPATCH: 0x70007000) -> S_OK (0)")
        ql.arch.regs.rax = 0  # S_OK
    else:
        if p_fetched != 0:
            ql.mem.write(p_fetched, struct.pack('<I', 0))
        print("[+] IEnumVARIANT::Next: Fine enumerazione record -> S_FALSE (1)")
        ql.arch.regs.rax = 1  # S_FALSE (Fine enumerazione)

def setup_com_mock(ql):
    """Costruisce in memoria virtuale il Mock COM Object, IEnumVARIANT, SWbemObject e le VTable."""
    map_dns_memory(ql)

    # 0x70005000: Istanza COM base (SWbemServices / ObjectSet)
    ql.mem.write(0x70005000, struct.pack('<Q', 0x70005100))

    # 0x70007000: Istanza COM record singolo (win32_Processor)
    ql.mem.write(0x70007000, struct.pack('<Q', 0x70005100))

    # Scrittura istruzione RET (0xC3) agli indirizzi dei trampolines
    trampoline_addrs = [
        0x70005800, 0x70005820, 0x70005840, 0x70005860, 0x70005880, 0x700058A0,
        0x70006800, 0x70006820, 0x70006840, 0x70006860
    ]
    for a in trampoline_addrs:
        ql.mem.write(a, b'\xC3')

    ql.hook_address(hook_QueryInterface_trampoline, 0x70005800)
    ql.hook_address(hook_AddRef_trampoline, 0x70005820)
    ql.hook_address(hook_Release_trampoline, 0x70005840)
    ql.hook_address(hook_GenericCOM_trampoline, 0x70005860)
    ql.hook_address(hook_GetIDsOfNames_trampoline, 0x70005880)
    ql.hook_address(hook_Invoke_trampoline, 0x700058A0)

    # Hook per IEnumVARIANT::Next
    ql.hook_address(hook_EnumVARIANT_Next_trampoline, 0x70006860)

    # Costruzione VTable IDispatch (64 slot a 64 bit)
    vtable = bytearray()
    vtable.extend(struct.pack('<Q', 0x70005800))  # 0: QueryInterface
    vtable.extend(struct.pack('<Q', 0x70005820))  # 1: AddRef
    vtable.extend(struct.pack('<Q', 0x70005840))  # 2: Release
    vtable.extend(struct.pack('<Q', 0x70005860))  # 3: GetTypeInfoCount
    vtable.extend(struct.pack('<Q', 0x70005860))  # 4: GetTypeInfo
    vtable.extend(struct.pack('<Q', 0x70005880))  # 5: GetIDsOfNames
    vtable.extend(struct.pack('<Q', 0x700058A0))  # 6: Invoke
    for _ in range(7, 64):
        vtable.extend(struct.pack('<Q', 0x70005860))  # 7..63: Generic Method -> S_OK

    ql.mem.write(0x70005100, bytes(vtable))

    # Setup Mock IEnumVARIANT (0x70006000) con vtable a 0x70006100
    ql.mem.write(0x70006000, struct.pack('<Q', 0x70006100))
    enum_vtable = bytearray()
    enum_vtable.extend(struct.pack('<Q', 0x70005800))  # 0: QueryInterface
    enum_vtable.extend(struct.pack('<Q', 0x70005820))  # 1: AddRef
    enum_vtable.extend(struct.pack('<Q', 0x70005840))  # 2: Release
    enum_vtable.extend(struct.pack('<Q', 0x70006860))  # 3: Next (Hardware Spoofing)
    enum_vtable.extend(struct.pack('<Q', 0x70006860))  # 4: Skip
    enum_vtable.extend(struct.pack('<Q', 0x70005860))  # 5: Reset
    enum_vtable.extend(struct.pack('<Q', 0x70005860))  # 6: Clone
    for _ in range(7, 16):
        enum_vtable.extend(struct.pack('<Q', 0x70005860))
    ql.mem.write(0x70006100, bytes(enum_vtable))

    print("[+] Setup COM Mock Object completato: Instance=0x70005000, Enum=0x70006000, Processor=0x70007000")

# ==============================================================================
# PROCESS HOLLOWING & PAYLOAD DUMPER
# ==============================================================================
payload_counter = 0

def dump_payload(data, source_api):
    global payload_counter
    payload_counter += 1
    dump_filename = os.path.join(_output_dir, f"trickbot_payload_{payload_counter}.bin")
    with open(dump_filename, "wb") as f:
        f.write(data)
    print(f"\n[🔥🔥🔥] DUMP PAYLOAD EFFETTUATO DA {source_api}!")
    print(f"[+] Salvato in: {os.path.abspath(dump_filename)} ({len(data)} bytes)")
    if len(data) >= 2 and data[:2] == b'MZ':
        print("[+] 🎯 CONFERMATO: Il buffer estratto è un eseguibile PE Windows valido (Magic MZ)!")

@winsdkapi(cc=STDCALL, params={
    'lpApplicationName': STRING,
    'lpCommandLine': STRING,
    'lpProcessAttributes': POINTER,
    'lpThreadAttributes': POINTER,
    'bInheritHandles': BOOL,
    'dwCreationFlags': DWORD,
    'lpEnvironment': POINTER,
    'lpCurrentDirectory': STRING,
    'lpStartupInfo': POINTER,
    'lpProcessInformation': POINTER
})
def hook_CreateProcessA(ql, address, params):
    app = params['lpApplicationName']
    cmd = params['lpCommandLine']
    flags = params['dwCreationFlags']
    p_info = params['lpProcessInformation']
    print("\n" + "!" * 70)
    print(f"[!] 🚨 PROCESS HOLLOWING RILEVATO: Chiamata a CreateProcess")
    print(f"[!] Target: {app} | Cmd: {cmd} | Flags: {hex(flags)}")
    if flags & 0x4:
        print("[!] ⚠️ PROCESSO CREATO IN STATO SOSPESO (CREATE_SUSPENDED)! Tentativo di iniezione imminente.")
    print("!" * 70 + "\n")
    if p_info and p_info != 0:
        fake_pi = struct.pack('<QQII', 0x1111, 0x2222, 1234, 5678)
        try:
            ql.mem.write(p_info, fake_pi)
        except Exception:
            pass
    return 1

@winsdkapi(cc=STDCALL, params={
    'lpApplicationName': WSTRING,
    'lpCommandLine': WSTRING,
    'lpProcessAttributes': POINTER,
    'lpThreadAttributes': POINTER,
    'bInheritHandles': BOOL,
    'dwCreationFlags': DWORD,
    'lpEnvironment': POINTER,
    'lpCurrentDirectory': WSTRING,
    'lpStartupInfo': POINTER,
    'lpProcessInformation': POINTER
})
def hook_CreateProcessW(ql, address, params):
    app = params['lpApplicationName']
    cmd = params['lpCommandLine']
    flags = params['dwCreationFlags']
    env_ptr = params['lpEnvironment']
    p_info = params['lpProcessInformation']
    cur_dir = params['lpCurrentDirectory']
    print("\n" + "!" * 70)
    print(f"[!] 🚨 STAGE 1 -> STAGE 2 SPAWN RILEVATO: Chiamata a CreateProcessW")
    print(f"[!] Target App   : {app}")
    print(f"[!] Command Line : {cmd}")
    print(f"[!] Cur Directory: {cur_dir}")
    print(f"[!] Flags        : {hex(flags)} (DETACHED_PROCESS=0x8 | CREATE_NO_WINDOW=0x8000000 | CREATE_UNICODE_ENVIRONMENT=0x400)")
    if flags & 0x80000:
        print("[!] ℹ️ EXTENDED_STARTUPINFO_PRESENT rilevato (STARTUPINFOEXW in uso)!")
    if flags & 0x4:
        print("[!] ⚠️ PROCESSO CREATO IN STATO SOSPESO (CREATE_SUSPENDED)! Tentativo di iniezione imminente.")

    # Estrazione blocco di ambiente Unicode per verificare _HIDDEN_CHILD=1
    extracted_env = []
    if env_ptr and env_ptr != 0:
        try:
            raw_env = bytes(ql.mem.read(env_ptr, 4096))
            env_text = raw_env.decode('utf-16le', errors='ignore')
            for entry in env_text.split('\x00'):
                if not entry:
                    break
                if '_HIDDEN_CHILD' in entry or 'COMPUTERNAME' in entry or 'USERNAME' in entry or 'APPDATA' in entry:
                    extracted_env.append(entry)
            if extracted_env:
                print(f"[!] Variabili Ambiente Figlio: {extracted_env}")
        except Exception:
            pass
    print("!" * 70 + "\n")

    # Attiva lo switch a Stage 2 (_HIDDEN_CHILD=1) nel processo corrente
    ql.hidden_child_spawned = True

    stage1_meta = (
        f"STAGE1_CREATEPROCESSW\n"
        f"ApplicationName: {app}\n"
        f"CommandLine: {cmd}\n"
        f"CreationFlags: {hex(flags)}\n"
        f"CurrentDirectory: {cur_dir}\n"
        f"Environment: {extracted_env}\n"
    ).encode('utf-8')
    dump_payload(stage1_meta, "Stage1_CreateProcessW_HiddenChild")

    if p_info and p_info != 0:
        fake_pi = struct.pack('<QQII', 0x1111, 0x2222, 1234, 5678)
        try:
            ql.mem.write(p_info, fake_pi)
            print(f"[+] PROCESS_INFORMATION popolato: hProcess=0x1111, hThread=0x2222, PID=1234, TID=5678")
        except Exception as e:
            print(f"[-] Errore scrittura PROCESS_INFORMATION: {e}")
    return 1

def hook_stage_transition(ql):
    """
    Hook chirurgico a 0x77dd94 (in main.setupHiddenProcess subito dopo call sysinfo.SetupHiddenProcess).
    Quando CreateProcessW ha creato il processo figlio nascosto (_HIDDEN_CHILD=1), SetupHiddenProcess
    ritorna RAX=1 (true), che normalmente causerebbe l'uscita del processo padre (os.Exit(0) a 0x77de40).
    Impostando RAX=0 qui, forziamo l'emulatore a proseguire direttamente nello Stage 2 (main payload)
    nello stesso processo senza terminare!
    """
    if getattr(ql, 'hidden_child_spawned', False):
        print("\n" + "=" * 70)
        print("[*] 🔄 [STAGE TRANSITION @ 0x77dd94] Bypass os.Exit(0) del processo padre!")
        print("[*] 🚀 Transizione diretta in-process dallo Stage 1 (Dropper) allo Stage 2 (Hidden Child Payload _HIDDEN_CHILD=1)!")
        print("=" * 70 + "\n")
        ql.arch.regs.rax = 0

@winsdkapi(cc=STDCALL, params={
    'hProcess': HANDLE,
    'lpAddress': POINTER,
    'dwSize': SIZE_T,
    'flAllocationType': DWORD,
    'flProtect': DWORD
})
def hook_VirtualAllocEx(ql, address, params):
    hProc = params['hProcess']
    size = params['dwSize']
    prot = params['flProtect']
    print(f"\n[!] 💉 ALLOCAZIONE NEL PROCESSO TARGET (VirtualAllocEx): Process={hex(hProc)}, Size={hex(size)}, Protect={hex(prot)}")
    return 0x20000000

@winsdkapi(cc=STDCALL, params={
    'ProcessHandle': HANDLE,
    'BaseAddress': POINTER,
    'ZeroBits': ULONG,
    'RegionSize': POINTER,
    'AllocationType': ULONG,
    'Protect': ULONG
})
def hook_NtAllocateVirtualMemory(ql, address, params):
    hProc = params['ProcessHandle']
    base_ptr = params['BaseAddress']
    size_ptr = params['RegionSize']
    req_size = 0x100000
    if size_ptr and size_ptr != 0:
        try:
            req_size = struct.unpack('<Q', ql.mem.read(size_ptr, 8))[0]
        except Exception:
            pass
    alloc_base = 0x20000000
    try:
        ql.mem.map(alloc_base, (req_size + 0xfff) & ~0xfff)
    except Exception:
        pass
    if base_ptr and base_ptr != 0:
        try:
            ql.mem.write(base_ptr, struct.pack('<Q', alloc_base))
        except Exception:
            pass
    print(f"\n[!] 💉 NtAllocateVirtualMemory: Proc={hex(hProc)}, Base={hex(alloc_base)}, Size={hex(req_size)}")
    return 0

@winsdkapi(cc=STDCALL, params={
    'hProcess': HANDLE,
    'lpBaseAddress': POINTER,
    'lpBuffer': POINTER,
    'nSize': SIZE_T,
    'lpNumberOfBytesWritten': POINTER
})
def hook_WriteProcessMemory(ql, address, params):
    base = params['lpBaseAddress']
    buf = params['lpBuffer']
    size = params['nSize']
    written_ptr = params['lpNumberOfBytesWritten']
    print("\n" + "=" * 70)
    print(f"[!] 💉 SCRITTURA NEL PROCESSO TARGET (WriteProcessMemory)!")
    print(f"[!] Destinazione: {hex(base)} | Dimensione buffer: {size} bytes")
    try:
        data = ql.mem.read(buf, size)
        dump_payload(bytes(data), "WriteProcessMemory")
    except Exception as e:
        print(f"[-] Errore lettura buffer di iniezione: {e}")
    print("=" * 70 + "\n")
    if written_ptr and written_ptr != 0:
        try:
            ql.mem.write(written_ptr, struct.pack('<Q', size))
        except Exception:
            pass
    return 1

@winsdkapi(cc=STDCALL, params={
    'ProcessHandle': HANDLE,
    'BaseAddress': POINTER,
    'Buffer': POINTER,
    'BufferSize': SIZE_T,
    'NumberOfBytesWritten': POINTER
})
def hook_NtWriteVirtualMemory(ql, address, params):
    base = params['BaseAddress']
    buf = params['Buffer']
    size = params['BufferSize']
    written_ptr = params['NumberOfBytesWritten']
    print("\n" + "=" * 70)
    print(f"[!] 💉 SCRITTURA NEL PROCESSO TARGET (NtWriteVirtualMemory)!")
    print(f"[!] Destinazione: {hex(base)} | Dimensione: {size} bytes")
    try:
        data = ql.mem.read(buf, size)
        dump_payload(bytes(data), "NtWriteVirtualMemory")
    except Exception as e:
        print(f"[-] Errore lettura buffer NtWriteVirtualMemory: {e}")
    print("=" * 70 + "\n")
    if written_ptr and written_ptr != 0:
        try:
            ql.mem.write(written_ptr, struct.pack('<Q', size))
        except Exception:
            pass
    return 0

@winsdkapi(cc=STDCALL, params={'hThread': HANDLE, 'lpContext': POINTER})
def hook_SetThreadContext(ql, address, params):
    hThread = params['hThread']
    lpContext = params['lpContext']
    print(f"\n[!] 💉 PROCESS HOLLOWING: SetThreadContext! Thread={hex(hThread)}, Context={hex(lpContext)}")
    return 1

@winsdkapi(cc=STDCALL, params={'hThread': HANDLE, 'lpContext': POINTER})
def hook_NtSetContextThread(ql, address, params):
    hThread = params['hThread']
    lpContext = params['lpContext']
    print(f"\n[!] 💉 PROCESS HOLLOWING: NtSetContextThread! Thread={hex(hThread)}, Context={hex(lpContext)}")
    return 0

@winsdkapi(cc=STDCALL, params={'hThread': HANDLE})
def hook_ResumeThread(ql, address, params):
    hThread = params['hThread']
    print("\n" + "=" * 70)
    print(f"[!] 🚀 PROCESS HOLLOWING COMPLETATO: ResumeThread sul thread {hex(hThread)}!")
    print("[*] Il malware ha risvegliato il processo con il payload iniettato.")
    print("=" * 70 + "\n")
    return 1

@winsdkapi(cc=STDCALL, params={'hThread': HANDLE, 'SuspendCount': POINTER})
def hook_NtResumeThread(ql, address, params):
    hThread = params['hThread']
    print("\n" + "=" * 70)
    print(f"[!] 🚀 PROCESS HOLLOWING: NtResumeThread sul thread {hex(hThread)}!")
    print("=" * 70 + "\n")
    return 0

# ==============================================================================
# GESTIONE CONSOLE & OUTPUT (kernel32.dll)
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    'hConsoleOutput': HANDLE,
    'lpBuffer': POINTER,
    'nNumberOfCharsToWrite': DWORD,
    'lpNumberOfCharsWritten': POINTER,
    'lpReserved': POINTER
})
def hook_WriteConsoleW(ql, address, params):
    h = params['hConsoleOutput']
    buf = params['lpBuffer']
    n_chars = params['nNumberOfCharsToWrite']
    out_written = params['lpNumberOfCharsWritten']
    try:
        raw = ql.mem.read(buf, n_chars * 2)
        text = raw.decode('utf-16le', errors='replace')
        print(f"\n[DEBUG/CONSOLE] 📟 WriteConsoleW (Handle={hex(h)}, Chars={n_chars}): \"{text}\"")
    except Exception as e:
        print(f"\n[DEBUG/CONSOLE] 📟 WriteConsoleW (Handle={hex(h)}, Chars={n_chars}) [Decode err: {e}]")
    if out_written and out_written != 0:
        try:
            ql.mem.write(out_written, struct.pack('<I', n_chars))
        except Exception:
            pass
    return 1

@winsdkapi(cc=STDCALL, params={
    'hConsoleOutput': HANDLE,
    'lpBuffer': POINTER,
    'nNumberOfCharsToWrite': DWORD,
    'lpNumberOfCharsWritten': POINTER,
    'lpReserved': POINTER
})
def hook_WriteConsoleA(ql, address, params):
    h = params['hConsoleOutput']
    buf = params['lpBuffer']
    n_chars = params['nNumberOfCharsToWrite']
    out_written = params['lpNumberOfCharsWritten']
    try:
        raw = ql.mem.read(buf, n_chars)
        text = raw.decode('latin1', errors='replace')
        print(f"\n[DEBUG/CONSOLE] 📟 WriteConsoleA (Handle={hex(h)}, Chars={n_chars}): \"{text}\"")
    except Exception as e:
        print(f"\n[DEBUG/CONSOLE] 📟 WriteConsoleA (Handle={hex(h)}, Chars={n_chars}) [Decode err: {e}]")
    if out_written and out_written != 0:
        try:
            ql.mem.write(out_written, struct.pack('<I', n_chars))
        except Exception:
            pass
    return 1

@winsdkapi(cc=STDCALL, params={'hFile': HANDLE})
def hook_FlushFileBuffers(ql, address, params):
    return 1

# ==============================================================================
# SETUP HOOKS & REGISTRAZIONE API
# ==============================================================================
def setup_hooks(ql):
    # Inizializza tracciamento IOCP, stato C2 ed eventi asincroni
    ql.last_iocp_key = 0
    ql.last_iocp_port = 0x50001
    ql.last_overlapped = 0
    ql.last_transferred_bytes = 0
    ql.overlapped_transferred = {}
    ql.iocp_events = []
    ql.hidden_child_spawned = False
    ql.c2_closing = False

    # Hook temporali
    ql.os.set_api("Sleep", hook_Sleep)
    ql.os.set_api("GetTickCount", hook_GetTickCount)
    ql.os.set_api("GetTickCount64", hook_GetTickCount64)
    ql.os.set_api("QueryPerformanceCounter", hook_QueryPerformanceCounter)
    ql.os.set_api("QueryPerformanceFrequency", hook_QueryPerformanceFrequency)
    ql.os.set_api("timeBeginPeriod", hook_timeBeginPeriod)
    ql.os.set_api("timeEndPeriod", hook_timeEndPeriod)

    # Fix per Crash, Anti-Evasion & Ricognizione Sistema (gopsutil)
    ql.os.set_api("GetErrorMode", hook_GetErrorMode)
    ql.os.set_api("WerGetFlagsWorker", hook_WerGetFlagsWorker)
    ql.os.set_api("WerSetFlagsWorker", hook_WerSetFlagsWorker)
    ql.os.set_api("AddVectoredContinueHandler", hook_AddVectoredContinueHandler)
    ql.os.set_api("CreateWaitableTimerExW", hook_CreateWaitableTimerExW)
    ql.os.set_api("SetWaitableTimer", hook_SetWaitableTimer)
    ql.os.set_api("CancelWaitableTimer", hook_CancelWaitableTimer)
    ql.os.set_api("GetProcessAffinityMask", hook_GetProcessAffinityMask)
    ql.os.set_api("SetProcessPriorityBoost", hook_SetProcessPriorityBoost)
    ql.os.set_api("SetConsoleCtrlHandler", hook_SetConsoleCtrlHandler)
    ql.os.set_api("NtCreateWaitCompletionPacket", hook_NtCreateWaitCompletionPacket)
    ql.os.set_api("GetSystemTimes", hook_GetSystemTimes)
    ql.os.set_api("NtQuerySystemInformation", hook_NtQuerySystemInformation)
    ql.os.set_api("ZwQuerySystemInformation", hook_NtQuerySystemInformation)
    ql.os.set_api("GlobalMemoryStatusEx", hook_GlobalMemoryStatusEx)
    ql.os.set_api("GetLogicalDriveStringsW", hook_GetLogicalDriveStringsW)
    ql.os.set_api("GetDriveTypeW", hook_GetDriveTypeW)
    ql.os.set_api("GetVolumeInformationW", hook_GetVolumeInformationW)
    ql.os.set_api("GetDiskFreeSpaceExW", hook_GetDiskFreeSpaceExW)
    ql.os.set_api("RtlGetVersion", hook_RtlGetVersion)
    ql.os.set_api("RtlGetCurrentPeb", hook_RtlGetCurrentPeb)
    ql.os.set_api("RegOpenKeyExW", hook_RegOpenKeyExW)
    ql.os.set_api("RegCreateKeyExW", hook_RegCreateKeyExW)
    ql.os.set_api("RegQueryValueExW", hook_RegQueryValueExW)
    ql.os.set_api("RegSetValueExW", hook_RegSetValueExW)
    ql.os.set_api("RegDeleteValueW", hook_RegDeleteValueW)
    ql.os.set_api("RegCloseKey", hook_RegCloseKey)
    ql.os.set_api("GetNativeSystemInfo", hook_GetNativeSystemInfo)
    ql.os.set_api("GetSystemInfo", hook_GetNativeSystemInfo)
    ql.os.set_api("EnumProcesses", hook_EnumProcesses)
    ql.os.set_api("K32EnumProcesses", hook_EnumProcesses)

    # NLS & Locale Suite (kernel32.dll)
    ql.os.set_api("GetUserDefaultLCID", hook_GetUserDefaultLCID)
    ql.os.set_api("GetSystemDefaultLCID", hook_GetSystemDefaultLCID)
    ql.os.set_api("GetUserDefaultLangID", hook_GetUserDefaultLangID)
    ql.os.set_api("GetSystemDefaultLangID", hook_GetSystemDefaultLangID)
    ql.os.set_api("GetUserDefaultUILanguage", hook_GetUserDefaultUILanguage)
    ql.os.set_api("GetSystemDefaultUILanguage", hook_GetSystemDefaultUILanguage)
    ql.os.set_api("GetThreadLocale", hook_GetThreadLocale)
    ql.os.set_api("SetThreadLocale", hook_SetThreadLocale)
    ql.os.set_api("IsValidLocale", hook_IsValidLocale)
    ql.os.set_api("GetUserDefaultLocaleName", hook_GetUserDefaultLocaleName)
    ql.os.set_api("GetSystemDefaultLocaleName", hook_GetSystemDefaultLocaleName)
    ql.os.set_api("GetLocaleInfoW", hook_GetLocaleInfoW)
    ql.os.set_api("GetLocaleInfoA", hook_GetLocaleInfoA)
    ql.os.set_api("GetUserGeoID", hook_GetUserGeoID)
    ql.os.set_api("GetGeoInfoW", hook_GetGeoInfoW)

    # Host Fingerprinting
    ql.os.set_api("GetComputerNameExW", hook_GetComputerNameExW)
    ql.os.set_api("GetComputerNameW", hook_GetComputerNameW)
    ql.os.set_api("GetComputerNameA", hook_GetComputerNameA)

    # Fix Privilege Escalation (advapi32.dll)
    ql.os.set_api("LookupPrivilegeValueW", hook_LookupPrivilegeValueW)
    ql.os.set_api("AdjustTokenPrivileges", hook_AdjustTokenPrivileges)
    ql.os.set_api("GetTokenInformation", hook_GetTokenInformation)

    # Fix Gestione Memoria (Allocatore a 64 Bit e Query Stack)
    ql.os.set_api("VirtualAlloc", hook_VirtualAlloc)
    ql.os.set_api("VirtualQuery", hook_VirtualQuery)

    # Hook File I/O, Metadati & Seeking (TrickBot Loader & RAT File Manager)
    ql.os.set_api("GetFileInformationByHandle", hook_GetFileInformationByHandle)
    ql.os.set_api("GetFileInformationByHandleEx", hook_GetFileInformationByHandleEx)
    ql.os.set_api("GetFileAttributesW", hook_GetFileAttributesW)
    ql.os.set_api("GetFileAttributesExW", hook_GetFileAttributesExW)
    ql.os.set_api("SetFilePointerEx", hook_SetFilePointerEx)
    ql.os.set_api("SetFilePointer", hook_SetFilePointer)
    ql.os.set_api("GetFileSizeEx", hook_GetFileSizeEx)
    ql.os.set_api("CreateFileW", hook_CreateFileW)
    ql.os.set_api("CreateFileA", hook_CreateFileA)
    ql.os.set_api("ReadFile", hook_ReadFile)
    ql.os.set_api("WriteFile", hook_WriteFile)
    ql.os.set_api("CreateDirectoryW", hook_CreateDirectoryW)
    ql.os.set_api("DeleteFileW", hook_DeleteFileW)
    ql.os.set_api("RemoveDirectoryW", hook_RemoveDirectoryW)
    ql.os.set_api("GetFileSize", hook_GetFileSize)
    ql.os.set_api("GetConsoleMode", hook_GetConsoleMode)
    ql.os.set_api("GetFileType", hook_GetFileType)
    ql.os.set_api("CloseHandle", hook_CloseHandle)

    # Hook I/O Completion Ports (kernel32.dll)
    ql.os.set_api("CreateIoCompletionPort", hook_CreateIoCompletionPort)
    ql.os.set_api("GetQueuedCompletionStatus", hook_GetQueuedCompletionStatus)
    ql.os.set_api("GetQueuedCompletionStatusEx", hook_GetQueuedCompletionStatusEx)
    ql.os.set_api("PostQueuedCompletionStatus", hook_PostQueuedCompletionStatus)
    ql.os.set_api("CancelIo", hook_CancelIo)
    ql.os.set_api("CancelIoEx", hook_CancelIoEx)

    # Hook Directory & Percorsi (kernel32.dll)
    ql.os.set_api("GetCurrentDirectoryW", hook_GetCurrentDirectoryW)
    ql.os.set_api("GetCurrentDirectoryA", hook_GetCurrentDirectoryA)
    ql.os.set_api("SetCurrentDirectoryW", hook_SetCurrentDirectoryW)
    ql.os.set_api("SetCurrentDirectoryA", hook_SetCurrentDirectoryA)
    ql.os.set_api("GetFullPathNameW", hook_GetFullPathNameW)
    ql.os.set_api("GetTempPath2W", hook_GetTempPath2W)
    ql.os.set_api("GetTempPath2A", hook_GetTempPath2A)
    ql.os.set_api("GetTempPathW", hook_GetTempPathW)
    ql.os.set_api("GetTempPathA", hook_GetTempPathA)
    ql.os.set_api("GetTempFileNameW", hook_GetTempFileNameW)
    ql.os.set_api("GetTempFileNameA", hook_GetTempFileNameA)
    ql.os.set_api("SearchPathW", hook_SearchPathW)
    ql.os.set_api("SearchPathA", hook_SearchPathA)

    # Hook Variabili d'Ambiente (kernel32.dll)
    ql.os.set_api("GetEnvironmentVariableW", hook_GetEnvironmentVariableW)
    ql.os.set_api("GetEnvironmentVariableA", hook_GetEnvironmentVariableA)
    ql.os.set_api("SetEnvironmentVariableW", hook_SetEnvironmentVariableW)
    ql.os.set_api("SetEnvironmentVariableA", hook_SetEnvironmentVariableA)

    # Hook STARTUPINFOEX & Process Attributes (kernel32.dll)
    ql.os.set_api("InitializeProcThreadAttributeList", hook_InitializeProcThreadAttributeList)
    ql.os.set_api("UpdateProcThreadAttribute", hook_UpdateProcThreadAttribute)
    ql.os.set_api("DeleteProcThreadAttributeList", hook_DeleteProcThreadAttributeList)

    # Hook Adattatori e Rete (iphlpapi.dll)
    ql.os.set_api("GetAdaptersAddresses", hook_GetAdaptersAddresses)
    ql.os.set_api("GetAdaptersInfo", hook_GetAdaptersInfo)
    ql.os.set_api("GetIfEntry", hook_GetIfEntry)
    ql.os.set_api("GetIfEntry2", hook_GetIfEntry2)
    ql.os.set_api("GetBestInterface", hook_GetBestInterface)
    ql.os.set_api("GetNetworkParams", hook_GetNetworkParams)

    # Hook Rete Winsock (ws2_32.dll)
    ql.os.set_api("WSAStartup", hook_WSAStartup)
    ql.os.set_api("WSACleanup", hook_WSACleanup)
    ql.os.set_api("WSAEnumProtocolsW", hook_WSAEnumProtocolsW)
    ql.os.set_api("SetFileCompletionNotificationModes", hook_SetFileCompletionNotificationModes)
    ql.os.set_api("WSAIoctl", hook_WSAIoctl)
    ql.os.set_api("WSASocketW", hook_WSASocketW)
    ql.os.set_api("WSASocketA", hook_WSASocketA)
    ql.os.set_api("socket", hook_socket)
    ql.os.set_api("closesocket", hook_closesocket)
    ql.os.set_api("bind", hook_bind)
    ql.os.set_api("listen", hook_listen)
    ql.os.set_api("accept", hook_accept)
    ql.os.set_api("WSAAccept", hook_WSAAccept)
    ql.os.set_api("ConnectEx", hook_ConnectEx_api)
    ql.os.set_api("connect", hook_connect)
    ql.os.set_api("WSAConnect", hook_WSAConnect)
    ql.os.set_api("send", hook_send)
    ql.os.set_api("WSASend", hook_WSASend)
    ql.os.set_api("recv", hook_recv)
    ql.os.set_api("WSARecv", hook_WSARecv)
    ql.os.set_api("getsockname", hook_getsockname)
    ql.os.set_api("getpeername", hook_getpeername)
    ql.os.set_api("ioctlsocket", hook_ioctlsocket)
    ql.os.set_api("setsockopt", hook_setsockopt)
    ql.os.set_api("getsockopt", hook_getsockopt)
    ql.os.set_api("WSAEventSelect", hook_WSAEventSelect)
    ql.os.set_api("WSAGetLastError", hook_WSAGetLastError)
    ql.os.set_api("WSASetLastError", hook_WSASetLastError)
    ql.os.set_api("shutdown", hook_shutdown)
    ql.os.set_api("gethostbyname", hook_gethostbyname)
    ql.os.set_api("gethostname", hook_gethostname)
    ql.os.set_api("GetAddrInfoW", hook_GetAddrInfoW)
    ql.os.set_api("GetAddrInfoA", hook_GetAddrInfoA)
    ql.os.set_api("FreeAddrInfoW", hook_FreeAddrInfoW)
    ql.os.set_api("freeaddrinfo", hook_freeaddrinfo)
    ql.os.set_api("WSAGetOverlappedResult", hook_WSAGetOverlappedResult)
    ql.os.set_api("GetOverlappedResult", hook_GetOverlappedResult)
    ql.os.set_api("WSACreateEvent", hook_WSACreateEvent)
    ql.os.set_api("WSACloseEvent", hook_WSACloseEvent)
    ql.os.set_api("WSAWaitForMultipleEvents", hook_WSAWaitForMultipleEvents)
    ql.os.set_api("WSAEnumNetworkEvents", hook_WSAEnumNetworkEvents)

    # Hook COM & OLE Automation (ole32.dll & oleaut32.dll)
    ql.os.set_api("CoInitialize", hook_CoInitialize)
    ql.os.set_api("CoInitializeEx", hook_CoInitializeEx)
    ql.os.set_api("CoUninitialize", hook_CoUninitialize)
    ql.os.set_api("CLSIDFromProgID", hook_CLSIDFromProgID)
    ql.os.set_api("CLSIDFromString", hook_CLSIDFromString)
    ql.os.set_api("ProgIDFromCLSID", hook_ProgIDFromCLSID)
    ql.os.set_api("CoCreateInstance", hook_CoCreateInstance)
    ql.os.set_api("CoCreateInstanceEx", hook_CoCreateInstanceEx)
    ql.os.set_api("CoSetProxyBlanket", hook_CoSetProxyBlanket)
    ql.os.set_api("StringFromCLSID", hook_StringFromCLSID)
    ql.os.set_api("StringFromGUID2", hook_StringFromGUID2)
    ql.os.set_api("CoTaskMemAlloc", hook_CoTaskMemAlloc)
    ql.os.set_api("CoTaskMemFree", hook_CoTaskMemFree)

    # BSTR & SafeArray Suite (oleaut32.dll)
    ql.os.set_api("SysAllocStringLen", hook_SysAllocStringLen)
    ql.os.set_api("SysAllocString", hook_SysAllocString)
    ql.os.set_api("SysAllocStringByteLen", hook_SysAllocStringByteLen)
    ql.os.set_api("SysFreeString", hook_SysFreeString)
    ql.os.set_api("SysStringLen", hook_SysStringLen)
    ql.os.set_api("SysStringByteLen", hook_SysStringByteLen)
    ql.os.set_api("VariantInit", hook_VariantInit)
    ql.os.set_api("VariantClear", hook_VariantClear)
    ql.os.set_api("VariantCopy", hook_VariantCopy)
    ql.os.set_api("VariantChangeType", hook_VariantChangeType)
    ql.os.set_api("SafeArrayCreate", hook_SafeArrayCreate)
    ql.os.set_api("SafeArrayDestroy", hook_SafeArrayDestroy)
    ql.os.set_api("SafeArrayGetUBound", hook_SafeArrayGetUBound)
    ql.os.set_api("SafeArrayGetLBound", hook_SafeArrayGetLBound)
    ql.os.set_api("SafeArrayAccessData", hook_SafeArrayAccessData)
    ql.os.set_api("SafeArrayUnaccessData", hook_SafeArrayUnaccessData)

    # 🌟 Setup Mock COM, VTable IDispatch e IEnumVARIANT (0x70005000 / 0x70006000)
    setup_com_mock(ql)

    # 🌟 Setup ConnectEx Trampoline (0x70003000) con RET (0xC3)
    map_dns_memory(ql)
    try:
        ql.mem.write(0x70003000, b'\xC3')
        ql.hook_address(hook_ConnectEx_trampoline, 0x70003000)
        print("[+] Setup ConnectEx Trampoline a 0x70003000 completato.")
    except Exception as e:
        print(f"[-] Errore setup ConnectEx trampoline: {e}")

    # Hook Console & Output (kernel32.dll)
    ql.os.set_api("WriteConsoleW", hook_WriteConsoleW)
    ql.os.set_api("WriteConsoleA", hook_WriteConsoleA)
    ql.os.set_api("FlushFileBuffers", hook_FlushFileBuffers)

    # Hook Multithreading
    ql.os.set_api("CreateThread", hook_CreateThread)
    ql.os.set_api("SuspendThread", hook_SuspendThread)
    ql.os.set_api("SetThreadPriority", hook_SetThreadPriority)
    ql.os.set_api("SwitchToThread", hook_SwitchToThread)

    # Mappatura continua 0x0 - 0x6000
    try:
        ql.mem.map(0x0, 0x6000)
        ql.mem.write(0x0, b'\xC3')
        ql.hook_address(hook_zero_address, 0x0)
    except Exception as e:
        print(f"[-] Errore nel setup della memoria bassa 0x0-0x6000: {e}")

    # Hook chirurgico routine di stack switch (0x47344e)
    try:
        ql.hook_address(hook_stack_switch, 0x47344e)
    except Exception as e:
        print(f"[-] Errore hook 0x47344e: {e}")

    # Hook entry point thread Go worker (0x475400)
    try:
        ql.hook_address(hook_tstart, 0x475400)
    except Exception as e:
        print(f"[-] Errore hook 0x475400: {e}")

    # Hook chirurgico bypass gcenable (0x417560)
    try:
        ql.hook_address(hook_gcenable, 0x417560)
    except Exception as e:
        print(f"[-] Errore hook 0x417560: {e}")

    # Hook chirurgico transizione Stage 1 -> Stage 2 in main.setupHiddenProcess (0x77dd94)
    try:
        ql.hook_address(hook_stage_transition, 0x77dd94)
        # Downgrade trasparente in-memory di https://api.ipify.org?format=json (33B) -> http://api.ipify.org/?format=json (33B)
        # per intercettare la query IP pubblico in chiaro senza handshake TLS
        ql.mem.write(0x842cb5, b"http://api.ipify.org/?format=json")
        # Bypass di os/signal.loop (0x53b240) con RET (0xC3) per evitare il panic 'signal_recv: inconsistent state' in single-thread
        ql.mem.write(0x53b240, b"\xC3")
    except Exception as e:
        print(f"[-] Errore hook 0x77dd94: {e}")

    # Inizializzazione pagina KUSER_SHARED_DATA (0x7ffe0000)
    try:
        ql.mem.write(0x7ffe0008, struct.pack('<Q', 10000000000))
        ql.mem.write(0x7ffe0014, struct.pack('<Q', 10000000000))
        ql.mem.write(0x7ffe0320, struct.pack('<I', 1000000))
    except Exception as e:
        print(f"[-] Errore inizializzazione KUSER_SHARED_DATA: {e}")

    # Intercettazione Iniezione Process Hollowing & Payload Dumper
    ql.os.set_api("CreateProcessA", hook_CreateProcessA)
    ql.os.set_api("CreateProcessW", hook_CreateProcessW)
    ql.os.set_api("VirtualAllocEx", hook_VirtualAllocEx)
    ql.os.set_api("NtAllocateVirtualMemory", hook_NtAllocateVirtualMemory)
    ql.os.set_api("WriteProcessMemory", hook_WriteProcessMemory)
    ql.os.set_api("NtWriteVirtualMemory", hook_NtWriteVirtualMemory)
    ql.os.set_api("ZwWriteVirtualMemory", hook_NtWriteVirtualMemory)
    ql.os.set_api("SetThreadContext", hook_SetThreadContext)
    ql.os.set_api("NtSetContextThread", hook_NtSetContextThread)
    ql.os.set_api("ResumeThread", hook_ResumeThread)
    ql.os.set_api("NtResumeThread", hook_NtResumeThread)

# ==============================================================================
# MAIN ENTRY POINT & INTERFACCIA CLI
# ==============================================================================
def _reset_runtime_globals(pe_path, output_dir):
    """Ripristina i contatori globali per garantire esecuzioni ripetibili e indipendenti."""
    global malware_exe_path, _output_dir
    global handle_auto_counter, tempo_simulato, simulated_qpc, nt_cpu_call_count
    global custom_event_counter, iocp_port_counter, current_working_dir, temp_file_counter
    global dns_mapped, socket_counter, bstr_pool_base, enum_query_count, payload_counter

    malware_exe_path = pe_path
    _output_dir = output_dir

    handle_auto_counter = 0xA0001000
    tempo_simulato = 0x1000
    simulated_qpc = 10000000
    nt_cpu_call_count = 0
    custom_event_counter = 0x4000
    iocp_port_counter = 0x50000
    current_working_dir = r"C:\Windows\Documenti\Source\TrickBot"
    temp_file_counter = 1000
    dns_mapped = False
    socket_counter = 0x8000
    bstr_pool_base = 0x70010000
    enum_query_count = 0
    payload_counter = 0


def avvia_analisi(pe_path, rootfs_path, output_dir=None, verbose_debug=False):
    pe_path = os.path.abspath(pe_path)
    rootfs_path = os.path.abspath(rootfs_path)
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))
    else:
        output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    _reset_runtime_globals(pe_path=pe_path, output_dir=output_dir)

    print("\n" + "=" * 75)
    print("[*] AVVIO ANALISI COMPLETA TRICKBOT (GO RAT: STAGE 1 + STAGE 2 + C2)")
    print(f"[*] Sample analizzato   : {os.path.basename(pe_path)}")
    print(f"[*] Target SHA-256      : {SAMPLE_SHA256}")
    print(f"[*] Rootfs Qiling       : {rootfs_path}")
    print(f"[*] Directory di output : {output_dir}")
    print("=" * 75 + "\n")

    # Rimuove eventuale client_id preesistente per osservare la generazione da zero
    client_id_host = os.path.join(
        rootfs_path, "Users", "Qiling", "AppData", "Roaming", "RemoteAdmin", "client_id"
    )
    if os.path.exists(client_id_host):
        try:
            os.remove(client_id_host)
        except Exception:
            pass

    try:
        log_level = QL_VERBOSE.DEBUG if verbose_debug else QL_VERBOSE.DEFAULT
        ql = Qiling([pe_path], rootfs_path, verbose=log_level)
        setup_hooks(ql)

        print("[*] Emulatore in ascolto. Esecuzione multi-stage e C2 WebSocket/Protobuf in corso...\n")
        ql.run()
        report_file = os.path.join(output_dir, "trickbot_c2_full_report.json")
        print("\n" + "=" * 75)
        print("[+] ESECUZIONE DEL MALWARE COMPLETATA CON SUCCESSO!")
        print(f"[+] Payload estratti salvati: {payload_counter} file in '{output_dir}' (trickbot_payload_*.bin)")
        print(f"[+] Report C2 completo salvato in: {report_file}")
        print("=" * 75 + "\n")

    except Exception as e:
        print(f"\n[!] Eccezione durante l'esecuzione: {e}")
        import traceback
        traceback.print_exc()


def _resolve_default_sample(base_dir, rootfs_path):
    """Ricerca il sample nei percorsi predefiniti per compatibilita' immediata."""
    cwd = os.getcwd()
    candidates = [
        os.path.join(base_dir, "Source", "TrickBot", "TrickBot.exe"),
        os.path.join(cwd, "Source", "TrickBot", "TrickBot.exe"),
        os.path.join(rootfs_path, "Windows", "Documenti", "Source", "TrickBot", "TrickBot.exe"),
        os.path.join(base_dir, "TrickBot.exe"),
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
    default_rootfs = os.path.abspath(os.path.join(base_dir, "..", ".."))

    parser = argparse.ArgumentParser(
        description=(
            "TrickBot (Go x86_64 RAT) Multi-Stage Anti-VM & WebSocket C2 Analyzer "
            f"[Target SHA-256: {SAMPLE_SHA256}]"
        )
    )
    parser.add_argument(
        "-s", "--sample",
        default=None,
        help="Percorso al sample TrickBot compilato in Go (PE32+ x86_64)",
    )
    parser.add_argument(
        "-r", "--rootfs",
        default=default_rootfs,
        help="Percorso al rootfs Windows x86_64 (64-bit) di Qiling (es. examples/rootfs/x8664_windows)",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=base_dir,
        help="Cartella di destinazione per i dump e il report JSON C2 (default: cartella dello script)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Imposta la verbosita' di Qiling a DEBUG (default: DEFAULT)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = args.sample if args.sample else _resolve_default_sample(base_dir, args.rootfs)

    if not os.path.isfile(sample_path):
        print(f"\n[-] Errore: Eseguibile malware non trovato in: {sample_path}")
        print(f"    Fornisci il campione (SHA-256: {SAMPLE_SHA256}) tramite:")
        print(f"    python {os.path.basename(__file__)} -s <percorso_sample> -r <percorso_rootfs_x8664_windows>\n")
        sys.exit(1)

    if not os.path.isdir(args.rootfs):
        print(f"\n[-] Errore: Directory rootfs di Qiling non trovata in: {args.rootfs}")
        print("    Specifica il rootfs x8664_windows con: -r <percorso_rootfs_x8664_windows>\n")
        sys.exit(1)

    try:
        entries_lower = [entry.lower() for entry in os.listdir(args.rootfs)]
        if "windows" not in entries_lower:
            print(
                f"[!] Avviso: La cartella 'Windows' non sembra presente in '{args.rootfs}'. "
                f"Se Qiling fallisce l'avvio, passa il percorso esplicito con -r <rootfs/x8664_windows>."
            )
    except OSError:
        pass

    avvia_analisi(
        pe_path=sample_path,
        rootfs_path=args.rootfs,
        output_dir=args.output_dir,
        verbose_debug=args.verbose,
    )
