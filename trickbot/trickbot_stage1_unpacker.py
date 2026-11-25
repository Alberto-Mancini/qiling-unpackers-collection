"""
PlugX Stage-1 In-Memory Unpacker (LZNT1)
Leverages Qiling for targeted emulation to extract the decompressed payload.

"""
# -*- coding: utf-8 -*-
import os
import sys
import random
import time as time_mod
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# ==========================================
# CONFIGURAZIONE COMPORTAMENTO E STADIO
# ==========================================
# 1 = STADIO 1 (Analisi Dropper: esegue bypass Anti-VM, clona se stesso e dumperà il payload)
# 2 = STADIO 2 (Analisi Post-Riavvio: esegue il file droppato falsificando il path per attivare il RAT)
STADIO_ANALISI = 2

# Flag Anti-VM Generali
SIMULA_UTENTE_REALE = True
GET_TICK_REALISTIC = True
GET_CURSOR_REALISTIC = True
GET_WINDOW_REALISTIC = True
GET_COMPUTER_NAME_REALISTIC = True
GET_VOLUME_INFORMATION_REALISTIC = True

# ==========================================
# CONFIGURAZIONE TRACCIAMENTO ASSEMBLY
# ==========================================
TRACCIA_ASSEMBLY = False  
INDIRIZZO_MIN = 0x4012e0  
INDIRIZZO_MAX = 0x4012f2  
ISTRUZIONI_TARGET = [] 

class AntiEvasion:
    def __init__(self):
        self.tick = 0x1000
        self.cursor_x = 500
        self.cursor_y = 500
        self.window_handle = 0x10000
        self.tempo_in_sospeso = 0

    def get_tick(self):
        print("\n" + "="*60)
        print("🕒 [DEBUG TEMPO] AGGIORNAMENTO OROLOGIO INTERNO (get_tick)")
        print("="*60)
        print(f" [*] Uptime corrente prima della richiesta : {self.tick} ms")
        
        if SIMULA_UTENTE_REALE and GET_TICK_REALISTIC:
            print(f" [*] [Modalita' Realistica ON] Aggiungo 50 ms (simulazione CPU)")
            if self.tempo_in_sospeso > 0:
                print(f" [*] [Modalita' Realistica ON] Aggiungo in blocco {self.tempo_in_sospeso} ms (salvati dagli Sleep)")
            else:
                print(f" [*] Nessun tempo in sospeso da sommare.")
            
            self.tick += 50
            self.tick += self.tempo_in_sospeso
            self.tempo_in_sospeso = 0 
            
        else:
            print(f" [*] [Modalita' Realistica OFF] PROVOCAZIONE: Il tempo rimane fermo e congelato a {self.tick} ms.")
            self.tick += 0
            
        print(f" [+] RISULTATO FINALE: Uptime che verra' restituito = {self.tick} ms")
        print("="*60 + "\n")
            
        return self.tick

    def get_cursor(self):
        if SIMULA_UTENTE_REALE and GET_CURSOR_REALISTIC:
            self.cursor_x += random.randint(-15, 15)
            self.cursor_y += random.randint(-15, 15)
            return (self.cursor_x, self.cursor_y)
        else:
            return (0, 0)
            
    def get_window(self):
        if SIMULA_UTENTE_REALE and GET_WINDOW_REALISTIC:
            self.window_handle += 4
            return self.window_handle
        else:
            return 0

    def get_computer_name(self):
        if SIMULA_UTENTE_REALE and GET_COMPUTER_NAME_REALISTIC:
            return b"DESKTOP-OFFICE\x00"
        else:
            return b"CUCKOO-PC\x00"
            
    def get_volume_serial(self):
        if SIMULA_UTENTE_REALE and GET_VOLUME_INFORMATION_REALISTIC:
            return 0x9A2B3C4D
        else:
            return 0xDEADBEEF
    
anti_evasion = AntiEvasion()

# ==========================================
# TRACCIATORE ASSEMBLY DINAMICO
# ==========================================
def hook_code_assembly(ql, address, size):
    if not (INDIRIZZO_MIN <= address <= INDIRIZZO_MAX):
        return
    try:
        buf = ql.mem.read(address, size)
        for i in ql.arch.disassembler.disasm(buf, address):
            mnemonic = i.mnemonic.lower()
            if len(ISTRUZIONI_TARGET) > 0 and mnemonic not in ISTRUZIONI_TARGET:
                return
            print(f"[ASM] 0x{address:X}:\t{i.mnemonic.ljust(6)} {i.op_str}")
    except Exception:
        pass 

# ==========================================
# INTERAZIONE UTENTE E TEMPO (ANTI-VM)
# ==========================================
@winsdkapi(cc=STDCALL, params={'lpPoint': POINTER})
def hook_GetCursorPos(ql, address, params):
    x, y = anti_evasion.get_cursor()
    print(f"\n[ANTI-VM/USER] 🖱️ GetCursorPos richiesto -> Rispondo con (X: {x}, Y: {y})")
    ql.mem.write(params['lpPoint'], x.to_bytes(4, 'little', signed=True) + y.to_bytes(4, 'little', signed=True))
    return 1

@winsdkapi(cc=STDCALL, params={})
def hook_GetForegroundWindow(ql, address, params):
    hwnd = anti_evasion.get_window()
    print(f"\n[ANTI-VM/USER] 🪟 GetForegroundWindow richiesto -> Fornito HWND fittizio: {hex(hwnd)}")
    return hwnd

@winsdkapi(cc=STDCALL, params={'dwMilliseconds': DWORD})
def hook_Sleep(ql, address, params):
    tempo_richiesto = params['dwMilliseconds']
    anti_evasion.tempo_in_sospeso += tempo_richiesto
    print(f"\n⏱ [DEBUG TEMPO] Salvati {tempo_richiesto} ms (Sleep bypassato).")
    return 0

@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    t = anti_evasion.get_tick()
    return t

# ==========================================
# PROFILAZIONE DEL SISTEMA & PRIVILEGI
# ==========================================
@winsdkapi(cc=STDCALL, params={'nIndex': DWORD})
def hook_GetSystemMetrics(ql, address, params):
    index = params['nIndex']
    if index == 0: return 1920 if SIMULA_UTENTE_REALE else 800
    elif index == 1: return 1080 if SIMULA_UTENTE_REALE else 600
    return 1

@winsdkapi(cc=STDCALL, params={
    'lpRootPathName': STRING, 'lpVolumeNameBuffer': POINTER, 'nVolumeNameSize': DWORD,
    'lpVolumeSerialNumber': POINTER, 'lpMaximumComponentLength': POINTER, 'lpFileSystemFlags': POINTER,
    'lpFileSystemNameBuffer': POINTER, 'nFileSystemNameSize': DWORD
})
def hook_GetVolumeInformationA(ql, address, params):
    print(f"\n[PROFILING/INFO] 💾 GetVolumeInformationA: {params['lpRootPathName']}")
    if params['lpVolumeSerialNumber'] != 0:
        serial = anti_evasion.get_volume_serial()
        ql.mem.write(params['lpVolumeSerialNumber'], serial.to_bytes(4, 'little'))
    return 1

@winsdkapi(cc=STDCALL, params={'hModule': HANDLE, 'lpFilename': POINTER, 'nSize': DWORD})
def hook_GetModuleFileNameA(ql, address, params):
    fake_path = b"C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe\x00"
    ql.mem.write(params['lpFilename'], fake_path)
    print(f"\n[BEHAVIOR/EVASION] 🕵️ GetModuleFileNameA falsato! (STADIO 2) Il malware crede di essere in: {fake_path.decode()}")
    return len(fake_path) - 1

@winsdkapi(cc=STDCALL, params={'lpBuffer': POINTER, 'lpnSize': POINTER})
def hook_GetComputerNameA(ql, address, params):
    comp_name = anti_evasion.get_computer_name()
    ql.mem.write(params['lpBuffer'], comp_name)
    ql.mem.write(params['lpnSize'], len(comp_name).to_bytes(4, 'little'))
    return 1

@winsdkapi(cc=STDCALL, params={})
def hook_IsUserAnAdmin(ql, address, params):
    return 1 if SIMULA_UTENTE_REALE else 0

@winsdkapi(cc=STDCALL, params={'lpSrc': STRING, 'lpDst': POINTER, 'nSize': DWORD})
def hook_ExpandEnvironmentStringsA(ql, address, params):
    src = params['lpSrc']
    expanded = b"C:\\Users\\Admin\\AppData\\Local\\Temp\x00"
    if params['lpDst'] != 0:
        ql.mem.write(params['lpDst'], expanded[:params['nSize']])
    return len(expanded)

# Fix per il crash durante lo spacchettamento (PECompact2)
@winsdkapi(cc=STDCALL, params={'lpBuffer': POINTER, 'uSize': UINT})
def hook_GetSystemWow64DirectoryA(ql, address, params):
    syswow64_path = b"C:\\Windows\\SysWOW64\x00"
    size = params['uSize']
    if params['lpBuffer'] != 0:
        ql.mem.write(params['lpBuffer'], syswow64_path[:size])
    print(f"\n[DEBUG/FIX] 📂 GetSystemWow64DirectoryA richiesto dal packer -> Fornito: {syswow64_path.decode('utf-8')}")
    return len(syswow64_path) - 1

# ==========================================
# [NOVITÀ] API TEMPORALI (MSVCRT)
# ==========================================
@winsdkapi(cc=CDECL, params={'timer': POINTER})
def hook_time(ql, address, params):
    t = int(time_mod.time())
    if params['timer'] != 0:
        ql.mem.write(params['timer'], t.to_bytes(4, 'little'))
    print(f"\n[DEBUG/FIX] ⏱️ API time richiamata -> Restituito {t}")
    return t

@winsdkapi(cc=CDECL, params={'timer': POINTER})
def hook_time32(ql, address, params):
    return hook_time(ql, address, params)

# ==========================================
# COMPORTAMENTO: INJECTION & PROCESS HOLLOWING
# ==========================================
@winsdkapi(cc=STDCALL, params={
    'lpApplicationName': STRING, 'lpCommandLine': STRING, 'lpProcessAttributes': POINTER,
    'lpThreadAttributes': POINTER, 'bInheritHandles': BOOL, 'dwCreationFlags': DWORD,
    'lpEnvironment': POINTER, 'lpCurrentDirectory': STRING, 'lpStartupInfo': POINTER,
    'lpProcessInformation': POINTER
})
def hook_CreateProcessA(ql, address, params):
    app_name = params['lpApplicationName']
    cmd_line = params['lpCommandLine']
    flags = params['dwCreationFlags']
    
    print("\n" + "="*60)
    print("🚀 [BEHAVIOR/INJECTION] CreateProcessA chiamato!")
    print(f" [*] Eseguibile target: {app_name}")
    print(f" [*] Riga di comando: {cmd_line}")
    if flags & 0x4: 
        print(" [!] ATTENZIONE: Il processo target e' stato avviato in stato SOSPESO.")
        print("     Questa e' la fase 1 del Process Hollowing!")
    print("="*60)
    return 1 

@winsdkapi(cc=STDCALL, params={'hProcess': HANDLE, 'lpAddress': LPVOID, 'dwSize': SIZE_T, 'flAllocationType': DWORD, 'flProtect': DWORD})
def hook_VirtualAllocEx(ql, address, params):
    size = params['dwSize']
    print(f"\n[BEHAVIOR/INJECTION] 🧠 VirtualAllocEx: Allocazione remota di {hex(size)} bytes.")
    return 0x20000000 

@winsdkapi(cc=STDCALL, params={'hProcess': HANDLE, 'lpBaseAddress': LPVOID, 'lpBuffer': POINTER, 'nSize': SIZE_T, 'lpNumberOfBytesWritten': POINTER})
def hook_WriteProcessMemory(ql, address, params):
    size = params['nSize']
    dest_addr = params['lpBaseAddress']
    
    print("\n" + "="*60)
    print("💉 [BEHAVIOR/INJECTION] WriteProcessMemory chiamato!")
    print(f" [*] Il malware sta scrivendo {size} bytes all'indirizzo {hex(dest_addr)} del processo sospeso.")
    
    if size > 0:
        try:
            data = ql.mem.read(params['lpBuffer'], size)
            dump_name = f"payload_dump_{hex(dest_addr)}.bin"
            with open(dump_name, "wb") as f:
                f.write(data)
            print(f" [+] DUMP COMPLETATO: Payload esportato con successo in '{dump_name}'")
        except Exception as e:
            print(f" [-] ERRORE durante il dump della memoria: {e}")
            
    print("="*60)
    return 1 

@winsdkapi(cc=STDCALL, params={'hThread': HANDLE})
def hook_ResumeThread(ql, address, params):
    print("\n🏃‍♂️ [BEHAVIOR/INJECTION] ResumeThread chiamato!")
    print(" [!] Il malware ha riattivato il thread. L'infezione del nuovo processo e' ora LIVE!")
    return 1

# ==========================================
# FIX CRASH QILING (STRING FORMATTING)
# ==========================================
@winsdkapi(cc=CDECL, params={'buffer': POINTER, 'format': STRING})
def hook_sprintf(ql, address, params):
    fmt = params['format']
    print(f"\n[DEBUG/FIX] 📝 sprintf (Format string) bypassato: {fmt}")
    dummy_str = b"DUMMY_FORMATTED_STRING\x00"
    ql.mem.write(params['buffer'], dummy_str)
    return len(dummy_str) - 1

# ==========================================
# FIX CRASH QILING (FILE I/O C RUNTIME) - CUSTOM VFS
# ==========================================
file_buffers = {}
file_cursors = {}

@winsdkapi(cc=CDECL, params={'filename': STRING, 'mode': STRING})
def hook_fopen(ql, address, params):
    filename = params['filename']
    mode = params['mode']
    print(f"\n[BEHAVIOR/FILE I/O] 📝 fopen: {filename} (Mode: {mode})")
    
    ptr = ql.os.heap.alloc(0x1000)
    
    if STADIO_ANALISI == 1:
        if 'r' in mode and 'MediaCenter.exe' in filename:
            print(" [!] [STADIO 1] Il malware verifica se e' gia' installato. Rispondo: NON ESISTE (0x0)")
            return 0
            
        if 'PlugXV0.exe' in filename:
            try:
                real_path = os.path.join(os.getcwd(), "Source", "PlugX", "PlugXV0.exe")
                with open(real_path, 'rb') as f:
                    file_buffers[ptr] = f.read()
                file_cursors[ptr] = 0
                print(f" [+] File originale caricato per estrazione ({len(file_buffers[ptr])} bytes).")
            except Exception as e:
                file_buffers[ptr] = b""
                file_cursors[ptr] = 0
        else:
            file_buffers[ptr] = b""
            file_cursors[ptr] = 0
            
    elif STADIO_ANALISI == 2:
        if 'MediaCenter.exe' in filename or 'PlugXV0.exe' in filename or 'dropped_payload' in filename:
            try:
                real_path = os.path.join(os.getcwd(), "dropped_payload_0x5014f15.bin") 
                with open(real_path, 'rb') as f:
                    file_buffers[ptr] = f.read()
                file_cursors[ptr] = 0
                print(f" [+] File droppato caricato per esecuzione POST-RIAVVIO ({len(file_buffers[ptr])} bytes).")
            except Exception as e:
                file_buffers[ptr] = b""
                file_cursors[ptr] = 0
        else:
            file_buffers[ptr] = b""
            file_cursors[ptr] = 0
            
    return ptr

@winsdkapi(cc=CDECL, params={'filename': STRING, 'mode': STRING, 'shflag': DWORD})
def hook_fsopen(ql, address, params):
    return hook_fopen(ql, address, params)

@winsdkapi(cc=CDECL, params={'stream': POINTER, 'offset': INT, 'origin': INT})
def hook_fseek(ql, address, params):
    stream = params['stream']
    offset = params['offset']
    origin = params['origin'] 
    
    if stream in file_cursors:
        if origin == 0:
            file_cursors[stream] = offset
        elif origin == 1:
            file_cursors[stream] += offset
        elif origin == 2:
            file_cursors[stream] = len(file_buffers[stream]) + offset
        print(f" [DEBUG FILE] fseek -> Cursore spostato a {file_cursors[stream]}")
        return 0
    return -1

@winsdkapi(cc=CDECL, params={'buffer': POINTER, 'size': SIZE_T, 'count': SIZE_T, 'stream': POINTER})
def hook_fread(ql, address, params):
    stream = params['stream']
    dest_buffer = params['buffer']
    total_bytes = params['size'] * params['count']
    
    if stream in file_cursors:
        pos = file_cursors[stream]
        data_to_read = file_buffers[stream][pos : pos + total_bytes]
        ql.mem.write(dest_buffer, data_to_read)
        file_cursors[stream] += len(data_to_read)
        print(f" [DEBUG FILE] fread -> Letti {len(data_to_read)} bytes")
        
        if params['size'] == 0: 
            return 0
        return int(len(data_to_read) / params['size'])
    return 0

@winsdkapi(cc=CDECL, params={'buffer': POINTER, 'size': SIZE_T, 'count': SIZE_T, 'stream': POINTER})
def hook_fwrite(ql, address, params):
    stream = params['stream']
    src_buffer = params['buffer']
    total_bytes = params['size'] * params['count']
    
    print(f"\n[BEHAVIOR/FILE I/O] ✍️ fwrite -> Il malware sta scrivendo {total_bytes} bytes su file!")
    
    if total_bytes > 0:
        try:
            data = ql.mem.read(src_buffer, total_bytes)
            dump_name = f"dropped_payload_{hex(stream)}.bin"
            with open(dump_name, "ab") as f:
                f.write(data)
            print(f" [+] EXPLOIT! DUMP COMPLETATO: File droppato salvato su disco come '{dump_name}'")
        except Exception as e:
            print(f" [-] ERRORE durante il dump fwrite: {e}")
            
    if params['size'] == 0:
        return 0
    return params['count']

@winsdkapi(cc=CDECL, params={'stream': POINTER})
def hook_ftell(ql, address, params):
    stream = params['stream']
    if stream in file_cursors:
        return file_cursors[stream]
    return -1

@winsdkapi(cc=CDECL, params={'stream': POINTER})
def hook_fclose(ql, address, params):
    return 0

@winsdkapi(cc=CDECL, params={'file': POINTER})
def hook_lock(ql, address, params):
    return 0

@winsdkapi(cc=CDECL, params={'file': POINTER})
def hook_unlock(ql, address, params):
    return 0

# ==========================================
# COMPORTAMENTO: RETE & COMMAND AND CONTROL (C2)
# ==========================================
@winsdkapi(cc=STDCALL, params={'wVersionRequired': WORD, 'lpWSAData': POINTER})
def hook_WSAStartup(ql, address, params):
    print("\n[BEHAVIOR/NETWORK] 🌐 WSAStartup: Il malware sta inizializzando le librerie di rete!")
    return 0 

@winsdkapi(cc=STDCALL, params={'name': STRING})
def hook_gethostbyname(ql, address, params):
    domain = params['name']
    print(f"\n[BEHAVIOR/NETWORK] 🚨 gethostbyname: Tentativo di risoluzione DNS per il dominio C2: {domain}")
    return 0 

@winsdkapi(cc=STDCALL, params={'lpszAgent': STRING, 'dwAccessType': DWORD, 'lpszProxy': STRING, 'lpszProxyBypass': STRING, 'dwFlags': DWORD})
def hook_InternetOpenA(ql, address, params):
    agent = params['lpszAgent']
    print(f"\n[BEHAVIOR/NETWORK] 🌐 InternetOpenA: Preparazione connessione HTTP (User-Agent: {agent})")
    return 0x12345678 

@winsdkapi(cc=STDCALL, params={'hInternet': HANDLE, 'lpszServerName': STRING, 'nServerPort': DWORD, 'lpszUserName': STRING, 'lpszPassword': STRING, 'dwService': DWORD, 'dwFlags': DWORD, 'dwContext': DWORD})
def hook_InternetConnectA(ql, address, params):
    server = params['lpszServerName']
    port = params['nServerPort']
    print("\n" + "="*60)
    print(f"🔥 [BEHAVIOR/C2] InternetConnectA: Il RAT sta contattando il server attaccante!")
    print(f" [*] Server C2 Target : {server}")
    print(f" [*] Porta            : {port}")
    print("="*60)
    return 0x87654321

def setup_advanced_hooks(ql):
    if TRACCIA_ASSEMBLY:
        print("\n[!] ATTENZIONE: Tracciamento Assembly ATTIVATO. L'emulazione sara' molto piu' lenta.")
        ql.hook_code(hook_code_assembly)

    # API Hooks generali
    ql.os.set_api("GetCursorPos", hook_GetCursorPos)
    ql.os.set_api("GetForegroundWindow", hook_GetForegroundWindow)
    ql.os.set_api("Sleep", hook_Sleep)
    ql.os.set_api("GetTickCount", hook_GetTickCount)
    ql.os.set_api("GetSystemMetrics", hook_GetSystemMetrics)
    ql.os.set_api("GetVolumeInformationA", hook_GetVolumeInformationA)
    ql.os.set_api("GetComputerNameA", hook_GetComputerNameA)
    ql.os.set_api("IsUserAnAdmin", hook_IsUserAnAdmin)
    ql.os.set_api("ExpandEnvironmentStringsA", hook_ExpandEnvironmentStringsA)
    ql.os.set_api("sprintf", hook_sprintf)
    
    # API Temporali (MSVCRT)
    ql.os.set_api("time", hook_time)
    ql.os.set_api("_time32", hook_time32)
    
    # Path Evasion (Simulazione Riavvio)
    if STADIO_ANALISI == 2:
        ql.os.set_api("GetModuleFileNameA", hook_GetModuleFileNameA)
    
    # Fix per Packer (PECompact2 / SysWOW64)
    ql.os.set_api("GetSystemWow64DirectoryA", hook_GetSystemWow64DirectoryA)
    
    # Process Hollowing Hooks 
    ql.os.set_api("CreateProcessA", hook_CreateProcessA)
    ql.os.set_api("VirtualAllocEx", hook_VirtualAllocEx)
    ql.os.set_api("WriteProcessMemory", hook_WriteProcessMemory)
    ql.os.set_api("ResumeThread", hook_ResumeThread)
    
    # File I/O Fixes (Custom VFS)
    ql.os.set_api("fopen", hook_fopen)
    ql.os.set_api("_fsopen", hook_fsopen)
    ql.os.set_api("fseek", hook_fseek)
    ql.os.set_api("fread", hook_fread)
    ql.os.set_api("fwrite", hook_fwrite)
    ql.os.set_api("ftell", hook_ftell)
    ql.os.set_api("fclose", hook_fclose)
    ql.os.set_api("_lock", hook_lock)
    ql.os.set_api("_unlock", hook_unlock)

    # Network Hooks
    ql.os.set_api("WSAStartup", hook_WSAStartup)
    ql.os.set_api("gethostbyname", hook_gethostbyname)
    ql.os.set_api("InternetOpenA", hook_InternetOpenA)
    ql.os.set_api("InternetConnectA", hook_InternetConnectA)

def avvia_analisi(pe_path, rootfs_path):
    print("\n" + "="*70)
    print(f"[*] AVVIO ANALISI AVANZATA: {os.path.basename(pe_path)}")
    print(f"[*] Esecuzione in STADIO: {STADIO_ANALISI}")
    print("="*70 + "\n")
    
    try:
        # [NOVITÀ] Creiamo le cartelle vitali richieste dal packer/malware
        temp_dir = os.path.join(rootfs_path, "Users", "Admin", "AppData", "Local", "Temp")
        syswow64_dir = os.path.join(rootfs_path, "Windows", "SysWOW64")
        os.makedirs(temp_dir, exist_ok=True)
        os.makedirs(syswow64_dir, exist_ok=True)
        
        ql = Qiling([pe_path], rootfs_path, verbose=QL_VERBOSE.DEFAULT)
        setup_advanced_hooks(ql)
        
        print("[*] Motore di emulazione avviato. In attesa del comportamento del malware...\n")
        ql.run() 
        print("\n[*] Esecuzione terminata correttamente.")

    except Exception as e:
        print(f"\n[!] Eccezione durante l'esecuzione: {e}")

if __name__ == "__main__":
    rootfs = os.path.join(os.getcwd(), "..", "..") 
    
    if STADIO_ANALISI == 1:
        malware_path = os.path.join(os.getcwd(), "Source", "PlugX", "PlugXV0.exe")
    else:
        malware_path = os.path.join(os.getcwd(), "dropped_payload_0x5014f15.bin") 
    
    if not os.path.exists(malware_path):
        print(f"\n[-] Errore CRITICO: Eseguibile del malware non trovato.\n    Percorso cercato: {malware_path}\n")
        sys.exit(1)
        
    avvia_analisi(malware_path, rootfs)