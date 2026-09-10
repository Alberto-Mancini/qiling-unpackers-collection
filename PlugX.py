# -*- coding: utf-8 -*-
import os
import sys
import random
from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.api import *
from qiling.os.windows.fncc import *

# ==========================================
# CONFIGURAZIONE COMPORTAMENTO
# ==========================================
SIMULA_UTENTE_REALE = True
GET_TICK_REALISTIC = True
GET_CURSOR_REALISTIC = True
GET_WINDOW_REALISTIC = True
GET_COMPUTER_NAME_REALISTIC = True
GET_VOLUME_INFORMATION_REALISTIC = True

# ==========================================
# CONFIGURAZIONE TRACCIAMENTO ASSEMBLY
# ==========================================
TRACCIA_ASSEMBLY = True  # Imposta a True per accendere il tracciatore

# Filtri (per evitare che il terminale esploda di milioni di righe inutili)
# Se lasci 0x0 e 0xFFFFFFFF traccerà tutto.
INDIRIZZO_MIN = 0x4012e0  # Partiamo un po' prima della prima chiamata
INDIRIZZO_MAX = 0x4012f2  # Finiamo un bel po' dopo la seconda chiamata

# Quali istruzioni vogliamo spiare? (Vuoto [] = tutte)
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
            
            if mnemonic in ["cmp", "sub", "test"]:
                try:
                    eax = getattr(ql.arch.regs, 'eax', 0)
                    ebx = getattr(ql.arch.regs, 'ebx', 0)
                    ecx = getattr(ql.arch.regs, 'ecx', 0)
                    edx = getattr(ql.arch.regs, 'edx', 0)
                    print(f"      ---> [REGISTRI CPU] EAX: {hex(eax)} | EBX: {hex(ebx)} | ECX: {hex(ecx)} | EDX: {hex(edx)}")
                except:
                    pass 
    except Exception:
        pass 

# ==========================================
# INTERAZIONE UTENTE (VERI ANTI-VM)
# ==========================================
@winsdkapi(cc=STDCALL, params={'lpPoint': POINTER})
def hook_GetCursorPos(ql, address, params):
    x, y = anti_evasion.get_cursor()
    print(f"\n[ANTI-VM/USER] 🖱️ GetCursorPos richiesto -> Rispondo con (X: {x}, Y: {y})")
    ql.mem.write(params['lpPoint'], x.to_bytes(4, 'little', signed=True) + y.to_bytes(4, 'little', signed=True))
    return 1 # TRUE

@winsdkapi(cc=STDCALL, params={})
def hook_GetForegroundWindow(ql, address, params):
    hwnd = anti_evasion.get_window()
    print(f"\n[ANTI-VM/USER] 🪟 GetForegroundWindow richiesto -> Fornito HWND fittizio: {hex(hwnd)}")
    return hwnd

# ==========================================
# GESTIONE TEMPO (VERI ANTI-VM)
# ==========================================
@winsdkapi(cc=STDCALL, params={'dwMilliseconds': DWORD})
def hook_Sleep(ql, address, params):
    tempo_richiesto = params['dwMilliseconds']
    anti_evasion.tempo_in_sospeso += tempo_richiesto
    
    print("\n" + "="*60)
    print("⏱️ [DEBUG TEMPO] RILEVATO TENTATIVO DI PAUSA (Sleep)")
    print("="*60)
    print(f" [*] Il malware ha richiesto di aspettare per : {tempo_richiesto} ms")
    print(f" [+] L'esecuzione NON verra' interrotta. La funzione Sleep viene bypassata.")
    print(f" [+] Il valore di {tempo_richiesto} ms e' stato salvato in memoria.")
    print(f" [*] Totale accumulato in sospeso attuale   : {anti_evasion.tempo_in_sospeso} ms")
    print("     (Questo valore verra' sommato all'orologio al prossimo GetTickCount)")
    print("="*60 + "\n")
    
    return 0

@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    print("\n[ANTI-VM/TIMING] 🕒 Il malware ha chiamato GetTickCount. Calcolo in corso...")
    t = anti_evasion.get_tick()
    print(f"[ANTI-VM/TIMING] 🕒 GetTickCount completato -> Restituisco al malware: {t} ms")
    return t

@winsdkapi(cc=STDCALL, params={'lpPerformanceCount': POINTER})
def hook_QueryPerformanceCounter(ql, address, params):
    print("\n[ANTI-VM/TIMING] 🕒 Il malware ha chiamato QueryPerformanceCounter. Calcolo in corso...")
    t = anti_evasion.get_tick()
    print(f"[ANTI-VM/TIMING] 🕒 QueryPerformanceCounter completato -> Restituisco al malware: {t} ms")
    ql.mem.write(params['lpPerformanceCount'], t.to_bytes(8, 'little'))
    return 1 # TRUE

# ==========================================
# ANTI-DEBUGGING (VERI ANTI-ANALISI)
# ==========================================
@winsdkapi(cc=STDCALL, params={})
def hook_IsDebuggerPresent(ql, address, params):
    res = 0 if SIMULA_UTENTE_REALE else 1
    print(f"\n[ANTI-DEBUG] 🐛 IsDebuggerPresent chiamato -> Ritorno: {res} (0 = Nessun debugger)")
    return res

@winsdkapi(cc=STDCALL, params={'hProcess': HANDLE, 'pbDebuggerPresent': POINTER})
def hook_CheckRemoteDebuggerPresent(ql, address, params):
    res = 0 if SIMULA_UTENTE_REALE else 1
    print(f"\n[ANTI-DEBUG] 🐛 CheckRemoteDebuggerPresent chiamato -> Imposto la risposta a: {bool(res)}")
    ql.mem.write(params['pbDebuggerPresent'], res.to_bytes(1, 'little'))
    return 1 # TRUE

# ==========================================
# PROFILAZIONE DEL SISTEMA (NON ANTI-VM)
# ==========================================
@winsdkapi(cc=STDCALL, params={'nIndex': DWORD})
def hook_GetSystemMetrics(ql, address, params):
    index = params['nIndex']
    if index == 0: # SM_CXSCREEN
        val = 1920 if SIMULA_UTENTE_REALE else 800
        print(f"\n[PROFILING/ENV] 🖥️ GetSystemMetrics(Risoluzione X) -> Restituisco: {val}")
        return val
    elif index == 1: # SM_CYSCREEN
        val = 1080 if SIMULA_UTENTE_REALE else 600
        print(f"\n[PROFILING/ENV] 🖥️ GetSystemMetrics(Risoluzione Y) -> Restituisco: {val}")
        return val
    return 1

@winsdkapi(cc=STDCALL, params={
    'lpRootPathName': STRING,
    'lpVolumeNameBuffer': POINTER,
    'nVolumeNameSize': DWORD,
    'lpVolumeSerialNumber': POINTER,
    'lpMaximumComponentLength': POINTER,
    'lpFileSystemFlags': POINTER,
    'lpFileSystemNameBuffer': POINTER,
    'nFileSystemNameSize': DWORD
})
def hook_GetVolumeInformationA(ql, address, params):
    root_path = params['lpRootPathName']
    print(f"\n[PROFILING/INFO] 💾 GetVolumeInformationA. Il malware esplora il disco: {root_path}")
    if params['lpVolumeSerialNumber'] != 0:
        serial = anti_evasion.get_volume_serial()
        ql.mem.write(params['lpVolumeSerialNumber'], serial.to_bytes(4, 'little'))
        print(f" [*] Fornito Volume Serial Number: {hex(serial)}")
    return 1 # TRUE

@winsdkapi(cc=STDCALL, params={'lpBuffer': POINTER, 'lpnSize': POINTER})
def hook_GetComputerNameA(ql, address, params):
    comp_name = anti_evasion.get_computer_name()
    ql.mem.write(params['lpBuffer'], comp_name)
    ql.mem.write(params['lpnSize'], len(comp_name).to_bytes(4, 'little'))
    print(f"\n[PROFILING/INFO] 💻 GetComputerNameA richiesto -> Fornito nome PC: {comp_name.decode().strip(chr(0))}")
    return 1

@winsdkapi(cc=STDCALL, params={'lpBuffer': POINTER, 'pcbBuffer': POINTER})
def hook_GetUserNameA(ql, address, params):
    user_name = b"Admin\x00" if SIMULA_UTENTE_REALE else b"MalwareAnalyst\x00"
    ql.mem.write(params['lpBuffer'], user_name)
    ql.mem.write(params['pcbBuffer'], len(user_name).to_bytes(4, 'little'))
    print(f"\n[PROFILING/INFO] 👤 GetUserNameA richiesto -> Fornito utente: {user_name.decode().strip(chr(0))}")
    return 1

# ==========================================
# COMPORTAMENTO (FILE, REGISTRO, MEMORIA, PRIVILEGI)
# ==========================================
@winsdkapi(cc=STDCALL, params={'TokenHandle': HANDLE, 'SidToCheck': LPVOID, 'IsMember': POINTER})
def hook_CheckTokenMembership(ql, address, params):
    is_admin = 1 if SIMULA_UTENTE_REALE else 0
    print(f"\n[BEHAVIOR/PRIV] 🛡️ CheckTokenMembership (Privilegi di sistema). Diciamo al malware che Admin = {bool(is_admin)}")
    ql.mem.write(params['IsMember'], is_admin.to_bytes(4, 'little'))
    return 1 # TRUE

@winsdkapi(cc=STDCALL, params={})
def hook_IsUserAnAdmin(ql, address, params):
    is_admin = 1 if SIMULA_UTENTE_REALE else 0
    print(f"\n[BEHAVIOR/PRIV] 🛡️ IsUserAnAdmin chiamato. Ritorno: {bool(is_admin)}")
    return is_admin

@winsdkapi(cc=STDCALL, params={'lpSrc': STRING, 'lpDst': POINTER, 'nSize': DWORD})
def hook_ExpandEnvironmentStringsA(ql, address, params):
    src = params['lpSrc']
    print(f"\n[BEHAVIOR/ENV] 📝 Espansione variabili d'ambiente richiesta per: {src}")
    expanded = b"C:\\Users\\Admin\\AppData\\Local\\Temp\x00"
    if params['lpDst'] != 0:
        ql.mem.write(params['lpDst'], expanded[:params['nSize']])
    return len(expanded)

@winsdkapi(cc=STDCALL, params={'hKey': HANDLE, 'lpSubKey': STRING, 'ulOptions': DWORD, 'samDesired': DWORD, 'phkResult': POINTER})
def hook_RegOpenKeyExA(ql, address, params):
    subkey = params['lpSubKey']
    if subkey:
        print(f"\n[BEHAVIOR/REGISTRO] 🔑 Tentativo di accesso alla chiave: {subkey}")
        if any(x in subkey.lower() for x in ["vmware", "vbox", "virtualbox", "wine"]):
            print(f" [!] ATTENZIONE: Il malware sta cercando tracce di Macchine Virtuali nel registro!")
            if not SIMULA_UTENTE_REALE:
                return 0 
    return 2 # ERROR_FILE_NOT_FOUND

@winsdkapi(cc=STDCALL, params={'lpFileName': STRING, 'dwDesiredAccess': DWORD, 'dwShareMode': DWORD, 'lpSecurityAttributes': LPVOID, 'dwCreationDisposition': DWORD, 'dwFlagsAndAttributes': DWORD, 'hTemplateFile': HANDLE})
def hook_CreateFileA(ql, address, params):
    file_name = params['lpFileName']
    if file_name:
        print(f"\n[BEHAVIOR/FILE] 📁 CreateFileA su: {file_name}")
        if any(x in file_name.lower() for x in ["vbox", "vmware", "vmmouse", "vmtoolsd"]):
             print(f" [!] ATTENZIONE: Il malware cerca driver tipici delle VM ({file_name})!")
    return 0

@winsdkapi(cc=STDCALL, params={'lpAddress': LPVOID, 'dwSize': SIZE_T, 'flAllocationType': DWORD, 'flProtect': DWORD})
def hook_VirtualAlloc(ql, address, params):
    size = params['dwSize']
    prot = params['flProtect']
    prot_str = "PAGE_EXECUTE_READWRITE" if prot == 0x40 else hex(prot)
    print(f"\n[BEHAVIOR/MEMORIA] 🧠 VirtualAlloc chiamato. Il malware alloca memoria: Dim={hex(size)}, Protezione={prot_str}")
    return 0

@winsdkapi(cc=STDCALL, params={'hProcess': HANDLE, 'lpAddress': LPVOID, 'dwSize': SIZE_T, 'flAllocationType': DWORD, 'flProtect': DWORD})
def hook_VirtualAllocEx(ql, address, params):
    print(f"\n[BEHAVIOR/INJECTION] 💉 VirtualAllocEx. Possibile tentativo di code injection! Processo: {hex(params['hProcess'])}, Dim={hex(params['dwSize'])}")
    return 0

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
# FIX CRASH QILING (FILE I/O C RUNTIME)
# ==========================================
dummy_file_ptr = None

@winsdkapi(cc=CDECL, params={'filename': STRING, 'mode': STRING})
def hook_fopen(ql, address, params):
    global dummy_file_ptr
    filename = params['filename']
    mode = params['mode']
    print(f"\n[BEHAVIOR/FILE I/O] 📝 fopen (Apertura file): {filename} (Modalita': {mode})")
    
    if 'r' in mode:
        print(f" [!] Simulo che il file NON esista (lettura bloccata)")
        return 0
        
    if dummy_file_ptr is None:
        dummy_file_ptr = ql.os.heap.alloc(0x100)
    return dummy_file_ptr

@winsdkapi(cc=CDECL, params={'filename': STRING, 'mode': STRING, 'shflag': DWORD})
def hook_fsopen(ql, address, params):
    global dummy_file_ptr
    filename = params['filename']
    mode = params['mode']
    print(f"\n[BEHAVIOR/FILE I/O] 📝 _fsopen (Apertura file): {filename} (Modalita': {mode})")
    
    if 'r' in mode:
        print(f" [!] Simulo che il file NON esista (lettura bloccata)")
        return 0
        
    if dummy_file_ptr is None:
        dummy_file_ptr = ql.os.heap.alloc(0x100)
    return dummy_file_ptr

@winsdkapi(cc=CDECL, params={'stream': POINTER})
def hook_fclose(ql, address, params):
    print(f"\n[BEHAVIOR/FILE I/O] 📝 fclose (Chiusura file) bypassata correttamente.")
    return 0

@winsdkapi(cc=CDECL, params={'buffer': POINTER, 'size': SIZE_T, 'count': SIZE_T, 'stream': POINTER})
def hook_fwrite(ql, address, params):
    total_bytes = params['size'] * params['count']
    print(f"\n[BEHAVIOR/FILE I/O] ✍️ fwrite: Il malware sta cercando di scrivere {total_bytes} bytes su disco!")
    
    if total_bytes > 0:
        try:
            data = ql.mem.read(params['buffer'], total_bytes)
            with open("payload_intercettato.bin", "ab") as f:
                f.write(data)
            print(f" [+] DUMP COMPLETATO: {total_bytes} bytes esportati con successo in 'payload_intercettato.bin'")
        except Exception as e:
            print(f" [-] ERRORE durante l'esportazione del payload: {e}")
            
    return params['count']

def setup_advanced_hooks(ql):
    # Hook del tracciatore Assembly (viene registrato solo se TRACCIA_ASSEMBLY è True)
    if TRACCIA_ASSEMBLY:
        print("\n[!] ATTENZIONE: Tracciamento Assembly ATTIVATO. L'emulazione sara' molto piu' lenta.")
        ql.hook_code(hook_code_assembly)

    # User Interaction
    ql.os.set_api("GetCursorPos", hook_GetCursorPos)
    ql.os.set_api("GetForegroundWindow", hook_GetForegroundWindow)

    # Timing
    ql.os.set_api("Sleep", hook_Sleep)
    ql.os.set_api("GetTickCount", hook_GetTickCount)
    ql.os.set_api("QueryPerformanceCounter", hook_QueryPerformanceCounter)
    
    # Anti-Debug
    ql.os.set_api("IsDebuggerPresent", hook_IsDebuggerPresent)
    ql.os.set_api("CheckRemoteDebuggerPresent", hook_CheckRemoteDebuggerPresent)
    
    # Env Checks
    ql.os.set_api("GetSystemMetrics", hook_GetSystemMetrics)
    ql.os.set_api("GetVolumeInformationA", hook_GetVolumeInformationA)
    ql.os.set_api("GetComputerNameA", hook_GetComputerNameA)
    ql.os.set_api("GetUserNameA", hook_GetUserNameA)
    
    # Registry & Files
    ql.os.set_api("RegOpenKeyExA", hook_RegOpenKeyExA)
    ql.os.set_api("CreateFileA", hook_CreateFileA)
    
    # Memory & Injection
    ql.os.set_api("VirtualAlloc", hook_VirtualAlloc)
    ql.os.set_api("VirtualAllocEx", hook_VirtualAllocEx)
    
    # Privileges
    ql.os.set_api("CheckTokenMembership", hook_CheckTokenMembership)
    ql.os.set_api("IsUserAnAdmin", hook_IsUserAnAdmin)
    
    # Environment Strings
    ql.os.set_api("ExpandEnvironmentStringsA", hook_ExpandEnvironmentStringsA)
    
    # Fix Crashes & File I/O
    ql.os.set_api("sprintf", hook_sprintf)
    ql.os.set_api("fopen", hook_fopen)
    ql.os.set_api("_fsopen", hook_fsopen)
    ql.os.set_api("fclose", hook_fclose)
    ql.os.set_api("fwrite", hook_fwrite)

def avvia_analisi(pe_path, rootfs_path):
    print("\n" + "="*70)
    print(f"[*] AVVIO ANALISI AVANZATA: {os.path.basename(pe_path)}")
    print(f"[*] Modalità SIMULA_UTENTE_REALE = {SIMULA_UTENTE_REALE}")
    print("="*70 + "\n")
    
    try:
        temp_dir = os.path.join(rootfs_path, "Users", "Admin", "AppData", "Local", "Temp")
        os.makedirs(temp_dir, exist_ok=True)
        print(f"[+] Ambiente preparato. Creata cartella fittizia per i drop: {temp_dir}\n")
        
        ql = Qiling([pe_path], rootfs_path, verbose=QL_VERBOSE.DEFAULT)
        setup_advanced_hooks(ql)
        
        print("[*] Motore di emulazione avviato. In attesa del comportamento del malware...")
        print("[*] (Premi Ctrl+C per interrompere in qualsiasi momento)\n")
        
        ql.run() 
        
        print("\n[*] Esecuzione terminata correttamente.")

    except Exception as e:
        print(f"\n[!] Eccezione durante l'esecuzione: {e}")

if __name__ == "__main__":
    malware_path = os.path.join(os.getcwd(), "Source", "PlugX", "PlugXV0.exe")
    rootfs = os.path.join(os.getcwd(), "..", "..") 
    
    if not os.path.exists(malware_path):
        print(f"\n[-] Errore CRITICO: Eseguibile del malware non trovato.\n    Percorso cercato: {malware_path}\n")
        sys.exit(1)
        
    avvia_analisi(malware_path, rootfs)