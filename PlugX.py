# -*- coding: utf-8 -*-
import os
import sys
import re
import random

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.fncc import winsdkapi, STDCALL, CDECL
from qiling.os.windows.api import DWORD, POINTER, LPCWSTR, HMODULE, POINTER, LPSTR, HANDLE

# ==========================================
# HOOKS DI BASE E BYPASS ANTI-DEBUG/SANDBOX
# ==========================================

global_tick = 0x1000


@winsdkapi(cc=STDCALL, params={"lpLibFileName": POINTER})
def hook_LoadLibraryA(ql, address, params):
    try:
        lpLibFileName = params["lpLibFileName"]
        dll_name = ql.mem.string(lpLibFileName)
        print(f"[@][ATTENZIONE][API] LoadLibraryA: {dll_name}")
    except Exception:
        pass


@winsdkapi(cc=STDCALL, params={"lpLibFileName": LPCWSTR})
def hook_LoadLibraryW(ql, address, params):
    try:
        lpLibFileName = params["lpLibFileName"]
        dll_name = ql.mem.string(lpLibFileName, encoding="utf-16-le")
        print(f"[@][ATTENZIONE][API] LoadLibraryW: {dll_name}")
    except Exception:
        pass


@winsdkapi(cc=STDCALL, params={"lpFileName": POINTER})
def hook_CreateFileA(ql, address, params):
    try:
        lpFileName = params["lpFileName"]
        file_name = ql.mem.string(lpFileName)
        print(f"[@][ATTENZIONE][API] CreateFileA: {file_name}")
    except Exception:
        pass
    return 0x4000


@winsdkapi(cc=STDCALL, params={"lpFileName": POINTER})
def hook_CreateFileW(ql, address, params):
    try:
        lpFileName = params["lpFileName"]
        file_name = ql.mem.string(lpFileName, encoding="utf-16-le")
        print(f"[@][ATTENZIONE][API] CreateFileW: {file_name}")
    except Exception:
        pass
    return 0x4000

# ==========================================
# HOOK: Anti-debugging/sandboxing
# ==========================================

@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    global global_tick
    global_tick += 5000
    return global_tick


@winsdkapi(cc=STDCALL, params={"dwMilliseconds": DWORD})
def hook_Sleep(ql, address, params):
    return 0


@winsdkapi(cc=STDCALL, params={})
def hook_GetForegroundWindow(ql, address, params):
    return 0


@winsdkapi(cc=STDCALL, params={"lpPoint": POINTER})
def hook_GetCursorPos(ql, address, params):

    print(f"GetCursorPos chiamata da {hex(address)}")
    lpPoint = params["lpPoint"]

#    if lpPoint:
#        x = (500).to_bytes(4, byteorder='little', signed=True)
#        y = (300).to_bytes(4, byteorder='little', signed=True)

#        ql.mem.write(lpPoint, x)
#        ql.mem.write(lpPoint + 4, y)

    global global_tick
    lpPoint = params["lpPoint"]
    
    if lpPoint:
        x_val = random.randint(100, 1000).to_bytes(4, byteorder='little')
        y_val = random.randint(100, 1000).to_bytes(4, byteorder='little')
        ql.mem.write(lpPoint, x_val)
        ql.mem.write(lpPoint + 4, y_val)

    return 1

def my_callback(ql):
    regs = ql.arch.regs

    print("=" * 40)
    print("PC :", hex(regs.arch_pc))
    print("EAX:", hex(regs.eax))
    print("EBX:", hex(regs.ebx))
    print("ECX:", hex(regs.ecx))
    print("EDX:", hex(regs.edx))


# ==========================================
# HOOK: GetVolumeInformationA
# ==========================================

@winsdkapi(cc=STDCALL, params={
    "lpRootPathName": POINTER,
    "lpVolumeNameBuffer": LPSTR,
    "nVolumeNameSize": DWORD,
    "lpVolumeSerialNumber": POINTER,
    "lpMaximumComponentLength": POINTER,
    "lpFileSystemFlags": POINTER,
    "lpFileSystemNameBuffer": LPSTR,
    "nFileSystemNameSize": DWORD
})
def hook_GetVolumeInformationA(ql, address, params):
    print(f"[@][ATTENZIONE][API] GetVolumeInformationA chiamata e bypassata")

    if params["lpVolumeNameBuffer"] and params["nVolumeNameSize"] > 0:
        vol_name = b"System\x00"
        size_to_write = min(len(vol_name), params["nVolumeNameSize"])
        ql.mem.write(params["lpVolumeNameBuffer"], vol_name[:size_to_write])

    if params["lpVolumeSerialNumber"]:
        ql.mem.write(params["lpVolumeSerialNumber"], (0x12345678).to_bytes(4, byteorder='little'))

    if params["lpMaximumComponentLength"]:
        ql.mem.write(params["lpMaximumComponentLength"], (255).to_bytes(4, byteorder='little'))

    if params["lpFileSystemFlags"]:
        ql.mem.write(params["lpFileSystemFlags"], (0x00000002).to_bytes(4, byteorder='little'))

    if params["lpFileSystemNameBuffer"] and params["nFileSystemNameSize"] > 0:
        fs_name = b"NTFS\x00"
        size_to_write = min(len(fs_name), params["nFileSystemNameSize"])
        ql.mem.write(params["lpFileSystemNameBuffer"], fs_name[:size_to_write])

    return 1

@winsdkapi(cc=CDECL, params={'buffer': LPSTR, 'format': POINTER})
def hook_sprintf_safe(ql, address, params):
    buff = params['buffer']
    format_ptr = params['format']

    # 1. Lettura limitata (max 100 byte) per evitare il crash se manca il \x00
    try:
        fmt_bytes = ql.mem.read(format_ptr, 100)
        fmt = fmt_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
        print(f"[@][ATTENZIONE][API] sprintf chiamata: formato '{fmt}'")
    except Exception:
        fmt = "%X"
        print(f"[@][ATTENZIONE][API] sprintf: fallback stringa di formato")

    # 2. Lettura sicura degli argomenti dallo stack (cdecl)
    esp = ql.arch.regs.esp
    args = []
    try:
        args = [
            ql.mem.read_ptr(esp + 12),
            ql.mem.read_ptr(esp + 16),
            ql.mem.read_ptr(esp + 20)
        ]
    except Exception:
        pass

    arg_idx = 0

    def replacer(match):
        nonlocal arg_idx
        if arg_idx >= len(args):
            return ""
        
        val = args[arg_idx]
        arg_idx += 1
        spec = match.group(0)

        try:
            if 's' in spec:
                if val == 0:
                    return "(null)"
                s_bytes = ql.mem.read(val, 200)  # Lettura stringa sicura limitata
                return s_bytes.split(b'\x00')[0].decode('utf-8', errors='ignore')
            elif 'x' in spec or 'X' in spec or 'd' in spec or 'i' in spec or 'u' in spec:
                return spec % val
            elif 'c' in spec:
                return chr(val & 0xff)
        except Exception:
            pass
            
        return "0"

    # 3. Formattazione e scrittura controllata
    try:
        res = re.sub(r'%[0-9]*[a-zA-Z]', replacer, fmt)
        res_bytes = res.encode('utf-8') + b'\x00'
        ql.mem.write(buff, res_bytes)
        return len(res_bytes) - 1
    except Exception as e:
        safe_str = b"12345678\x00"
        ql.mem.write(buff, safe_str)
        return len(safe_str) - 1

# ==========================================
# HOOK: CheckTokenMembership (bypass amministratore)
# ==========================================

@winsdkapi(cc=STDCALL, params={
    "TokenHandle": HANDLE, # Il toekn dell'utente è richiesto in HANDLE dalla documentazione ufficiale di Microsoft
    "SidToCheck": POINTER,
    "IsMember": POINTER
})
def hook_CheckTokenMembership(ql, address, params): 
    print("[API] CheckTokenMembership bypassata: ti farò credere di essere Amministratore!")

    # params["IsMember"] contiene l'indirizzo di memoria dove il malware si aspetta la risposta.
    if params["IsMember"]:
        # Scriviamo in quella memoria il valore 1 (TRUE) per dirgli "Sì, fai parte del gruppo"
        ql.mem.write(params["IsMember"], (1).to_bytes(4, byteorder='little'))

    # L'API ritorna 1 in caso l'operazione di check sia andata a buon fine
    return 1

# ==========================================
# HOOK: ExpandEnvironmentStringsA
# ==========================================

@winsdkapi(cc=STDCALL, params={
    "lpSrc": POINTER,
    "lpDst": LPSTR,
    "nSize": DWORD
})
def hook_ExpandEnvironmentStringsA(ql, address, params):
    src = ql.mem.string(params["lpSrc"])
    print(f"[API] ExpandEnvironmentStringsA: Risolvo il percorso per {src}")

    # Sostituiamo le variabili più usate dai malware con percorsi fasulli
    res = src.upper()
    res = res.replace("%APPDATA%", "C:\\Users\\Admin\\AppData\\Roaming")
    res = res.replace("%TEMP%", "C:\\Users\\Admin\\AppData\\Local\\Temp")
    res = res.replace("%USERPROFILE%", "C:\\Users\\Admin")
    res = res.replace("%WINDIR%", "C:\\Windows")
    res = res.replace("%SYSTEMROOT%", "C:\\Windows")

    res_bytes = res.encode('utf-8') + b'\x00'

    # Se il buffer destinazione esiste ed è abbastanza grande, ci scriviamo dentro
    if params["lpDst"] and params["nSize"] >= len(res_bytes):
        ql.mem.write(params["lpDst"], res_bytes)
        return len(res_bytes)

    # Ritorna la grandezza necessaria
    return len(res_bytes)


 # ==========================================
# HOOK: RtlInitAnsiStringEx
# ==========================================
@winsdkapi(cc=STDCALL, params={
    "DestinationString": POINTER,
    "SourceString": POINTER
})
def hook_RtlInitAnsiStringEx(ql, address, params):
    src_ptr = params["SourceString"]
    dst_ptr = params["DestinationString"]

    if src_ptr == 0:
        # Se la stringa è vuota, azzeriamo la struttura (8 byte di zeri)
        ql.mem.write(dst_ptr, b'\x00' * 8)
    else:
        src = ql.mem.string(src_ptr)
        print(f"[API] RtlInitAnsiStringEx chiamata per: {src}")
        length = len(src)

        # Una ANSI_STRING è una struttura in C composta da 8 byte:
        # [2 byte: Lunghezza] [2 byte: MaxLunghezza] [4 byte: Puntatore al testo]
        ql.mem.write(dst_ptr, length.to_bytes(2, byteorder='little'))
        ql.mem.write(dst_ptr + 2, (length + 1).to_bytes(2, byteorder='little'))
        ql.mem.write(dst_ptr + 4, src_ptr.to_bytes(4, byteorder='little'))

    return 0 # 0 equivale a STATUS_SUCCESS in Windows

# ==========================================
# HOOK: CreateDirectory
# ==========================================
@winsdkapi(cc=STDCALL, params={
    "lpPathName": POINTER,
    "lpSecurityAttributes": POINTER
})
def hook_CreateDirectoryA(ql, address, params):
    path_ptr = params["lpPathName"]
    if path_ptr:
        path = ql.mem.string(path_ptr)
        print(f"[API] CreateDirectoryA bypassata. Il malware crede di aver creato: {path}")

    # 1 significa TRUE/Successo in Windows
    return 1

@winsdkapi(cc=STDCALL, params={
    "lpPathName": POINTER,
    "lpSecurityAttributes": POINTER
})
def hook_CreateDirectoryW(ql, address, params):
    path_ptr = params["lpPathName"]
    if path_ptr:
        # La versione W usa l'encoding utf-16-le
        path = ql.mem.string(path_ptr, encoding="utf-16-le")
        print(f"[API] CreateDirectoryW bypassata. Il malware crede di aver creato: {path}")

    return 1



# ==========================================
# HOOKS: Gestione File in C (fopen, fwrite, fclose)
# ==========================================

@winsdkapi(cc=CDECL, params={
    "filename": POINTER,
    "mode": POINTER
})
def hook_fopen(ql, address, params):
    fname_ptr = params["filename"]
    if fname_ptr:
        fname = ql.mem.string(fname_ptr)
        print(f"[API] fopen bypassata. Finto file aperto: '{fname}'")

    # Restituiamo un finto puntatore FILE*
    return 0x8888

@winsdkapi(cc=CDECL, params={
    "filename": POINTER,
    "mode": POINTER,
    "shflag": DWORD
})
def hook_fsopen(ql, address, params):
    fname_ptr = params["filename"]
    if fname_ptr:
        fname = ql.mem.string(fname_ptr)
        print(f"[API] _fsopen bypassata. Finto file aperto: '{fname}'")
    return 0x8888

@winsdkapi(cc=CDECL, params={
    "ptr": POINTER,      # Indirizzo in memoria dei dati da scrivere
    "size": DWORD,       # Grandezza di un blocco
    "count": DWORD,      # Numero di blocchi
    "stream": POINTER
})
def hook_fwrite(ql, address, params):
    ptr = params["ptr"]
    total_size = params["size"] * params["count"]

    if total_size > 0:
        # 1. Leggiamo i dati puri dalla memoria del malware
        dati_rubati = ql.mem.read(ptr, total_size)

        # 2. Li salviamo fisicamente sul nostro Linux!
        with open("payload_estratto.bin", "ab") as f:
            f.write(dati_rubati)

        print(f"[+] DUMP: Rubati {total_size} byte dal malware e salvati su disco!")

    return params["count"]

@winsdkapi(cc=CDECL, params={
    "stream": POINTER
})
def hook_fclose(ql, address, params):
    # 0 significa chiusura avvenuta senza errori
    return 0

# ==========================================
# Modulo principale di emulazione
# ==========================================

def avvia_emulazione_base(pe_path, rootfs_path):
    print("=" * 50)
    print(f"[*] Avvio Analisi Rapida: {os.path.basename(pe_path)}")
    print("=" * 50)

    try:
        ql = Qiling([pe_path], rootfs_path, verbose=QL_VERBOSE.DEBUG)

        # Registriamo gli hook essenziali
        ql.os.set_api("LoadLibraryA", hook_LoadLibraryA)
        ql.os.set_api("LoadLibraryW", hook_LoadLibraryW)
        ql.os.set_api("CreateFileA", hook_CreateFileA)
        ql.os.set_api("CreateFileW", hook_CreateFileW)

        # Hook per bypass anti-sandboxing
        ql.os.set_api("GetTickCount", hook_GetTickCount)
        ql.os.set_api("Sleep", hook_Sleep)
        ql.os.set_api("GetForegroundWindow", hook_GetForegroundWindow)
        ql.os.set_api("GetCursorPos", hook_GetCursorPos)


        

        # Hook custom avanzati per evitare i crash di PlugX
        ql.os.set_api("GetVolumeInformationA", hook_GetVolumeInformationA)
        ql.os.set_api("sprintf", hook_sprintf_safe)
        ql.os.set_api("CheckTokenMembership", hook_CheckTokenMembership)
        ql.os.set_api("ExpandEnvironmentStringsA", hook_ExpandEnvironmentStringsA)
        ql.os.set_api("RtlInitAnsiStringEx", hook_RtlInitAnsiStringEx)
        ql.os.set_api("CreateDirectoryA", hook_CreateDirectoryA)
        ql.os.set_api("CreateDirectoryW", hook_CreateDirectoryW)
        ql.os.set_api("fopen", hook_fopen)
        ql.os.set_api("_fsopen", hook_fsopen)
        ql.os.set_api("fwrite", hook_fwrite)
        ql.os.set_api("fclose", hook_fclose)

        print("[*] Esecuzione in corso")
        print("-" * 50)

        ql.run()

        print("-" * 50)
        print("[*] Esecuzione terminata con successo.")

    except Exception as e:
        pc = ql.arch.regs.arch_pc if 'ql' in locals() else 0
        print(f"\n[!] L'emulazione si è fermata:")
        print(f"    Motivo: {e}")
        print(f"    PC: 0x{pc:x}")


if __name__ == "__main__":
    malware_path = os.path.join(os.getcwd(), "Source", "PlugX", "PlugXV0.exe")
    rootfs = os.path.join(os.getcwd(), "..", "..")

    if not os.path.exists(malware_path):
        print(f"[-] Errore: File malware non trovato al percorso:")
        print(f"    {malware_path}")
        sys.exit(1)

    avvia_emulazione_base(malware_path, rootfs)