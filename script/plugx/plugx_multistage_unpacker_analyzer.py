# -*- coding: utf-8 -*-
"""
PlugX - Multi-Stage Anti-Evasion Unpacker & Post-Reboot Analyzer
================================================================
Harness di emulazione dinamica basato su Qiling Framework per l'analisi
completa dei due stadi del campione PlugX (dropper iniziale + payload
persistente protetto da PECompact2).

Metadati del Campione Target (per riproducibilita'):
  - Famiglia  : PlugX (loader/offuscamento XOR condiviso con Sakula/ScanBox)
  - SHA-256   : 7362590eec1693d6ead5f274aa546f276bcc6939962f195eb997fcd57f02be02
  - Fonte     : MalwareBazaar
  - Formato   : PE32 (x86 32-bit, C/C++); Stadio 2 compresso con PECompact2
  - Ambiente  : Qiling Framework (testato su v1.4.6) con rootfs Windows x86 (32-bit)

Modalita' operative (--stage):
  - STADIO 1 (--stage 1, default): Analisi del dropper iniziale.
      1. Supera l'alterazione temporale accumulando i millisecondi richiesti a
         Sleep() e sommandoli in GetTickCount().
      2. Simula la presenza di un operatore umano variando le coordinate di
         GetCursorPos() (+/-15 px) e fornendo handle crescenti non nulli in
         GetForegroundWindow().
      3. Falsifica il controllo di pre-infezione (lettura di MediaCenter.exe -> 0)
         e intercetta tramite Custom VFS (fopen/fseek/fread/fwrite) la decifratura
         e il salvataggio su disco del secondo stadio completo (74.358 byte).
  - STADIO 2 (--stage 2): Analisi post-riavvio del secondo stadio estratto.
      1. Falsifica GetModuleFileNameA() simulando l'avvio dal percorso di
         persistenza atteso (C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe).
      2. Intercetta l'inizializzazione di rete e il contatto HTTP verso il server
         C2 (camuffato con User-Agent Internet Explorer 8).
      3. Fornisce il percorso C:\\Windows\\SysWOW64 richiesto dal compressore
         PECompact2 e monitora eventuali API di Process Hollowing.

Utilizzo:
  # Fase 1: Estrazione del secondo stadio dal sample iniziale
  python plugx_multistage_unpacker_analyzer.py --stage 1 -s <sample_plugx> -r <rootfs_x86_windows>

  # Fase 2: Analisi post-riavvio sul payload appena estratto
  python plugx_multistage_unpacker_analyzer.py --stage 2 -s <dropped_payload.bin> -r <rootfs_x86_windows>
"""

import argparse
import glob
import os
import random
import sys
import time as time_mod

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.api import (
    BOOL,
    DWORD,
    HANDLE,
    INT,
    LPVOID,
    POINTER,
    SIZE_T,
    STRING,
    UINT,
    WORD,
)
from qiling.os.windows.fncc import CDECL, STDCALL, winsdkapi

# ==============================================================================
# METADATI E CONFIGURAZIONE COMPORTAMENTO / STADIO
# ==============================================================================
SAMPLE_SHA256 = "7362590eec1693d6ead5f274aa546f276bcc6939962f195eb997fcd57f02be02"

# 1 = STADIO 1 (Analisi Dropper: bypass Anti-VM ed estrazione secondo stadio via VFS)
# 2 = STADIO 2 (Analisi Post-Riavvio: falsificazione path di persistenza e cattura C2)
STADIO_ANALISI = 1

# Flag Anti-VM Generali
SIMULA_UTENTE_REALE = True
GET_TICK_REALISTIC = True
GET_CURSOR_REALISTIC = True
GET_WINDOW_REALISTIC = True
GET_COMPUTER_NAME_REALISTIC = True
GET_VOLUME_INFORMATION_REALISTIC = True

# ==============================================================================
# CONFIGURAZIONE TRACCIAMENTO ASSEMBLY OPZIONALE
# ==============================================================================
TRACCIA_ASSEMBLY = False
INDIRIZZO_MIN = 0x004012E0
INDIRIZZO_MAX = 0x004012F2
ISTRUZIONI_TARGET = []

# Percorsi runtime gestiti dal motore per garantire portabilita' su qualsiasi nome file
_active_sample_path = ""
_output_dir = os.path.dirname(os.path.abspath(__file__))
_initialized_dumps = set()
_last_dropped_files = []


class AntiEvasion:
    """Gestisce lo stato coerente delle risposte ambientali simulate (orologio, input, host)."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.tick = 0x1000
        self.cursor_x = 500
        self.cursor_y = 500
        self.window_handle = 0x10000
        self.tempo_in_sospeso = 0

    def get_tick(self):
        print("\n" + "=" * 60)
        print("🕒 [DEBUG TEMPO] AGGIORNAMENTO OROLOGIO INTERNO (get_tick)")
        print("=" * 60)
        print(f" [*] Uptime corrente prima della richiesta : {self.tick} ms")

        if SIMULA_UTENTE_REALE and GET_TICK_REALISTIC:
            print(" [*] [Modalita' Realistica ON] Aggiungo 50 ms (simulazione CPU)")
            if self.tempo_in_sospeso > 0:
                print(
                    f" [*] [Modalita' Realistica ON] Aggiungo in blocco "
                    f"{self.tempo_in_sospeso} ms (salvati dagli Sleep)"
                )
            else:
                print(" [*] Nessun tempo in sospeso da sommare.")

            self.tick += 50
            self.tick += self.tempo_in_sospeso
            self.tempo_in_sospeso = 0
        else:
            print(
                f" [*] [Modalita' Realistica OFF] PROVOCAZIONE: "
                f"Il tempo rimane fermo e congelato a {self.tick} ms."
            )
            self.tick += 0

        print(f" [+] RISULTATO FINALE: Uptime che verra' restituito = {self.tick} ms")
        print("=" * 60 + "\n")

        return self.tick

    def get_cursor(self):
        if SIMULA_UTENTE_REALE and GET_CURSOR_REALISTIC:
            self.cursor_x += random.randint(-15, 15)
            self.cursor_y += random.randint(-15, 15)
            return (self.cursor_x, self.cursor_y)
        return (0, 0)

    def get_window(self):
        if SIMULA_UTENTE_REALE and GET_WINDOW_REALISTIC:
            self.window_handle += 4
            return self.window_handle
        return 0

    def get_computer_name(self):
        if SIMULA_UTENTE_REALE and GET_COMPUTER_NAME_REALISTIC:
            return b"DESKTOP-OFFICE\x00"
        return b"CUCKOO-PC\x00"

    def get_volume_serial(self):
        if SIMULA_UTENTE_REALE and GET_VOLUME_INFORMATION_REALISTIC:
            return 0x9A2B3C4D
        return 0xDEADBEEF


anti_evasion = AntiEvasion()


# ==============================================================================
# TRACCIATORE ASSEMBLY DINAMICO
# ==============================================================================
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


# ==============================================================================
# INTERAZIONE UTENTE E TEMPO (ANTI-VM / ANTI-SANDBOX)
# ==============================================================================
@winsdkapi(cc=STDCALL, params={"lpPoint": POINTER})
def hook_GetCursorPos(ql, address, params):
    x, y = anti_evasion.get_cursor()
    print(f"\n[ANTI-VM/USER] 🖱️ GetCursorPos richiesto -> Rispondo con (X: {x}, Y: {y})")
    ql.mem.write(
        params["lpPoint"],
        x.to_bytes(4, "little", signed=True) + y.to_bytes(4, "little", signed=True),
    )
    return 1


@winsdkapi(cc=STDCALL, params={})
def hook_GetForegroundWindow(ql, address, params):
    hwnd = anti_evasion.get_window()
    print(f"\n[ANTI-VM/USER] 🪟 GetForegroundWindow richiesto -> Fornito HWND fittizio: {hex(hwnd)}")
    return hwnd


@winsdkapi(cc=STDCALL, params={"dwMilliseconds": DWORD})
def hook_Sleep(ql, address, params):
    tempo_richiesto = params["dwMilliseconds"]
    anti_evasion.tempo_in_sospeso += tempo_richiesto
    print(f"\n⏱ [DEBUG TEMPO] Salvati {tempo_richiesto} ms (Sleep bypassato).")
    return 0


@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    return anti_evasion.get_tick()


# ==============================================================================
# PROFILAZIONE DEL SISTEMA & PRIVILEGI
# ==============================================================================
@winsdkapi(cc=STDCALL, params={"nIndex": DWORD})
def hook_GetSystemMetrics(ql, address, params):
    index = params["nIndex"]
    if index == 0:
        return 1920 if SIMULA_UTENTE_REALE else 800
    elif index == 1:
        return 1080 if SIMULA_UTENTE_REALE else 600
    return 1


@winsdkapi(cc=STDCALL, params={
    "lpRootPathName": STRING,
    "lpVolumeNameBuffer": POINTER,
    "nVolumeNameSize": DWORD,
    "lpVolumeSerialNumber": POINTER,
    "lpMaximumComponentLength": POINTER,
    "lpFileSystemFlags": POINTER,
    "lpFileSystemNameBuffer": POINTER,
    "nFileSystemNameSize": DWORD,
})
def hook_GetVolumeInformationA(ql, address, params):
    print(f"\n[PROFILING/INFO] 💾 GetVolumeInformationA: {params['lpRootPathName']}")
    if params["lpVolumeSerialNumber"] != 0:
        serial = anti_evasion.get_volume_serial()
        ql.mem.write(params["lpVolumeSerialNumber"], serial.to_bytes(4, "little"))
    return 1


@winsdkapi(cc=STDCALL, params={"hModule": HANDLE, "lpFilename": POINTER, "nSize": DWORD})
def hook_GetModuleFileNameA(ql, address, params):
    fake_path = b"C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe\x00"
    ql.mem.write(params["lpFilename"], fake_path)
    print(
        f"\n[BEHAVIOR/EVASION] 🕵️ GetModuleFileNameA falsato! (STADIO 2) "
        f"Il malware crede di essere in: {fake_path[:-1].decode()}"
    )
    return len(fake_path) - 1


@winsdkapi(cc=STDCALL, params={"lpBuffer": POINTER, "lpnSize": POINTER})
def hook_GetComputerNameA(ql, address, params):
    comp_name = anti_evasion.get_computer_name()
    ql.mem.write(params["lpBuffer"], comp_name)
    ql.mem.write(params["lpnSize"], len(comp_name).to_bytes(4, "little"))
    return 1


@winsdkapi(cc=STDCALL, params={})
def hook_IsUserAnAdmin(ql, address, params):
    return 1 if SIMULA_UTENTE_REALE else 0


@winsdkapi(cc=STDCALL, params={"lpSrc": STRING, "lpDst": POINTER, "nSize": DWORD})
def hook_ExpandEnvironmentStringsA(ql, address, params):
    expanded = b"C:\\Users\\Admin\\AppData\\Local\\Temp\x00"
    if params["lpDst"] != 0:
        ql.mem.write(params["lpDst"], expanded[: params["nSize"]])
    return len(expanded)


@winsdkapi(cc=STDCALL, params={"lpBuffer": POINTER, "uSize": UINT})
def hook_GetSystemWow64DirectoryA(ql, address, params):
    """Fornisce il percorso SysWOW64 richiesto durante lo spacchettamento PECompact2."""
    syswow64_path = b"C:\\Windows\\SysWOW64\x00"
    size = params["uSize"]
    if params["lpBuffer"] != 0:
        ql.mem.write(params["lpBuffer"], syswow64_path[:size])
    print(
        f"\n[DEBUG/FIX] 📂 GetSystemWow64DirectoryA richiesto dal packer -> "
        f"Fornito: {syswow64_path[:-1].decode('utf-8')}"
    )
    return len(syswow64_path) - 1


# ==============================================================================
# API TEMPORALI C RUNTIME (MSVCRT)
# ==============================================================================
@winsdkapi(cc=CDECL, params={"timer": POINTER})
def hook_time(ql, address, params):
    t = int(time_mod.time())
    if params["timer"] != 0:
        ql.mem.write(params["timer"], t.to_bytes(4, "little"))
    print(f"\n[DEBUG/FIX] ⏱️ API time richiamata -> Restituito {t}")
    return t


@winsdkapi(cc=CDECL, params={"timer": POINTER})
def hook_time32(ql, address, params):
    return hook_time(ql, address, params)


# ==============================================================================
# COMPORTAMENTO: INJECTION & PROCESS HOLLOWING
# ==============================================================================
@winsdkapi(cc=STDCALL, params={
    "lpApplicationName": STRING,
    "lpCommandLine": STRING,
    "lpProcessAttributes": POINTER,
    "lpThreadAttributes": POINTER,
    "bInheritHandles": BOOL,
    "dwCreationFlags": DWORD,
    "lpEnvironment": POINTER,
    "lpCurrentDirectory": STRING,
    "lpStartupInfo": POINTER,
    "lpProcessInformation": POINTER,
})
def hook_CreateProcessA(ql, address, params):
    app_name = params["lpApplicationName"]
    cmd_line = params["lpCommandLine"]
    flags = params["dwCreationFlags"]

    print("\n" + "=" * 60)
    print("🚀 [BEHAVIOR/INJECTION] CreateProcessA chiamato!")
    print(f" [*] Eseguibile target: {app_name}")
    print(f" [*] Riga di comando: {cmd_line}")
    if flags & 0x4:
        print(" [!] ATTENZIONE: Il processo target e' stato avviato in stato SOSPESO.")
        print("     Questa e' la fase 1 del Process Hollowing!")
    print("=" * 60)
    return 1


@winsdkapi(cc=STDCALL, params={
    "hProcess": HANDLE,
    "lpAddress": LPVOID,
    "dwSize": SIZE_T,
    "flAllocationType": DWORD,
    "flProtect": DWORD,
})
def hook_VirtualAllocEx(ql, address, params):
    size = params["dwSize"]
    print(f"\n[BEHAVIOR/INJECTION] 🧠 VirtualAllocEx: Allocazione remota di {hex(size)} bytes.")
    return 0x20000000


@winsdkapi(cc=STDCALL, params={
    "hProcess": HANDLE,
    "lpBaseAddress": LPVOID,
    "lpBuffer": POINTER,
    "nSize": SIZE_T,
    "lpNumberOfBytesWritten": POINTER,
})
def hook_WriteProcessMemory(ql, address, params):
    size = params["nSize"]
    dest_addr = params["lpBaseAddress"]

    print("\n" + "=" * 60)
    print("💉 [BEHAVIOR/INJECTION] WriteProcessMemory chiamato!")
    print(f" [*] Il malware sta scrivendo {size} bytes all'indirizzo {hex(dest_addr)} del processo sospeso.")

    if size > 0:
        try:
            data = ql.mem.read(params["lpBuffer"], size)
            dump_path = os.path.join(_output_dir, f"payload_dump_{hex(dest_addr)}.bin")
            with open(dump_path, "wb") as f:
                f.write(data)
            print(f" [+] DUMP COMPLETATO: Payload esportato con successo in '{dump_path}'")
        except Exception as e:
            print(f" [-] ERRORE durante il dump della memoria: {e}")

    print("=" * 60)
    return 1


@winsdkapi(cc=STDCALL, params={"hThread": HANDLE})
def hook_ResumeThread(ql, address, params):
    print("\n🏃‍♂️ [BEHAVIOR/INJECTION] ResumeThread chiamato!")
    print(" [!] Il malware ha riattivato il thread. L'infezione del nuovo processo e' ora LIVE!")
    return 1


# ==============================================================================
# FIX CRASH QILING (STRING FORMATTING)
# ==============================================================================
@winsdkapi(cc=CDECL, params={"buffer": POINTER, "format": STRING})
def hook_sprintf(ql, address, params):
    fmt = params["format"]
    print(f"\n[DEBUG/FIX] 📝 sprintf (Format string) bypassato: {fmt}")
    dummy_str = b"DUMMY_FORMATTED_STRING\x00"
    ql.mem.write(params["buffer"], dummy_str)
    return len(dummy_str) - 1


# ==============================================================================
# FILE I/O C RUNTIME - CUSTOM VIRTUAL FILE SYSTEM (VFS)
# ==============================================================================
file_buffers = {}
file_cursors = {}


def _reset_vfs_state(pe_path, output_dir):
    global _active_sample_path, _output_dir
    _active_sample_path = pe_path
    _output_dir = output_dir
    file_buffers.clear()
    file_cursors.clear()
    _initialized_dumps.clear()
    _last_dropped_files.clear()
    anti_evasion.reset()


@winsdkapi(cc=CDECL, params={"filename": STRING, "mode": STRING})
def hook_fopen(ql, address, params):
    filename = params["filename"] or ""
    mode = params["mode"] or ""
    print(f"\n[BEHAVIOR/FILE I/O] 📝 fopen: {filename} (Mode: {mode})")

    ptr = ql.os.heap.alloc(0x1000)
    sample_basename = os.path.basename(_active_sample_path).lower() if _active_sample_path else ""
    filename_lower = filename.lower()

    if STADIO_ANALISI == 1:
        if "r" in mode and "mediacenter.exe" in filename_lower:
            print(" [!] [STADIO 1] Il malware verifica se e' gia' installato. Rispondo: NON ESISTE (0x0)")
            return 0

        if "plugxv0.exe" in filename_lower or (sample_basename and sample_basename in filename_lower):
            try:
                with open(_active_sample_path, "rb") as f:
                    file_buffers[ptr] = f.read()
                file_cursors[ptr] = 0
                print(f" [+] File originale caricato per estrazione ({len(file_buffers[ptr])} bytes).")
            except Exception:
                file_buffers[ptr] = b""
                file_cursors[ptr] = 0
        else:
            file_buffers[ptr] = b""
            file_cursors[ptr] = 0

    elif STADIO_ANALISI == 2:
        if (
            "mediacenter.exe" in filename_lower
            or "plugxv0.exe" in filename_lower
            or "dropped_payload" in filename_lower
            or (sample_basename and sample_basename in filename_lower)
        ):
            try:
                with open(_active_sample_path, "rb") as f:
                    file_buffers[ptr] = f.read()
                file_cursors[ptr] = 0
                print(f" [+] File droppato caricato per esecuzione POST-RIAVVIO ({len(file_buffers[ptr])} bytes).")
            except Exception:
                file_buffers[ptr] = b""
                file_cursors[ptr] = 0
        else:
            file_buffers[ptr] = b""
            file_cursors[ptr] = 0

    return ptr


@winsdkapi(cc=CDECL, params={"filename": STRING, "mode": STRING, "shflag": DWORD})
def hook_fsopen(ql, address, params):
    return hook_fopen(ql, address, params)


@winsdkapi(cc=CDECL, params={"stream": POINTER, "offset": INT, "origin": INT})
def hook_fseek(ql, address, params):
    stream = params["stream"]
    offset = params["offset"]
    origin = params["origin"]

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


@winsdkapi(cc=CDECL, params={"buffer": POINTER, "size": SIZE_T, "count": SIZE_T, "stream": POINTER})
def hook_fread(ql, address, params):
    stream = params["stream"]
    dest_buffer = params["buffer"]
    total_bytes = params["size"] * params["count"]

    if stream in file_cursors:
        pos = file_cursors[stream]
        data_to_read = file_buffers[stream][pos : pos + total_bytes]
        ql.mem.write(dest_buffer, data_to_read)
        file_cursors[stream] += len(data_to_read)
        print(f" [DEBUG FILE] fread -> Letti {len(data_to_read)} bytes")

        if params["size"] == 0:
            return 0
        return int(len(data_to_read) / params["size"])
    return 0


@winsdkapi(cc=CDECL, params={"buffer": POINTER, "size": SIZE_T, "count": SIZE_T, "stream": POINTER})
def hook_fwrite(ql, address, params):
    stream = params["stream"]
    src_buffer = params["buffer"]
    total_bytes = params["size"] * params["count"]

    print(f"\n[BEHAVIOR/FILE I/O] ✍️ fwrite -> Il malware sta scrivendo {total_bytes} bytes su file!")

    if total_bytes > 0:
        try:
            data = ql.mem.read(src_buffer, total_bytes)
            dump_name = f"dropped_payload_{hex(stream)}.bin"
            dump_path = os.path.join(_output_dir, dump_name)

            # Tronca eventuali residui di esecuzioni precedenti al primo write sullo stream,
            # poi appende eventuali blocchi successivi nella stessa esecuzione.
            write_mode = "ab" if dump_path in _initialized_dumps else "wb"
            _initialized_dumps.add(dump_path)
            if dump_path not in _last_dropped_files:
                _last_dropped_files.append(dump_path)

            with open(dump_path, write_mode) as f:
                f.write(data)
            print(f" [+] DUMP COMPLETATO: File droppato salvato su disco come '{dump_path}'")
        except Exception as e:
            print(f" [-] ERRORE durante il dump fwrite: {e}")

    if params["size"] == 0:
        return 0
    return params["count"]


@winsdkapi(cc=CDECL, params={"stream": POINTER})
def hook_ftell(ql, address, params):
    stream = params["stream"]
    if stream in file_cursors:
        return file_cursors[stream]
    return -1


@winsdkapi(cc=CDECL, params={"stream": POINTER})
def hook_fclose(ql, address, params):
    return 0


@winsdkapi(cc=CDECL, params={"file": POINTER})
def hook_lock(ql, address, params):
    return 0


@winsdkapi(cc=CDECL, params={"file": POINTER})
def hook_unlock(ql, address, params):
    return 0


# ==============================================================================
# COMPORTAMENTO: RETE & COMMAND AND CONTROL (C2)
# ==============================================================================
@winsdkapi(cc=STDCALL, params={"wVersionRequired": WORD, "lpWSAData": POINTER})
def hook_WSAStartup(ql, address, params):
    print("\n[BEHAVIOR/NETWORK] 🌐 WSAStartup: Il malware sta inizializzando le librerie di rete!")
    return 0


@winsdkapi(cc=STDCALL, params={"name": STRING})
def hook_gethostbyname(ql, address, params):
    domain = params["name"]
    print(f"\n[BEHAVIOR/NETWORK] 🚨 gethostbyname: Tentativo di risoluzione DNS per il dominio C2: {domain}")
    return 0


@winsdkapi(cc=STDCALL, params={
    "lpszAgent": STRING,
    "dwAccessType": DWORD,
    "lpszProxy": STRING,
    "lpszProxyBypass": STRING,
    "dwFlags": DWORD,
})
def hook_InternetOpenA(ql, address, params):
    agent = params["lpszAgent"]
    print(f"\n[BEHAVIOR/NETWORK] 🌐 InternetOpenA: Preparazione connessione HTTP (User-Agent: {agent})")
    return 0x12345678


@winsdkapi(cc=STDCALL, params={
    "hInternet": HANDLE,
    "lpszServerName": STRING,
    "nServerPort": DWORD,
    "lpszUserName": STRING,
    "lpszPassword": STRING,
    "dwService": DWORD,
    "dwFlags": DWORD,
    "dwContext": DWORD,
})
def hook_InternetConnectA(ql, address, params):
    server = params["lpszServerName"]
    port = params["nServerPort"]
    print("\n" + "=" * 60)
    print("🔥 [BEHAVIOR/C2] InternetConnectA: Il RAT sta contattando il server attaccante!")
    print(f" [*] Server C2 Target : {server}")
    print(f" [*] Porta            : {port}")
    print("=" * 60)
    return 0x87654321


# ==============================================================================
# SETUP HOOKS E MOTORE DI ESECUZIONE
# ==============================================================================
def setup_advanced_hooks(ql):
    if TRACCIA_ASSEMBLY:
        print("\n[!] ATTENZIONE: Tracciamento Assembly ATTIVATO. L'emulazione sara' molto piu' lenta.")
        ql.hook_code(hook_code_assembly)

    # API Hooks generali e Anti-Sandbox
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

    # Path Evasion (Simulazione Riavvio nello Stadio 2)
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


def _prepare_rootfs_directories(rootfs_path):
    """Prepara nel rootfs Qiling le cartelle richieste da PlugX e PECompact2."""
    win_dir_name = "Windows"
    try:
        for entry in os.listdir(rootfs_path):
            if entry.lower() == "windows":
                win_dir_name = entry
                break
    except OSError:
        pass

    temp_dir = os.path.join(rootfs_path, "Users", "Admin", "AppData", "Local", "Temp")
    syswow64_dir = os.path.join(rootfs_path, win_dir_name, "SysWOW64")
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(syswow64_dir, exist_ok=True)


def avvia_analisi(pe_path, rootfs_path, stadio=None, output_dir=None, verbose_debug=False):
    """Avvia l'emulazione mirata di PlugX per lo stadio selezionato (1 o 2)."""
    global STADIO_ANALISI

    if stadio is not None:
        STADIO_ANALISI = stadio

    pe_path = os.path.abspath(pe_path)
    rootfs_path = os.path.abspath(rootfs_path)
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(__file__))
    else:
        output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    _reset_vfs_state(pe_path=pe_path, output_dir=output_dir)

    print("\n" + "=" * 70)
    print(f"[*] AVVIO ANALISI AVANZATA PLUGX: {os.path.basename(pe_path)}")
    print(f"[*] Esecuzione in STADIO        : {STADIO_ANALISI}")
    if STADIO_ANALISI == 1:
        print(f"[*] Target SHA-256 Stadio 1     : {SAMPLE_SHA256}")
    print(f"[*] Rootfs Qiling               : {rootfs_path}")
    print("=" * 70 + "\n")

    try:
        _prepare_rootfs_directories(rootfs_path)

        log_level = QL_VERBOSE.DEBUG if verbose_debug else QL_VERBOSE.DEFAULT
        ql = Qiling([pe_path], rootfs_path, verbose=log_level)
        setup_advanced_hooks(ql)

        print("[*] Motore di emulazione avviato. In attesa del comportamento del malware...\n")
        ql.run()
        print("\n[*] Esecuzione terminata correttamente.")

    except Exception as e:
        print(f"\n[!] Eccezione durante l'esecuzione: {e}")

    if STADIO_ANALISI == 1 and _last_dropped_files:
        print("\n" + "-" * 70)
        print(f"[+] Secondo stadio estratto in: {_last_dropped_files[0]}")
        print("[*] Per avviare l'analisi post-riavvio (Stadio 2) esegui:")
        print(
            f'    python {os.path.basename(__file__)} --stage 2 '
            f'-s "{_last_dropped_files[0]}" -r "{rootfs_path}"'
        )
        print("-" * 70)


def _resolve_default_sample(base_dir, stage):
    """Ricerca il sample predefinito per lo Stadio 1 o per lo Stadio 2."""
    cwd = os.getcwd()

    if stage == 1:
        candidates = [
            os.path.join(cwd, "Source", "PlugX", "PlugXV0.exe"),
            os.path.join(base_dir, "Source", "PlugX", "PlugXV0.exe"),
            os.path.join(base_dir, "PlugXV0.exe"),
            os.path.join(base_dir, f"{SAMPLE_SHA256}.exe"),
            os.path.join(base_dir, "sample.exe"),
            os.path.join(base_dir, "sample.dat"),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return path
        return candidates[1]

    # Stage 2: cerca prima il file classico o eventuali dropped_payload_*.bin estratti dallo Stadio 1
    stage2_candidates = [
        os.path.join(cwd, "dropped_payload_0x5014f15.bin"),
        os.path.join(base_dir, "dropped_payload_0x5014f15.bin"),
    ]
    for pattern_dir in (base_dir, cwd):
        matches = sorted(
            glob.glob(os.path.join(pattern_dir, "dropped_payload_*.bin")),
            key=os.path.getmtime,
            reverse=True,
        )
        stage2_candidates.extend(matches)

    stage2_candidates.extend([
        os.path.join(base_dir, "MediaCenter.exe"),
        os.path.join(cwd, "MediaCenter.exe"),
    ])

    for path in stage2_candidates:
        if os.path.isfile(path):
            return path
    return stage2_candidates[1]


def _parse_args():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    default_rootfs = os.path.abspath(os.path.join(base_dir, "..", ".."))

    parser = argparse.ArgumentParser(
        description=(
            "PlugX Multi-Stage Qiling Unpacker & Post-Reboot Analyzer "
            f"[Stage-1 SHA-256: {SAMPLE_SHA256}]"
        )
    )
    parser.add_argument(
        "--stage",
        type=int,
        choices=[1, 2],
        default=1,
        help="Stadio da analizzare: 1 = Dropper iniziale (estrazione MediaCenter.exe), 2 = Payload post-riavvio (default: 1)",
    )
    parser.add_argument(
        "-s", "--sample",
        default=None,
        help="Percorso al sample PE32 (Stadio 1: PlugXV0.exe / sample iniziale; Stadio 2: dropped_payload_*.bin)",
    )
    parser.add_argument(
        "-r", "--rootfs",
        default=default_rootfs,
        help="Percorso al rootfs Windows x86 (32-bit) di Qiling (es. examples/rootfs/x86_windows)",
    )
    parser.add_argument(
        "-o", "--output-dir",
        default=base_dir,
        help="Cartella di destinazione per i payload estratti (default: cartella dello script)",
    )
    parser.add_argument(
        "--trace-asm",
        action="store_true",
        help="Abilita il tracciamento assembly nell'intervallo configurato (INDIRIZZO_MIN..INDIRIZZO_MAX)",
    )
    parser.add_argument(
        "--provoke-evasion",
        action="store_true",
        help="Disattiva la simulazione dell'utente reale (SIMULA_UTENTE_REALE=False) per osservare il blocco Anti-Sandbox",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Imposta la verbosita' di Qiling a DEBUG (default: DEFAULT)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    STADIO_ANALISI = args.stage
    if args.trace_asm:
        TRACCIA_ASSEMBLY = True
    if args.provoke_evasion:
        SIMULA_UTENTE_REALE = False

    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_path = args.sample if args.sample else _resolve_default_sample(base_dir, args.stage)

    if not os.path.isfile(sample_path):
        print(f"\n[-] Errore CRITICO: Eseguibile del malware non trovato.\n    Percorso cercato: {sample_path}")
        if args.stage == 1:
            print(f"    Fornisci il campione Stadio 1 (SHA-256: {SAMPLE_SHA256}) tramite:")
            print(f"    python {os.path.basename(__file__)} --stage 1 -s <percorso_sample> -r <percorso_rootfs_x86_windows>\n")
        else:
            print("    Esegui prima lo Stadio 1 (--stage 1) per estrarre il secondo stadio, oppure passa -s <dropped_payload.bin>\n")
        sys.exit(1)

    if not os.path.isdir(args.rootfs):
        print(f"\n[-] Errore CRITICO: Directory rootfs di Qiling non trovata in:\n    {args.rootfs}")
        print("    Specifica il rootfs x86_windows con: -r <percorso_rootfs_x86_windows>\n")
        sys.exit(1)

    try:
        entries_lower = [entry.lower() for entry in os.listdir(args.rootfs)]
        if "windows" not in entries_lower:
            print(
                f"\n[-] Errore: '{args.rootfs}' non sembra essere un rootfs Windows di Qiling "
                f"(cartella 'Windows' assente).\n"
                f"    Specifica il percorso corretto con: -r <percorso_rootfs_x86_windows>\n"
            )
            sys.exit(1)
    except OSError as exc:
        print(f"\n[-] Errore di accesso al rootfs '{args.rootfs}': {exc}\n")
        sys.exit(1)

    avvia_analisi(
        pe_path=sample_path,
        rootfs_path=args.rootfs,
        stadio=args.stage,
        output_dir=args.output_dir,
        verbose_debug=args.verbose,
    )
