# -*- coding: utf-8 -*-
"""
Latrodectus Stage-1 Loader - Targeted Emulation Harness (Negative Case Study)
=============================================================================
Harness Qiling per l'analisi dinamica del primo stadio del loader multi-stadio
a 64 bit Latrodectus e la verifica sperimentale dei limiti strutturali
dell'emulazione user-mode.

Metadati del Campione Target (per riproducibilita'):
  - Famiglia  : Latrodectus
  - SHA-256   : fc58ae120d35b751525f6c312f9aeff75e9151f02fa113815bd01acc49f63596
  - Fonte     : MalwareBazaar
  - Formato   : PE32+ (x86_64 64-bit), libreria DLL mascherata con estensione .exe
  - Ambiente  : Qiling Framework (testato su v1.4.6) con rootfs Windows x86_64 (64-bit)

Funzionamento e Risultato Atteso (Caso di Studio con Esito Negativo):
  1. Il punto d'ingresso standard (DllMain) e' una funzione vuota progettata per
     ingannare le sandbox automatiche restituendo subito successo.
  2. Tutte le 203 funzioni esportate dalla libreria puntano al vero entry point
     del primo stadio (0x180065709): lo script scavalca DllMain forzando l'avvio
     direttamente a tale indirizzo e registrando hook sulle API di sistema e tempo.
  3. All'avvio di 0x180065709, il malware esegue un doppio ciclo matematico annidato
     (>456 milioni di iterazioni sui registri CPU circondate da istruzioni SIMD
     inutili) senza invocare alcuna API Windows intercettabile, mandando in stallo
     o timeout l'emulazione software user-mode (e causando successivamente crash su
     puntatori PE corrotti / chiamate syscall dirette lette da ntdll.dll su disco).

Utilizzo:
  python latrodectus_stage1_emulation_harness.py -s <percorso_sample> -r <percorso_rootfs_x8664_windows>
  python latrodectus_stage1_emulation_harness.py -s <percorso_sample> -r <percorso_rootfs_x8664_windows> -t 10
"""

import argparse
import os
import sys

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.os.windows.api import DWORD, HANDLE, POINTER
from qiling.os.windows.fncc import STDCALL, winsdkapi

# ==============================================================================
# COSTANTI DEL CAMPIONE TARGET (SHA-256: fc58ae12...c49f63596)
# ==============================================================================
SAMPLE_SHA256 = "fc58ae120d35b751525f6c312f9aeff75e9151f02fa113815bd01acc49f63596"

# Vero punto d'ingresso del primo stadio condiviso dalle 203 funzioni esportate
# (utilizzato per scavalcare il falso DllMain vuoto del campione)
STAGE1_EXPORT_VA = 0x180065709


# ==============================================================================
# HOOKS DI BASE E ANTI-EVASIONE (Compatibili x64 tramite @winsdkapi)
# ==============================================================================

@winsdkapi(cc=STDCALL, params={"lpLibFileName": POINTER})
def hook_LoadLibraryA(ql, address, params):
    lp_name = params["lpLibFileName"]
    try:
        if lp_name:
            dll_name = ql.mem.string(lp_name)
            print(f"[API] LoadLibraryA: {dll_name}")
    except Exception:
        pass
    return 0x10000000


@winsdkapi(cc=STDCALL, params={"lpLibFileName": POINTER})
def hook_LoadLibraryW(ql, address, params):
    lp_name = params["lpLibFileName"]
    try:
        if lp_name:
            dll_name = ql.mem.string(lp_name, encoding="utf-16-le")
            print(f"[API] LoadLibraryW: {dll_name}")
    except Exception:
        pass
    return 0x10000000


@winsdkapi(cc=STDCALL, params={"hModule": HANDLE, "lpProcName": POINTER})
def hook_GetProcAddress(ql, address, params):
    lp_proc = params["lpProcName"]
    try:
        if lp_proc:
            if lp_proc <= 0xFFFF:
                print(f"[API] GetProcAddress: ordinal #{lp_proc}")
            else:
                proc_name = ql.mem.string(lp_proc)
                print(f"[API] GetProcAddress: {proc_name}")
    except Exception:
        pass
    return 0x10001000


@winsdkapi(cc=STDCALL, params={
    "lpFileName": POINTER,
    "dwDesiredAccess": DWORD,
    "dwShareMode": DWORD,
    "lpSecurityAttributes": POINTER,
    "dwCreationDisposition": DWORD,
    "dwFlagsAndAttributes": DWORD,
    "hTemplateFile": HANDLE,
})
def hook_CreateFileA(ql, address, params):
    lp_file = params["lpFileName"]
    try:
        if lp_file:
            file_name = ql.mem.string(lp_file)
            print(f"[API] CreateFileA: {file_name}")
    except Exception:
        pass
    return 0x4000


@winsdkapi(cc=STDCALL, params={
    "lpFileName": POINTER,
    "dwDesiredAccess": DWORD,
    "dwShareMode": DWORD,
    "lpSecurityAttributes": POINTER,
    "dwCreationDisposition": DWORD,
    "dwFlagsAndAttributes": DWORD,
    "hTemplateFile": HANDLE,
})
def hook_CreateFileW(ql, address, params):
    lp_file = params["lpFileName"]
    try:
        if lp_file:
            file_name = ql.mem.string(lp_file, encoding="utf-16-le")
            print(f"[API] CreateFileW: {file_name}")
    except Exception:
        pass
    return 0x4000


# --- HOOKS ANTI-STALLO TEMPORALE ---

@winsdkapi(cc=STDCALL, params={"dwMilliseconds": DWORD})
def hook_Sleep(ql, address, params):
    dw_ms = params["dwMilliseconds"]
    print(f"[ANTI-VM] ⏱️ Il malware voleva dormire per {dw_ms} ms. Risveglio immediato!")
    return 0  # Restituisce 0 (successo) immediatamente


@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    print("[ANTI-VM] 🕒 Intercettato GetTickCount (Controllo del tempo). Falsifico...")
    return 0x5000000  # Restituisce un uptime elevato per eludere i controlli base


# ==============================================================================
# MOTORE PRINCIPALE DI EMULAZIONE
# ==============================================================================

def setup_latrodectus_hooks(ql):
    """Registra gli hook API di monitoraggio e anti-evasione."""
    ql.os.set_api("LoadLibraryA", hook_LoadLibraryA)
    ql.os.set_api("LoadLibraryW", hook_LoadLibraryW)
    ql.os.set_api("GetProcAddress", hook_GetProcAddress)
    ql.os.set_api("CreateFileA", hook_CreateFileA)
    ql.os.set_api("CreateFileW", hook_CreateFileW)
    ql.os.set_api("Sleep", hook_Sleep)
    ql.os.set_api("GetTickCount", hook_GetTickCount)


def _get_rip_str(ql):
    """Restituisce in modo sicuro il valore corrente di RIP / PC in esadecimale."""
    if ql is None:
        return "N/A"
    try:
        return hex(ql.arch.regs.rip)
    except Exception:
        try:
            return hex(ql.arch.regs.arch_pc)
        except Exception:
            return "N/A"


def avvia_emulazione_base(pe_path, rootfs_path, timeout_sec=0, quiet=False):
    """
    Carica Latrodectus in Qiling (x86_64) e avvia l'esecuzione direttamente
    dall'entry point esportato del primo stadio (0x180065709), scavalcando DllMain.
    """
    pe_path = os.path.abspath(pe_path)
    rootfs_path = os.path.abspath(rootfs_path)

    print("=" * 65)
    print(f"[*] Avvio Analisi Dinamica: {os.path.basename(pe_path)}")
    print(f"[*] Target SHA-256 atteso : {SAMPLE_SHA256}")
    print(f"[*] Rootfs Qiling         : {rootfs_path}")
    print("=" * 65)

    ql = None
    try:
        log_level = QL_VERBOSE.DEFAULT if quiet else QL_VERBOSE.DEBUG
        ql = Qiling([pe_path], rootfs_path, verbose=log_level)

        setup_latrodectus_hooks(ql)

        target_address = STAGE1_EXPORT_VA
        timeout_us = int(timeout_sec * 1_000_000) if timeout_sec and timeout_sec > 0 else 0

        print(f"[*] Bypass DllMain vuoto -> Esecuzione forzata a: {hex(target_address)}")
        if timeout_us > 0:
            print(f"[*] Esecuzione in corso (timeout impostato a {timeout_sec}s)...")
        else:
            print("[*] Esecuzione in corso (nessun timeout; premi Ctrl+C o usa -t <secondi> per interrompere lo stallo CPU)...")
        print("-" * 65)

        ql.run(begin=target_address, timeout=timeout_us)

        print("-" * 65)
        print(f"[*] Esecuzione terminata (RIP finale: {_get_rip_str(ql)}).")

    except KeyboardInterrupt:
        print(f"\n[!] Emulazione interrotta manualmente dall'utente (RIP={_get_rip_str(ql)}).")
    except Exception as e:
        print(f"\n[!] L'emulazione si è fermata (RIP={_get_rip_str(ql)}): {e}")


# Alias descrittivo mantenendo la retrocompatibilita' con avvia_emulazione_base
avvia_emulazione_latrodectus = avvia_emulazione_base


def _resolve_default_sample_and_rootfs(base_dir):
    """Ricerca il sample nei percorsi predefiniti mantenendo compatibilita' col layout originale."""
    cwd = os.getcwd()
    cwd_candidate = os.path.join(cwd, "Source", "Latrodectus", "Latrodectus.exe")
    if os.path.isfile(cwd_candidate):
        return cwd_candidate, os.path.abspath(os.path.join(cwd, "..", ".."))

    candidates = [
        os.path.join(base_dir, "Source", "Latrodectus", "Latrodectus.exe"),
        os.path.join(base_dir, "Latrodectus.exe"),
        os.path.join(base_dir, f"{SAMPLE_SHA256}.exe"),
        os.path.join(base_dir, "sample.exe"),
        os.path.join(base_dir, "sample.dat"),
    ]
    default_rootfs = os.path.abspath(os.path.join(base_dir, "..", ".."))
    for path in candidates:
        if os.path.isfile(path):
            return path, default_rootfs

    return candidates[0], default_rootfs


def _parse_args():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    default_sample, default_rootfs = _resolve_default_sample_and_rootfs(base_dir)

    parser = argparse.ArgumentParser(
        description=(
            "Latrodectus Stage-1 Qiling Emulation Harness "
            f"[Target SHA-256: {SAMPLE_SHA256}]"
        )
    )
    parser.add_argument(
        "-s", "--sample",
        default=default_sample,
        help="Percorso al sample Latrodectus (DLL PE32+ x86_64 con estensione .exe)",
    )
    parser.add_argument(
        "-r", "--rootfs",
        default=default_rootfs,
        help="Percorso al rootfs Windows x86_64 (64-bit) di Qiling (es. examples/rootfs/x8664_windows)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=0,
        help="Timeout massimo di emulazione in secondi (default: 0 = nessun limite, es. -t 10 per 10s)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Riduce la verbosita' di Qiling da DEBUG a DEFAULT",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if not os.path.isfile(args.sample):
        print(f"[-] Errore: File malware non trovato al percorso:\n    {args.sample}")
        print(f"    Fornisci il campione (SHA-256: {SAMPLE_SHA256}) tramite:")
        print(f"    python {os.path.basename(__file__)} -s <percorso_sample> -r <percorso_rootfs_x8664_windows>")
        sys.exit(1)

    if not os.path.isdir(args.rootfs):
        print(f"[-] Errore: Directory rootfs di Qiling non trovata in:\n    {args.rootfs}")
        print(f"    Specifica il rootfs x8664_windows con: -r <percorso_rootfs_x8664_windows>")
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

    avvia_emulazione_base(
        pe_path=args.sample,
        rootfs_path=args.rootfs,
        timeout_sec=args.timeout,
        quiet=args.quiet,
    )
