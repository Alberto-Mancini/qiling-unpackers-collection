# Relazione Tecnica

**Studente:** Alberto Mancini  
**Matricola:** 352637  
**Data:** 1 Settembre 2026  

**Analisi e Bypass delle Tecniche Anti-VM nel Malware PlugX**  
**Obiettivo:** Identificare ed eludere le difese Anti-VM e Anti-Sandbox del malware PlugX attraverso l'emulazione dinamica sfruttando il Qiling Framework.

---

## 1. Introduzione e Architettura dell'Infezione

Questo documento descrive dettagliatamente le tecniche di evasione usate dal malware PlugX, classificato come *Remote Access Trojan (RAT)*. Per ostacolare le attività di analisi e reverse engineering, PlugX implementa una serie di rigorosi controlli Anti-VM (Anti-Virtual Machine) e Anti-Sandbox. Questi controlli operano in sinergia per rilevare alterazioni del tempo di esecuzione, accertare l'effettiva presenza di un utente fisico e verificare l'esistenza di un'interfaccia grafica coerente con un normale ambiente desktop, smascherando così gli ambienti di analisi automatizzati.

L'analisi approfondita condotta tramite emulazione ha rivelato che la catena di esecuzione della minaccia non è monolitica, bensì articolata in due fasi distinte e sequenziali:

* **Fase 1 (Dropper e Persistenza):** Il primo stadio è gestito dal binario originale, `PlugXV0.exe`. Il suo mandato principale è quello di sondare attivamente l'ambiente circostante per aggirare le sandbox, verificare se l'host sia già compromesso e, in caso negativo, estrarre il payload malevolo vero e proprio su disco, garantendogli al contempo la persistenza nel sistema tramite chiavi di registro di avvio (Autostart).
* **Fase 2 (Payload RAT):** Questo stadio è gestito dal file binario droppato su disco, identificato nel corso dell'analisi come `dropped_payload_0x5014f15.bin` (concepito nativamente per mascherarsi sotto il nome di `MediaCenter.exe`). Lo Stage 2, fortemente offuscato e protetto dal noto packer *PECompact2*, è incaricato di instaurare la comunicazione di rete verso il server attaccante (Command & Control) e di eseguire l'infiltrazione finale del RAT all'interno della memoria.

---

## 2. Analisi dei Requisiti e Specifiche del Problema

L'obiettivo dell'elaborato è analizzare in modo dinamico il malware in un ambiente completamente isolato e automatizzato, costringendolo a rivelare i propri comportamenti eludendo contemporaneamente le sue difese attive. 
Il problema critico emerso durante la fase di triage è che, qualora PlugX acquisisca il sospetto di trovarsi in una sandbox (ad esempio registrando salti anomali nel clock di sistema o l'immobilità prolungata del mouse), esso non si arresta causando un'uscita sospetta. Al contrario, adotta un comportamento elusivo "stealth": entra in un loop infinito in cui ripete in modo ciclico i propri controlli, di fatto ibernando l'esecuzione della vera routine malevola (dropper). 

È divenuto quindi imperativo ingegnerizzare un sistema capace di falsificare, in tempo reale, i parametri ambientali di sistema, in modo da superare iterativamente i controlli e sbloccare le pipeline di esecuzione senza allertare le routine di difesa del malware.

---

## 3. Architettura del Sistema e Tecnologie Adottate

Per far fronte a tali requisiti, la metodologia prescelta si impernia sull'emulazione dinamica del codice mediante l'adozione del **Qiling Framework**. Questo motore avanzato permette di eseguire il malware in user-mode all'interno di un perimetro controllato, rendendo possibile l'intercettazione chirurgica delle chiamate al sistema operativo Windows (tramite *API hooking*).

Il layer di bypass è stato interamente sviluppato tramite script in linguaggio Python. Avvalendosi dei decoratori nativi di Qiling (es. `@winsdkapi`), è stato possibile non solo manipolare e leggere la memoria allocata dal malware (mediante `ql.mem.write`), ma anche alterare a piacimento i valori di ritorno delle API di sistema. 
In tal modo, l'hardware e i subsystem di Windows (orologio, periferiche di input, filesystem) sono stati simulati logicamente, restituendo all'eseguibile risposte fittizie ma internamente coerenti. Questo ha permesso di simulare un ambiente desktop verosimile senza il gravoso *overhead* associato al setup di un'intera macchina virtuale tradizionale o di una Cuckoo Sandbox.

---

## 4. FASE 1: Evasione Anti-VM ed Estrazione del Payload (File: `PlugXV0.exe`)

### 4.1 Alterazione Temporale (Timing Evasion)

**Funzionamento della Tecnica**
Gli ambienti di *automated malware analysis* spesso manipolano il tempo, accelerandolo o scartando del tutto i ritardi artificiali (come la funzione `Sleep`), allo scopo di efficientare l'estrazione degli IOC (Indicator of Compromise).
PlugX rileva queste alterazioni misurando il tempo operativo di sistema (mediante la funzione `GetTickCount`) nell'istante precedente e immediatamente successivo a una istruzione di attesa. Se il delta temporale misurato si rivela inferiore alla durata richiesta (ad esempio, uno stallo di 5 secondi consumato in pochi millisecondi), il malware deduce l'esistenza di un emulatore o sandbox. Anziché bloccarsi palesemente, esso cicla costantemente i check in attesa di un utente, paralizzando l'indagine.

**Logica di Bypass**
Per oltrepassare tale barriera preservando al contempo il risparmio di tempo fornito dall'emulatore, si è optato per intercettare tali chiamate manipolandone l'aritmetica temporale:

```python
# 1. Intercettiamo lo Sleep e parcheggiamo il tempo senza bloccare il flusso
@winsdkapi(cc=STDCALL, params={'dwMilliseconds': DWORD})
def hook_Sleep(ql, address, params):
    anti_evasion.tempo_in_sospeso += params['dwMilliseconds']
    return 0

# 2. Forniamo il tick "falsato" al successivo controllo del malware
@winsdkapi(cc=STDCALL, params={})
def hook_GetTickCount(ql, address, params):
    anti_evasion.tick += 50 + anti_evasion.tempo_in_sospeso
    anti_evasion.tempo_in_sospeso = 0
    return anti_evasion.tick
```

Come illustrato, il valore dei millisecondi imposti dalla funzione `Sleep` viene acquisito e salvato in una variabile di comodo. Alla successiva chiamata diagnostica a `GetTickCount`, tale ammontare temporale viene sommato al finto orologio dell'emulatore, inducendo il malware a ritenere che il blocco d'attesa sia stato fedelmente onorato.

### 4.2 Controllo Movimento Cursore (Mouse Movement Check)

**Funzionamento della Tecnica**
L'assenza di un operatore umano è un indicatore principe di una virtual machine dedicata all'analisi. Il malware accerta la presenza umana avvalendosi dell'API `GetCursorPos`. Reiterando le interrogazioni a tale funzione, il codice compara le coordinate orizzontali (X) registrate a intervalli di tempo. Qualora la sottrazione risulti nulla (assenza di spostamento), l'assenza di input spinge il programma nel medesimo loop conservativo discusso in precedenza.

**Logica di Bypass**
Il superamento è stato ottenuto tramite l'iniezione programmatica di un disturbo pseudocasuale (jitter), capace di simulare lo spostamento impreciso di un vero mouse:

```python
@winsdkapi(cc=STDCALL, params={'lpPoint': POINTER})
def hook_GetCursorPos(ql, address, params):
    anti_evasion.cursor_x += random.randint(-15, 15)
    anti_evasion.cursor_y += random.randint(-15, 15)
    ql.mem.write(params['lpPoint'],
        anti_evasion.cursor_x.to_bytes(4, 'little', signed=True) +
        anti_evasion.cursor_y.to_bytes(4, 'little', signed=True))
    return 1
```

A ogni invocazione, il framework somma un delta casuale compreso tra -15 e +15 pixel, iniettando le nuove coordinate all'indirizzo di memoria puntato da `lpPoint`, sventando così la routine di rilevamento dell'immobilità.

### 4.3 Controllo Finestra Attiva (Foreground Window Check)

**Funzionamento della Tecnica**
La presenza di finestre attive e dei relativi cambi di "focus" è sintomo di naturale interazione. PlugX richiama `GetForegroundWindow` con lo scopo di reperire l'ID (Handle) della finestra in primo piano. All'interno di ambienti *headless* (sprovvisti di monitor e GUI), l'API ritorna intrinsecamente `0`. 
Il reverse engineering statico ha evidenziato in PlugX una negligenza implementativa: se l'API fornisce un Handle valido, questo viene certamente salvato, ma a causa di una flag interna settata staticamente a `0`, la validazione successiva (che appurerebbe il cambio reale della finestra) viene aggirata da un salto incondizionato (unconditional jump).

**Logica di Bypass**
Facendo leva su questa debolezza strutturale, l'implementazione si riduce alla sola restituzione di un Handle valido al fine di superare la condizione nulla di base:

```python
@winsdkapi(cc=STDCALL, params={})
def hook_GetForegroundWindow(ql, address, params):
    anti_evasion.window_handle += 4
    return anti_evasion.window_handle
```

Questo ID numerico progressivo viene accolto dal processo, il quale sblocca definitivamente la propria esecuzione svincolandosi dal loop anti-analisi.

### 4.4 Controllo di Pre-Infezione ed Estrazione (Virtual File System)

Scongiurati gli stalli logici, il dropper compie un sondaggio su disco primario (sanity test). Avvalendosi dell'API `fopen`, sonda in lettura l'ubicazione destinata al proprio clone (`C:\Users\Admin\AppData\Local\Temp\MicroMedia\MediaCenter.exe`). La presenza del file confermerebbe l'avvenuta installazione in sessioni precedenti, ordinando l'arresto immediato (prevenzione di processi multipli e race condition). Restituendo dinamicamente un Handle `NULL` (`0x0`) per le sole richieste di lettura su determinati file, il dropper è stato indotto a proseguire l'installazione.

Durante la fase culminante di estrazione del payload decifrato, PlugX adotta funzioni a basso livello derivate dalla Standard C Library (`fseek`, `fread`, `fwrite`), scarsamente coperte nativamente da Qiling e portatrici di errori di memoria *unmapped*. Per raggirare il fault, è stata predisposta l'implementazione di un primitivo File System Virtuale (VFS) in Python. Catturando l'innesco di `fwrite` con apposito hook, i flussi binari in transito sul buffer sono stati dirottati ed estratti al volo, convalidando lo sversamento fisico su disco dell'archivio cifrato `dropped_payload_0x5014f15.bin` (esattamente 74.358 byte).

---

## 5. FASE 2: Analisi Post-Riavvio e Command & Control (File: `dropped_payload_...bin`)

Lo studio isolato dello "Stage 2" (il payload RAT) ha palesato la necessità di simulare il contesto del sistema al riavvio. Il software, per operare attivamente, esige infatti di essere originato specificamente dalla cartella definita dalla chiave di autostart (Run). In caso contrario, rifiuta di propagare l'infezione.

### 5.1 Falsificazione del Percorso (Path Spoofing)

Il bypassing d'ambiente è avvenuto sfruttando l'API nativa `GetModuleFileNameA`, iniettandole a forza un *path* ingannevole:

```python
@winsdkapi(cc=STDCALL, params={'hModule': HANDLE, 'lpFilename': POINTER, 'nSize': DWORD})
def hook_GetModuleFileNameA(ql, address, params):
    fake_path = b"C:\\Users\\Admin\\AppData\\Local\\Temp\\MicroMedia\\MediaCenter.exe\x00"
    ql.mem.write(params['lpFilename'], fake_path)
    return len(fake_path) - 1
```

Il RAT, convincendosi di essere processato legittimamente dalla propria directory di persistenza, ha validato l'identità dell'infezione e proseguito verso l'attivazione della rete.

### 5.2 Intercettazione Rete (Command & Control)

Forte della verifica, il codice ha richiesto la mappatura in memoria delle librerie Windows destinate ai socket (`ws2_32.dll` e `wininet.dll`). Inserendosi sull'invocazione di `InternetOpenA`, l'emulatore ha stampato e disinnescato l'inizializzazione del layer di rete destinato al C2:

```text
[BEHAVIOR/EVASION] 🕵️ GetModuleFileNameA falsato! Il malware crede di essere in: C:\...\MediaCenter.exe
[BEHAVIOR/NETWORK] 🌐 InternetOpenA: Preparazione connessione HTTP (User-Agent: Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+5.1;+SV1))
```

Questa evidenza prova come PlugX, pur essendo un agente avanzato, faccia ricorso a basilari pratiche di offuscamento, camuffando il proprio traffico beaconing fra quello generabile da un retrogrado e insospettabile *Internet Explorer 8*.

### 5.3 Limiti dell'Emulatore e Interruzione dell'Esecuzione

Innescato il protocollo C2, il packer protettivo *PECompact2* è insorto tentando la decompressione finale in memoria (Process Injection). La routine ha tentato la validazione dell'integrità strutturale dell'host richiedendo l'albero di directory via `GetSystemWow64DirectoryA` e analizzandolo con `FindFirstFileA`.
Malgrado l'albero nativo fittizio (`C:\Windows\SysWOW64`) sia stato fornito in modo coerente dagli script Python, il frame architetturale Qiling è incorso in un blocco irreversibile (Exception Handler letale):

```text
[DEBUG/FIX] 📂 GetSystemWow64DirectoryA richiesto dal packer -> Fornito: C:\Windows\SysWOW64
IsADirectoryError: [Errno 21] Is a directory: '/home/remnux/.../Windows/SysWOW64'
[!] Eccezione durante l'esecuzione: Windows API Implementation Error
```

Quest'avaria non va in alcun modo imputata a difese Anti-VM, bensì a una discrasia di compatibilità tra i layer (Windows-to-Linux mapping) intrinseca allo strumento: nel mappare l'ispezione della directory sulle chiamate POSIX sottostanti del kernel Linux (Remnux), Qiling invoca funzioni previste esclusivamente per la lettura di file. Imbattendosi in una risorsa directory, s'imbatte nell'eccezione nativa `IsADirectoryError`, precludendo lo scenario di injection del payload de-offuscato nella RAM.

---

## 6. Conclusione

In sintesi, il binomio composto dal Qiling Framework e dagli script Python di *API Hooking* si è dimostrato uno strumento potente e formidabile per smantellare i presidi difensivi di PlugX (Fase 1). L'alterazione del tessuto cronologico, la riproduzione del jitter nei dispositivi di interazione umana (HID) e il mirato sfruttamento di asimmetrie nel codice maligno, hanno consentito di neutralizzare i loop di difesa. Si è creata, in tal modo, un'infrastruttura fiduciaria sufficiente affinché l'impianto estrattivo portasse a termine lo scarto del Dropper a favore del binario silente (Payload dumping).

D'altronde, i limiti evidenziati dall'analisi del packer nello Stage 2 (Fase 2) rendono evidente che le emulazioni User-Mode risentono di forti restrizioni nell'handling architetturale (come le mappature a basso livello del File System). Per approfondimenti legati a de-packing di memorie strutturate o all'estrapolazione di routine Kernel-level, l'emulatore puro dovrà essere integrato da pratiche ibride o sessioni di Live Debugging. Nondimeno, l'obiettivo preposto di tracciare dinamicamente le tattiche evasive e de-isolato il protocollo Command & Control (C2), disarticolandone le verifiche ostative, è da definirsi compiuto con successo.
