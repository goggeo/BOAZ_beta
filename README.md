<img width="423" alt="loglo" src="https://github.com/thomasxm/Boaz_beta/assets/44269971/a5427ccc-e2ed-4cc3-ab81-084de691b23f">





<img width="352" alt="small_logo" src="https://github.com/thomasxm/Boaz_beta/assets/44269971/99abcf82-7084-47e5-a993-2a712b4ca664">

# BOAZ Evasion and Antivirus Testing Tool (for educational purpose)



![c](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white) ![python](https://img.shields.io/badge/Python-00599C?style=for-the-badge&logo=python&logoColor=red) ![assembly](https://img.shields.io/badge/ASSEMBLY-ED8B00?style=for-the-badge&logo=Assembly&logoColor=white) ![windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)


[Features](#Features) | [Installation](#installation) | [Usage](#Usage) | [Evasion Module](#evasion-modules)

## Presentation

1. [BlackHat USA, 2024 - Arsenal](https://www.blackhat.com/us-24/arsenal/schedule/index.html#boaz-yet-another-layered-evasion-tool-evasion-tool-evaluations-and-av-testing-38960)
2. [DEF CON Red Team Village - Haven Track 1](https://redteamvillage.io/schedule.html)

Special thanks to Professor Rich Macfarlane [@rjmacfarlane](https://x.com/rjmacfarlane?lang=en).

## Description

BOAZ (Bypass, Obfuscate, Adapt, Zero-Trust) evasion was inspired by the concept of multi-layered approach which is the evasive version of defence-in-depth ([Swinnen & Mesbahi, 2014](https://www.blackhat.com/docs/us-14/materials/us-14-Mesbahi-One-Packer-To-Rule-Them-All.pdf)). It was developed to aid the security testing and antivirus defence evaluation. 

BOAZ aims to bypass the before and during execution phases that span signature, heuristic and behavioural-based detection methods. BOAZ supports x64 binary (PE) or raw playload (.bin) as input. It has been tested on separated Window-11 VMs with 14 Desktop AVs. The design of BOAZ evasion is modularised so users can add their own toolset, encoding or new techniques to the framework at will. It is written in both C and C++, and uses Python as the main program to link all modules together.

For students and researchers in offensive security, no advanced programming or scripting knowledge or skills are required to use BOAZ to generate undetectable polymorphic samples.

This tool has an alternative use: it can function as a packer or obfuscator.




## Features

- **Modular Design**: Easily extendable with new tactics and techniques by adding scripts.

- [ ] **Signature Evasion**:
    - **LLVM IR level Obfuscation**: Pluto and Akira LLVM-based obfuscation including string encryption and control flow flattening.
    - **CodeBase obfuscation**:
        - Function name and string obfuscated from chars: [0-9a-zA-Z_] by 3 randomly selected algorithms: Mt19937, MinstdRand and ranlux48_base.
        - Shikata Ga Nai (SGN) encoding.
    - **Payload encoding (T1132)**:
        - UUID (Universally Unique Identifier)
        - MAC
        - IP4 format
        - base-64
        - base-45
        - base-58
        - Chacha20
        - AES
        - AES with divide and conquer to bypass logical path hijacking
    - **Compilation time obfuscation (LLVM, T1140, T1027)**:    
        - **Pluto**:
            - `bcf`: Bogus Control Flow
            - `fla`: Control Flow Flattening
            - `gle`: Global Variable Encryption
            - `mba`: Mixed-Boolean Arithmetic expressions ([MBA](https://theses.hal.science/tel-01623849/file/75068_EYROLLES_2017_archivage.pdf))
            - `sub`: Instruction Substitutions
            - `idc`: Indirect Call Promotion
            - `hlw`: Hide LLVM IR Level Warnings
        - **Akira**:
            - Indirect jumps and encrypted jump targets
            - Encrypted indirect function calls
            - Encrypted indirect global variable references
            - String encryption
            - Procedure-related control flow flattening
    - **Stripped binary (T1027.008)**
    - **Two methods to reduce entropy to below threshold by padding Pokémon names or null bytes**
    - **Signed certificate (T1036.001)**
    - **Metadata copied from window binary (T1036)**

- [ ] **Heuristic Evasion**: 
    - **Anti-Emulation (T1497)**: checks based on file system operation, process and network information and “offer you have to refuse” [15, 38]. A simple heuristic that if 2 or more checks are failed, execution will stop. 
    - **Junk API instructions (“no-op” calls, or mimicry attack)**: 5 benign API functions to vary the API call sequences 
    - **API Unhooking**:
        - 1. Read the syscall stub from the original ntdll and rewrite the loaded ntdll’s stub
        - 2. Custom Peruns’ Fart unhooking
        - 3. Halo’s gate (TartarusGate)
    - **Sifu Memory Guard**
        - New memory guard inspired by hardware breakpoints hooking techniques (Loader 48, 49, 51, 52, 57)
    - **Sleep obfuscation: Custom Ekko (CreateTimerQueueTimer) with arbitrary sleep time invoked at run time**
    - **Stack encryption sleep**: Local variables and shellcode were being stored on stack. This part of memory is available for scanning both in emulator pre-execution and post-execution. 
    - **PIC convertor (T1027.009, T1027.002, T1620)**:
        - The donut (The Wover)
        - PE2SH (hasherezade)
        - RC4 encrypted convertor
        - Amber (by Ege Balcı)
        - Shoggoth (by frkngksl)
          
- [ ] **Behavioral Evasion**: 
    - **Various code execution and process injection loaders (T1055, T1106, T1027.007)**: A variety of loaders for different evasion scenarios
    - **Two LLVM-obfuscation compilers (T1027)**
    - **Output DLL/CPL (side-loading) (T1574.002, T1218.011/002)**
    - **ETW-patching (patch ETW stub with “xor rax, rax; ret”) (T1562.006)**
    - **API name spoofing via IAT, using CallObfuscator by d35ha**
    - **Process code injection and execution mitigation policy (M1038) (e.g. CFG, XFG, module tampering prevention, Structured Exception Handler Overwrite Protection (SEHOP), etc)**
    - **Post-execution self-deletion: output binary can be marked as self-delete upon execution (T1070.004)**
    - **New memory scanner evasion techniques:**
      - Conventional VEH memory guard
      - PG (page guard) --> VEH (vectored exception handler)
      - PG --> VEH --> VCH (vectored continued handler) stealth guard
      - Virtual table hooking execution guard
  -  **A new code execution and process injection primitive via data corruption**


## Prerequisites

- Linux environment with Wine configured. Kali Linux or other Debian prefered. 
- CMake, Git, GCC, G++, MingW, LLVM and other build essentials installed.

## Installation

1. **Install required packages:**:

```console
git clone https://github.com/thomasxm/Boaz_beta/
cd Boaz_beta
```

```console
bash requirements.sh
```

2. **Cavets**:

It should be noted that SGN encoder sometimes can generate bad characters, use with caution. 
requirements.sh will install LLVM, which takes a while to complete. BOAZ can be run without the -llvm handle; however, it is not optimised without the latter.

## Usage

Example usage:

```console
python3 Boaz.py -f ~/testing_payloads/notepad_64.exe -o ./alice_notepad.exe -t donut -obf -l 1 -c pluto -e uuid -g
```

Use a built ELF executable in Linux environment:
```console
./Boaz -f ~/testing_payloads/notepad_64.exe -o ./alice_notepad.exe -t donut -obf -l 1 -c pluto -e uuid -g
```

Refer to the help command for more details on usage:

```console
python3 Boaz.py -h 
```

```console
./Boaz -h 
```

```bash
usage: Boaz [-h] -f INPUT_FILE [-o OUTPUT_FILE] [-divide] [-l LOADER] [-dll] [-cpl] [-sleep]
            [-a] [-etw] [-j] [-dream [DREAM]] [-u] [-g] [-t {donut,pe2sh,rc4,amber,shoggoth}]
            [-sd] [-sgn] [-e {uuid,xor,mac,ipv4,base45,base64,base58,aes,chacha,aes2,ascon}]
            [-c {mingw,pluto,akira}] [-mllvm MLLVM] [-obf] [-obf_api] [-w [SYSWHISPER]]
            [-entropy {1,2}] [-b [BINDER]] [-wm [WATERMARK]] [-s [SIGN_CERTIFICATE]]

Process loader and shellcode.

options:
  -h, --help            show this help message and exit
  -f INPUT_FILE, --input-file INPUT_FILE
                        Path to binary.exe
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        Optional: Specify the output file path and name. If not provided, a
                        random file name will be used in the ./output directory.
  -divide               Divide flag (True or False)
  -l LOADER, --loader LOADER
                        Loader number (must be a non-negative integer)
  -dll                  Compile the output as a DLL instead of an executable, can be run with
                        rundll32.exe
  -cpl                  Compile the output as a CPL instead of an executable, can be run with
                        control.exe
  -sleep                Obfuscation Sleep flag with random sleep time (True or False)
  -a, --anti-emulation  Anti-emulation flag (True or False)
  -etw                  Enable ETW patching functionality
  -j, --junk-api        Insert junk API function call at a random location in the main function
                        (5 API functions)
  -dream [DREAM]        Optional: Sleep with encrypted stacks for specified time in
                        milliseconds. Defaults to 1500ms if not provided.
  -u, --api-unhooking   Enable API unhooking functionality
  -g, --god-speed       Enable advanced unhooking technique Peruns Fart (God Speed)
  -t {donut,pe2sh,rc4,amber,shoggoth}, --shellcode-type {donut,pe2sh,rc4,amber,shoggoth}
                        Shellcode generation tool: donut (default), pe2sh, rc4, amber or
                        shoggoth
  -sd, --star_dust      Enable Stardust PIC generator, input should be .bin
  -sgn, --encode-sgn    Encode the generated shellcode using sgn tool.
  -e {uuid,xor,mac,ipv4,base45,base64,base58,aes,chacha,aes2,ascon}, --encoding {uuid,xor,mac,ipv4,base45,base64,base58,aes,chacha,aes2,ascon}
                        Encoding type: uuid, xor, mac, ip4, base64, base58 AES and aes2. aes2 is
                        a devide and conquer AES decryption to bypass logical path hijacking.
                        Other encoders are under development.
  -c {mingw,pluto,akira}, --compiler {mingw,pluto,akira}
                        Compiler choice: mingw (default), pluto, or akira
  -mllvm MLLVM          LLVM passes for Pluto or Akira compiler
  -obf, --obfuscate     Enable obfuscation of codebase (source code)
  -obf_api, --obfuscate-api
                        Enable obfuscation of API calls in ntdll and kernel32.
  -w [SYSWHISPER], --syswhisper [SYSWHISPER]
                        Optional: Use SysWhisper for direct syscalls. 1 for random syscall jumps
                        (default), 2 for compiling with MingW and NASM.
  -entropy {1,2}        Entropy level for post-processing the output binary. 1 for null_byte.py,
                        2 for pokemon.py
  -b [BINDER], --binder [BINDER]
                        Optional: Path to a utility for binding. Defaults to binder/calc.exe if
                        not provided.
  -wm [WATERMARK], --watermark [WATERMARK]
                        Add watermark to the binary (0 for False, 1 or no value for True)
  -s [SIGN_CERTIFICATE], --sign-certificate [SIGN_CERTIFICATE]
                        Optional: Sign the output binary and copy metadata from another binary
                        to your output. If a website or filepath is provided, use it. Defaults
                        to interactive mode if no argument is provided.

```


## Evasion Modules

![Evasion101 (1)](https://github.com/thomasxm/Boaz_beta/assets/44269971/e5fd38a1-fd95-47f9-a7b0-e85710596902)

![layered](https://github.com/user-attachments/assets/b42a7ab9-7a14-4b16-8538-df20a334e234)


## Process Injection Loaders

![Process_injection_101](https://github.com/thomasxm/BOAZ/assets/44269971/232e635b-b692-4010-a65d-e5ceb39c1e5e)


## New Memory Guard

<img width="400" alt="Sifu" src="https://github.com/user-attachments/assets/935ee41b-02cd-46dc-8d29-2fd67d365b7f">

### Introduction

Due to the prevalence of Kernel PatchGuard, System Service Descriptor Table (SSDT) hooking has become less popular among AV companies. Userland hooks and kernel callback inspection are the two main methods adopted by contemporary AVs.

### Userland Hooks

- **Description**:
  - Replace a syscall or API instruction opcode with a JMP-like instruction set to a trampoline code or memory page owned by the AV’s DLL.
  - Inspect the passed arguments and associated memory for suspicious byte patterns.
  - If non-suspicious bytes or a benign call stack are found, execute the replaced instructions and JMP back to the syscall location.
  - If suspicious bytes are found, terminate the process based on the heuristic score engine.
  - Trigger memory inspection via a kernel callback notification for process and thread creation, such as `PsSetCreateThreadNotifyRoutine`.

- **Various Hooking Methods**:
  - **IAT, EAT hooking**
  - **Virtual Table hooking**
  - **Inline hooking**
  - **Detour**
  - **Kernel mode hook**
  - **Software breakpoints** (page guard, error exception)
  - **Hardware breakpoints**

Marcus proposed using hardware breakpoints to set up the function arguments at the desired instructions. In their example, they set up debug registers Dr0 and Dr1 at syscall and return instructions to evade Sophos Intercept X, which was known to check the Rcx register’s value in case NtSetContextThread is called. Hardware breakpoints offer flexibility in setting breakpoints at arbitrary locations while having a single point of detection. 

### New Memory Guard Family: 

The aim is to make the shellcode "non-exist" to the AV as long as possible except when it is executed in a thread.

I intend to name this memory guard “Sifu memory guard” to pay tribute to the researchers who have shared their work with the community and passed their knowledge on.

#### Implementation

At Defcon32, a presentation was delivered on how to detect the abuse of VEH using the Volatility framework for post-execution analysis [51]. This research comprehensively covers the indicators of compromise (IoCs) that VEH can generate and proposed to be implemented within Volatility to enhance post-execution detection. New plug-in would monitor breakpoints (Dr0~Dr3) set at syscall addresses. It also tracks specific registers in VEH, including:
-	RAX
-	R10
-	RSP
-	RIP
-	RCX

  When combined with Ollie’s research on VEH, additional IoCs emerge, such as CrossProcessFlags in the PEB, register changes within the VEH handler for the thread context, and the presence of a custom handler in the LdrpVectorHandlerList in ntdll.dll, which is a doubly linked list [52]. Each entry in this list contains a pointer to the VEH handler that manages exceptions, protected by an encoding scheme involving shift and XOR operations, as used by RtlEncodePointer [53].

  To mitigate the risk of data corruption attacks on VEH, Microsoft (MS) has moved the storage of VEH and Vectored Continue Handling (VCH) lists to the .mrdata section in Windows 10-11 and the .rdata section in Windows Server. These are read-only memory regions. Thus, manually adding a VEH to the lists would necessitate modifying memory through either Return Oriented Programming (RoP) or direct syscalls, both of which are alert-worthy actions. However, VEH is not validated for chain integrity with dummy VEH entries and does not require RoP to execute arbitrary code. As demonstrated by syscall tampering techniques in [54], all execution can occur within the exception handler itself.

  Microsoft’s decision is based on performance considerations: “Due to performance concerns, the OS/Application cannot move all critical data into kernel space. In most cases, such user-space data will be protected by either the 'read-only' memory attribute (such as the PE module’s import/export table sections and the .mrdata section of ntdll.dll) or simple encoding (RtlEncodePointer)” [32]. 

  Despite the IoCs pointed out in [51], such as changes to registers (RCX, RIP, R10, RAX, Dr0 to Dr7) within VEH, there are still novel ways to evade detection. First, inspecting breakpoints (BPs) post-execution is ineffective, as breakpoints can be removed before executing shellcode within VEH or VCH they triggered. Secondly, a straightforward way to bypass VEH inspection is to exploit the calling sequence and priority of handlers. If a page guard is set at an arbitrary location and all available exception handlers are set, the handlers will be triggered by and in the sequence: PG → VEH → SEH → UEH → VCH. However, this sequence is not entirely rigid; each exception handler in the chain can either manage the exception or pass it on to the next handler.


![Picture 2](https://github.com/user-attachments/assets/bec1f6f1-07fb-4e6c-88d7-48f922c84ba6)
**Figure: Simplified exception handling priority**

  As shown in Figure above, if VEH indicates that the exception has been handled, it will not be passed to SEH, but handled exception will be passed to VCH. If VEH does not handle the exception, it will be passed to SEH. If none of SEH's exception handling functions can handle the exception, the default top level SEH (which is essentially UEH, but the method belongs to SEH) handling function will be called. If SEH handles the exception and starts executing from except, it will no longer pass the exception to VCH. If SEH returns execution to the point where the exception was raised, VCH will be called before the return. AddVectoredContinueHandler registers a handler that is called after the system has processed the exception, and just before the system performs any default post-exception cleanup. This allows custom logic to be executed after exception handling but before process continuation  

  In Figure below, when a CPU exception occurs, the kernel invokes the KiDispatchException function (ring 0), which passes the exception to the KiUserExceptionDispatcher method in ntdll (ring 3). This method then calls RtlDispatchException, attempting to handle the exception through the Vectored Exception Handler (VEH). It traverses the VEH handler list using RtlCallVectoredHandlers, invoking each handler until one returns EXCEPTION_CONTINUE_EXECUTION. If a handler returns this status, the RtlCallVectoredContinueHandlers function is invoked, which calls all continue exception handlers.

  In the second half of Figure below, both RtlAddVectoredContinueHandler and RtlAddVectoredExceptionHandler call the same function, RtlpAddVectoredHandler, with the r8 register containing 1 for VCH and 0 for VEH. 
 
 

![image22](https://github.com/user-attachments/assets/a7769670-a8d8-482c-9066-fa3195ba0a60)
![image23](https://github.com/user-attachments/assets/b306bf7e-348a-4976-8f2b-487bbfe50c0e)


**Figure: Exception path of exceptions**

  Taking all this into account, once VEH and VCH are set, VEH can perform benign activities and return EXCEPTION_CONTINUE_EXECUTION, handing control over to VCH to perform tasks such as decrypting shellcode and redirecting execution flow by modifying the stack register. This method evades detection by scanners or post-execution forensic tools that specifically search for IoCs within VEH. Furthermore, VCH can be used to set and unset hardware breakpoints and modify volatile registers after use.

  The proposed future implementation of Volatility only inspects RCX as the "start address of thread creation" in VEH [51]. However, kernel32!BaseThreadInitThunk uses the RDX register to store the function address, which Volatility does not currently inspect.

  This is likely to improve with the publication of this memory guard technique. Nonetheless, custom VEH and VCH handlers added to the LdrpVectorHandlerList can be manually unlinked within exception handlers before shellcode execution by locating them in the .rdata section of ntdll.dll, which resides at a fixed location depending on the architecture (x64 or x86). The 0xc value, representing both VEH and VCH from CrossProcessFlags in the PEB, can also be removed within the exception handler, leaving no digital forensic artifacts except the working sets for post-execution detection.

  GuLoader, notably, has employed various methods to trigger an exception handled by the first VEH, such as EXCEPTION_INT_DIVIDE_BY_ZERO or EXCEPTION_ILLEGAL_INSTRUCTION. Setting debug registers using NtThreadSetContext is considered suspicious by EDR and antivirus products. Therefore, a page guard can be used instead to trigger the first exception. A page guard can be set on the first byte of an arbitrary function to trigger an exception STATUS_GUARD_PAGE_VIOLATION, which is then handled by the exception handler, allowing it to manage the thread context and set the debug registers.

  Page guards automatically unset themselves after being triggered and are extremely common in legitimate Windows processes. In Figure below, a small program enumerates all Windows processes and determines which ones have page guards enabled, as well as how many page guard regions each process contains. The results show that 198 processes have page guards set, with an average of 12.32 regions per process. Given this frequency, it is not feasible for EDRs to scan Windows processes for suspicious page guards regularly. Consequently, we can use the sequence: PG (Page Guard) → VEH → VCH, or PG → UEH (SetUnhandledExceptionFilter) → VCH, to achieve stealthy code execution or memory guard.

  Alternatively, after setting PAGE_NOACCESS on our shellcode, we can directly invoke it using any function, such as NtCreateThreadEx. This will trigger a STATUS_ACCESS_VIOLATION (0xC0000005) exception, which can be handled by VEH  VCH. The shellcode’s page permissions can then be changed back to PAGE_EXECUTE_READ once control flow reaches kernel32!BaseThreadInitThunk.

 ![image29](https://github.com/user-attachments/assets/a8cb9fed-2c9c-40a5-9075-a6dfd6b255d0)
**Figure: Page Guard enumeration on Windows processes**

  In the following procedure, an exception handler combo enables code execution:
•	Set up a page guard on NtCreateThreadEx or any functions that can create a thread at a decoy address.
•	Use RtlAddVectoredExceptionHandler and RtlAddVectoredContinueHandler to set up VEH and VCH handlers. Or manually insert the handler lists. 
•	When STATUS_GUARD_PAGE_VIOLATION is handled within our custom VEH handler, we do some housekeeping and do not modify anything. Housekeeping includes anti-debugging techniques or confirm we are in the right thread by comparing thread ID.  
•	When the control is passed to VCH custom handler, we set up hardware breakpoints on debug registers from Dr0 to Dr3 at ntdll!RtlUserThreadStart and or Kernel32!BaseThreadInitThunk, and then set up the local registers on Dr7, the control register. Alternatively, we can only set-up one debug register and in the next breakpoint set up the following ones. 
•	We can apply encryption to real start address, and changing its memory protection to PAGE_NOACCESS before the first handler. Alternatively, when ntdll!RtlUserThreadStart has Rcx pointed to decoy start address. 
•	In the last exception passed to VCH before BaseThreadInitThunk is proceeded to the last step, unset the debug registers, and VEH, VCH handlers by set he CrosssProceeFlag to 0x0. 
•	At Kernel32!BaseThreadInitThunk and inside the VCH handler, we can apply decryption to the real start address, changing its memory protection to PAGE_EXECUTE_READ when Kernel32!BaseThreadInitThunk has Rdx pointing to the decoy start address. Then, change Rdx to the real start address and continue execution. 
•	Return any NTSTATUS values we prefer to the calling function. 
•	The relationship between VEH, SEH, UEH, and VCH in Windows Exception Handling when an exception is handled by the user: PG → VEH → SEH → UEH → VCH. 
•	Hardware debug registers can be set within any of the handlers we choose, whether VEH or VCH. This makes the technique so flexible that detections looking for changes to registers within the exception thread context in VEH may not identify any IoCs, as all the changes have been made inside VCH following VEH.
•	This technique does not use NtGetContextThread or NtSetThreadContext, thus avoiding detection on those two functions. 
•	To ensure continuous execution, our shellcode have to end with return value of EXECEPTION_CONTINUE_SEARCH. 
•	We can either remove our handler within our exception handler or within our executed shellcode to clean up the traces. This will clean up the TEB PEB CrossProcessFlag for 0x4 and 0x8 bits. 


<img width="800" alt="image30" src="https://github.com/user-attachments/assets/c7037f31-ade6-496e-8ef8-1e87e693da71" />
**Figure:VEH & VCH Scanner by NCC Group**



<img width="1549" alt="image31" src="https://github.com/user-attachments/assets/ff50a59c-f5f9-4511-ac20-fc18052dc7fb" />
**Figure:VEH & VCH detected in target process before execution**


<img width="1529" alt="image32" src="https://github.com/user-attachments/assets/c66cf57f-8e02-4c54-ab67-074610583547" />
**Figure:VEH & VCH manually removed inside VCH**

Three Figures above illustrated that VEH and VCH can be detected by the exception handler scanner developed by NCC Group. However, after manually removing the CrossProcessFlag from the PEB and unlinking the handlers from the doubly linked handler lists inside the exception handler, the scanner can no longer detect VEH and VCH, even before shellcode execution. In fact, removing the CrossProcessFlag is sufficient to eliminate the presence of VEH without unlinking the handler lists. If an EDR or antivirus memory scanner searches for VEH at any time except between its manual insertion and before code execution, it will not detect VEH. Even if it does, no alert is raised, as VEH does not modify any registers. 

Additionally, a DLL Bomb technique can be used as follows:
•	Generate source code with a DllMain function that contains a function to be called in the case of DLL_PROCESS_ATTACH. 
•	Once the DLL is loaded into the target process, the function will register a VEH and VCH handler in the handler lists. 
•	The function will then encrypt the shellcode region aligned with memory pages of 4096 bytes in the .text section and changes the memory pages to PAGE_NOACCESS. 
•	The VEH and VCH handlers contain code that decrypts the shellcode, changes the .text section back to PAGE_EXECUTE_READ, and executes the code. At the end of VCH, the pages are re-encrypted and the handlers deregistered.
•	The VEH and VCH handlers can implement protection mechanisms, such as anti-debugging techniques and access authorisation checks. For instance, the VEH handler may verify that the e/rip register points to authorised memory by comparing it with a hard-coded pointer to an encrypted memory address. It can also check specific registers to validate argument values. 
•	An attacker can execute the shellcode by setting a page guard at a decoy address and calling any API function that accesses that memory region. Common functions for triggering the page guard include NtCreateThreadEx or ReadProcessMemory. 
 
![Uploading image33.png…]()


Manually inserting handler lists generates modified code IoCs that are visible to tools like Moneta before shellcode execution. Detection logic can also be developed to detect writes to VEH and VCH handler lists in ntdll.dll at a fixed offset from the base address. Using RtlAddVectoredExceptionHandler and RtlCallVectoredHandlers, however, risks triggering antivirus or EDR hooks. Continuous monitoring of the CrossProcessFlag changes from the start of the process execution in the absence of RtlAddVectoredExceptionHandler could also be detected, although this is expensive and may be impractical.
  

### x64 Calling Convention

- First four arguments of a callee function: `Rcx`, `Rdx`, `R8`, and `R9`.
- Additional arguments stored on the stack starting from `(Rsp + 0x28)`.


## A new threadless process injection primitive (Coming soon...)




## Example:

Boaz evasion wrapped Mimikatz.exe x64 release. The detection rate for wrapped Mimikatz is zero on Jotti: 

<img width="1197" alt="Screenshot 2024-02-28 at 14 46 17" src="https://github.com/user-attachments/assets/312fdffe-7024-4e21-8830-07bcea3004c9">



## Roadmap

- **Docker**: Make it available with Docker without installation
- **Add a GUI for users**: Web UI or Python UI.
- **Loaders**: Implement more loader templates (process injection and code execution methods) with a divide and conquer option available.
- **Rust**: Loader should be language agnostic. Rust loader would be a good choice. 
- **COFF loaders**: Implement COFF loader suppport.
- **RISC-V VM** Implement new loader using RISC-V VM concept. 
- **Obfuscation**: Enhancing obfuscation methods and integrating new LLVM passes. 
- **Shellcode Generation**: Expand to include more techniques, e.g., PIC generated from arbitrary command, and offer users the choice of shellcode generation technique.
- **PIC Chain Reactions**: ....
- **Sleep Techniques**: Implementing additional anti-emulation and sleep techniques, like encrypting heap and stack while sleeping during pre-shellcode-execution phase. 
- **Syscall**: Improving Syswhisper2 integration for signature reduction. (e.g. on detecting virtual machine introspection and dynamic binary instrumentation)
- **Compilation**: Integrate additional compiler options like Cosmopolitan compiler.
- **File format**: Extend more file format supports, so that user can execute sample with signed utilities and more options.
- **modularised modules**: Although Boaz has all its implementations modularised in concept, it is not 'actually' modularised in its current beta version. Owing to the fact that this tool is a side project for my dissertation, I need to find time to separate each function into an actual module and ensure that each is presented with a template so that users can add a new technique and integrate it into the main program without the need to change the main program or other modules.
- **Templates**: using YAML and JSON files to configure and modularise the program. 

## Contributing

We welcome contributions to improve the Boaz Evasion Tool. Please review `CONTRIBUTING.md` for guidelines on how to submit contributions. 


We welcome submissions to [pull requests](https://github.com/thomasxm/Boaz_beta/pulls) and [issues](https://github.com/thomasxm/Boaz_beta/issues).


This is in development, please feel free to reach out to me @thomasmeeeee on X for any suggestions! 

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

A special thanks to the researchers and developers whose work has inspired, contributed to, and made this tool possible. 
All credit goes to the original authors of the techniques and tools: 

* [Inceptor - Bypass AV-EDR solutions combining well known techniques](https://github.com/klezVirus/inceptor/blob/main/slides/Inceptor%20-%20Bypass%20AV-EDR%20solutions%20combining%20well%20known%20techniques.pdf)

* [The donut](https://github.com/TheWover/donut)

* [avcleaner](https://github.com/scrt/avcleaner)

* [Pluto](https://github.com/bluesadi/Pluto)

* [Arkari](https://github.com/KomiMoe/Arkari)

* [pe_to_shellcode](https://github.com/hasherezade/pe_to_shellcode)
* [Shellcode-Hide](https://github.com/SaadAhla/Shellcode-Hide)

* [PE2Shellcode](https://github.com/r00tkiter/PE2Shellcode)
* [Amber](https://github.com/thomasxm/amber)
* [Shoggoth](https://github.com/frkngksl/Shoggoth)
* [Mangle](https://github.com/optiv/Mangle)
* [CallObfuscator](https://github.com/d35ha/CallObfuscator)
* [Stardust](https://github.com/Cracked5pider/Stardust/tree/main)
* [Carbon Copy](https://github.com/paranoidninja/CarbonCopy)
* [Shikata ga nai](https://github.com/EgeBalci/sgn)
* [x86matthew](https://www.x86matthew.com/)
* [DarkLoadLibrary](https://github.com/bats3c/DarkLoadLibrary)
* [Red Team Notes](https://www.ired.team/)

And many more blogs and articles. Please feel free to add more...

## Contact

For any queries or contributions, please contact the repository owner.










![Boaz_logo3](https://github.com/thomasxm/Boaz_beta/assets/44269971/0118a0cf-9cd9-48df-8f20-37a059e4bf6a)





































