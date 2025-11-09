---
title: Infobahn CTF 2025/rev-disthis
date: 2025-10-27
authors:
    - wrenches
visible: true # change this to true to view locally; change to false before pushing
---

I enjoyed this challenge a lot, here's a writeup about how I solved it by using an obscure Python debugging feature to dump the stack + instructions of a `.pyc` file, named `LLTRACE`.

# `rev/disthis`

> Sillymaxxing.
>
> Tested to run on the python:3.13.8-slim docker image.
>
> Solves: 12
>
> Author: oh-word

It's a `.pyc` file (compiled Python bytecode). Some background: Python has its own special stack-based Python interpreter that forms the basis for all program functionality - when we run some Python `.py` file, the Python interpreter converts each function, statement, expression, etc. into its corresponding Python bytecode representation, and executes it.

```ansi
[22;1;32mnavi@curette[22;39m ([22;1;34m-work/infobahn/re/disthis[22;39m) > [36mpython[39m [22;1moutput.pyc[22m     
Your flag file > slight_smile :)
Traceback (most recent call last):
  File "/chal/check.py", line -1, in debug_func
FileNotFoundError: [Errno 2] No such file or directory: 'slight_smile :)'
```

In terms of actual program functionality, it's just a flag checker: it asks for a filename, reads the contents of that file, and then performs a series of checks to validate the contents.


It's quite difficult to debug this! We can't naively dump the stack or step back and forth between instructions without doing a lot of legwork. To get a better handle of what's going on during program execution, we can compile Python with debug symbols and use [LLTRACE]([https://groups.google.com/g/dev-python/c/LBAoguBxD6Y), which provides a step-by-step dump of each instruction call, _and_ the stack layout (represented as a list) on every instruction. This feature is barely even documented! I only stumbled across it by poking around at the actual CPython source, seeing a function named `dump_stack` and going.. eh... huh? Can like that ah...
 
To break kayfabe for a moment: dude this shit is an actual lifesaver. I can't imagine solving the challenge without it. I've tried to write my own obfuscated `.pyc` reversing challenges and it is an absolutely infuriating undertaking. If you want to dump the stack you just have to patch in early `RETURN_VALUE` calls and hope the temperament of the Python interpreter smiles upon you or something so it doesn't segfault. Dealing with `.pyc` files is a nightmare and is a _significant_ source of difficulty for this challenge (given that the actual flag checking functionality is not so bad).

### GETTING OUTPUT

The LLTRACE output is what we'll be working with. First, we'll need a version of Python with debug symbols such that we can enable it. The challenge informs us of the Python version used (3.13.8), so we grab it.

```ansi
[22;1;32mnavi@curette[22;39m ([22;1;34m-work/infobahn/re/disthis[22;39m) > [36mcurl[39m [32m-X[39m GET https://www.python.org/ftp/python/3.13.8/Python-3.13.8.tar.xz [32m-o[39m [22;1mpython-3.13.8.tar.xz
[22m  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 21.6M  100 21.6M    0     0  24.5M      0 --:--:-- --:--:-- --:--:-- 24.5M
                                                                                                                                       
[22;1;32mnavi@curette[22;39m ([22;1;34m-work/infobahn/re/disthis[22;39m) > [36mtar[39m [32m-xvf[39m [22;1mpython-3.13.8.tar.xz[22m [22;1;34m1>[39m/dev/null
[22m                                                                                                                                    
[22;1;32mnavi@curette[22;39m ([22;1;34m-work/infobahn/re/disthis[22;39m) > [36mls
[39magain.txt  block_parser.py  extract.py  [22;1;31moutput_1.gz[22;39m  [22;1;35moutput.png[22;39m  output_with_colors.txt  patch.py  [22;1;34mPython-3.13.8[22;39m         sample.txt
a.pkl      [22;1;35mbroken.png[22;39m       flag.txt    [22;1;31moutput.gz[22;39m    output.pyc  parser.py               [22;1;31;40mpython[22;39;49m    [22;1;31mpython-3.13.8.tar.xz
```

Then, we `./configure` with debug enabled and run `make`:

```ansi
[22;1;32mnavi@curette[22;39m ([22;1;34m/re/disthis/Python-3.13.8[22;39m) > [36m./configure[39m [32m--with-pydebug[39m                                   
checking build system type... x86_64-pc-linux-gnu
checking host system type... x86_64-pc-linux-gnu
checking for Python interpreter freezing... ./_bootstrap_python
checking for python3.13... python3.13
checking Python for regen version... Python 3.13.5
checking for pkg-config... /usr/bin/pkg-config
checking pkg-config is at least version 0.9.0... yes
...
...

[22;1;32mnavi@curette[22;39m ([22;1;34m/re/disthis/Python-3.13.8[22;39m) > [36mmake[39m [32m-j8[39m

gcc -c -fno-strict-overflow -Wsign-compare -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g -Og -Wall    -std=c11 -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wstrict-prototypes -Werror=implicit-function-declaration -fvisibility=hidden  -I./Include/internal -I./Include/internal/mimalloc  -I. -I./Include    -DPy_BUILD_CORE -o Programs/python.o ./Programs/python.c
gcc -c -fno-strict-overflow -Wsign-compare -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g -Og -Wall    -std=c11 -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wstrict-prototypes -Werror=implicit-function-declaration -fvisibility=hidden  -I./Include/internal -I./Include/internal/mimalloc  -I. -I./Include    -DPy_BUILD_CORE -o Parser/token.o Parser/token.c
gcc -c -fno-strict-overflow -Wsign-compare -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -g -Og -Wall    -std=c11 -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -Wstrict-prototypes -Werror=implicit-function-declaration -fvisibility=hidden  -I./Include/internal -I./Include/internal/mimalloc  -I. -I./Include    -DPy_BUILD_CORE -o Parser/pegen.o Parser/pegen.c
```


Now that we have our debug build, we just set `__lltrace__ = True` and let it run.

```py
import marshal, dis, opcode
__lltrace__ = True
with open("output.pyc", "rb") as f:
    header = f.read(16)  # skip pyc header
    code_obj = marshal.load(f)
exec(code_obj)
```

Let's just run it:

```ansi
[22;1;32mnavi@curette[22;39m ([22;1;34m-work/infobahn/re/disthis[22;39m) > [36m./python[39m [22;1mpatch.py
```
```python
    stack=['l', 'w', 227, 129, 230, 104, 101, 'F', 65, 160, 44, 'g', 'v', '5', 26, 'r', 188, '}', 207, 'a', 9, 153, 'G', 115, 'T', 144, 88, 170, 8, 80, 5, 'E', 68, 4, '7', 54, 'q', '"', 159, '\\', 0, 51, 118, 251, 185, 90, 234, 141, 152, 239, 191, 105, 255, 173, 'D', 6, 189, 107, 76, 197, 120, '|', 60, 138, 82, 210, '%', 71, 'N', 163, '*', 'X', 145, '`', 57, 'M', 172, 206, 'K', 'I', 'C', '{', 156, 244, 'W', 56, 7, 165, 46, 218, 39, 133, 204, 'n', 187, 66, 45, 58, 243, '3', 55, 143, 196, 169, 246, 81, 161, 123, 22, 24, 121, 11, 12, 174, 182, 'Y', 116, 96, 109, 233, 162, 91, 149, "'", 47, 131, 254, 241, 25, 36, 135, 59, 69, '$', 37, 209, 'e', 112, ' ', 229, 92, 154, '=', 238, 216, 'A', 102, 217, '?', 83, 166, 89, 117, 53, 151, 84, 253, 10, 'L', 'x', 126, 'J', 2, 247, 122, 67, 99, 177, 221, 147, '&', 103, '6', 30, 3, 94, 183, 79, 236, 27, 201, 195, 242, 'f', 93, '^', 'R', ',', 'y', 70, 'z', 171, 'o', 223, 179, 1, 73, 23, '+', '.', 61, 214, 199, 'b', '(', '4', '<', 97, 232, 86, '/', 136, 220, 148, 124, 137, 35, 'H', 119, 228, 181, 178, 's', 18, 175, 'm', 16, ';', 193, 42, 192, 'd', 31, 21, 87, 203, 249, 184, 155, 235, ']', 't', 150, 114, 208, 'Q', 14, 231, 128, 'O', 29, 'c', 'S', 38, 113, '2', 'P', '-', 'i', 13, '_', 252, 186, 62, 64, 222, 226, 40, 28, 194, '#', 180, ':', '[', 132, 215, 248, 'j', '@', 110, 205, 95, '0', 142, 98, 240, 250, 78, 139, 202, 157, 63, 43, 130, 17, 213, 'p', '1', 'Z', 168, 41, 245, 77, 140, 125, 127, 74, 15, 111, 48, 'h', 20, 190, 'V', 134, 33, 198, 50, 52, 106, '!', 108, 158, 'k', 100, 75, 146, 'u', 32, 200, 211, 72, 225, '8', '>', 164, ')', 224, 'B', 219, 237, 212, '9', 167, 176, 'U', 34, 85, 49, 19, '~', None, None, None, None, None, <builtin_function_or_method at 0x7f3561ce2990>, <nil>, <builtin_function_or_method at 0x7f3561c932f0>, <nil>, 'Y', 'o', 'u', 'r', ' ', 'f', 'l', 'a', 'g', ' ', 'f', 'i', 'l', 'e', ' ', '>', ' ']
1004: BUILD_STRING 17
    stack=['l', 'w', 227, 129, 230, 104, 101, 'F', 65, 160, 44, 'g', 'v', '5', 26, 'r', 188, '}', 207, 'a', 9, 153, 'G', 115, 'T', 144, 88, 170, 8, 80, 5, 'E', 68, 4, '7', 54, 'q', '"', 159, '\\', 0, 51, 118, 251, 185, 90, 234, 141, 152, 239, 191, 105, 255, 173, 'D', 6, 189, 107, 76, 197, 120, '|', 60, 138, 82, 210, '%', 71, 'N', 163, '*', 'X', 145, '`', 57, 'M', 172, 206, 'K', 'I', 'C', '{', 156, 244, 'W', 56, 7, 165, 46, 218, 39, 133, 204, 'n', 187, 66, 45, 58, 243, '3', 55, 143, 196, 169, 246, 81, 161, 123, 22, 24, 121, 11, 12, 174, 182, 'Y', 116, 96, 109, 233, 162, 91, 149, "'", 47, 131, 254, 241, 25, 36, 135, 59, 69, '$', 37, 209, 'e', 112, ' ', 229, 92, 154, '=', 238, 216, 'A', 102, 217, '?', 83, 166, 89, 117, 53, 151, 84, 253, 10, 'L', 'x', 126, 'J', 2, 247, 122, 67, 99, 177, 221, 147, '&', 103, '6', 30, 3, 94, 183, 79, 236, 27, 201, 195, 242, 'f', 93, '^', 'R', ',', 'y', 70, 'z', 171, 'o', 223, 179, 1, 73, 23, '+', '.', 61, 214, 199, 'b', '(', '4', '<', 97, 232, 86, '/', 136, 220, 148, 124, 137, 35, 'H', 119, 228, 181, 178, 's', 18, 175, 'm', 16, ';', 193, 42, 192, 'd', 31, 21, 87, 203, 249, 184, 155, 235, ']', 't', 150, 114, 208, 'Q', 14, 231, 128, 'O', 29, 'c', 'S', 38, 113, '2', 'P', '-', 'i', 13, '_', 252, 186, 62, 64, 222, 226, 40, 28, 194, '#', 180, ':', '[', 132, 215, 248, 'j', '@', 110, 205, 95, '0', 142, 98, 240, 250, 78, 139, 202, 157, 63, 43, 130, 17, 213, 'p', '1', 'Z', 168, 41, 245, 77, 140, 125, 127, 74, 15, 111, 48, 'h', 20, 190, 'V', 134, 33, 198, 50, 52, 106, '!', 108, 158, 'k', 100, 75, 146, 'u', 32, 200, 211, 72, 225, '8', '>', 164, ')', 224, 'B', 219, 237, 212, '9', 167, 176, 'U', 34, 85, 49, 19, '~', None, None, None, None, None, <builtin_function_or_method at 0x7f3561ce2990>, <nil>, <builtin_function_or_method at 0x7f3561c932f0>, <nil>, 'Your flag file > ']
1006: CALL 1
```

First things first: this is still remarkably ugly. For some reason there is a _lot_ of ugly nonsense in the stack? I'm not sure if this is challenge-specific obfuscation or just typical Python nonsense (I highly suspect the latter). If we squint, however, we can see objects of interest at the _very_ tail end of the stack:

```python
stack = [
...<builtin_function_or_method at 0x7f3561ce2990>, 
<nil>, 
<builtin_function_or_method at 0x7f3561c932f0>, 
<nil>, 
'Your flag file > '
]
1006: CALL 1
```

Consulting the documentation for [dis](https://docs.python.org/3/library/dis.html):

> CALL(argc)
> Calls a callable object with the number of arguments specified by argc. On the stack are (in ascending order):
> 
> The callable
>
> self or NULL
>
> The remaining positional arguments
>
> argc is the total of the positional arguments, excluding self.
>
> CALL pops all arguments and the callable object off the stack, calls the callable object with those arguments, and pushes the return value returned by the callable object.

Staring at the bottom of our stack, we can see that there are three objects: some `<builtin function>`, `NULL`, and the string that forms our input prompt `Your flag file > `. We can then see how that `CALL` corresponds to our `input()` call, which is neat.

Of course, the main program functionality happens _after_ that. For now let's just write something to dump all the calls in a nicer format. I just asked the LLM of my choice to write an `awk` command to filter out every stack printout to the last 50 or so characters (forgive me, I'm a cringe zoomer who never learned `awk`):

```ansi
[22;1;32mnavi@curette[22;39m ([22;1;34m-work/infobahn/re/disthis[22;39m) > [36m./python[39m [22;1m./patch.py[22m [22;1;34m|[22;39m [36mawk[39m [33m'/stack=/ [22;1;34m{[22;33mline = $0; if [22;1;32m([22;33mmatch[22;1;35m([22;33mline, /stack=\[22;1m[[22m.*\[22;1m][22m/[22;1;35m)[32m)[22;33m [22;1;32m{[22;33mstack_part = substr[22;1;35m([22;33mline, RSTART, RLENGTH[22;1;35m)[22;33m; if [22;1;35m([22;33mlength[22;1m([22mstack_part[22;1m)[22m > 50[22;1;35m)[22;33m [22;1;35m{[22;33mprint substr[22;1m([22mstack_part, length[22;1;36m([22;33mstack_part[22;1;36m)[22;33m-49[22;1m)[35m}[22;33m else [22;1;35m{[22;33mprint stack_part[22;1;35m}[32m}[22;33m next[22;1;34m}[22;33m 1'
```
This works pretty neat:

```python
986: LOAD_FAST 183
 'o', 'u', 'r', ' ', 'f', 'l', 'a', 'g', ' ', 'f']
988: EXTENDED_ARG 1
 'o', 'u', 'r', ' ', 'f', 'l', 'a', 'g', ' ', 'f']
990: LOAD_FAST 258
 'u', 'r', ' ', 'f', 'l', 'a', 'g', ' ', 'f', 'i']
992: LOAD_FAST 0
 'r', ' ', 'f', 'l', 'a', 'g', ' ', 'f', 'i', 'l']
994: LOAD_FAST 136
 ' ', 'f', 'l', 'a', 'g', ' ', 'f', 'i', 'l', 'e']
996: LOAD_FAST 138
 'f', 'l', 'a', 'g', ' ', 'f', 'i', 'l', 'e', ' ']
998: EXTENDED_ARG 1
 'f', 'l', 'a', 'g', ' ', 'f', 'i', 'l', 'e', ' ']
1000: LOAD_FAST 334
 'l', 'a', 'g', ' ', 'f', 'i', 'l', 'e', ' ', '>']
1002: LOAD_FAST 138
 'a', 'g', ' ', 'f', 'i', 'l', 'e', ' ', '>', ' ']
1004: BUILD_STRING 17
od at 0x7f6439ba72f0>, <nil>, 'Your flag file > ']
1006: CALL 1
```

After putting in any random filename:

```py
1342: EXTENDED_ARG 1
e5e68a7a10>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <dict at 0x7fcbbfc3a9f0>]
1344: LOAD_FAST 258
a7a10>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <dict at 0x7fcbbfc3a9f0>, 'i']
1346: LOAD_FAST 93
>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <dict at 0x7fcbbfc3a9f0>, 'i', 'n']
1348: LOAD_FAST 241
 None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <dict at 0x7fcbbfc3a9f0>, 'i', 'n', 't']
1350: BUILD_STRING 3
a10>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <dict at 0x7fcbbfc3a9f0>, 'int']
1352: BINARY_SUBSCR
e5e68a7a10>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <type at 0x55e5e6767fe0>]
1356: PUSH_NULL
a10>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <type at 0x55e5e6767fe0>, <nil>]
1358: EXTENDED_ARG 1
a10>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <type at 0x55e5e6767fe0>, <nil>]
1360: LOAD_FAST 297
 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <type at 0x55e5e6767fe0>, <nil>, '1']
1362: BUILD_STRING 1
 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, <type at 0x55e5e6767fe0>, <nil>, '1']
1364: CALL 1
19, '~', <bytes at 0x55e5e68a7a10>, 0, None, None, None, None, <Quitter at 0x7fcbbfbc7b80>, <nil>, 1]
1372: CALL 1
Incorrect :(
```

This is still really verbose. We can't tell what condition is triggered for the check to even occur. There has to be some conditional somewhere, and consulting the `dis` documentation once more we see that there's a lot of opcodes for `JUMP` instructions: let's just grep for those...

```ansi
[22;1;32mnavi@curette[22;39m ([22;1;34m-work/infobahn/re/disthis[22;39m) > [36m./python[39m [22;1m./patch.py[22m [22;1;34m|[22;39m [36mawk[39m [33m'/stack=/ [22;1;34m{[22;33mline = $0; if [22;1;32m([22;33mmatch[22;1;35m([22;33mline, /stack=\[22;1m[[22m.*\[22;1m][22m/[22;1;35m)[32m)[22;33m [22;1;32m{[22;33mstack_part = substr[22;1;35m([22;33mline, RSTART, RLENGTH[22;1;35m)[22;33m; if [22;1;35m([22;33mlength[22;1m([22mstack_part[22;1m)[22m > 100[22;1;35m)[22;33m [22;1;35m{[22;33mprint substr[22;1m([22mstack_part, length[22;1;36m([22;33mstack_part[22;1;36m)[22;33m-100[22;1m)[35m}[22;33m else [22;1;35m{[22;33mprint stack_part[22;1;35m}[32m}[22;33m next[22;1;34m}[22;33m 1'[39m [22;1;34m|[22;39m [36mgrep[39m [33m'JUMP'
stack=[<dict at 0x7f01ebe66210>, '[22;1;31mJUMP[22;39m_BACKWARD']
stack=[<dict at 0x7f01ebe66210>, '[22;1;31mJUMP[22;39m_BACKWARD_NO_INTERRUPT']
stack=[<dict at 0x7f01ebe66210>, '[22;1;31mJUMP[22;39m_FORWARD']
stack=[<dict at 0x7f01ebe66210>, 'POP_[22;1;31mJUMP[22;39m_IF_FALSE']
stack=[<dict at 0x7f01ebe66210>, 'POP_[22;1;31mJUMP[22;39m_IF_NONE']
stack=[<dict at 0x7f01ebe66210>, 'POP_[22;1;31mJUMP[22;39m_IF_NOT_NONE']
stack=[<dict at 0x7f01ebe66210>, 'POP_[22;1;31mJUMP[22;39m_IF_TRUE']
stack=[<dict at 0x7f01ebe66210>, 'INSTRUMENTED_[22;1;31mJUMP[22;39m_FORWARD']
stack=[<dict at 0x7f01ebe66210>, 'INSTRUMENTED_[22;1;31mJUMP[22;39m_BACKWARD']
stack=[<dict at 0x7f01ebe66210>, 'INSTRUMENTED_POP_[22;1;31mJUMP[22;39m_IF_TRUE']
stack=[<dict at 0x7f01ebe66210>, 'INSTRUMENTED_POP_[22;1;31mJUMP[22;39m_IF_FALSE']
stack=[<dict at 0x7f01ebe66210>, 'INSTRUMENTED_POP_[22;1;31mJUMP[22;39m_IF_NONE']
stack=[<dict at 0x7f01ebe66210>, 'INSTRUMENTED_POP_[22;1;31mJUMP[22;39m_IF_NOT_NONE']
stack=[<dict at 0x7f01ebe66210>, '[22;1;31mJUMP[22;39m']
stack=[<dict at 0x7f01ebe66210>, '[22;1;31mJUMP[22;39m_NO_INTERRUPT']
1206: POP_[22;1;31mJUMP[22;39m_IF_FALSE 91
1302: POP_[22;1;31mJUMP[22;39m_IF_FALSE 43
```

Let's check the lines above the `POP_JUMP`:

```python
'9', 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, True]
1190: COPY 1
67, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, True, True]
1192: TO_BOOL
67, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, True, True]
1200: NOP
67, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, True, True]
1202: NOP
67, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, True, True]
1204: NOP
67, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, True, True]
1206: POP_JUMP_IF_FALSE 91
```

Okay. A lot of nonsense, let's keep scrolling up...

```py
1018: BUILD_STRING 2
ne, None, None, None, None, <builtin_function_or_method at 0x7fbe3fb7a990>, <nil>, 'again.txt', 'rb']
1020: CALL 2
 176, 'U', 34, 85, 49, 19, '~', None, None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>]
1028: PUSH_NULL
U', 34, 85, 49, 19, '~', None, None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>]
1030: EXTENDED_ARG 255
U', 34, 85, 49, 19, '~', None, None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>]
1032: EXTENDED_ARG 65535
U', 34, 85, 49, 19, '~', None, None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>]
1034: EXTENDED_ARG 16777215
U', 34, 85, 49, 19, '~', None, None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>]
1036: LOAD_FAST -5
one, None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>]
1038: LOAD_FAST 11
None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'g']
1040: LOAD_FAST 136
 None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'g', 'e']
1042: LOAD_FAST 241
, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'g', 'e', 't']
1044: LOAD_FAST 19
e, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'g', 'e', 't', 'a']
1046: LOAD_FAST 241
ne, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'g', 'e', 't', 'a', 't']
1048: LOAD_FAST 241
_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'g', 'e', 't', 'a', 't', 't']
1050: LOAD_FAST 15
ufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'g', 'e', 't', 'a', 't', 't', 'r']
1052: BUILD_STRING 7
None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>, 'getattr']
```

Now this is a bit more substantial. We can observe a key part of the obfuscation in the bytecode: all strings are built character by character through nonsense with `LOAD_FAST` and `BUILD_STRING`, and resolved with strategic `getattr` and `BINARY_SUBSCR` calls. Note this specific `LOAD_FAST -5` call:

```python
1036: LOAD_FAST -5
one, None, None, None, None, <_io.BufferedReader at 0x7fbe3f47d610>, <nil>, <dict at 0x7fbe3fb2a9f0>]
```

This is a reference to Python's `globals()` dictionary. The way we access builtin functions like `len` is by building the string and indexing into that dictionary (note that in an actual program, there would simply be a reference to `len` stored somewhere in `co_consts`).

We can keep cutting through the chaff:

```python
1068: BUILD_STRING 4
builtin_function_or_method at 0x7fbe3fb2b0b0>, <nil>, <_io.BufferedReader at 0x7fbe3f47d610>, 'read']
1070: CALL 2
```

This is equivalent to `getattr(<our file>, 'read')`. We then call this function and store it at index `351`:

```python
1080: CALL 0
12, '9', 167, 176, 'U', 34, 85, 49, 19, '~', None, None, None, None, None, <bytes at 0x7fbe3f479a40>]
1088: EXTENDED_ARG 1
12, '9', 167, 176, 'U', 34, 85, 49, 19, '~', None, None, None, None, None, <bytes at 0x7fbe3f479a40>]
1090: STORE_FAST 351
237, 212, '9', 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, None, None, None, None]
1092: EXTENDED_ARG 255
237, 212, '9', 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, None, None, None, None]
1094: EXTENDED_ARG 65535
237, 212, '9', 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, None, None, None, None]
1096: EXTENDED_ARG 16777215
237, 212, '9', 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, None, None, None, None]
```

From here we can see that the `<bytes at ...>` object is our input text. Tracing the logic further...

```python
1104: LOAD_FAST 93
 19, '~', <bytes at 0x7fbe3f479a40>, None, None, None, None, <dict at 0x7fbe3fb2a9f0>, 'l', 'e', 'n']
1106: BUILD_STRING 3
 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, None, None, None, None, <dict at 0x7fbe3fb2a9f0>, 'len']
1108: BINARY_SUBSCR
', <bytes at 0x7fbe3f479a40>, None, None, None, None, <builtin_function_or_method at 0x7fbe3fb2b4d0>]
```

A reference to `len()` - we're finally getting some flag-checking logic...

```py
1170: LOAD_FAST 205
at 0x7fbe3f479a40>, 5, None, None, None, 5, <type at 0x55f0134f6fe0>, <nil>, '3', '9', '9', '4', '4']
1172: BUILD_STRING 5
19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 5, <type at 0x55f0134f6fe0>, <nil>, '39944']
1174: CALL 1
2, '9', 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 5, 39944]
```

We construct the string `39944` and create an integer and push it on the stack.

```python
1184: COPY 2
 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, 5, 39944]
1186: COMPARE_OP 103
'9', 167, 176, 'U', 34, 85, 49, 19, '~', <bytes at 0x7fbe3f479a40>, 5, None, None, None, 39944, True]
```

And finally, a `COMPARE_OP`. This first section is just checking if our flag text has length `39944`. So let's create a file of that size and run it.

### ACTUAL FLAG CHECKING LOGIC

This is where I began to run into size issues. The `LLTRACE` dump is fucking gigantic, and trying to pass it into `awk` would've crashed my computer. In the actual CTF I reached this point at around 4am - I realized that collecting every single call would take around an hour, so I just piped it into a `gzip` command and went to sleep. Without the compression the output's about 4GB.

(unfortunately I also compiled my debug build of Python with no optimizations, this is what we call a "skill issue"...)

The command takes around an hour or so to run, but afterwards we're left with a compressed version of all the output.

I wrote a simple script to stream the `gzip` decompression and print out the lines so we can investigate the logic.

```python
import gzip
from collections import deque

lines = 250000
with gzip.open("output.gz", "rt") as f:
    for idx, line in enumerate(f):
        if 'stack' in line:
            print(idx, 'stack > [...', line[-100:])
        else:
            print(idx, line)

        if idx > lines: exit()
```

The flag-checking logic is actually quite simple, it is just _extremely_ verbose. We start by putting the input bytes on the stack, followed by building an integer to serve as an index with the old `BUILD_STRING` nonsense. Then, we call `BINARY_SUBSCR` to get the character at that index. 

```python
4481 1474: LOAD_FAST 282
4482 stack > [... 39944, 0, None, None, 0, <bytes at 0x562d6c3fe5d0>, <type at 0x562d35383fe0>, <nil>, '0']
4483 1476: BUILD_STRING 1
4484 stack > [... 39944, 0, None, None, 0, <bytes at 0x562d6c3fe5d0>, <type at 0x562d35383fe0>, <nil>, '0']
4485 1478: CALL 1
4486 stack > [... 39944, 0, None, None, 0, <bytes at 0x562d6c3fe5d0>, 0]
4487 1486: BINARY_SUBSCR
4488 stack > [... 39944, 0, None, None, 0, 65]
```

The top of the stack now has our flag byte as a numerical value. Then, from here, we build mathematical operations, which are once again, Heavily Obfuscated...

```python
4521 1524: BUILD_STRING 3
4522 stack > [... 39944, 0, None, None, 0, 65, <type at 0x562d35383fe0>, <nil>, '196']
4523 1526: CALL 1
4524 stack > [... 39944, 0, None, None, 0, 65, 196]
4525 1534: BINARY_OP 12
4526 stack > [... 39944, 0, None, None, 0, 133]
```

(There's like fifty instructions between the two chunks above but these are the only actual relevant pieces.)

However we can see a call to `BINARY_OP`, which performs a certain operation according the argument, pops the two topmost values off the stack and pushes the result back on.

This goes on for quite a few more instructions...

```python
4591 1614: CALL 1
4592 stack > [... 39944, 0, None, None, 0, 204, 255]
4593 1622: BINARY_OP 1
4594 stack > [... 39944, 0, None, None, 0, 204]
```

Until we finally hit `COMPARE_OP` which pushes a boolean on the stack.

```python
4629 1662: CALL 1
4630 stack > [... 39944, 0, None, None, 0, 204, 148]
4631 1670: COMPARE_OP 72
4632 stack > [... 39944, 0, None, None, 0, False]
```

Naturally, that boolean is then added to a running tally (the `0` value directly below it on the stack):

```python
4633 1674: BINARY_OP 0
4634 stack > [... 39944, 0, None, None, 0]
```

Afterwards, there's a call to `STORE_FAST` to store and update our new value:

```python

4819 1910: COMPARE_OP 72
4820 stack > [... 39944, 0, None, None, 0, False]
4821 1914: BINARY_OP 0
4822 stack > [... 39944, 0, None, None, 0]
4823 1918: EXTENDED_ARG 1
4824 stack > [... 39944, 0, None, None, 0]
4825 1920: STORE_FAST 353
```

And we just keep going from here. At the very very end, we just compare the number of 'correct' bytes to the value `39944`.

```python
8461829 10718324: LOAD_FAST 352
8461830 stack > [... 39944, 134, None, None, 134, 39944]
8461831 10718326: COMPARE_OP 72
8461832 stack > [... 39944, 134, None, None, False]
```

As mentioned above, the logic is actually quite simple, and it is made a lot easier by the fact that we can see the stack. We can make a parser to parse each expression.

Unfortunately I am not a seasoned reverse engineer. I think for any good revver this is something that they could do with their eyes closed, but after getting to this point at around 1pm my time I still _really_ struggled with parsing and lifting the operations into something easier to deal with. I first chunked the output into blocks, knowing that we start and end with a `STORE_FAST` instruction:

```python
import gzip

START = "LOAD_FAST 353"
END   = "STORE_FAST 353"

def chunk_blocks_gz(filename):
    blocks = []
    current = []
    in_block = False

    with gzip.open(filename, "rt") as f:
        for line in f:
            raw = line.rstrip()
            if 'stack' in raw:
                raw = 'stack > [...' + raw[-150:]
            if START in raw:
                if in_block and current:
                    blocks.append(current)
                current = [raw]
                in_block = True
                continue

            if in_block:
                current.append(raw)

                if END in raw:
                    blocks.append(current)
                    print('\n\n\n', current, '\n\n\n')
                    current = []
                    in_block = False
                continue

            continue
    return blocks

import pickle
pickle.dump(chunk_blocks_gz('output.gz'), open('a.pkl', 'wb'))
```

I serialized it to disk for less of a headache. Then, we go through each block and parse the opcodes. A small caveat here: I don't think that the documentation for which opcode argument goes to which binary operation.. exists? At all? I just had to manually create a function and figure out the mapping myself:

```python
def generate_func():
    function_lines = []
    function_lines.append('def func(a, b):')
    function_lines.append(' c = []')
    for i in binary_op_names:
        function_lines.append(f' c.append(a {i} b)')
    function_lines.append(' return')
    exec('\n'.join(function_lines), globals())
    dis.dis(func)

generate_func()
exit()
```

The world spins.

I'm going to handwave over the parser despite it taking me two hours, because it's not very interesting (just isolating the opcodes and constants by reading directly from the stack output provided by LLTRACE). After the analysis, we can see that there are two different kinds of operation:

```python
['flag[1491]', '^', 67, '+', 63, '&', 255, '^', 148] 22
['flag[1492]', '^', 213, '+', 24, '&', 255, '^', 6] 235
['flag[1493]', '^', 225, '+', 5, '&', 255] 230
['flag[1494]', '^', 237, '+', 16, '&', 255, '^', 57] 196
['flag[1495]', '^', 26, '^', 6] 220
['flag[1496]', '^', 113, '+', 35, '&', 255, '^', 129] 224
['flag[1497]', '^', 91, '+', 89, '&', 255, '^', 179] 187
['flag[1498]', '<<', 6, 'flag[1498]', '>>', 2, '|', 16, '&', 255, '^', 242] 167
['flag[1499]', '^', 155, '+', 81, '&', 255] 27
['flag[1500]', '^', 135, '-', 15, '&', 255] 16
['flag[1501]', '<<', 1, 'flag[1501]', '>>', 7, '|', 0, '&', 255, '^', 24] 185
['flag[1502]', '^', 79, '-', 49, '&', 255] 109
['flag[1503]', '^', 165, '-', 94, '&', 255] 22
['flag[1504]', '^', 75, '+', 39, '&', 255, '^', 223] 94
['flag[1505]', '+', 25, '&', 255, '^', 150] 184
```

One's a rotate and mask, and the other's arithmetic operations like +, -, so on. Both are trivial to invert, but I was too lazy to invert them and just asked GPT to write a brute forcer.

Here is the extremely ugly parser code:

```python
binary_op_names = {
    0: '+',
    10: '-',
    5: '*',
    4: '@',
    11: '/',
    6: '%',
    8: '**',
    3: '<<',
    9: '>>',
    7: '|',
    1: '&',
    12: '^',
    2: '//'
} 

def eval_expr(x, arr):
    if isinstance(arr[0], str) and arr[0].startswith('flag['):
        val = x
    else:
        val = int(arr[0])
    
    i = 1
    while i < len(arr):
        op = arr[i]
        rhs = arr[i+1]

        if isinstance(rhs, str) and rhs.startswith('flag['):
            rhs = x
        else:
            rhs = int(rhs)

        if op == '+':
            val = val + rhs
        elif op == '-':
            val = val - rhs
        elif op == '*':
            val = val * rhs
        elif op == '/':
            val = val // rhs
        elif op == '^':
            val = val ^ rhs
        elif op == '&':
            val = val & rhs
        elif op == '|':
            val = val | rhs
        elif op == '<<':
            val = val << rhs
        elif op == '>>':
            val = val >> rhs
        else:
            raise ValueError(f"Unknown operator {op}")
        i += 2
    return val

def solve_expression(arr, target, search_range=range(256)):
    for x in search_range:
        if eval_expr(x, arr) == target:
            return x
    return None

important_ops = ['CALL', 'BINARY_OP', 'COMPARE_OP', 'BINARY_SUBSCR']
blocks = pickle.load(open('a.pkl', 'rb'))
output_png = open('output.png', 'wb')
bytearr = bytearray()
from tqdm import tqdm
for idx, block in tqdm(enumerate(blocks)):
    printing = False
    done = False
    comparing = False
    actual_ops = []
    prev_stack = None
    for line in block:
        if done: break
        if printing:
            stack = line[line.find('39944'):].split(', ')
            stack[-1] = stack[-1][:-1]
            if all(['type' not in stack_elem for stack_elem in stack]) and len(stack) > 1 and stack[-1] != 'False':
    #            print(prev_line, stack)
                printing = False
                if 'BINARY_SUBSCR' in prev_line:
                    actual_ops.append(f'flag[{idx}]')
                if 'BINARY_OP' in prev_line:
                    operand = int(prev_line.split(' ')[-1])
    #                print(binary_op_names[operand])
                    actual_ops.append(binary_op_names[operand])
                    actual_ops.append(int(prev_stack[-1]))
            prev_stack = stack
        for i in important_ops:
            if i in line:
                prev_line = line
                printing = True
                if i == 'COMPARE_OP':
                    compared_value = stack[-1]
    #                print(f'{compared_value = }')
                    done = True
    if actual_ops[1] != '<<':
        val = solve_expression(actual_ops, int(compared_value))
    else:
        ror_amt = actual_ops[2]
        val = rotate_right(int(compared_value) ^ actual_ops[-1], ror_amt)
    bytearr.append(val)

for i in bytearr:
    output_png.write(i.to_bytes(1))
output_png.close()
```

You can see where the GPT nonsense ends and my nonsense begins pretty clearly, which I find funny. Anyways, this outputs a file, which has our flag!

![when i saw 89PNG in the byte output i was so happy](/assets/images/infobahn-ctf-25/flag.png)

Flag: `infobahn{this_is_by_far_the_worst_obfuscator_ive_had_the_displeasure_of_writing_i_dont_even_know_how_the_code_ran_e891ac534881}`

### CLOSING THOUGHTS

Why does no one know about LLTRACE why is this not a feature that anybody ever talks about or is even remotely documented i guess its like really niche or whatever but what the hell?? this is the interpreter for _the_ biggest programming language in the world. why is writing tooling to interact with the interpreter itself so god awful??? I hope that if any other poor soul tries .pyc rev they're able to find this writeup and use LLTRACE for something because Lord above I _need_ people to know about this.




