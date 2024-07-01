# triton-symexe

My personal storage for triton code I wrote for the first time.

The crackme is the simplest possible, just doing strcmp on buffer and correct password.

I symbolized the buffer memory and solved `buffer == correct_password` using triton AST.
It worked but the code is incredibly messy cuz I didnt know how else I could do! triton was fucking incomprehensible. But I like it.

The output is below.

```Shell
0x4011fa: push 0x4030ac
0x4011ff: push 0x40302c
0x401204: call 0x401288
[*] hook_lstrcmpA hooked ! return -> 0x401209
0x401209: test eax, eax
# [0x64, 0x6f, 0x6f, 0x6d, 0x6f] in ascii is "doomo" which is identical to correct answer
{0: buffer:8 = 0x64, 1: buffer:8 = 0x6f, 2: buffer:8 = 0x6f, 3: buffer:8 = 0x6d, 4: buffer:8 = 0x6f}
emulation end
total instruction count: 5
```

This is the part I'm executing symbolically in my code
![symbolic executed part](https://github.com/vxcall/triton-first-time/assets/33578715/6ccf7055-8229-4323-902f-5bacc550d5b2)
