# Level00
Level00 is simple. Very simple.

# Tools
GDB

# Walkthrough
The home of level0 contains a binary. You can try a few arguments but it will always aggressively respond "No !"
Upon using GDB on the executable, we get the code that you can see in the `main.asm` file.
We see that the binary calls `atoi()`, and compares the result of the function with `0x1a7`, which is the hexa for 423.
We start `level0` with 423 as the first argument and we are prompted with a shell, as `level1` (that's why the flag is empty).
For better access, we look at what's inside the home of `level1`, it contains a binary with the same name.
We copy it to `/tmp`, then exit the terminal, and move it to the home of `level0` as user `level0`.
Then, we can `scp` it on the host machine for better examination.