from pwn import *
#p = process(["./lib/ld.so.1", "./eserver"], env={"LD_PRELOAD":"./lib/libc.so.6"})
p = remote("172.35.19.12",9999)


#gdb.attach(p)







p.interactive()

