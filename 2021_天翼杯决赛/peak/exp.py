from pwn import *
context.log_level = 'debug'

p = remote("10.103.8.4",80)




p.interactive()