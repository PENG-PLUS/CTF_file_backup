import string
f = "2(88\x006\x1a\x10\x10\x1aIKIJ+\x1a\x10\x10\x1a\x06"
passwd = list(string.printable)
flag = ''
for i in f:
    for j in passwd:
        tmp = ord(i)^ord(j)^123
        if(tmp==0):
            flag+=j
            break

print(flag)