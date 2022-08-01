from flag import text,flag
import md5
from Crypto.Util.number import long_to_bytes,bytes_to_long,getPrime

assert md5.new(text).hexdigest() == flag[6:-1]

#提取flag片段
msg1 = text[:xx]
msg2 = text[xx:yy]
msg3 = text[yy:]

#转换为字节
msg1 = bytes_to_long(msg1)
msg2 = bytes_to_long(msg2)
msg3 = bytes_to_long(msg3)

p1 = getPrime(512)
q1 = getPrime(512)
N1 = p1*q1
e1 = 3
print pow(msg1,e1,N1)
print (e1,N1)

p2 = getPrime(512)
q2 = getPrime(512)
N2 = p2*q2
e2 = 17
e3 = 65537
print pow(msg2,e2,N2)
print pow(msg2,e3,N2)
print (e2,N2)
print (e3,N2)

p3 = getPrime(512)
q3 = getPrime(512)
N3 = p3*q3
print pow(msg3,e3,N3)
print (e3,N3)
print p3>>200


