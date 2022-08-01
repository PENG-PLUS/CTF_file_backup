#!/usr/bin/env python3

from decimal import *
import math
import random
import struct
from flag import flag

assert (len(flag) == 48)
msg1 = flag[:24]
msg2 = flag[24:]
primes = [2]
for i in range(3, 90):
    f = True
    for j in primes:
        if i * i < j:
            break
        if i % j == 0:
            f = False
            break
    if f:
        primes.append(i)

getcontext().prec = 100
keys = []
for i in range(len(msg1)):
    keys.append(Decimal(primes[i]).ln())

sum_ = Decimal(0.0)
for i, c in enumerate(msg1):
    sum_ += c * Decimal(keys[i])

ct = math.floor(sum_ * 2 ** 256)
print(ct)

sum_ = Decimal(0.0)
for i, c in enumerate(msg2):
    sum_ += c * Decimal(keys[i])

ct = math.floor(sum_ * 2 ** 256)
print(ct)
