#!/usr/bin/python -u
#-*- coding: utf-8 -*-
import os
import sys
import time
import base64
import signal
import random
import string

S = string.letters+string.digits+'_'

def handler(signum, frame):
    print('time up!')
    exit(0)

def generate_filename():
    a = '/tmp/'
    for ch in os.urandom(2):
        a += S[ord(ch) % len(S)]
    return a

if __name__ == "__main__":
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(30)
    try:
        inputs = ""
        print("Please input your b64-encode exploit")
        while True:
            line = sys.stdin.readline()
            line = line.strip()
            if line == "EOF":
                break
            inputs = inputs + line
        inputs = base64.b64decode(inputs)
        if len(inputs) > 2**12:
            print('Too big')
            sys.exit(0)
        try:
            filename = generate_filename()
            print(filename)
            with open(filename, 'wb') as tmp:
                size = len(inputs)
                cur_idx = 0
                while(cur_idx < size):
                    tmp.write(inputs[cur_idx])
                    cur_idx += 1
            print('running ....')
            os.system("/home/ctf/jerry %s" % filename)
        except:
            print('error')

        finally:
            if os.path.exists(filename):
                os.remove(filename)
    except:
        print('error')

    finally:
        if os.path.exists(filename):
            os.remove(filename)
        sys.exit(0)
