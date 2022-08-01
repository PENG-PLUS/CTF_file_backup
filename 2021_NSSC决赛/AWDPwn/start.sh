cd /home/ctf/Desktop/
#timeout --foreground -s 9 120s ./rachell
LD_PRELOAD=/home/ctf/Desktop/libc.so.6 timeout --foreground -s 9 30s ./chall
