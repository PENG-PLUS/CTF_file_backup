all: httpd
LIBS = -pthread #-lsocket
httpd: httpd.c
	gcc -g -W -Wall $(LIBS) -g -o $@ $<

clean:
	rm httpd
