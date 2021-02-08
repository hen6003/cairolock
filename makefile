all: cairolock

CFLAGS = -Wall

cairolock: cairolock.o
	cc cairolock.o -o cairolock -lX11 -lpam -lcairo

clean:
	rm -f cairolock *.o

install: all
	cp cairolock /usr/local/bin/
	cp cairolock_pam /etc/pam.d/cairolock

uninstall:
	rm -f /usr/local/bin/cairolock
	rm -f /etc/pam.d/cairolock
