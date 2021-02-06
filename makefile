all: cairolock

CFLAGS = -Wall

cairolock: cairolock.o
	cc cairolock.o -o cairolock -lX11 -lpam -lcairo

clean:
	rm -f cairolock *.o
