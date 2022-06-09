CC=gcc
CFLAGS=-lgmp
OUTPUT=rsa

build:
	$(CC) rsa.c rsa.h -o $(OUTPUT) $(CFLAGS)


