CC=gcc
CFLAGS=-lgmp
OUTPUT=rsa.out

build:
	$(CC) rsa.c rsa.h -o $(OUTPUT) $(CFLAGS)


