CFLAGS=-Wall -Wextra
CFLAGS1 = -pipe  -O -W -Wpointer-arith -Wno-unused-parameter -g -O2 -pipe -Wall -lm -lgmp
CC = gcc
MAIN = main.c gfsr5.c
TEST = test.c
TEST2 = test2.c
COMMAND = valgrind --leak-check=full --show-leak-kinds=all --tool=memcheck -s
EXECUTABLE = run

all:
	gcc $(MAIN) $(CFLAGS1) -o file1 && $(COMMAND) ./file1

test:
	gcc $(TEST) $(CFLAGS1) -o file1 -lm && $(COMMAND) ./file1

test2:
	gcc $(TEST2) -o file1 -lm && $(COMMAND) ./file1

clear:
	rm file1