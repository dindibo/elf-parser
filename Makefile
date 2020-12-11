CC=gcc
CFLAGS= -Wall -g -I.
DEPS = elf-parser.h
OBJ = disasm.o elf-parser.o elf-parser-main.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

elfparser: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)
	rm -f *.o

clean:
	rm -rf *.o elfparser

