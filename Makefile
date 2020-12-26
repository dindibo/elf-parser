CC=gcc
CFLAGS= -Wall -g -I.
DEPS = elf-parser.h
OBJ = disasm.o elf-parser.o elf-parser-main.o
TEST_EXEC = elf-test
TEST_OBJ = testing.o
EXEC_NAME = elfparser

.PHONY: build test

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

elfparser: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)
	rm -f *.o

clean:
	rm -rf *.o $(TEST_EXEC)

build: $(OBJ)
	ls *.o
	gcc -o $(EXEC_NAME) $(OBJ) $(CFLAGS)
	$(MAKE) clean

remove:
	$(MAKE) clean
	rm -f $(EXEC_NAME) $(TEST_EXEC)

test testing.o $(TEST_EXEC):
	$(MAKE) clean
	$(CC) -c -D TEST *.c $(CFLAGS)
	gcc -D TEST $(TEST_OBJ) $(OBJ) -o $(TEST_EXEC) && ./$(TEST_EXEC)
	@rm -f *.o
