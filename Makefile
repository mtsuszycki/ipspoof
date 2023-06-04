
CFLAGS=-O2 -fomit-frame-pointer -malign-loops=2
OBJ=spoofs.o


spoofs: $(OBJ)
	gcc -o spoofs $(OBJ)
	strip spoofs
clean: 
	rm -f ./*.o
	rm -f ./core
	rm -f ./spoofs