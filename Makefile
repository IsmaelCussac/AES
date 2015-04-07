all: compiler
compiler: 
	gcc aes.c -o aes -lm
clean: 
	aes

