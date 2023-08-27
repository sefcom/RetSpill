all: poc

poc: poc.c
	gcc -static -o poc poc.c -fno-stack-protector

clean:
	rm -rf poc

