inarpd: inarpd.c
	gcc -o inarpd inarpd.c

.PHONY: clean

clean:
	rm -f inarpd
