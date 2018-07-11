certcheck: certcheck.c
	gcc -o certcheck certcheck.c -lssl -lcrypto

