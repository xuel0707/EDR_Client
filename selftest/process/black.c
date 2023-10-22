#include <stdio.h>
#include <string.h>

void main(int argc, char **argv)
{
	if (strstr(argv[0], "var")) {
		printf("%s is a black variant, which appends something to tail. %s\n", argv[0], argv[1]);
	} else {
		printf("%s is a black test routine. %s\n", argv[0], argv[1]);
	}
}
