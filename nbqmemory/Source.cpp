#include "nbqmemory.h"

#include <stdio.h>

int main() {
	nbqmemory memory("csgo.exe", PROCESS_ALL_ACCESS);
	(void)getchar();
	return 0;
}