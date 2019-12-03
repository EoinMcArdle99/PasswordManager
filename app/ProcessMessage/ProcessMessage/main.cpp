#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "ExtensionComms.h"

int main(int argc, char *argv[]) {
	ExtensionComms estComms;

	bool messageSent = false;

	while (!messageSent) {
		estComms.readMessage();
		messageSent = estComms.sendMessage();
	}

	return 0;
}