#pragma once
#include "../PasswordManagerApp/SharedData.h"
#include "Encryption.h"
#include <iostream>
#include <stdlib.h>
#include <string>
#include <errno.h>
#include <string>
#include <Windows.h>

class ExtensionComms
{
public:
	ExtensionComms();
	~ExtensionComms();

	void readMessage();
	bool sendMessage();

private:
	account accountToSend;

	void processMessage();
	void formatMessage();

	void retrievePassword();
	char password[200];

	char *receivedMessageText;
	char sentMessageText[200];
};

