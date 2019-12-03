#pragma once
#define NUMDATAELEMENTS 7
#define PIPE "\\\\.\\pipe\\Pipe"
#define DELIMPIPECOMMS "\t";
#define SALT "88C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120"

enum dataElements { WebsiteURL, EmailID, PasswordID, LoginID, EmailAddress, Password, IV };

typedef struct {
	int lengths[NUMDATAELEMENTS];
	char *data[NUMDATAELEMENTS];
} account;

