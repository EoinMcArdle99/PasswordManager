#include "ExtensionComms.h"

 void ExtensionComms::readMessage() {
	unsigned int receivedMessageLength = 0;
	
	for (int i = 0; i < 4; i++) {
		unsigned int read_char = getchar();
		receivedMessageLength = receivedMessageLength | (read_char << i * 8);
	}

	receivedMessageText = (char *) calloc(receivedMessageLength + 1, sizeof(char));

	for (int i = 0; i < receivedMessageLength; i++) { receivedMessageText[i] = getchar(); }

	processMessage();
	
	return;
}

void ExtensionComms::processMessage() {
	FILE *database; 
	database = fopen("accountDatabase.dat", "rb");

	if (database == NULL) {
		
		return;
	}
	else {
		Encryption decryptor;

		char salt[] = SALT;

		while (fread(&accountToSend, sizeof(accountToSend), 1, database)) {

			for (int i = 0; i < NUMDATAELEMENTS; i++) {
				accountToSend.data[i] = (char *)calloc(accountToSend.lengths[i] + 1, sizeof(char));
				fread(accountToSend.data[i], accountToSend.lengths[i], 1, database);
			}

			if (strstr(receivedMessageText, accountToSend.data[WebsiteURL])) {
				// Get password from password manager app
				retrievePassword();
				int result = decryptor.decrypt(std::string(accountToSend.data[IV]), std::string(accountToSend.data[Password]), std::string(password), std::string(salt));

				free(accountToSend.data[Password]);

				accountToSend.data[Password] = (char *)calloc(strlen(decryptor.getDecryptedText().c_str()) + 1, sizeof(char));
				strcpy(accountToSend.data[Password], decryptor.getDecryptedText().c_str());
				fclose(database);
				return;
			}
			decryptor.~Encryption();
		}
	}
	//TODO handle not found case
	fclose(database);
	return;
}

void ExtensionComms::retrievePassword() {

	char delim[] = DELIMPIPECOMMS;

	HANDLE hPipe;
	DWORD dwWrite, dwRead, dwRead1;

	hPipe = CreateFile(TEXT(PIPE), // Name of file
		GENERIC_READ | GENERIC_WRITE, // Access
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (hPipe != INVALID_HANDLE_VALUE)
	{
		//FILE *ptr;
		//ptr = fopen("debugFile.txt", "w");

		DiffieHellman keyExchange;
		keyExchange.generateKeyPair();
		char localPub[PUBKEYLENGTH];
		strcpy(localPub, keyExchange.getPublicKey().c_str());
		char externalPub[PUBKEYLENGTH];

		ReadFile(hPipe, externalPub, sizeof(externalPub) - 1, &dwRead, NULL);
		externalPub[dwRead] = '\0';
		
		WriteFile(hPipe, localPub, strlen(localPub) + 1, &dwWrite, NULL);
		
		keyExchange.createKeyEncryptionKey(std::string(externalPub));

		char buff[1024];
		char *cekIV, *encryptedMasterPassword, *salt, *kekIV, *encryptedCEK, *token = NULL;

		ReadFile(hPipe, buff, sizeof(buff) - 1, &dwRead1, NULL);

		token = strtok(buff, delim);
		cekIV = (char *)malloc((strlen(token) + 1) * sizeof(char));
		strcpy(cekIV, token);

		token = strtok(NULL, delim);
		encryptedMasterPassword = (char *)malloc((strlen(token) + 1) * sizeof(char));
		strcpy(encryptedMasterPassword, token);

		token = strtok(NULL, delim);
		salt = (char *)malloc((strlen(token) + 1) * sizeof(char));
		strcpy(salt, token);

		token = strtok(NULL, delim);
		kekIV = (char *)malloc((strlen(token) + 1) * sizeof(char));
		strcpy(kekIV, token);

		token = strtok(NULL, delim);
		encryptedCEK = (char *)malloc((strlen(token) + 1) * sizeof(char));
		strcpy(encryptedCEK, token);

		keyExchange.decrypt(std::string(kekIV), std::string(encryptedCEK), keyExchange.getKEK(), std::string(salt));

		char *decryptedCEK = NULL;
		decryptedCEK = (char *)malloc((strlen(keyExchange.getDecryptedText().c_str()) + 1) * sizeof(char));

		strcpy(decryptedCEK, keyExchange.getDecryptedText().c_str());

		strcpy(password, keyExchange.simpleDecrypt(std::string(encryptedMasterPassword), std::string(decryptedCEK), std::string(cekIV)).c_str());

		free(cekIV);
		free(encryptedMasterPassword);
		free(salt);
		free(kekIV);
		free(encryptedCEK);
		free(decryptedCEK);

		CloseHandle(hPipe);
		//fclose(ptr);
	}

	return;
}

void ExtensionComms::formatMessage() {
	strcpy(sentMessageText, "{");

	strcat(sentMessageText, "\"emailID\":\"");
	strcat(sentMessageText, accountToSend.data[EmailID]);

	strcat(sentMessageText, "\",");

	strcat(sentMessageText, "\"passwordID\":\"");
	strcat(sentMessageText, accountToSend.data[PasswordID]);

	strcat(sentMessageText, "\",");

	strcat(sentMessageText, "\"loginID\":\"");
	strcat(sentMessageText, accountToSend.data[LoginID]);

	strcat(sentMessageText, "\",");

	strcat(sentMessageText, "\"emailAddress\":\"");
	strcat(sentMessageText, accountToSend.data[EmailAddress]);

	strcat(sentMessageText, "\",");

	strcat(sentMessageText, "\"password\":\"");
	strcat(sentMessageText, accountToSend.data[Password]);

	strcat(sentMessageText, "\"}");
}

bool ExtensionComms::sendMessage() {
	formatMessage();

	unsigned int sentMessageLength = strlen(sentMessageText);
	printf("%c%c%c%c", char(sentMessageLength >> 0), char(sentMessageLength >> 8), char(sentMessageLength >> 16), char(sentMessageLength >> 24));
	puts(sentMessageText);

	return true;
}

ExtensionComms::ExtensionComms() {
	receivedMessageText = NULL;
}

ExtensionComms::~ExtensionComms() {
	//Free all allocated memory on heap
	for (int i = 0; i < NUMDATAELEMENTS; i++) {
		free(accountToSend.data[i]);
	}
	free(receivedMessageText);
}