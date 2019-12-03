#include "PasswordManagerApp.h"

int main(int argc, char *argv[]) {

	if (argc == 1) {
		printf("Enter (as parameter) /r to run or /a to add account\n");
		return 0;
	}
	else if (argc == 2) {
		if (!strcmp(argv[1], RUNMODE)) {
			runBackground();
		}
		else if (!strcmp(argv[1], ADDACCOUNT)) {
			addAccount();
		}
	}
	return 0;
}

void runBackground() {
	char masterPassword[MAXCHARS];
	printf("Enter master password: ");
	gets_s(masterPassword, MAXCHARS);

	char CEK[MAXCHARS];
	system("CLS");
	puts("In run mode...");
	printf("\n\n");

	unsigned int retrieveCount = 1;

	Encryption encryptMaster;

	strcpy(CEK, encryptMaster.randomEncrypt(std::string(masterPassword)).c_str());

	for (int i = 0; i < strlen(masterPassword); i++) {
		masterPassword[i] = '\0';
	}

	HANDLE hPipe;
	DWORD dwWrite0, dwWrite1, dwRead;

	hPipe = CreateNamedPipe(TEXT(PIPE),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_WRITE_THROUGH, // Makes the pipe bi-directional
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,   //Specifies to send a stream of bytes or discrete messages
		1, // Specifies the number of instances the pipe can create
		1024 * 16, // Number of bytes for the output buffer
		1024 * 16, // Number of bytes for the input buffer
		NMPWAIT_USE_DEFAULT_WAIT, // Default time out value in milliseconds
		NULL); // Security attributes
	
	while (true) {
		while (hPipe != INVALID_HANDLE_VALUE) {
			if (ConnectNamedPipe(hPipe, NULL) != FALSE) {
				// Create key pair
				DiffieHellman keyExchange;
				keyExchange.generateKeyPair();
				char publicKey[PUBKEYLENGTH];
				strcpy(publicKey, keyExchange.getPublicKey().c_str());
				char externalPubKey[PUBKEYLENGTH];

				// Send public key
				WriteFile(hPipe, publicKey, strlen(publicKey) + 1, &dwWrite0, NULL);

				// Get public key
				ReadFile(hPipe, externalPubKey, sizeof(externalPubKey) - 1, &dwRead, NULL);
				externalPubKey[dwRead] = '\0';

				// Generate kek
				keyExchange.createKeyEncryptionKey(std::string(externalPubKey));

				// Send encryption details and encrypted password
				char buff[150];
				char *passwordData = NULL;
				char delim[] = DELIMPIPECOMMS;
				unsigned int stringLength = 0;

				strcpy(buff, encryptMaster.getIV().c_str());
				stringLength = appendData(buff, &passwordData, delim, stringLength);

				strcpy(buff, encryptMaster.getEncryptedText().c_str());
				stringLength = appendData(buff, &passwordData, delim, stringLength);

				strcpy(buff, keyExchange.generateRandomString().c_str());
				stringLength = appendData(buff, &passwordData, delim, stringLength);
				keyExchange.encryptionWithKeyExpansion(keyExchange.getKEK(), std::string(CEK), std::string(buff));

				strcpy(buff, keyExchange.getIV().c_str());
				stringLength = appendData(buff, &passwordData, delim, stringLength);

				strcpy(buff, keyExchange.getEncryptedText().c_str());
				stringLength = appendData(buff, &passwordData, delim, stringLength);

				WriteFile(hPipe, passwordData, strlen(passwordData) + 1, &dwWrite1, NULL);

				printf("Sent password #%d\n\n", retrieveCount);
				retrieveCount++;

				free(passwordData);
			}
			DisconnectNamedPipe(hPipe);
		}
	}
	return;
}

int appendData(char *buff, char **dataStream, char *delim,  int stringLength) {
	stringLength += strlen(buff) + 2;
	if (*dataStream == NULL) {
		*dataStream = (char *)malloc(sizeof(char) * stringLength);
		strcpy(*dataStream, buff);
	}
	else {
		*dataStream = (char *)realloc(*dataStream, sizeof(char) * stringLength);
		strcat(*dataStream, buff);
	}
	strcat(*dataStream, delim);
	return stringLength;
}

void addAccount() {
	account addAccount;
	Encryption encryptor;

	char masterPassword[MAXCHARS];
	char salt[] = SALT;
	printf("Enter master password: ");
	gets_s(masterPassword, MAXCHARS);

	int userSelection = 1;
	char buffer[MAXCHARS];
	//puts("Password Manager Application");
	//printf("Add new account (1): ");
	//scanf("%d", &userSelection);
	int dataIndex = 0;
	if (userSelection == 1) {

		printf("Enter website URL: ");
		//getchar();
		gets_s(buffer, MAXCHARS);
		addAccount.data[dataIndex - 1] = allocateMemory(buffer, &addAccount, &dataIndex);
		printf("Enter emailID: ");
		gets_s(buffer, MAXCHARS);
		addAccount.data[dataIndex - 1] = allocateMemory(buffer, &addAccount, &dataIndex);
		printf("Enter passwordID: ");
		gets_s(buffer, MAXCHARS);
		addAccount.data[dataIndex - 1] = allocateMemory(buffer, &addAccount, &dataIndex);
		printf("Enter loginID: ");
		gets_s(buffer, MAXCHARS);
		addAccount.data[dataIndex - 1] = allocateMemory(buffer, &addAccount, &dataIndex);
		printf("Enter email address: ");
		gets_s(buffer, MAXCHARS);
		addAccount.data[dataIndex - 1] = allocateMemory(buffer, &addAccount, &dataIndex);
		printf("Enter password: ");
		gets_s(buffer, MAXCHARS);
		encryptor.encryptionWithKeyExpansion(std::string(masterPassword), std::string(buffer), std::string(salt));
		addAccount.data[dataIndex - 1] = allocateMemory((char *)encryptor.getEncryptedText().c_str(), &addAccount, &dataIndex);
		addAccount.data[dataIndex - 1] = allocateMemory((char *)encryptor.getIV().c_str(), &addAccount, &dataIndex);

		encryptor.~Encryption();

		printf("\nConfirm details:\n");
		printf("WebsiteURL: ");
		puts(addAccount.data[0]);
		printf("EmailID: ");
		puts(addAccount.data[1]);
		printf("PasswordID: ");
		puts(addAccount.data[2]);
		printf("Enter loginID: ");
		puts(addAccount.data[3]);
		printf("Email Addresss: ");
		puts(addAccount.data[4]);
		printf("Password: ");
		puts(addAccount.data[5]);

		if (!updateDatabase(addAccount)) {
			puts("Database Updated");
		}
		else {
			puts("Database could not be updated");
		}
	}

	if (userSelection == 2) {
		printf("Enter websiteURL to retrieve details: ");
		gets_s(buffer, MAXCHARS);
	}

	for (int i = 0; i < NUMDATAELEMENTS; i++) {
		free(addAccount.data[i]);
	}

	return;
}

char * allocateMemory(char *data, account * addAccount, int *dataIndex){
	char *ptr;
	ptr = (char *)calloc((strlen(data) + 1), sizeof(char));
	strcpy(ptr, data);
	addAccount->lengths[*dataIndex] = strlen(ptr);
	*dataIndex = *dataIndex + 1;
	return ptr;
}

int updateDatabase(account addAccount) {
	char fileName[] = "../ProcessMessage/accountDatabase.dat";
	char fileMode[] = "ab";

	FILE *dataBase;
	printf("\nUpdating Database....\n");
	if (dataBase = fopen(fileName, fileMode)) {

		fwrite(&addAccount, sizeof(addAccount), 1, dataBase);

		for (int i = 0; i < NUMDATAELEMENTS; i++) {
			fwrite(addAccount.data[i], addAccount.lengths[i], 1, dataBase);
		}
		fclose(dataBase);
		readFile();
		
		return 0;
	}
	else {
		return 1;
	}

}

void readFile() {
	char fileName[] = "../ProcessMessage/accountDatabase.dat";
	char fileMode[] = "rb";

	FILE *dataBase;
	dataBase = fopen(fileName, fileMode);

	account readAccount;
	fread(&readAccount, sizeof(readAccount), 1, dataBase);

	for (int i = 0; i < NUMDATAELEMENTS; i++) {
		readAccount.data[i] = (char *)calloc(readAccount.lengths[i] + 1, sizeof(char));
		fread(readAccount.data[i], readAccount.lengths[i], 1, dataBase);
		puts(readAccount.data[i]);
	}
	fclose(dataBase);
}
