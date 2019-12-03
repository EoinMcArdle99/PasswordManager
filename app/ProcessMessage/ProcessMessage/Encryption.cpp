#include "Encryption.h"

Encryption::Encryption() {
	//Initialise variables with no value
	EncryptedText = NO_VAL;
	IVHex = NO_VAL;
	DecryptedData = NO_VAL;
}

Encryption::~Encryption() {
	//Clear memory after use for security
	EncryptedText.clear();
	IVHex.clear();
	DecryptedData.clear();
}

void Encryption::encryptionWithKeyExpansion(std::string masterPassword, std::string dataToEncrypt, std::string salt) {
	//Expand plaintext master password into usable key
	CryptoPP::SecByteBlock derivedKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
	derivedKey = keyExpansion(masterPassword, salt);

	//Clear memory after use
	masterPassword.clear();
	salt.clear();

	//Generate new, random IV for encryption
	CryptoPP::AutoSeededRandomPool rand;
	CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
	rand.GenerateBlock(iv, iv.size());

	//Set up encryption
	std::string cipherText = EAXEncryption(dataToEncrypt, derivedKey, iv);

	//Clear memory after use
	dataToEncrypt.clear();
	
	//Encode IV and cipherText in hex to store in database
	IVHex = encodeHex(iv, CryptoPP::AES::BLOCKSIZE);
	EncryptedText = encodeHex(cipherText);
}

//Return 0 on succes, 1 on failure
int Encryption::decrypt(std::string ivHex, std::string dataToDecrypt, std::string masterPassword, std::string salt) {
	//Expand plaintext master password into usable key
	CryptoPP::SecByteBlock derivedKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
	derivedKey = keyExpansion(masterPassword, salt);

	//Decode the hex IV and create an IV block
	std::string decodedIV = decodeHex(ivHex);
	CryptoPP::SecByteBlock ivBlk((CryptoPP::byte *) decodedIV.data(), CryptoPP::AES::BLOCKSIZE);

	//Decode hex cipherText back into normal ciphertext
	dataToDecrypt = decodeHex(dataToDecrypt);

	//Clear memory after use
	masterPassword.clear();
	salt.clear();

	DecryptedData = EAXDecrypt(derivedKey, ivBlk, dataToDecrypt);

	return 0;
}

CryptoPP::SecByteBlock Encryption::keyExpansion(std::string plainTextPassword, std::string salt) {
	//Block to hold expanded key
	CryptoPP::SecByteBlock expandedKey(CryptoPP::AES::BLOCKSIZE);
	
	//Used to slow expansion
	unsigned int iterations = 20000;

	//Hash function to expand key
	CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> expansionFunction;
	expansionFunction.DeriveKey(expandedKey.data(), expandedKey.size(), 0, (CryptoPP::byte *)plainTextPassword.data(), plainTextPassword.length(), (CryptoPP::byte *)salt.data(), salt.length(), iterations);

	//Clear memory after use
	plainTextPassword.clear();
	salt.clear();

	return expandedKey;
}

// Returns CEC
std::string Encryption::randomEncrypt(std::string data) {
	CryptoPP::AutoSeededRandomPool rnd;
	CryptoPP::SecByteBlock randomKey(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
	rnd.GenerateBlock(randomKey, randomKey.size());

	CryptoPP::SecByteBlock randomIV(CryptoPP::AES::BLOCKSIZE);
	rnd.GenerateBlock(randomIV, randomIV.size());

	//Encryption
	std::string cipherText = EAXEncryption(data, randomKey, randomIV);

	IVHex = encodeHex(randomIV, CryptoPP::AES::BLOCKSIZE);
	EncryptedText = encodeHex(cipherText);

	data.clear();
	return encodeHex(randomKey, randomKey.size());
}

std::string Encryption::simpleDecrypt(std::string encryptedData, std::string key, std::string iv) {
	std::string decodedKey = decodeHex(key);
	std::string decodedIV = decodeHex(iv);

	CryptoPP::SecByteBlock keyBlk((CryptoPP::byte *) decodedKey.data(), CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::SecByteBlock ivBlk((CryptoPP::byte *) decodedIV.data(), CryptoPP::AES::BLOCKSIZE);

	encryptedData = decodeHex(encryptedData);
	
	return EAXDecrypt(keyBlk, ivBlk, encryptedData);;
}


std::string Encryption::EAXEncryption(std::string data, CryptoPP::SecByteBlock key ,CryptoPP::SecByteBlock iv) {
	std::string cipherText;
	// Set up encryption
	CryptoPP::EAX<CryptoPP::AES>::Encryption encryptor;
	encryptor.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

	//AD mode -> adds additional authentication data to cipher text to prevent data being tampered with
	CryptoPP::AuthenticatedEncryptionFilter authenticate(encryptor, new CryptoPP::StringSink(cipherText));
	authenticate.Put((CryptoPP::byte *)data.data(), data.size());
	authenticate.MessageEnd();

	return cipherText;
}

std::string Encryption::EAXDecrypt(CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv, std::string cipherText) {
	std::string plainText;
	try {
		//Set up decryption
		CryptoPP::EAX<CryptoPP::AES>::Decryption decryptor;
		decryptor.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

		//AEAD mode checks for data tampering
		plainText.clear(); //Clear buffer before passing to StringSink (StringSink appends original text)
		CryptoPP::AuthenticatedDecryptionFilter df(decryptor, new CryptoPP::StringSink(plainText));
		df.Put((CryptoPP::byte *)cipherText.data(), cipherText.size());
		cipherText.clear(); //Clear memory after use
		df.MessageEnd();
	}
	//If data has been tampered with
	catch (CryptoPP::Exception& ex) {
		return std::string(NO_VAL);
	}

	return plainText;
}

std::string Encryption::decodeHex(std::string encodedText) {
	std::string decodedData;
	//Decode hex back into original format
	CryptoPP::StringSource ss(encodedText, true,
		new CryptoPP::HexDecoder(
			new CryptoPP::StringSink(decodedData)
		)
	);
	return decodedData;
}

std::string Encryption::encodeHex(std::string cipherText) {
	std::string temp;
	//Encode text into hex format
	CryptoPP::StringSource ss(cipherText, true,
		new CryptoPP::HexEncoder(
			new CryptoPP::StringSink(temp)
		)
	);
	return temp;
}

std::string Encryption::encodeHex(CryptoPP::SecByteBlock plainIV, size_t length) {
	//Encode block into hex format
	CryptoPP::HexEncoder encd;
	std::string temp;
	encd.Detach(new CryptoPP::StringSink(temp));
	encd.Put(plainIV.data(), length); // Change made  here CryptoPP::AES::BLOCKSIZE
	encd.MessageEnd();
	return temp;
}

//Getter functions
std::string Encryption::getEncryptedText() const { return EncryptedText; }
std::string Encryption::getIV() const { return IVHex; }
std::string Encryption::getDecryptedText() const { return DecryptedData; }


/*****************************************************************************/

// Diffe Hellman Class Inherited From Encryption Class

/*****************************************************************************/

DiffieHellman::~DiffieHellman() {
	KEK.clear();
	DecryptedData.clear();
	publicKey.clear();
	DecryptedData.clear();
}

void DiffieHellman::generateKeyPair() {
	CryptoPP::Integer prime("0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF");
	CryptoPP::Integer subgroupOrder("0x7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6D241B0E2AE9CD348B1FD47E9267AFC1B2AE91EE51D6CB0E3179AB1042A95DCF6A9483B84B4B36B3861AA7255E4C0278BA3604650C10BE19482F23171B671DF1CF3B960C074301CD93C1D17603D147DAE2AEF837A62964EF15E5FB4AAC0B8C1CCAA4BE754AB5728AE9130C4C7D02880AB9472D45556216D6998B8682283D19D42A90D5EF8E5D32767DC2822C6DF785457538ABAE83063ED9CB87C2D370F263D5FAD7466D8499EB8F464A702512B0CEE771E9130D697735F897FD036CC504326C3B01399F643532290F958C0BBD90065DF08BABBD30AEB63B84C4605D6CA371047127D03A72D598A1EDADFE707E884725C16890549D69657FFFFFFFFFFFFFFFH");
	CryptoPP::Integer generator("0x2");

	dhUnathenticated.AccessGroupParameters().Initialize(prime, subgroupOrder, generator);

	CryptoPP::AutoSeededRandomPool rnd;

	//Run validation steps here

	CryptoPP::SecByteBlock priv(dhUnathenticated.PrivateKeyLength());
	CryptoPP::SecByteBlock pub(dhUnathenticated.PublicKeyLength());
	dhUnathenticated.GenerateKeyPair(rnd, priv, pub);

	privateKey = priv;

	publicKey = encodeHex(pub, pub.size());

	return;
}

void DiffieHellman::createKeyEncryptionKey(std::string externalPublicKey) {
	std::string decodedData = decodeHex(externalPublicKey);
	CryptoPP::SecByteBlock externPubKey((CryptoPP::byte *) decodedData.data(), decodedData.size());

	CryptoPP::SecByteBlock sharedSecret(dhUnathenticated.AgreedValueLength());
	
	if (!dhUnathenticated.Agree(sharedSecret, privateKey, externPubKey)) {
		throw std::runtime_error("Failed to reach agreement");
	}

	KEK = encodeHex(sharedSecret, sharedSecret.size());

	return;
}

std::string DiffieHellman::generateRandomString() {
	CryptoPP::SecByteBlock rndBlk(32);
	CryptoPP::AutoSeededRandomPool rnd;
	rnd.GenerateBlock(rndBlk, rndBlk.size());

	return encodeHex(rndBlk, rndBlk.size());
}

std::string DiffieHellman::getPublicKey() const { return publicKey; }
std::string DiffieHellman::getKEK() const { return KEK; }