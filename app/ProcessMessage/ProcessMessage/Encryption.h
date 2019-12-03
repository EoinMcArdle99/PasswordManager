#pragma once
#include <iostream>
#include <string>

//CryptoPP library headers
#include "modes.h"
#include "aes.h"
#include "hkdf.h"
#include "sha.h"
#include "hex.h"
#include "pwdbased.h"
#include "eax.h"
#include "randpool.h"
#include "osrng.h"
#include "rdrand.h"
#include "dh.h"
#include "dh2.h"
#include "secblock.h"
#include "filters.h"
#include "cryptlib.h"
#include "files.h"
#include "xtrcrypt.h"
#include "integer.h"

#define NO_VAL "NO_VAL"
#define PRIME "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
#define SUBGROUPORDER "0x7fffffffffffffffe487ed5110b4611a62633145c06e0e68948127044533e63a0105df531d89cd9128a5043cc71a026ef7ca8cd9e69d218d98158536f92f8a1ba7f09ab6b6a8e122f242dabb312f3f637a262174d31bf6b585ffae5b7a035bf6f71c35fdad44cfd2d74f9208be258ff324943328f6722d9ee1003e5c50b1df82cc6d241b0e2ae9cd348b1fd47e9267afc1b2ae91ee51d6cb0e3179ab1042a95dcf6a9483b84b4b36b3861aa7255e4c0278ba3604650c10be19482f23171b671df1cf3b960c074301cd93c1d17603d147dae2aef837a62964ef15e5fb4aac0b8c1ccaa4be754ab5728ae9130c4c7d02880ab9472d45556216d6998b8682283d19d42a90d5ef8e5d32767dc2822c6df785457538abae83063ed9cb87c2d370f263d5fad7466d8499eb8f464a702512b0cee771e9130d697735f897fd036cc504326c3b01399f643532290f958c0bbd90065df08babbd30aeb63b84c4605d6ca371047127d03a72d598a1edadfe707e884725c16890549d69657fffffffffffffffh"

#define GENERATOR "0x2"

#define PUBKEYLENGTH 800

class Encryption
{
public:
	Encryption();
	~Encryption();

	void encryptionWithKeyExpansion(std::string masterPassword, std::string dataToEncrypt, std::string salt);
	int decrypt(std::string ivHex, std::string dataToDecrypt, std::string masterPassword, std::string salt);
	std::string randomEncrypt(std::string data);
	std::string simpleDecrypt(std::string encryptedData, std::string key, std::string iv);
	

	std::string getEncryptedText() const;
	std::string getIV() const;
	std::string getDecryptedText() const;

protected:
	CryptoPP::SecByteBlock keyExpansion(std::string plainTextPassword, std::string salt);
	std::string EAXEncryption(std::string data, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv);
	std::string EAXDecrypt(CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv, std::string cipherText);
	
	std::string decodeHex(std::string encodedText);
	std::string encodeHex(CryptoPP::SecByteBlock plainIV, size_t length);
	std::string encodeHex(std::string cipherText);

	std::string EncryptedText;
	std::string IVHex;
	std::string DecryptedData;
};


class DiffieHellman : public Encryption {
public:
	~DiffieHellman();
	void generateKeyPair();
	void createKeyEncryptionKey(std::string externalPublicKey);
	std::string generateRandomString();

	std::string getPublicKey() const;
	std::string getKEK() const;

private:
	std::string publicKey;
	CryptoPP::SecByteBlock privateKey;
	CryptoPP::DH dhUnathenticated;
	std::string KEK;
};