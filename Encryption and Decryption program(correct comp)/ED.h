#pragma once
// using namespace CryptoPP
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <cstring>
#include <iomanip>
#include <string>
#include <fstream>
#ifndef ED.H
#define ED_H
#include "ED.h"
#include <cryptlib.h>
#include "osrng.h"
#include "rijndael.h"
#include "filters.h"
#include "aes.h"
#include "rijndael.h"
#include "modes.h"
#include "hex.h"
#include "files.h"
#include "base64.h"
using namespace std;
using namespace CryptoPP;
/*class ED {
private:
	AutoSeededRandomPool full;
	CryptoPP::SecByteBlock key, Initalization;
public:
	ED() : key(AES::DEFAULT_KEYLENGTH), Initalization(AES::BLOCKSIZE) {
		full.GenerateBlock(key, key.size());
		full.GenerateBlock(Initalization, Initalization.size());
	}
*/
void GenerateKey();
void GenerateInitalization();
void EncryptionFile();
int AmountOfData();
void EntryFile(string ED, string* plaintext, string* ciphertext, string* Base64ciphertext, string* Base64plaintext);
void DecryptionFile(string EncryptionEntryFile);
void CopyFile();
void DeleteCipher();
void SaveCipher(string Filename);
void InitalizationCipher();
void ChangeCipher();
//};
#endif // ED.H
