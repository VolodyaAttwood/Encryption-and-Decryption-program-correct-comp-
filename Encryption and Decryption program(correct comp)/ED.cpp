#include "ED.h"
int AmountOfData() {
	int _n = 0;
	ifstream Reading("EncryptionFiles.txt");
	if (Reading) {
		Reading >> _n;
	}
	else
		std::cout << "������ �������� �����" << endl;
	Reading.close();
	return _n;
}


void EntryFile(string ED, string *plaintext, string*ciphertext,string *Base64ciphertext,string *Base64plaintext) {
	//��������� �� ������� ��� ���� ��� �� ����� ���� ������� �� ����� ����������� ��� ���������� � DecryptedFile() � �������������� �� ������� � cbc
	AutoSeededRandomPool full;
	HexEncoder encoder(new FileSink(cout));
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock Initalization(AES::BLOCKSIZE);
	full.GenerateBlock(key, key.size());
	full.GenerateBlock(Initalization, Initalization.size());
	ifstream Reading("Encryption.txt");
	ofstream Record(ED, ios::app);
	int n = AmountOfData() + 1;
	if (Reading) {
		if (Record) {
			cout << "������� ����� ��� ����������";
			cin >> *plaintext;
			CBC_Mode<AES>::Encryption aesEncryption;
			aesEncryption.SetKeyWithIV(key, key.size(), Initalization);
			StringSource transformcipher(*plaintext, true,
				new StreamTransformationFilter(aesEncryption,
					new StringSink(*ciphertext)
				)
			);
			StringSource transformbasecipher(*ciphertext, true,
				new Base64Encoder(
					new StreamTransformationFilter(aesEncryption,
						new StringSink(*Base64ciphertext)
					)
				)
			);
			StringSource transformbaseplain(*plaintext, true,
				new Base64Encoder(
					new StreamTransformationFilter(aesEncryption,
						new StringSink(*Base64plaintext)
					)
				)
			);
			string Base64Key, Base64Initalization;
			StringSource transformbasekey(key, key.size(), true,
				new Base64Encoder(
					new StringSink(Base64Key)
				)
			);
			StringSource transformbaseInitalization(Initalization, Initalization.size(), true,
				new Base64Encoder(
					new StringSink(Base64Initalization)
				)
			);
			Reading >> Base64Key;
			Reading >> Base64Initalization;
			string* KeyPtr = &Base64Key;
			string* InitalizationPtr = &Base64Initalization;
			Reading >> n;
			Record << n;
			for (int i = 0; i < n; i++) {
				Record << KeyPtr;
				Record << Base64Initalization;
				Record << Base64ciphertext;
				Record << Base64plaintext;
			}
			cout << "������ ��������� � �����" << ED << endl;
		}
		else
			cout << "������ �������� �����" << endl;
	}
	else
		cout << "������ �������� ��������� �����" << endl;
	Reading.close();
	Record.close();

}

void DecryptionFile(string ED, string ReadingBase64ciphertext,string ReadingKey,string ReadingInitalization,string DecryptedCipher) {
	AutoSeededRandomPool full;
	ifstream Reading("Encryption.txt");
	ofstream Record("Encryption.txt");
	if (Reading.is_open() && Record.is_open()) {
		getline(Reading, ReadingKey);
		getline(Reading, ReadingInitalization);
		getline(Reading, ReadingBase64ciphertext);
		SecByteBlock TransformKey(AES::DEFAULT_KEYLENGTH);
		SecByteBlock TransformInitalization(AES::BLOCKSIZE);
		CBC_Mode<AES>::Decryption aesDecryption;
		Reading >> ReadingKey;
		Reading >> ReadingInitalization;
		Reading >> ReadingBase64ciphertext;
		aesDecryption.SetKeyWithIV(TransformKey,TransformKey.size(),TransformInitalization);
		StringSource transformtocipher(ReadingBase64ciphertext, true,
			new StreamTransformationFilter(aesDecryption,
				new StringSink(DecryptedCipher)
			)
		);
		Record << DecryptedCipher;
		cout << "Decrypted:" << DecryptedCipher << endl;
	}
	else
	{
		cerr << "�� ������� ������� ����";
	}
	Reading.close();
	Record.close();
}


void EncryptionFile() {
	AutoSeededRandomPool full;
	HexEncoder encoder(new FileSink(cout));
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock Initalization(AES::BLOCKSIZE);
	full.GenerateBlock(key, key.size());
	full.GenerateBlock(Initalization, Initalization.size());
	int n;
	cout << "������� ���������� ������:" << endl;
	cin >> n;
	ofstream Record("EncryptionFiles.txt", ios::app);
	if (Record) {
		for (int i = 0; i < n; i++) {
			string ciphertext, plaintext, decryptedtext;
			cout << "������� ����� ��� ����������:";
			cin >> plaintext;
			CBC_Mode<AES>::Encryption aesEncryption;
			aesEncryption.SetKeyWithIV(key, key.size(), Initalization);
			StringSource transform(plaintext, true,
				new StreamTransformationFilter(aesEncryption,
					new StringSink(ciphertext)
				)
			);
			Record << plaintext;
			std::cout << "key:";
			encoder.Put(key, key.size());
			encoder.MessageEnd();
			cout << "\n";
			cout << "Initalization:";
			encoder.Put(Initalization, Initalization.size());
			encoder.MessageEnd();
			cout << "\n";
			cout << "cipher text:";
			cout << "\n";
			encoder.Put((const byte*)&ciphertext[0], ciphertext.size());
			Record << key;
			Record << Initalization;
			Record << ciphertext;
			cout << "\n";
			cout << "________________________________________________" << endl;
			CBC_Mode<AES>::Decryption aesDecryption;
			aesDecryption.SetKeyWithIV(key, key.size(), Initalization);
			StringSource transf(ciphertext, true,
				new StreamTransformationFilter(aesDecryption,
					new StringSink(decryptedtext)
				)
			);
			cout << "Decrypted text: " << decryptedtext;
			cout << endl;
		}
	}
	Record.close();
}


void CopyFile() {
	AutoSeededRandomPool full;
	HexEncoder encoder(new FileSink(cout));
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock Initalization(AES::BLOCKSIZE);
	full.GenerateBlock(key, key.size());
	full.GenerateBlock(Initalization, Initalization.size());
	ifstream Reading("EncryptionFiles.txt");
	ofstream Record("EncryptionFiles.txt", ios::out);
	if (Reading) {
		if (Record) {
			string plaintext, ciphertext, decryptedtext;
			int n;
			Reading >> n;
			Record << n << endl;
			for (int i = 0; i < n; i++) {
				Reading >> plaintext;
				Record << plaintext << endl;
				Reading >> ciphertext;
				Record << ciphertext << endl;
				Reading >> decryptedtext;
				Record << decryptedtext << endl;
				Reading >> key; // �������� ���� ������ ������ ��� ��������� � ����������������� �������
				Record << key;
				Reading >> Initalization; // �������� ���� ������ ������ ��� ��������� � ����������������� �������
				Record << Initalization;
			}
		}
		else
			cout << "������ �������� �����" << endl;
	}
	else
		cout << "������ �������� ��������� �����" << endl;
	Reading.close();
	Record.close();
}


void DeleteCipher() {
	CopyFile();
	AutoSeededRandomPool full;
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock Initalization(AES::BLOCKSIZE);
	full.GenerateBlock(key, key.size());
	full.GenerateBlock(Initalization, Initalization.size());
	ifstream Reading("EncryptionFiles.txt");
	ofstream Record("EncryptionFiles.txt", ios::out);
	if (Reading) {
		if (Record) {
			string ciphertext, plaintext, decryptedtext;
			int n, _n;
			Reading >> n;
			int b = n - 1;
			cout << "������� ����� �������� ��� �������� �� (1 ��" << "n)" << endl;
			cin >> _n;
			_n--;
			system("cls");
			Record << b << endl;
			if (_n <= 0 && _n < n) {
				for (int i = 0; i < n; i++) {
					if (i != _n) {
						Reading >> plaintext;
						Record << plaintext;
						Reading >> ciphertext;
						Record << ciphertext;
						Reading >> decryptedtext;
						Record << decryptedtext;
						Reading >> key;
						Record << key;
						Reading >> Initalization;
						Record << Initalization;
					}
					else
					{
						Reading >> plaintext;
						Reading >> ciphertext;
						Reading >> decryptedtext;
						Reading >> key;
						Reading >> Initalization;
					}
				}
				cout << "������ �������" << endl;
			}
			else
				cout << "������ ������� �������" << endl;
		}
		else
			cout << "������ �������� �����" << endl;
	}
	else
		cout << "������ �������� ��������� �����" << endl;
	Reading.close();
	Record.close();
	remove("EncryptionFiles.txt");
}


void SaveCipher(string Filename) {
	AutoSeededRandomPool full;
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock Initalization(AES::BLOCKSIZE);
	full.GenerateBlock(key, key.size());
	full.GenerateBlock(Initalization, Initalization.size());
	ifstream Reading("EncryptionFiles.txt");
	ofstream Record(Filename, ios::app);
	if (Reading) {
		if (Record) {
			string ciphertext, plaintext, decryptedtext;
			int n;
			Reading >> n;
			Record << n;
			for (int i = 0; i < n; i++) {
				Reading >> plaintext;
				Record << plaintext;
				Reading >> ciphertext;
				Record << ciphertext;
				Reading >> decryptedtext;
				Record << decryptedtext;
				Reading >> key;
				Record << key;
				Reading >> Initalization;
				Record << Initalization;
			}
			cout << "������ ��������� � �����" << Filename << endl;
		}
		else
			cout << "������ �������� �����" << endl;
	}
	else
		cout << "������ �������� ��������� �����" << endl;

	Reading.close();
	Record.close();
}


void InitalizationCipher() {
	ofstream Record("EncryptionFiles.txt");
	if (!Record) {
		cout << "������ �������� �����" << endl;
	}
	Record.close();
}


void ChangeCipher() {

}