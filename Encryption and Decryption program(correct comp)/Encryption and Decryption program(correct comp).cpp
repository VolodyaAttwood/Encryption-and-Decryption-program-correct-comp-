#include "ED.h"

int _StateMenu;

void Menu() {
	cout << "Выберите действие: " << endl
		<< "(0) Выйти из программы" << endl
		<< "(1) Зашифровать файл" << endl
		<< "(2) Расшифровать файл" << endl
		<< "(3) Добавить несколько файлов для шифрования: " << endl
		<< "(4) Сохранить файл" << endl
		<< "(5) Удалить файл" << endl
		<< "__________________-" << endl;
	cin >> _StateMenu;
}


int main() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);
	InitalizationCipher();
	Menu();
	int _Actions;
	string Filename;
	extern string ED;
	extern string &plaintext;
	extern string &ciphertext;
	extern string &Base64ciphertext;
	extern string &Base64plaintext;
	while (_StateMenu != 0) {
		if (_StateMenu == 1) {
			system("cls");
			cout << "Введите файл в котором будут храниться данные:";
			cin >> ED;
			EntryFile(ED, &plaintext, &ciphertext, &Base64ciphertext, &Base64plaintext);
			Menu();
		}
		else if (_StateMenu == 2) {
			system("cls");
			cout << "Введите файл в котором хранятся зашифрованные данные:";
			cin >> ED;
			DecryptionFile(ED);
			Menu();
		}
		else if (_StateMenu == 3) {
			system("cls");
			EncryptionFile();
			system("cls");
			Menu();
		}
		else if (_StateMenu == 4) {
			system("cls");
			cout << "Введите название файла:" << endl;
			cin >> Filename;
			SaveCipher(Filename);
			Menu();
		}
		else if (_StateMenu == 5) {
			system("cls");
			DeleteCipher();
			Menu();
		}
	}

}
