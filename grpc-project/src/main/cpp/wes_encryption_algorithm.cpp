#include <iostream>
#include <string>
#include "wes_encryption_algorithm.h"

using namespace std;
 
// 加密算法可以公开
int encrypt(int plainText, int key)
{
	return plainText ^ key;
}
 
// 解密算法也可以公开
int decrypt(int cipherText, int key)
{
	return cipherText ^ key;
}

string encrypt(string password) {
	string encryptionPassword = "";
	const char* s = password.c_str();
	int i = 0;
	for (; i < password.length() - 1; i++) {
		encryptionPassword += to_string(encrypt((int)s[i], KEY)) + "%";
	}
	encryptionPassword += to_string(encrypt((int)s[i], KEY));
	return encryptionPassword;
}

string decrypt(string encryptionPassword) {
	vector<string> splitStrs = split(encryptionPassword, '%');
	string decryptionPassword = "";
	string password = "";
	for (int i = 0; i < splitStrs.size(); i++) {
		char temp = decrypt(atoi(splitStrs.at(i).c_str()) , KEY);
		password += temp;
	}
	cout << password << endl;  
	return password;
}
