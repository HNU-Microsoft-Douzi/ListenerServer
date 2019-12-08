#include<iostream>
#include"token_control.h"
using namespace std;

vector<string> split(string str, char c) {
	const char *p = str.c_str();
	int start = 0;
	vector<string> result;
	for (int i = 1; i < str.length(); i++) {
		if (p[i] == c) {
			result.push_back(str.substr(start, i - start));
			start = i + 1;
		}
	}
	result.push_back(str.substr(start, str.length() - start));
	return result;
}

/*
check whether the token is valid by this method
*/
bool isTokenValid(string token) {
	const char* str = token.c_str();
	// length judge
	if (token.length() < 25 || token.length() > 32) {
		return false;
	}
	// auth_code judge
	string auth_code = token.substr(0, 8);
	if (auth_code != "wxclient" && auth_code != "wxserver") {
		return false;
	}
	// timestamp judge
	for (int i = 9; i < 19; i++) {
		if (str[i] < 48 || str[i] > 57) {
			return false;
		}
	}
	// all characters judge
	for (int i = 0; i < token.length(); i++) {
		if (!((str[i] >= 48 && str[i] <= 57) || str[i] == 38 || 
			(str[i] >= 65 && str[i] <= 90) || (str[i] >= 97 && str[i] <= 122))) {
			return false;
		}
	}
	return true;
}

bool isTokenOvertime(string origin_token, string current_token) {
	if (!(isTokenValid(origin_token) && isTokenValid(current_token))) {
		return false;
	}
	Token origin_tk(origin_token);
	Token current_tk(current_token);
	long origin_timestamp = stol(origin_tk.get_timestamp());
	long current_timestamp = stol(current_tk.get_timestamp());
	// if delta-T > 60 min, it means current token is overtime 
	if (current_timestamp < origin_timestamp || 
		((current_timestamp - origin_timestamp) > TIMESTAMP_OVERTIME_LIMIT * 3600)) {
		return false;
	}
	return true;
} 

/*
	token generated rule:
		authcode + & + timestamp + & + account
		for example:
			- authcode: wxclient
			- timestamp: 1573787993
			- account: 376358913
			- token:wxclient&1573787993&376358913 
*/
string Token::generated_token() {
	// generated SERVER_TOKEN type token value
	return this->auth_code + "&" + this->timestamp  + "&" + this->account;
} 

bool Token::token_verify(token_type token_type) {
	// verify token code
	if (token_type == CLIENT_TOKEN) {
		if (this->auth_code == "wxclient") {
			return true;
		}
	}
	if (token_type == SERVER_TOKEN) {
		if (this->auth_code == "wxserver") {
			return true;
		}
	}
	return false;
}