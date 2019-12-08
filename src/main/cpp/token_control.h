/*
	token manage header
*/

#include <string>
#include <vector>
# define TIMESTAMP_OVERTIME_LIMIT 60 // 单位是分钟 

enum token_type {
	CLIENT_TOKEN,
	SERVER_TOKEN,
};

std::string generated_token();

bool token_verify(token_type token_type);

bool isTokenValid(std::string token);

std::vector<std::string> split(std::string str, char c);

bool isTokenOvertime(std::string origin_token, std::string current_token);

class Token {
	public:
		Token(std::string account, std::string timestamp, std::string auth_code) {
			this->account = account;
			this->timestamp = timestamp;
			this->auth_code = auth_code;
		}
		
		Token(std::string token) {
			bool valid = isTokenValid(token);
			if (!valid) {
				throw "token is invalid";
			}
			std::vector<std::string> parseResult = split(token, '&');
			this->auth_code = parseResult.at(0);
			this->timestamp = parseResult.at(1);
			this->account = parseResult.at(2);
		}
		
		std::string generated_token();
		
		bool token_verify(token_type token_type);
		
		std::string get_timestamp() {
			return this->timestamp;
		}
		
	private:
		std::string account;
		std::string timestamp;
		/*
			8λ 
			client_generated_token:wxclient
			server_generated_token:wxserver
		*/
		std::string auth_code; 
};
