#include <vector>
// KEY 非常重要，不能对公众泄露KEY值
// 发送端和接收端提前秘密约定好KEY值
#define KEY 53517 

std::vector<std::string> split(std::string str, char c);

std::string encrypt(std::string password);

std::string decrypt(std::string encryptionPassword);
