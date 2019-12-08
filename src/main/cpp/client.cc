#include<iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "src/main/proto/wxhomework.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;
using wxhomework::UserInfoRequest;
using wxhomework::UserLoginResponse;
using wxhomework::UserRegisterResponse;
using wxhomework::State;
using wxhomework::WxHomework;

class WxhomeworkClient {
public:
	WxhomeworkClient(std::shared_ptr<Channel> channel) 
		:stub_(WxHomework::NewStub(channel)) {}

	std::string doLogin(const std::string& account, const std::string& password) {
		UserInfoRequest request;
		request.set_account(account);
		request.set_encodepassword(password);

		UserLoginResponse response;
		ClientContext context;
		Status status = stub_->doLogin(&context, request, &response);

		if (status.ok()) {
			return response.message();
		}
		else {
			std::cout << status.error_code() << ": " << status.error_message()
				<< std::endl;
			return "RPC failed";
		}
	}

	std::string doRegister(const std::string& account, const std::string& password) {
		UserInfoRequest request;
		request.set_account(account);
		request.set_encodepassword(password);

		UserRegisterResponse response;
		ClientContext context;
		Status status = stub_->doRegister(&context, request, &response);

		if (status.ok()) {
			return response.message();
		}
		else {
			std::cout << status.error_code() << ": " << status.error_message()
				<< std::endl;
			return "RPC failed";
		}
	}
	
private:
	std::unique_ptr<WxHomework::Stub> stub_;
};

std::string doLoginCallByAndroidJNILayer(std::string account ,std::string password) {
		WxhomeworkClient client(grpc::CreateChannel(
			"49.235.120.103:50051", grpc::InsecureChannelCredentials()));
		std::string loginResponse = client.doLogin(account, password);
		return loginResponse;
}

std::string doRegisterCallByAndroidJNILayer(std::string account ,std::string password) {
		WxhomeworkClient client(grpc::CreateChannel(
			"49.235.120.103:50051", grpc::InsecureChannelCredentials()));
		std::string registerResponse = client.doRegister(account, password);
		return registerResponse;
}

int main(int argc, char** argv) {
	WxhomeworkClient client(grpc::CreateChannel(
		"49.235.120.103:50051", grpc::InsecureChannelCredentials()));
	std::string account = "376358913";
	std::string password = "zhang1998813123";

	std::string registerResponse = client.doRegister(account, password);
	std::string loginResponse = client.doLogin(account, password);
	//std::string registerResponse = "register";
	//std::string loginResponse = "login";
	std::cout << "register result:" << registerResponse << std::endl;
	std::cout << "login result:" << loginResponse << std::endl;

	return 0;
}
