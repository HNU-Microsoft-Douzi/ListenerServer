#include <iostream>
#include <stdio.h>
#include <string>
#include <memory>

#include <grpc/grpc.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/security/server_credentials.h>

#if defined(__linux__)
// Linux system
#include <sys/socket.h>
#include <mysql/mysql.h>
#elif defined(_WIN32)
// Windows system
#include <winsock.h>
#include "mysql.h"
#endif

#include "token_control.h"
#include "server_error.h"
#include "wes_encryption_algorithm.h"

#include "src/main/proto/wxhomework.grpc.pb.h"

#include <thread>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using wxhomework::UserInfoRequest;
using wxhomework::UserLoginResponse;
using wxhomework::UserRegisterResponse;
using wxhomework::UserPasswordChangeResponse;
using wxhomework::State;
using wxhomework::LoginService;
using wxhomework::CcatService;

using namespace std;

const char user[] = "root";
const char pswd[] = "zhang@1998813123";
char host[] = "49.235.120.103";
const char database[] = "wxhomework";
const unsigned int port = 3306;

const string SUCCESS = "success";
const string FAIL = "fail";
const string MISTAKE = "error";


MYSQL mysql;    //database struct
MYSQL_RES *res; //result set struct
MYSQL_ROW row;  //char** Two-dimensional array, store records

Status statusGenerated(string result, string code, string msg, UserRegisterResponse *response);

Status statusGenerated(string result, string code, string msg, UserPasswordChangeResponse *response);

Status statusGenerated(string result, string code, string msg, UserLoginResponse *response);

User getUserInfoFromDB(string account);

class CcatImpl final : public CcatService::Service {
public :
    /*
     * help user complete the identity authentication of doctor
     */
    Status doDoctorCCAT(ServerContext *context, const UserInfoRequest *request,
                        CCATResponse *response) {
        string account = request->account();
        string password = decrypt(request->encodepassword());
        string token = request->token();
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return statusGenerated(FAIL, USER_TOKEN_IS_INVALID, "token auth_code verify fail",
                                       response);
            }
        } catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return statusGenerated(MISTAKE, USER_TOKEN_IS_INVALID, errorMsg, response);
        }
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return statusGenerated(MISTAKE, USER_IS_NOT_EXIST,
                                   "The user name has not been registered, please try again",
                                   response);
        }

        string updateSql = "update user set mid = 1 where account = '" + account + "';";
        if (mysql_query(&mysql, updateSql.c_str()) == 0){
            cout << "execute update success!" << endl;
            User *user = getUserInfoFromDB(account);
            State *state = new State();
            state->set_result(SUCCESS);
            response->set_allocated_state(state);
            response->set_message("doctor authentication get succeed!");
            response->set_user(user);
        } else {
            printf("Select failed (%s)\n", mysql_error(&mysql));
            State *state = new State();
            state->set_result(FAIL);
            state->set_code(MYSQL_EXCUTE_EXCEPTION);
            response->set_allocated_state(state);
            response->set_message("mysql execute fail!");
        }
        return Status::OK;
    }
};

class LoginImpl final : public LoginService::Service {
public:

    Status doLogin(ServerContext *context, const UserInfoRequest *request,
                   UserLoginResponse *response) override {
        string account = request->account();
        string password = request->encodepassword();
        // here you can get a encode password from request.
        // you should to decode the password and verify whether it is equaled with the stored password.
        password = decrypt(password);
        string client_address = context->peer();
        int first_split_location = client_address.find(':');
        int second_split_location = client_address.rfind(':');
        string client_ip = client_address.substr(first_split_location + 1,
                                                 second_split_location - first_split_location - 1);
        string client_port = client_address.substr(second_split_location + 1);
        cout << "client_ip:" + client_ip + "        " + client_port << endl;
        string token = request->token();

        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return statusGenerated(FAIL, USER_TOKEN_IS_INVALID, "token auth_code verify fail",
                                       response);
            }
        } catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return statusGenerated(MISTAKE, USER_TOKEN_IS_INVALID, errorMsg, response);
        }

        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return statusGenerated(MISTAKE, USER_IS_NOT_EXIST,
                                   "The user name has not been registered, please try again",
                                   response);
        }

        string queryWords =
                "select is_login, user.password from user, login_state where user.account = '" +
                account + "';";
        // query data
        if (mysql_query(&mysql, queryWords.c_str()) != 0) {
            printf("Select failed (%s)\n", mysql_error(&mysql));
        }
        // get result set
        res = mysql_store_result(&mysql);
        if (!res) {
            cout << "----> mysql_store_result error" << endl;
        }
        string is_login = "";
        string passwordD = "";
        for (int i = 0; i < 1; i++) {
            row = mysql_fetch_row(res);
            is_login = row[0];
            passwordD = row[1];
        }
        if (password != passwordD) {
            cout << "login: user password is wrong!" << endl;
            return statusGenerated(FAIL, USER_PASSWORD_IS_WRONG, "user password is wrong!",
                                   response);
        }
        if (is_login == "0") {
            // Non-login status, can login in
            string sql =
                    "update login_state set is_login = 1, host = '" + client_ip + "', port = '" +
                    client_port + "', token = '" + token + "' where account = '" + account + "';";
            if (mysql_query(&mysql, sql.c_str()) == 0) cout << "execute update success!" << endl;
            else printf("Select failed (%s)\n", mysql_error(&mysql));
            cout << account + " login success!" << endl;
            return statusGenerated(SUCCESS, "null", "login success", response);
        } else {
            // Logon status, to kick out other logon status of the user and give a prompt
            cout << account + " login success! you picked out the other user who used your account!"
                 << endl;
            // kick out first login ip �������� server send log out message to first client ip
            // write account token to database
            string sql =
                    "update login_state set is_login = 1, host = '" + client_ip + "', port = '" +
                    client_port + "', token = '" + token + "' where account = '" + account + "';";
            if (mysql_query(&mysql, sql.c_str()) == 0) cout << "execute update success!" << endl;
            else printf("Select failed (%s)\n", mysql_error(&mysql));
            return statusGenerated(SUCCESS, "null",
                                   "login success, but the other user was picked out!", response);
        }
    }

    Status doLoginOut(ServerContext *context, const UserInfoRequest *request,
                      UserLoginResponse *response) override {
        string account = request->account();
        string password = request->encodepassword();
        password = decrypt(password);
        string client_address = context->peer();
        int first_split_location = client_address.find(':');
        int second_split_location = client_address.rfind(':');
        string client_ip = client_address.substr(first_split_location + 1,
                                                 second_split_location - first_split_location - 1);
        string client_port = client_address.substr(second_split_location + 1);
        string token = request->token();
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return statusGenerated(FAIL, USER_TOKEN_IS_INVALID, "token auth_code verify fail",
                                       response);
            }
        } catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return statusGenerated(MISTAKE, USER_TOKEN_IS_INVALID, errorMsg, response);
        }
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return statusGenerated(MISTAKE, USER_IS_NOT_EXIST,
                                   "The user name has not been registered, please try again",
                                   response);
        }
        string queryWords = "select is_login from login_state where account = '" + account + "';";
        // query data
        mysql_query(&mysql, queryWords.c_str());
        // get result set
        res = mysql_store_result(&mysql);
        string r0 = "";
        for (int i = 0; i < 1; i++) {
            row = mysql_fetch_row(res);
            r0 = row[0];
        }
        if (r0 == "0") {
            cout << "current user is not login, can not execute login out!" << endl;

            return statusGenerated(MISTAKE, USER_IS_NOT_LOGIN, "The user are not login", response);
        } else {
            string origin_token = getUserToken(account);
            string current_token = request->token();
            if (isTokenOvertime(origin_token, current_token)) {
                return statusGenerated(MISTAKE, USER_TOKEN_IS_OVERTIME,
                                       "The user token is overtime", response);
            }
            string sql =
                    "update login_state set is_login = 0, host = '0.0.0.0', port = '55555', token = '' where account = '" +
                    account + "';";
            mysql_query(&mysql, sql.c_str());
            cout << account + " login out success!" << endl;
            return statusGenerated(SUCCESS, "null", "login out success", response);
        }
    }

    /*
    logic:
        - check database, if current account not exist, reject user request with an error.
        - check database, if current account exitst, fix user password in database.
    */
    Status doPasswordChange(ServerContext *context, const UserInfoRequest *request,
                            UserPasswordChangeResponse *response) override {
        string account = request->account();
        string password = request->encodepassword();
        password = decrypt(password);
        bool isUE = this->isUserExist(account);
        if (!isUE) {
            return statusGenerated(MISTAKE, USER_IS_NOT_EXIST,
                                   "change password fail, user is not exist", response);
        } else {
            string sql =
                    "update user set password = " + password + "' where account = '" + account +
                    "';";
            mysql_query(&mysql, sql.c_str());
            return statusGenerated(SUCCESS, "null", "password change success", response);
        }

    }

    /*
    logic��
        - check database, if current account exist, reject user request with an error.
        - check database, if current account not exist, do data insert and return success.
    */
    Status doRegister(ServerContext *context, const UserInfoRequest *request,
                      UserRegisterResponse *response) override {
        string account = request->account();
        string password = request->encodepassword();
        password = decrypt(password);
        bool isUE = this->isUserExist(account);
        if (!isUE) {
            // database has no data, execute insert-operation is allowed, and insert result will be returned to client.
            string sql =
                    "insert into user (account, password) values ('" + account + "' ,'" + password +
                    "');";
            mysql_query(&mysql, sql.c_str());
            // maybe you should save login session in this words.
            sql = "insert into login_state (account, is_login) values ('" + account + "' ,0);";
            mysql_query(&mysql, sql.c_str());
            return statusGenerated(SUCCESS, "null", "register success", response);
        } else {
            // database has data, can't execute insert-operation, and return error info to client.
            cout << account + " insert fail! because user is exist!" << endl;
            return statusGenerated(MISTAKE, USER_IS_EXIST,
                                   "The user name has been registered, please try again", response);
        }
    }
};

/*
 * get user info from db except password
 */
User getUserInfoFromDB(string account) {
    string queryWords = "select account, mid, nick_name, level, head_url, video_url from user where account = '" + account + "';";
    // query data
    if (mysql_query(&mysql, queryWords.c_str()) != 0) {
        printf("Select failed (%s)\n", mysql_error(&mysql));
    }
    // get result set
    res = mysql_store_result(&mysql);
    if (!res) {
        cout << "----> mysql_store_result error" << endl;
    }
    User user = new User;
    row = mysql_fetch_row(res);
    user.set_account(row[0]);
    user.set_mid(row[1]);
    user.set_nick_name(row[2]);
    user.set_level(row[3]);
    user.set_head_url(row[4]);
    user.set_video_url(row[5]);
    return user;
}

string getUserToken(string account) {
    string queryWords = "select is_login from login_state where account = '" + account + "';";
    // query data
    if (mysql_query(&mysql, queryWords.c_str()) == 0) {
        cout << "---->Select data success!" << endl;
    } else {
        printf("Select failed (%s)\n", mysql_error(&mysql));
    }
    // get result set
    res = mysql_store_result(&mysql);
    if (!res) {
        cout << "----> mysql_store_result error" << endl;
    }
    string r0 = "";
    row = mysql_fetch_row(res);
    r0 = row[0];
    return r0;
}

bool isUserExist(string account) {
    string queryWords = "select * from user where user.account = '" + account + "';";
    // query data
    mysql_query(&mysql, queryWords.c_str());
    // get result_set
    res = mysql_store_result(&mysql);
    // get the count of result_set.
    int rowCount = mysql_num_rows(res);
    if (rowCount == 0) {
        return false;
    } else {
        return true;
    }
}

Status statusGenerated(string result, string code, string msg, UserRegisterResponse *response) {
    State *state = new State();
    state->set_result(result);
    state->set_code(code);
    response->set_allocated_state(state);
    response->set_message(msg);
    return Status::OK;
}

Status
statusGenerated(string result, string code, string msg, UserPasswordChangeResponse *response) {
    State *state = new State();
    state->set_result(result);
    state->set_code(code);
    response->set_allocated_state(state);
    response->set_message(msg);
    return Status::OK;
}

Status statusGenerated(string result, string code, string msg, UserLoginResponse *response) {
    State *state = new State();
    state->set_result(result);
    state->set_code(code);
    response->set_allocated_state(state);
    response->set_message(msg);
    return Status::OK;
}

void initDB() {
    // init database
    mysql_init(&mysql);
    // set encode-style
    mysql_options(&mysql, MYSQL_SET_CHARSET_NAME, "gbk");
    // connect database
    // output "connect failed" when progress judge connect failed
    if (mysql_real_connect(&mysql, host, user, pswd, database, port, NULL, 0) == NULL) {
        cout << "connect failed!" << endl;
    } else {
        cout << "connect succeed!" << endl;
    }
}

void closeDB() {
    // free result source
    mysql_free_result(res);
    // close database
    mysql_close(&mysql);
}

void RunServer() {
    string server_address("0.0.0.0:50051");
    initDB();
    LoginImpl loginService;
    CcatImpl ccatService;

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&loginService);
    builder.RegisterService(&ccatService);
    unique_ptr <Server> server(builder.BuildAndStart());
    cout << "Server listening on" << server_address << endl;

    closeDB();
    // Wait for the server to shutdown.Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
}

int main(int argc, char **argv) {
    RunServer();
    return 0;
}