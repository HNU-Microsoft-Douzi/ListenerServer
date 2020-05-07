#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <memory>
#include <vector>

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
#include "wes_encryption_algorithm.h"

#include "src/main/proto/wxhomework.grpc.pb.h"

#include <thread>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using grpc::ServerWriter;
using grpc::StatusCode;
using wxhomework::MessageReadRequest;
using wxhomework::MessageReadResponse;
using wxhomework::UserInfoRequest;
using wxhomework::UserLoginResponse;
using wxhomework::UserRegisterResponse;
using wxhomework::UserPasswordChangeResponse;
using wxhomework::PraiseRequest;
using wxhomework::PraiseResponse;
using wxhomework::ReceiveMessageRequest;
using wxhomework::HistoryMessageRequest;
using wxhomework::HistoryMessageResponse;
using wxhomework::RMResponse;
using wxhomework::SendMessageRequest;
using wxhomework::SendMessageResponse;
using wxhomework::Message;
using wxhomework::CCATResponse;
using wxhomework::User;
using wxhomework::JokeRequest;
using wxhomework::JokeResponse;
using wxhomework::QuestionRequest;
using wxhomework::QuestionResponse;
using wxhomework::GradeRequest;
using wxhomework::GradeResponse;
using wxhomework::AnswerRequest;
using wxhomework::AnswerResponse;
using wxhomework::DoctorMessageRequest;
using wxhomework::DoctorMessageResponse;
using wxhomework::OrganizationCodeRequest;
using wxhomework::OrganizationCodeResponse;
using wxhomework::MessageRequest;
using wxhomework::MessageResponse;
using wxhomework::MRDRequest;
using wxhomework::MRDResponse;
using wxhomework::DoctorWithdrawLevelRequest;
using wxhomework::DoctorWithdrawLevelResponse;
using wxhomework::WxHomework;

using namespace std;
const char user[] = "root";
const char pswd[] = "zhang@1998813123";
char host[] = "49.235.120.103";
const char database[] = "wxhomework";
const unsigned int port = 3306;
const unsigned int base_ad_rate = 10000;

const float doctor_star_one_rate = 0.0f;
const float doctor_star_two_rate = 0.0f;
const float doctor_star_three_rate = 0.0003f; // 3元奖励
const float doctor_star_four_rate = 0.0006f; // 6元奖励
const float doctor_star_five_rate = 0.001f; // 10元奖励

const int doctor_professionalism_rating_one = -10;
const int doctor_professionalism_rating_two = 0;
const int doctor_professionalism_rating_three = 5;
const int doctor_professionalism_rating_four = 10;
const int doctor_professionalism_rating_five = 20;

pthread_mutex_t p_mutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t method_mutex = PTHREAD_MUTEX_INITIALIZER;

class WxHomeworkServiceImpl final : public WxHomework::Service {
public:

    WxHomeworkServiceImpl() {
        // init database
        mysql_init(&mysql);
        // set encode-style
        mysql_options(&mysql, MYSQL_SET_CHARSET_NAME, "gbk");
        // connect database
        // output "connect failed" when progress judge connect failed
        if (mysql_real_connect(&mysql, host, user, pswd, database, port, NULL, 0) == NULL) {
            cout << "connect failed!" << endl;
        } else {
            cout << "connect successed!" << endl;
        }
    }

    ~WxHomeworkServiceImpl() {
        // free result source
        mysql_free_result(res);
        // close database
        mysql_close(&mysql);
    }

    /*-----------the following code is used to help user complete login operation------------*/
    /**
     * login method
     * @param context
     * @param request
     * @param response
     * @return
     */
    Status doLogin(ServerContext *context, const UserInfoRequest *request,
                   UserLoginResponse *response) override {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doLogin" << endl;
        string account = request->account();
        string password = request->encodepassword();
        // here you can get a encode password from request.
        // you should to decode the password and verify whether it is equaled with the stored password.
        password = decrypt(password);
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED,
                          "The user name has not been registered, please try again");
        }

        string client_address = context->peer();
        int first_split_location = client_address.find(':');
        int second_split_location = client_address.rfind(':');
        string client_ip = client_address.substr(first_split_location + 1,
                                                 second_split_location - first_split_location -
                                                 1);
        string client_port = client_address.substr(second_split_location + 1);
        cout << "client_ip:" + client_ip + "        " + client_port << endl;
        string token = request->token();
        cout << "token:" + token << endl;

        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                cout << "token auth_code verify fail, auth_code error" << endl;
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }

        string queryWords =
                "select is_login, user.password from user, login_state where user.account = '" +
                account + "';";
        executeSql(queryWords);
        string is_login = "";
        string passwordD = "";
        row = mysql_fetch_row(res);
        is_login = row[0];
        passwordD = row[1];
        if (password != passwordD) {
            cout << "login: user password is wrong!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user password is wrong");
        }
        if (is_login == "0") {
            // Non-login status, can login in
            string sql =
                    "update login_state set is_login = 1, host = '" + client_ip +
                    "', port = '" +
                    client_port + "', token = '" + token + "' where account = '" + account +
                    "';";
            if (mysql_query(&mysql, sql.c_str()) == 0)
                cout << "execute update success!" << endl;
            else printf("Select failed (%s)\n", mysql_error(&mysql));
            cout << account + " login success!" << endl;
        } else {
            // Logon status, to kick out other logon status of the user and give a prompt
            cout << account +
                    " login success! you picked out the other user who used your account!"
                 << endl;
            // kick out first login ip �������� server send log out message to first client ip
            // write account token to database
            string sql =
                    "update login_state set is_login = 1, host = '" + client_ip +
                    "', port = '" +
                    client_port + "', token = '" + token + "' where account = '" + account +
                    "';";
            executeSql(sql);
            // login success, but the other user was picked out!
        }
        response->set_token(token);
        User *user = getUserInfo(account);
        response->set_allocated_user(user);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:
    User *getUserInfo(string account) {
        cout << "---------> getUserInfo" << endl;
        mysql_query(&mysql, "SET NAMES UTF8");
        string sql = "select * from user where account = '" + account + "';";
        if (!executeSql(sql)) {
            return false;
        }
        row = mysql_fetch_row(res);
        string mid = row[2];
        string nick_name = row[3];
        string level = row[4];
        string head_url = row[5];
        string video_url = row[6];
        string ccat_mid = row[7];
        float with_draw = atof(row[8]);
        string eiStr = row[9];
        int experience_index = stoi(eiStr.c_str());
        User *user = new User();
        user->set_mid(mid);
        user->set_nick_name(nick_name);
        user->set_level(level);
        user->set_head_url(head_url);
        user->set_video_url(video_url);
        user->set_ccat_mid(ccat_mid);
        user->set_withdraw(with_draw);
        user->set_experience_index(experience_index);
        return user;
    }

public:
    Status doLoginOut(ServerContext *context, const UserInfoRequest *request,
                      UserLoginResponse *response) override {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doLoginOut" << endl;
        string account = request->account();
        string password = request->encodepassword();
        password = decrypt(password);
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "The user name has not been registered");
        }

        string client_address = context->peer();
        int first_split_location = client_address.find(':');
        int second_split_location = client_address.rfind(':');
        string client_ip = client_address.substr(first_split_location + 1,
                                                 second_split_location - first_split_location -
                                                 1);
        string client_port = client_address.substr(second_split_location + 1);
        string token = request->token();
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        string queryWords =
                "select is_login from login_state where account = '" + account + "';";
        executeSql(queryWords);
        string r0 = "";
        for (int i = 0; i < 1; i++) {
            row = mysql_fetch_row(res);
            r0 = row[0];
        }
        if (r0 == "0") {
            cout << "current user is not login, can not execute login out!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not login");
        } else {
            string origin_token = getUserToken(account);
            string current_token = request->token();
            if (isTokenOvertime(origin_token, current_token)) {
                clearLoginState(account);
                return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
            }
            string sql =
                    "update login_state set is_login = 0, host = '0.0.0.0', port = '55555', token = '' where account = '" +
                    account + "';";
            mysql_query(&mysql, sql.c_str());
            cout << account + " login out success!" << endl;
            pthread_mutex_unlock(&method_mutex);
            return Status::OK;
        }
    }

    /*
    logic:
        - check database, if current account not exist, reject user request with an error.
        - check database, if current account exitst, fix user password in database.
    */
    Status doPasswordChange(ServerContext *context, const UserInfoRequest *request,
                            UserPasswordChangeResponse *response) override {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doPasswordChange" << endl;
        // not login state, token can be none
        string account = request->account();
        string password = request->encodepassword();
        password = decrypt(password);
        bool isUE = this->isUserExist(account);
        if (!isUE) {
            return Status(StatusCode::PERMISSION_DENIED, "change password fail, user is not exist");
        }
        string sql =
                "update user set password = " + password + "' where account = '" + account +
                "';";
        executeSql(sql);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

    /*
    logic��
        - check database, if current account exist, reject user request with an error.
        - check database, if current account not exist, do data insert and return success.
    */
    Status doRegister(ServerContext *context, const UserInfoRequest *request,
                      UserRegisterResponse *response) override {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doRegister" << endl;
        // not login state, token can be none
        string account = request->account();
        string password = request->encodepassword();
        password = decrypt(password);
        bool isUE = this->isUserExist(account);
        if (!isUE) {
            // database has no data, execute insert-operation is allowed, and insert result will be returned to client.
            string sql =
                    "insert into user (account, password) values ('" + account + "' ,'" + password +
                    "');";
            executeSql(sql);
            // maybe you should save login session in this words.
            sql = "insert into login_state (account, is_login) values ('" + account + "' ,0);";
            executeSql(sql);
            pthread_mutex_unlock(&method_mutex);
            return Status::OK;
        } else {
            // database has data, can't execute insert-operation, and return error info to client.
            cout << account + " insert fail! because user is exist!" << endl;
            pthread_mutex_unlock(&method_mutex);
            return Status(StatusCode::PERMISSION_DENIED, "user has registered");
        }
    }

    /*-----------the following code is used to help user complete message operation------------*/
    Status doMessageBroadcast(ServerContext *context, const SendMessageRequest *request,
                              SendMessageResponse *response) override {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doMessageBroadcast" << endl;
        string account = request->account();
        Message message = request->message();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }

        // official operation
        string createTime = message.createtime();
        string content = message.content();
        int sharePersonNums = message.sharepersonnums();
        int shareDoctorNums = message.sharedoctornums();
        insertMessageToTable(account, content, createTime, sharePersonNums, shareDoctorNums);
        vector <string> originPersons = getNormalSharedPerson(account, sharePersonNums);
        vector <string> doctorPersons = getDoctorSharedPerson(account, shareDoctorNums);
        int messageId = getMessageId(account);
        insertMessageToSharedPersonTable(messageId, originPersons);
        insertMessageToSharedPersonTable(messageId, doctorPersons);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:

    // 给定人数，获取除了自己之外的普通聆听者列表
    vector <string> getNormalSharedPerson(string account, int num) {
        cout << "---------> getNormalSharedPerson" << endl;
        // 一次性拿到所有的普通人列表，然后随机数选出其中num的人
        //string sql = "select account from user where (account <> '"
        //             + account + "' and mid = 0) ORDER BY RAND() LIMIT "
        //             + to_string(num) + ";";
	// 为了方便测试，一次性拿到所有的普通用户列表
	string sql = "select account from user where (account <> '"
                     + account + "' and mid = 0)";
        executeSql(sql);
        if (!res) {
            cout << "----> mysql_store_result error" << endl;
        }
        vector <string> result;
        while (row = mysql_fetch_row(res)) {
            result.push_back(row[0]);
        }
        return result;
    }

    // 给定人数，获取除了自己之外的医生列表
    vector <string> getDoctorSharedPerson(string account, int num) {
        cout << "---------> getDoctorSharedPerson" << endl;
        // 一次性拿到所有的普通人列表，然后随机数选出其中num的人
        //string sql = "select account from user where (account <> '"
        //             + account + "' and mid = 1) ORDER BY RAND() LIMIT "
        //             + to_string(num) + ";";
	// 为了方便测试，一次性拿到所有的医生账号列表
	string sql = "select account from user where (account <> '"
	        	+ account + "' and mid = 1)";
        executeSql(sql);
        if (!res) {
            cout << "----> mysql_store_result error" << endl;
        }
        vector <string> result;
        while (row = mysql_fetch_row(res)) {
            result.push_back(row[0]);
        }
        return result;
    }

    // 将用户消息插入被分享者消息(receiver_message)表
    void insertMessageToSharedPersonTable(int messageId,
                                          vector <string> shared_account) {
        cout << "---------> insertMessageToSharedPersonTable" << endl;
        for (int i = 0; i < shared_account.size(); i++) {
            string account = shared_account[i];
            string sql = "insert into receiver_message (account, messageId) values ('"
                         + account + "','" + to_string(messageId)
                         + "');";
            cout << "---> sql : " + sql << endl;
            if (mysql_query(&mysql, sql.c_str()) != 0) {
                printf("insertMessageToSharedPersonTable: mysql error: (%s)\n",
                       mysql_error(&mysql));
            }
        }
    }

    // 根据用户account和createTime获得MessageId
    int getMessageId(string account) {
        cout << "---------> getMessageId" << endl;
        string sql = "select Id from message where account = '"
                     + account + "' order by id DESC limit 1;";
        if (!executeSql(sql)) {
            return -1;
        }
        string result;
        while (row = mysql_fetch_row(res)) {
            result = row[0];
        }
        return stoi(result.c_str());
    }

    // 将用户消息插入message表
    void
    insertMessageToTable(string account, string message, string createTime, int sharePersonNums,
                         int shareDoctorNums) {
        cout << "---------> insertMessageToTable" << endl;
        string sql =
                "insert into message(account, create_time, content, share_person_num, share_doctor_num) values('"
                + account + "', '" + createTime + "', '" + message + "', "
                + to_string(sharePersonNums) + ", " + to_string(shareDoctorNums) + ");";
        if (mysql_query(&mysql, sql.c_str()) != 0) {
            printf("insertMessageToTable: mysql error: (%s)\n", mysql_error(&mysql));
        }
    }

public:

    // 接收消息
    Status doMessageReceiver(ServerContext *context, const ReceiveMessageRequest *request,
                             ServerWriter <RMResponse> *writerResponse) override {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doMessageReceiver" << endl;
        string account = request->account();
        string token = request->token();
        bool isDoctor = request->isdoctor();

        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        vector <RMResponse> messages;
        if (!isDoctor) {
            messages = getReceiverMessage(account);
        } else {
            messages = getDoctorReturnMessage(account);
        }
        for (RMResponse message : messages) {
            writerResponse->Write(message);
        }
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:

    // 根据用户账号获取接收到的所有的消息（这里医生的身份也是倾诉者，接收到的是医生的倾诉消息，而医生的回执消息在doctor_message中）
    vector <RMResponse> getReceiverMessage(const string account) {
        cout << "---------> getReceiverMessage" << endl;
        string sql =
                "select m.Id, user.mid, user.account, m.content, m.praise_num, user.nick_name, user.head_url, m.create_time from user, message as m, receiver_message as rm where rm.account = '" +
                account + "' and m.Id = rm.messageId and user.account = m.account;";
        executeSql(sql);
        string message_account = "none", messageid = "-1", content = "null", mid = "0", nickName = "none", headUrl = "none", createTime = "2000-01-01 00:00";
        int praise_num = 0;
        vector <RMResponse> result;
        while (row = mysql_fetch_row(res)) {
            messageid = row[0];
            mid = row[1];
            message_account = row[2];
            content = row[3];
            string praise_str = row[4];
            praise_num = stoi(praise_str.c_str());
            nickName = row[5];
            headUrl = row[6];
            createTime = row[7];

            RMResponse response;
            response.set_messageid(messageid);
            response.set_content(content);
            response.set_mid(mid);
            response.set_praisenum(praise_num);
            response.set_createtime(createTime);
            response.set_userhead(headUrl);
            response.set_username(nickName);
            result.push_back(response);
        }
        return result;
    }

    vector <RMResponse> getDoctorReturnMessage(const string account) {
        cout << "---------> getDoctorReturnMessage" << endl;
        string sql =
                "select * from doctor_message where receiver = '" +
                account + "';";
        executeSql(sql);
        string doctorId = "none", messageid = "-1", content = "null", mid = "1", return_message_id = "";
        int level = 0;
        int praise_num = 0;
        vector <RMResponse> result;
        while (row = mysql_fetch_row(res)) {
            messageid = row[0];
            doctorId = row[1];
            content = row[3];
            string levelStr = row[4];
            return_message_id = row[5];
            level = stoi(levelStr.c_str());

            RMResponse response;
            response.set_messageid(messageid);
            response.set_doctorid(doctorId);
            response.set_content(content);
            response.set_mid(mid);
            response.set_praisenum(praise_num);
            response.set_level(level);
            response.set_return_message_id(return_message_id);
            result.push_back(response);
        }
        return result;
    }

public:
    Status doMessageSend(ServerContext *context, const DoctorMessageRequest *request,
                         DoctorMessageResponse *response) override {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doMessageSend" << endl;
        string account = request->account();
        string token = request->token();

        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        string messageId = request->messageid();
        string message = request->message();
        insertMessageToAim(account, messageId, message);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:
    void insertMessageToAim(string account, string messageId, string message) {
        cout << "---------> insertMessageToAim" << endl;
        string sql = "select account from message where Id = '"
                     + messageId + "';";
        executeSql(sql);
        string receiver;
        while (row = mysql_fetch_row(res)) {
            receiver = row[0];
        }
        string sql_1 = "insert into doctor_message(doctor, receiver,  message, return_message_id) values ('"
                       + account + "', '" + receiver + "', '" + message + "', " + messageId + ");";
        if (mysql_query(&mysql, sql_1.c_str()) != 0) {
            printf("insertMessageToAim mysql insert error(%s)\n", mysql_error(&mysql));
        }
    }

public:
    Status doMessageHasRead(ServerContext *context, const MessageReadRequest *request,
                            MessageReadResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doMessageHasRead" << endl;
        string account = request->account();
        string messageId = request->messageid();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        updateReceiverMessageReadState(account, messageId);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:
    void updateReceiverMessageReadState(string account, string messageid) {
        cout << "---------> updateReceiverMessageReadState" << endl;
        string sql =
                "update receiver_message set read_state = 1 where (account = '"
                + account + "' and messageId = '" + messageid + "');";
        if (mysql_query(&mysql, sql.c_str()) != 0) {
            printf("updateReceiverMessageReadState: mysql error: (%s)\n", mysql_error(&mysql));
        }
    }

public:
    Status doGetHistoryMessages(ServerContext *context, const HistoryMessageRequest *request,
                                ServerWriter <HistoryMessageResponse> *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doGetHistoryMessages" << endl;
        string account = request->account();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        vector <HistoryMessageResponse> result = getHistoryResponse(account);
        for (HistoryMessageResponse historyMessage : result) {
            response->Write(historyMessage);
        }
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:
    vector <HistoryMessageResponse> getHistoryResponse(const string &account) {
        cout << "---------> getHistoryResponse" << endl;
        string messageId;
        string content;
        string createTime;
        vector <HistoryMessageResponse> result;
        string queryMyMessageSql = "select Id, account, content, create_time from message where account = '"
                                   + account + "';";
        // 获得我的历史消息
        if (executeSql(queryMyMessageSql)) {
            while (row = mysql_fetch_row(res)) {
                messageId = row[0];
                if (row[1] == account) {
                }
                content = row[2];
                createTime = row[3];
                HistoryMessageResponse message;
                message.set_messageid(messageId);
                message.set_content(content);
                message.set_createtime(createTime);
                result.push_back(message);
            }
        }
        return result;
    }

public:

    // 给收到的某个消息点赞
    Status doPraise(ServerContext *context, const PraiseRequest *request,
                    PraiseResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doPraise" << endl;
        string account = request->account(); // 点赞者账号
        string messageId = request->messageid(); // 点赞消息id
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            pthread_mutex_unlock(&method_mutex);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        // 修改message的praise_num字段
        increasePraiseNum(messageId);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

    void increasePraiseNum(const string &messageId) {
        cout << "---------> increasePraiseNum" << endl;
        string sql =
                "update message set praise_num = praise_num + '1' where Id = " + messageId + ";";
        if (!executeSql(sql)) {
            printf("increasePraiseNum: mysql error: (%s)\n", mysql_error(&mysql));
        }
    }

    /*-----------the following code is used to help user complete ccat operation------------*/
    Status doDoctorCCAT(ServerContext *context, const UserInfoRequest *request,
                        CCATResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doDoctorCCAT" << endl;
        string account = request->account();
        string password = request->encodepassword();
        // here you can get a encode password from request.
        // you should to decode the password and verify whether it is equaled with the stored password.
        password = decrypt(password);
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        changeUserMid(account);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }


    // 修改用户的MID 0 -> 1
    void changeUserMid(const string &account) {
        cout << "---------> changeUserMid" << endl;
        string sql = "update user set mid = 1 where account = '"
                     + account + "';";
        if (!executeSql(sql) != 0) {
            printf("increasePraiseNum: mysql error: (%s)\n", mysql_error(&mysql));
        }
    }

    Status doQuestionGet(ServerContext *context, const QuestionRequest *request,
                         ServerWriter <QuestionResponse> *qrWriter) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doQuestionGet" << endl;
        string account = request->account();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        } catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        string type = request->type();
        int num = request->num();
        string sql = "select Id, title, right_answer_id from question where question_type = '"
                     + type + "' ORDER BY RAND() LIMIT " + to_string(num);
        if (executeSql(sql)) {
            while (row = mysql_fetch_row(res)) {
                string id = row[0];
                string title = row[1];
                string right_answer_id = row[2];
                QuestionResponse response;
                response.set_questionid(id);
                response.set_questiontitle(title);
                response.set_questionanswerid(right_answer_id);
                qrWriter->Write(response);
            }
        }
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

public:
    Status doOrganizationCodeVerify(ServerContext *context, const OrganizationCodeRequest *request,
            OrganizationCodeResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doOrganizationCodeVerify" << endl;
        string account = request->account();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        string code = request->code();
        // 向服务器查询机构码是否存在
        bool isExist = verifyCode(code);
        response->set_result(isExist);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:
    bool verifyCode(string code) {
        cout << "---------> verifyCode" << endl;
        string sql = "select * from organization_code where code = '"
                + code + "';";
        executeSql(sql);
        int resultLength = mysql_num_rows(res);
        if (resultLength == 0) {
            cout << "--->verifyCode:机构码不存在，校验失败";
            return false;
        } else {
            cout << "--->verifyCode:机构码存在，校验成功";
            return true;
        }
    }

public:
    Status doGetMessageById(ServerContext *context, const MessageRequest *request,
                            MessageResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doGetMessageById" << endl;
        string account = request->account();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        string messageid = request->messageid();
        string sql = "select content, create_time from message where Id = '" + messageid + "';";
        if (executeSql(sql)) {
            if (row = mysql_fetch_row(res)) {
                string content = row[0];
                string createTime = row[1];
                response->set_content(content);
                response->set_time(createTime);
            }
        }
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

    Status doMessageResponsedByDoctor(ServerContext *context, const MRDRequest *request,
            MRDResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doGetMessageById" << endl;
        string account = request->account();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        string messageid = request->messageid();
        string sql = "select * from doctor_message where return_message_id = '" + messageid + "';";
        executeSql(sql);
        int resultLength = mysql_num_rows(res);
        if (resultLength == 1) {
            // 已经有回执了
            response->set_result(true);
        } else {
            response->set_result(false);
        }
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

    Status doUpdateDoctorWithdrawLevel(ServerContext *context, const DoctorWithdrawLevelRequest *request,
            DoctorWithdrawLevelResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doUpdateDoctorWithdrawLevel" << endl;
        string account = request->account();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        string messageid = request->messageid();
        int level = request->level();
        // 根据评分结果依赖于messageId修正doctor_message的level字段
        string sql = "update doctor_message set level = " + to_string(level) + " where Id = '" + messageid + "';";
        executeSql(sql);
        // 根据评分结果并修正user的with_draw、职能指数、level字段
        int withDraw = getCurrentWithDrawByLevel(level);
        // 根据评分结果并修正user的职能指数和level字段
        int experienceIndex = getCurrentExperienceIndexByLevel(level);
        int doctorLevel = getDoctorLevelByExperienceIndex(experienceIndex);
        sql = "update user set level = " + to_string(doctorLevel) + " , account_withdraw = account_withdraw + " + to_string(withDraw) + " , experience_index = experience_index + " + to_string(experienceIndex) + " where account = '" + account + "';";
        executeSql(sql);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

public:
    Status doAnswerGet(ServerContext *context, const AnswerRequest *request,
                       ServerWriter <AnswerResponse> *arWriter) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doAnswerGet" << endl;
        string account = request->account();
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }

        string questionId = request->questionid();
        vector <AnswerResponse> result = getAnswerResponseList(questionId);
        for (AnswerResponse response : result) {
            arWriter->Write(response);
        }
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:
    vector <AnswerResponse> getAnswerResponseList(string questionId) {
        cout << "---------> getAnswerResponseList" << endl;
        string sql = "select Id, content from answer where question_id = '" + questionId + "';";
        vector <AnswerResponse> result;
        if (executeSql(sql)) {
            while (row = mysql_fetch_row(res)) {
                string id = row[0];
                string content = row[1];
                AnswerResponse response;
                response.set_answerid(id);
                response.set_content(content);
                result.push_back(response);
            }
        }
        return result;
    }

public:
    /*-----------the following code is used to help user complete joke operation------------*/
    Status doGetJoke(ServerContext *context, const JokeRequest *request,
                     ServerWriter <JokeResponse> *writerResponse) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doGetJoke" << endl;
        string account = request->account();
        int jokeNum = request->num();
        // here you can get a encode password from request.
        // you should to decode the password and verify whether it is equaled with the stored password.
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        cout << "--->doGetJoke:account = " + account << endl;
        cout << "--->doGetJoke:jokeNum = " + to_string(jokeNum) << endl;
        vector <JokeResponse> jokes = getJokes(jokeNum);
        for (int i = 0; i < jokes.size(); i++) {
            JokeResponse &joke = jokes[i];
            writerResponse->Write(joke);
        }
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

    Status doGradeUpdate(ServerContext *context, const GradeRequest *request,
                         GradeResponse *response) {
        pthread_mutex_lock(&method_mutex);
        cout << "---------> doGradeUpdate" << endl;
        string account = request->account();
        int grade = request->grade();
        // here you can get a encode password from request.
        // you should to decode the password and verify whether it is equaled with the stored password.
        string token = request->token();
        if (!this->isUserExist(account)) {
            cout << account + " is not register!" << endl;
            return Status(StatusCode::PERMISSION_DENIED, "user is not registered");
        }
        try {
            Token tk(token);
            if (!tk.token_verify(CLIENT_TOKEN)) {
                // client token verify fail, because auth_code is not equal with wxclient.
                return Status(StatusCode::UNAUTHENTICATED,
                              "token auth_code verify fail, auth_code error");
            }
        }
        catch (const char *msg) {
            string errorMsg = account + " " + msg;
            cout << errorMsg << endl;
            return Status(StatusCode::UNAUTHENTICATED,
                          "token auth_code verify fail, token format exception");
        }
        string origin_token = getUserToken(account);
        string current_token = request->token();
        if (isTokenOvertime(origin_token, current_token)) {
            clearLoginState(account);
            return Status(StatusCode::DEADLINE_EXCEEDED, "user token is overtime");
        }
        int level = updateGrade(account, grade);
        response->set_level(level);
        pthread_mutex_unlock(&method_mutex);
        return Status::OK;
    }

private:
    // 从数据库中随机获取指定数量的jokes
    vector <JokeResponse> getJokes(const int num) {
        cout << "---------> getJokes" << endl;
        string sql = "select * from joke ORDER BY RAND() LIMIT "
                     + to_string(num) + ";";
        executeSql(sql);
        string id, content;
        vector <JokeResponse> jokes;
        while (row = mysql_fetch_row(res)) {
            id = row[0];
            content = row[1];
            JokeResponse joke;
            joke.set_jokeid(id);
            joke.set_joke_content(content);
            jokes.push_back(joke);
        }
        return jokes;
    }

    int getCurrentWithDrawByLevel(int level) {
        int result = 0;
        switch (level) {
            case 0:
                break;
            case 1:
                break;
            case 2:
                break;
            case 3:
                result = (int) (base_ad_rate * doctor_star_three_rate);
                break;
            case 4:
                result = (int) (base_ad_rate * doctor_star_four_rate);
                break;
            case 5:
                result = (int) (base_ad_rate * doctor_star_five_rate);
                break;
        }
        return result;
    }

    int getCurrentExperienceIndexByLevel(int level) {
        int result = 0;
        switch (level) {
            case 0:
                break;
            case 1:
                result = doctor_professionalism_rating_one;
                break;
            case 2:
                result = doctor_professionalism_rating_two;
                break;
            case 3:
                result = doctor_professionalism_rating_three;
                break;
            case 4:
                result = doctor_professionalism_rating_four;
                break;
            case 5:
                result = doctor_professionalism_rating_five;
                break;
        }
        return result;
    }

    int getDoctorLevelByExperienceIndex(int experienceIndex) {
        if (experienceIndex < 100) return 1;
        else if (experienceIndex >= 100 && experienceIndex < 1000) return 2;
        else if (experienceIndex >= 1000 && experienceIndex < 5000) return 3;
        else if (experienceIndex >= 5000 && experienceIndex < 20000) return 4;
        else return 5;
    }

    int updateGrade(const string account, const int grade) {
        cout << "---------> updateGrade" << endl;
        string sql = "update user set ccat_mid = '1' where account = '"
                     + account + "';";
        executeSql(sql);
        string sql1 = "update user set level = '1' where account = '"
                      + account + "';";
        executeSql(sql1);
        string sql2 = "update user set account_withdraw = " + to_string(grade) + " where account = '" + account + "';";
        executeSql(sql2);
        if (grade <= 90) return 1;
        else return 2;
    }

    string getUserToken(const string &account) {
        string queryWords =
                "select is_login from login_state where account = '" + account + "';";
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

    bool isUserExist(const string &account) {
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

    bool executeSql(const string &sql) {
        cout << "------------> executeSql" + sql << endl;
        // query data
        pthread_mutex_lock(&p_mutex);
        if (mysql_query(&mysql, sql.c_str()) != 0) {
            printf("---Select failed (%s)\n", mysql_error(&mysql));
            return false;
        }
        cout << "----mysql_query succeed" << endl;
        // get result set
        res = mysql_store_result(&mysql);
        pthread_mutex_unlock(&p_mutex);
        if (!res) {
            cout << "---mysql_store_result error, error sql:" + sql << endl;
            return false;
        }
        cout << "----mysql_store_result succeed" << endl;
        return true;
    }

    // 清除用户的登录状态
    bool clearLoginState(const string &account) {
        cout << "---------> clearLoginState" << endl;
        string sql =
                "update login_state set is_login = 0, host = '0.0.0.0', port = '55555', token = 'none' where account = '"
                + account + "';";
        if (!executeSql(sql)) {
            cout << "clear login state error." << endl;
            return false;
        }
        cout << "clear login state succeed." << endl;
        return true;
    }


private:
    MYSQL mysql;    //database struct
    MYSQL_RES *res; //result set struct
    MYSQL_ROW row;  //char** Two-dimensional array, store records
};

void RunServer() {
    string server_address("0.0.0.0:50051");
    WxHomeworkServiceImpl service;

    ServerBuilder builder;
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    unique_ptr <Server> server(builder.BuildAndStart());
    cout << "Server listening on" << server_address << endl;
    pthread_mutex_destroy(&p_mutex);

    // Wait for the server to shutdown.Note that some other thread must be
    // responsible for shutting down the server for this call to ever return.
    server->Wait();
}

int main(int argc, char **argv) {
    RunServer();
    return 0;
}
