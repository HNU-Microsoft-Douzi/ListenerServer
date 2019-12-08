#include <iostream>
#include <string>
#include <dlfcn.h> 

using namespace std;

// 函数指针
typedef string(* _pLoginInterface)(string, string);

// dynamic load libclient.so library test-cpp file

int main(int argc, char** argv) {
	char* errstr;
	// 动态链接库句柄
	void *module_handle = NULL;
	_pLoginInterface loginInterface = NULL;
	char libraryName[1024] = {"./libclient.so"};
	
	// 打开动态链接库
	module_handle = dlopen(libraryName, RTLD_NOW);
	if (module_handle == NULL) {
		errstr = dlerror();
		cout << "Failed load library!" << endl;
		cout << errstr << endl;
		return -1;
	}
	
	dlerror(); // Clear any existing error
	
	*(void**)(&loginInterface) = dlsym(module_handle, "_Z28doLoginCallByAndroidJNILayerNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES4_");
	// *(void**)(&loginInterface) = dlsym(module_handle, "_Z31doRegisterCallByAndroidJNILayerNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES4_");
	errstr = dlerror();
	
	if (errstr != NULL) {
		cout << "Failed load Function!" << endl;
		string errorMsg = errstr;
		errorMsg = "error reason is:" + errorMsg;
		cout << errorMsg << endl;
		return -1;
	}
	
	// call function
	string loginResponse = (*loginInterface)("376358913", "zhang1998813123");
	cout << loginResponse << endl;
	
	// 关闭动态链接库
	dlclose(module_handle);
	return 0;
}
