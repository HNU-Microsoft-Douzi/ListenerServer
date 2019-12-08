# grpc项目介绍

*注：如果只需要使用server端的功能，不用向下看文档描述，因为默认服务端持续在后台运行server程序*

## 前言

整个grpc的项目是强依赖于linux平台的，在windows上运行需要做额外的配置工作。

实际开发的过程中，grpc的项目管理由bazel和android ndk及相关工具链共同负责。

## 目录文件说明

- cat_files：Debug过程的代码审计目录，用来将bazel build过程的缓存中的对应系统文件拷贝借助windows平台的工具复查bug，与项目实体无关
- compilers：grpc适应初期架构时的工具链文件夹
- runfiles:elf文件的存储位置
	- client（已弃用）
	- **server（server端可执行文件）**
	- libclient.so（弃用于当前架构，适用于linux平台的.so架构文件）
- **src:grpc项目的核心文件目录**
- third_party：grpc依赖的本地存储仓库（弃用于当前架构，为了解决grpc初期架构的项目依赖问题）
- **build_server:runfiles/server的构建脚本，修改了src的文件内容后，执行./build_server重新构建，生成的文件会替换runfiles的server文件**
- clear:grpc的项目缓存清理脚本（一般不建议使用）
- run_android_armv7:（弃用于当前架构），借助ndk工具生成适用于android平台的armv7的libclient.so
- run_linux_aarch64:（弃用于当前架构），借助linaro工具链生成适用于linux平台的aarch64的libclient.so
- run_linux_armv7:（弃用于当前架构），借助linaro工具链生成适用于linux平台的armv7的libclient.so
- WORKSPACE:bazel的根目录文件