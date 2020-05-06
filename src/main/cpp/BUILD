package(default_visibility = ["//visibility:public"])

load("@com_github_grpc_grpc//bazel:cc_grpc_library.bzl", "cc_grpc_library")

filegroup(
    name = "srcs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)

cc_binary(
    name = "server",
    srcs = [
		"server.cc", 
		"token_control.cpp",
		"wes_encryption_algorithm.cpp",
		"token_control.h",
		"wes_encryption_algorithm.h",
		],
    linkopts = ["-L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -ldl"],
    deps = [
        "//src/main/proto:wxhomework_proto",
        "@com_github_grpc_grpc//:grpc++",
    ],
)

cc_binary(
    name = "libclient.so",
    srcs = ["client.cc"],
    deps = [
        "//src/main/proto:wxhomework_proto",
        "@com_github_grpc_grpc//:grpc++",
	"//third_party/cares:ares"
    ],
    copts = ['-g -std=c++11'],
    linkopts=["-lstdc++ -lm -llog"],
    linkshared=True, 
    linkstatic=True,
)
