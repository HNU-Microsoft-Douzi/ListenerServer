load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

######## Skylark libraries ########
http_archive(
    name = "bazel_skylib",
    sha256 = "2ea8a5ed2b448baf4a6855d3ce049c4c452a6470b1efd1504fdb7c1c134d220a",
    strip_prefix = "bazel-skylib-0.8.0",
    url = "https://github.com/bazelbuild/bazel-skylib/archive/0.8.0.tar.gz",
)

######## Protobuf & Grpc ########
# zlib, required by Protobuf & Grpc. (Patched them to use @com_github_madler_zlib//:zlib)
http_archive(
    name = "com_github_madler_zlib",
    build_file = "//third_party:zlib.BUILD",
    sha256 = "c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1",
    strip_prefix = "zlib-1.2.11",
    urls = ["https://zlib.net/zlib-1.2.11.tar.gz"],
)

# boringssl, required by Grpc.
http_archive(
    name = "boringssl",
    sha256 = "78a7f1cf0889de5fc0c85b8c7b940a8fb032f66014d10197ffc1804f20c1d0e4",
    strip_prefix = "boringssl-a21f78d24bf645ccd6774b2c7e52e3c0514f7f29",
    urls = ["https://github.com/google/boringssl/archive/a21f78d24bf645ccd6774b2c7e52e3c0514f7f29.tar.gz"],  # 2019-08-05
)

# gtest, required by Grpc.
http_archive(
    name = "com_google_googletest",
    sha256 = "5aaa5d566517cae711e2a3505ea9a6438be1b37fcaae0ebcb96ccba9aa56f23a",
    strip_prefix = "googletest-b4d4438df9479675a632b2f11125e57133822ece",
    urls = ["https://github.com/google/googletest/archive/b4d4438df9479675a632b2f11125e57133822ece.zip"],  # 2018-07-16
)

# proto_library, cc_proto_library, and java_proto_library rules implicitly
# depend on @com_google_protobuf for protoc and proto runtimes.
http_archive(
    name = "com_google_protobuf",
    patch_args = ["-p1"],
    patches = ["//third_party/protobuf:0001-build-with-com_github_madler_zlib.patch"],
    sha256 = "c90d9e13564c0af85fd2912545ee47b57deded6e5a97de80395b6d2d9be64854",
    strip_prefix = "protobuf-3.9.1",
    urls = ["https://github.com/google/protobuf/archive/v3.9.1.zip"],
)

# java_lite_proto_library rules implicitly depend on @com_google_protobuf_javalite//:javalite_toolchain,
# which is the JavaLite proto runtime (base classes and common utilities).
bind(
    name = "com_google_protobuf_javalite",
    actual = "@com_google_protobuf",
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# grpc
# This needs to be placed after TensorFlow to resolve some bazel conflicts.
http_archive(
    name = "com_github_grpc_grpc",
    patch_args = ["-p1"],
    patches = ["//third_party/grpc:0001-build-with-com_github_madler_zlib.patch"],
    sha256 = "11ac793c562143d52fd440f6549588712badc79211cdc8c509b183cb69bddad8",
    strip_prefix = "grpc-1.22.0",
    urls = ["https://github.com/grpc/grpc/archive/v1.22.0.tar.gz"],
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")

grpc_deps()