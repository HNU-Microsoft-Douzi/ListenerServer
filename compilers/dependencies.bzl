load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def cross_compiler_dependencies(**kwargs):
    armv7_name = "org_linaro_components_toolchain_gcc_armv7"
    # armv7_sha256 = "987941c9fffdf56ffcbe90e8984673c16648c477b537fcf43add22fa62f161cd"
    armv7_prefix = "gcc-linaro-5.5.0-2017.10-x86_64_arm-linux-gnueabi"
    armv7_url = "http://download1483.mediafire.com/qrsqczrksvgg/bci3s4cstiyudqm/gcc-linaro-5.5.0-2017.10-x86_64_arm-linux-gnueabi.tar.xz"
    if armv7_name not in native.existing_rules():
        http_archive(
            name = armv7_name,
            strip_prefix = armv7_prefix,
            url = armv7_url,
            # sha256 = armv7_sha256,
            build_file_content = """
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "gcc",
    srcs = [
        "bin/arm-linux-gnueabi-gcc",
    ],
)

filegroup(
    name = "ar",
    srcs = [
        "bin/arm-linux-gnueabi-ar",
    ],
)

filegroup(
    name = "ld",
    srcs = [
        "bin/arm-linux-gnueabi-ld",
    ],
)

filegroup(
    name = "nm",
    srcs = [
        "bin/arm-linux-gnueabi-nm",
    ],
)

filegroup(
    name = "objcopy",
    srcs = [
        "bin/arm-linux-gnueabi-objcopy",
    ],
)

filegroup(
    name = "objdump",
    srcs = [
        "bin/arm-linux-gnueabi-objdump",
    ],
)

filegroup(
    name = "strip",
    srcs = [
        "bin/arm-linux-gnueabi-strip",
    ],
)

filegroup(
    name = "as",
    srcs = [
        "bin/arm-linux-gnueabi-as",
    ],
)

filegroup(
    name = "compiler_pieces",
    srcs = glob([
        "arm-linux-gnueabi/**",
        "libexec/**",
        "lib/gcc/arm-linux-gnueabi/**",
        "include/**",
    ]),
)

filegroup(
    name = "compiler_components",
    srcs = [
        ":ar",
        ":as",
        ":gcc",
        ":ld",
        ":nm",
        ":objcopy",
        ":objdump",
        ":strip",
    ],
)
""",
        )

    aarch64_name = "org_linaro_components_toolchain_gcc_aarch64"
    # aarch64_sha266 = "73eed74e593e2267504efbcf3678918bb22409ab7afa3dc7c135d2c6790c2345"
    # aarch64_prefix = "gcc-linaro-7.3.1-2018.05-x86_64_aarch64-linux-gnu"
    # aarch64_url = "https://releases.linaro.org/components/toolchain/binaries/7.3-2018.05/aarch64-linux-gnu/gcc-linaro-7.3.1-2018.05-x86_64_aarch64-linux-gnu.tar.xz"
    # aarch64_sha266 = "1941dcf6229d6706bcb89b7976d5d43d170efdd17c27d5fe1738e7ecf22adc37"
    aarch64_prefix = "gcc-linaro-5.5.0-2017.10-x86_64_aarch64-linux-gnu"
    aarch64_url = "http://download1348.mediafire.com/2e7m6fa2rbog/tdvrzt9cqcbh4np/gcc-linaro-5.5.0-2017.10-x86_64_aarch64-linux-gnu.tar.xz"
    if aarch64_name not in native.existing_rules():
        http_archive(
            name = aarch64_name,
            strip_prefix = aarch64_prefix,
            url = aarch64_url,
            # sha256 = aarch64_sha266,
            build_file_content = """
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "gcc",
    srcs = [
        "bin/aarch64-linux-gnu-gcc",
    ],
)

filegroup(
    name = "ar",
    srcs = [
        "bin/aarch64-linux-gnu-ar",
    ],
)

filegroup(
    name = "ld",
    srcs = [
        "bin/aarch64-linux-gnu-ld",
    ],
)

filegroup(
    name = "nm",
    srcs = [
        "bin/aarch64-linux-gnu-nm",
    ],
)

filegroup(
    name = "objcopy",
    srcs = [
        "bin/aarch64-linux-gnu-objcopy",
    ],
)

filegroup(
    name = "objdump",
    srcs = [
        "bin/aarch64-linux-gnu-objdump",
    ],
)

filegroup(
    name = "strip",
    srcs = [
        "bin/aarch64-linux-gnu-strip",
    ],
)

filegroup(
    name = "as",
    srcs = [
        "bin/aarch64-linux-gnu-as",
    ],
)

filegroup(
    name = "compiler_pieces",
    srcs = glob([
        "aarch64-linux-gnu/**",
        "libexec/**",
        "lib/gcc/aarch64-linux-gnu/**",
        "aarch64-linux-gnu/libc/usr/include/**",
        "include/**",
    ]),
)

filegroup(
    name = "compiler_components",
    srcs = [
        ":ar",
        ":as",
        ":gcc",
        ":ld",
        ":nm",
        ":objcopy",
        ":objdump",
        ":strip",
    ],
)
""",
        )
