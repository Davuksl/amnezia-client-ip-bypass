from conan import ConanFile
from conan.tools.layout import basic_layout
from conan.tools.scm import Git
from conan.tools.files import copy, collect_libs, load, save
from conan.errors import ConanInvalidConfiguration
from conan.internal.model.pkg_type import PackageType
from conan.tools.gnu import AutotoolsToolchain, Autotools
from conan.tools.apple import is_apple_os

import os
import shutil


required_conan_version = ">=2.26"


class HevSocks5Tunnel(ConanFile):
    name = "hev-socks5-tunnel"
    version = "2.15.0"
    settings = "os", "arch", "compiler"
    options = {
        "shared": [True, False],
        "as_framework": [True, False],
    }
    default_options = {
        "shared": False,
        "as_framework": False
    }

    def config_options(self):
        if not is_apple_os(self):
            del self.options.as_framework

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")
        if self.options.get_safe("as_framework"):
            self.options.shared = False

    def layout(self):
        basic_layout(self, build_folder=".")

    def source(self):
        git = Git(self)
        git.clone(
            url="https://github.com/heiher/hev-socks5-tunnel.git",
            target=".",
            args=["--recurse-submodules", "--branch", self.version]
        )

    def generate(self):
        tc = AutotoolsToolchain(self)
        tc.generate()

    def build(self):
        if is_apple_os(self):
            source_path = os.path.join(self.source_folder, "src", "hev-socks5-tunnel.c")
            source = load(self, source_path).replace("\r\n", "\n")
            blocking_stop = """    for (;;) {
        fd = READ_ONCE (event_fds[1]);
        if (fd >= 0)
            break;
        /* Wait for async initialization */
        usleep (100 * 1000);
    }

    res = write (fd, &res, 1);
    assert (res > 0 && "socks5 tunnel write event");"""
            nonblocking_stop = """    fd = READ_ONCE (event_fds[1]);
    if (fd >= 0)
        send (fd, &res, 1, MSG_DONTWAIT);"""
            readiness_function = "\nint\nhev_socks5_tunnel_is_running (void)\n{\n    return READ_ONCE (run);\n}\n"
            if blocking_stop in source:
                source = source.replace("#include <sys/ioctl.h>", "#include <sys/ioctl.h>\n#include <sys/socket.h>")
                source = source.replace(blocking_stop, nonblocking_stop)
                source += readiness_function
            elif nonblocking_stop not in source or readiness_function not in source:
                raise ConanInvalidConfiguration("HEV stop implementation does not match the pinned version")
            save(self, source_path, source)
            header_path = os.path.join(self.source_folder, "src", "hev-main.h")
            header = load(self, header_path).replace("\r\n", "\n")
            stop_declaration = "void hev_socks5_tunnel_quit (void);"
            readiness_declaration = "int hev_socks5_tunnel_is_running (void);"
            if readiness_declaration not in header:
                if stop_declaration not in header:
                    raise ConanInvalidConfiguration("HEV public API does not match the pinned version")
                header = header.replace(stop_declaration, stop_declaration + "\n" + readiness_declaration)
            save(self, header_path, header)
        autotools = Autotools(self)
        autotools.make("shared" if self.options.shared else "static")

        if self.options.get_safe("as_framework"):
            lib_path = os.path.join(self.build_folder, "bin", "libhev-socks5-tunnel.a")
            self.run(
                f"libtool -static -o {lib_path}"
                f" {lib_path}"
                f" {os.path.join(self.build_folder, 'third-part', 'lwip', 'bin', 'liblwip.a')}"
                f" {os.path.join(self.build_folder, 'third-part', 'yaml', 'bin', 'libyaml.a')}"
                f" {os.path.join(self.build_folder, 'third-part', 'hev-task-system', 'bin', 'libhev-task-system.a')}"
            )

            include_dir = os.path.join(self.build_folder, "framework_include")
            copy(self, "hev-main.h", src=os.path.join(self.source_folder, "src"), dst=include_dir)
            copy(self, "module.modulemap", src=os.path.join(self.source_folder), dst=include_dir)

            self.run('xcodebuild -create-xcframework'
                f' -library {lib_path}'
                f' -headers {include_dir}'
                f' -output {os.path.join(self.build_folder, "HevSocks5Tunnel.xcframework")}'
            )

    def package(self):
        if self.options.get_safe("as_framework"):
            shutil.copytree(src=os.path.join(self.build_folder, "HevSocks5Tunnel.xcframework"),
                            dst=os.path.join(self.package_folder, "HevSocks5Tunnel.xcframework"))
        else:
            copy(self, "hev-main.h", src=os.path.join(self.source_folder, "src"), dst=os.path.join(self.package_folder, "include"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "lwip"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "lwip"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "yaml"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "yaml"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.a", src=os.path.join(self.build_folder, "bin", "third-part", "hev-task-system"), dst=os.path.join(self.package_folder, "lib"))
            copy(self, "*.so", src=os.path.join(self.build_folder, "bin", "third-part", "hev-task-system"), dst=os.path.join(self.package_folder, "lib"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "heiher::hev-socks5-tunnel")
        if self.options.get_safe("as_framework"):
            self.cpp_info.type = PackageType.STATIC
            self.cpp_info.package_framework = True
            self.cpp_info.location = os.path.join(self.package_folder, "HevSocks5Tunnel.xcframework")
        else:
            self.cpp_info.libraries = collect_libs(self)
