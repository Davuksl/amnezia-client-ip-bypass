from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMake, CMakeToolchain
from conan.tools.files import chdir, copy, load, replace_in_file, save
from conan.tools.env import VirtualBuildEnv, Environment
from conan.errors import ConanInvalidConfiguration
from conan.tools.scm import Git

import os
import platform
from pathlib import Path

class AwgAndroid(ConanFile):
    name = "awg-android"
    version = "3.1.20260814"
    settings = "os", "arch", "build_type", "compiler"
    options = {"application_id": ["ANY"]}
    default_options = {"application_id": "org.amnezia.vpn"}

    @property
    def _upstream_folder(self):
        return os.path.join(self.source_folder, "upstream")

    def export_sources(self):
        source = os.path.join(self.recipe_folder, "../../client/platforms/warp")
        copy(self, "*", src=source, dst=os.path.join(self.export_sources_folder, "warp"))

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        cmake_layout(self)

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.4.1 <4]")
        if platform.system() == "Windows":
            self.tool_requires("ninja/[*]")
            self.tool_requires("go/[*]")
            if not self.conf.get("tools.microsoft.bash:path", check_type=str):
                self.tool_requires("msys2/cci.latest")

    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} v{self.version} does not support {self.settings.os}")

    def source(self):
        git = Git(self)
        git.clone(
            url="https://github.com/amnezia-vpn/amneziawg-android.git",
            target="upstream",
            args=["--recurse-submodules", "--branch", f"v{self.version}"]
        )

    def generate(self):
        VirtualBuildEnv(self).generate()

        tc = CMakeToolchain(self)
        tc.variables["ANDROID_PACKAGE_NAME"] = str(self.options.application_id)
        tc.variables["GRADLE_USER_HOME"] = Path(os.path.join(self.build_folder, "gradle_user_home")).as_posix()
        tc.variables["CMAKE_LIBRARY_OUTPUT_DIRECTORY"] = Path(os.path.join(self.build_folder, "out")).as_posix()
        # not to warn in case of strtok() usage
        tc.extra_cflags = ["-Wno-deprecated-declarations"]
        tc.generate()

    def _patch_sources(self):
        go_folder = os.path.join(self._upstream_folder, "tunnel", "tools", "libwg-go")
        for path in (os.path.join(go_folder, "Makefile"),
                     os.path.join(self._upstream_folder, "tunnel", "tools", "CMakeLists.txt")):
            save(self, path, load(self, path).replace("\r\n", "\n"))
        copy(self, "*", src=os.path.join(self.source_folder, "warp", "go"),
             dst=os.path.join(go_folder, "warptransport"), excludes="*_test.go")
        copy(self, "exports.go", src=os.path.join(self.source_folder, "warp", "native"), dst=go_folder)
        copy(self, "warp_transport.h", src=os.path.join(self.source_folder, "warp", "native"), dst=go_folder)
        save(self, os.path.join(go_folder, "warp_jni.c"),
             load(self, os.path.join(self.source_folder, "warp", "native", "jni.c")))
        module = os.path.join(go_folder, "go.mod")
        with open(module, encoding="utf-8") as source:
            contents = source.read()
        if "amnezia/warptransport" not in contents:
            with open(module, "a", encoding="utf-8") as source:
                source.write("\nrequire amnezia/warptransport v0.0.0\nreplace amnezia/warptransport => ./warptransport\n")
        if platform.system() == 'Darwin':
            replace_in_file(self,
                os.path.join(go_folder, "Makefile"),
                'flock "$@.lock" -c \' \\\n',
                "",
            )
            replace_in_file(self,
                os.path.join(go_folder, "Makefile"),
                'mv "$@.tmp" "$@"\'',
                'mv "$@.tmp" "$@"',
            )
            replace_in_file(self,
                os.path.join(go_folder, "Makefile"),
                'touch "$@"\'',
                'touch "$@"',
            )
            replace_in_file(self,
                os.path.join(go_folder, "Makefile"),
                'sha256sum -c',
                'shasum -a 256 -c'
            )
        elif platform.system() == 'Windows':
            # elf-cleaner uses sys/mman.h (POSIX only) and cannot be built on Windows;
            # skip it — DT_FLAGS_1 warnings only affect Android < 6.0
            replace_in_file(self,
                os.path.join(self._upstream_folder, "tunnel", "tools", "CMakeLists.txt"),
                '# Strip unwanted ELF sections to prevent DT_FLAGS_1 warnings on old Android versions\n'
                'file(GLOB ELF_CLEANER_SOURCES elf-cleaner/*.c elf-cleaner/*.cpp)\n'
                'add_custom_target(elf-cleaner COMMENT "Building elf-cleaner" VERBATIM COMMAND cc\n'
                '        -O2 -DPACKAGE_NAME="elf-cleaner" -DPACKAGE_VERSION="" -DCOPYRIGHT=""\n'
                '        -o "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner" ${ELF_CLEANER_SOURCES}\n'
                ')\n'
                'add_custom_command(TARGET libwg.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"\n'
                '        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg.so>")\n'
                'add_dependencies(libwg.so elf-cleaner)\n'
                'add_custom_command(TARGET libwg-quick.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"\n'
                '        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg-quick.so>")\n'
                'add_dependencies(libwg-quick.so elf-cleaner)',
                '',
            )
            # patch Makefile: skip Go download, use 'go' already in PATH from tool_requires
            replace_in_file(self,
                os.path.join(go_folder, "Makefile"),
                '$(DESTDIR)/libwg-go.so: export PATH := $(BUILDDIR)/go-$(GO_VERSION)/bin/:$(PATH)\n$(DESTDIR)/libwg-go.so: $(BUILDDIR)/go-$(GO_VERSION)/.prepared go.mod',
                '$(DESTDIR)/libwg-go.so: go.mod',
            )
        with chdir(self, go_folder):
            self.run("go mod tidy")

    def build(self):
        self._patch_sources()
        cmake = CMake(self)
        cmake.configure(build_script_folder=os.path.join(self._upstream_folder, "tunnel", "tools"))
        cmake.build(target=["libwg-go.so", "libwg.so", "libwg-quick.so"])

    def package(self):
        copy(self, "warp_transport.h", src=os.path.join(self._upstream_folder, "tunnel", "tools", "libwg-go"),
             dst=os.path.join(self.package_folder, "include"))
        copy(self, "libwg-go.h", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "libwg-go.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "lib"))
        copy(self, "libwg.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))
        copy(self, "libwg-quick.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-android")
        self.cpp_info.libs = [ "wg-go" ]
        self.cpp_info.set_property("cmake_extra_variables", {
            "AMNEZIA_ANDROID_LIBWG_PATH": Path(os.path.join(self.package_folder, "bin", "libwg.so")).as_posix(),
            "AMNEZIA_ANDROID_LIBWG_QUICK_PATH": Path(os.path.join(self.package_folder, "bin", "libwg-quick.so")).as_posix(),
        })
