# Unicorn Java Bindings

Java JNI bindings for the [Unicorn](https://github.com/zhkl0228/unicorn) CPU emulator engine, supporting ARM and AArch64 architectures.

## Supported Platforms

| Platform | Architecture | Build Method | Output |
|---|---|---|---|
| macOS | ARM64 | Native (clang) | `libunicorn_java.dylib` |
| macOS | x86_64 | Native (clang) | `libunicorn_java.dylib` |
| Linux | x86_64 | Docker (CentOS 7) | `libunicorn_java.so` |
| Linux | ARM64 | Docker (CentOS 7) | `libunicorn_java.so` |
| Windows | x86_64 | Docker (MinGW) | `unicorn_java.dll` |
| Windows | x86 | Docker (MinGW) | `unicorn_java.dll` |

## Prerequisites

### macOS Native Builds

- Xcode Command Line Tools (`xcode-select --install`)
- JDK with `JAVA_HOME` set
- Unicorn source tree (defaults to `../../`, i.e. the repository root)

### Docker Cross-Compilation (Linux / Windows)

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with multi-platform support enabled

## Build

All platforms are built through the unified `build.sh` script:

```bash
# Build all platforms
./build.sh

# macOS only (both architectures)
./build.sh osx

# macOS ARM64 only
./build.sh osx_arm64

# macOS x86_64 only
./build.sh osx_64

# All Docker targets (Linux + Windows)
./build.sh docker

# Individual Docker targets
./build.sh linux_64
./build.sh linux_arm64
./build.sh windows_64
./build.sh windows_32

# Force clean rebuild (Docker: --no-cache)
./build.sh --clean all
./build.sh --clean docker
```

### Custom Unicorn Source Path

By default, the script locates the Unicorn source tree at `../../` (the repository root). To use a different path:

```bash
export UNICORN_HOME=/path/to/unicorn
./build.sh osx
```

### Docker Auto-Rebuild on Source Changes

Docker builds automatically detect changes to the Unicorn source repository. When the git HEAD commit changes, Docker's build cache is invalidated and the Unicorn library is re-cloned and rebuilt from GitHub. Use `--clean` to force a full rebuild regardless.

## Output

Built native libraries are placed under `src/main/resources/natives/`:

```
src/main/resources/natives/
├── linux_64/         libunicorn_java.so
├── linux_arm64/      libunicorn_java.so
├── osx_64/           libunicorn_java.dylib
├── osx_arm64/        libunicorn_java.dylib
├── windows_32/       unicorn_java.dll
└── windows_64/       unicorn_java.dll
```

## Directory Structure

```
bindings/java/
├── build.sh                    # Unified build script
├── CMakeLists.txt              # CMake config (used by Docker Linux builds)
├── Dockerfile                  # Linux cross-compilation
├── Dockerfile.windows          # Windows x86_64 cross-compilation (MinGW)
├── Dockerfile.windows32        # Windows x86 cross-compilation (MinGW)
├── unicorn_Unicorn.c           # JNI implementation
├── unicorn_Unicorn.h           # JNI header (generated)
├── unicorn_Unicorn_NewHook.h   # JNI header (generated)
├── unicorn_Unicorn_Tuple.h     # JNI header (generated)
├── unicorn_Unicorn_UnHook.h    # JNI header (generated)
├── khash.h                     # Hash table utility
├── pom.xml                     # Maven project descriptor
└── src/                        # Java source & native resources
```

## Notes

- macOS builds compile the Unicorn static library (`libunicorn.a`) in-tree via `make.sh`, then link it into the JNI shared library.
- macOS deployment targets: x86_64 = 10.12, ARM64 = 11.0.
- Windows builds copy patched `cpu-exec.c` and `translate-all.c` from `qemu/` into the Docker context for VirtualProtect support. These temporary files are cleaned up automatically after the build.
- Linux Docker builds use CMake (`cmake3`) on CentOS 7 for maximum glibc compatibility.
