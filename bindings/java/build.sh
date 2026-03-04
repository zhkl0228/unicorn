#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/src/main/resources/natives"
UNICORN_HOME="${UNICORN_HOME:-$SCRIPT_DIR/../..}"
IMAGE_NAME="unicorn-java-builder"

CLEAN=false
while [[ "$1" == --* ]]; do
    case "$1" in
        --clean) CLEAN=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$SCRIPT_DIR"

# --- macOS native builds ---

build_osx() {
    local arch=$1
    local min_ver=$2
    local output_dir=$3

    echo "=== Building libunicorn.a for $arch (deployment target $min_ver) ==="
    cd "$UNICORN_HOME"
    make clean 2>/dev/null || true
    CC="clang -arch $arch" CFLAGS="-mmacosx-version-min=$min_ver" \
        UNICORN_ARCHS="arm aarch64" UNICORN_STATIC=yes ./make.sh
    cd "$SCRIPT_DIR"

    JAVA_INC="$(realpath "$JAVA_HOME/include")"
    JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

    echo "=== Building libunicorn_java.dylib for $arch ==="
    xcrun -sdk macosx clang -o libunicorn_java.dylib -shared -O3 -DNDEBUG \
        -arch "$arch" -mmacosx-version-min="$min_ver" \
        -I "$UNICORN_HOME/include" \
        -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" \
        -fPIC \
        unicorn_Unicorn.c \
        "$UNICORN_HOME/libunicorn.a"

    mkdir -p "$RESOURCES_DIR/$output_dir"
    mv libunicorn_java.dylib "$RESOURCES_DIR/$output_dir/"

    echo "Done: $RESOURCES_DIR/$output_dir/libunicorn_java.dylib"
    ls -l "$RESOURCES_DIR/$output_dir/libunicorn_java.dylib"
    echo
}

# --- Docker builds ---

get_unicorn_commit() {
    git -C "$UNICORN_HOME" rev-parse HEAD 2>/dev/null || echo "unknown"
}

prepare_windows_sources() {
    cp "$UNICORN_HOME/qemu/cpu-exec.c" "$SCRIPT_DIR/cpu-exec.c"
    cp "$UNICORN_HOME/qemu/translate-all.c" "$SCRIPT_DIR/translate-all.c"
}

cleanup_windows_sources() {
    rm -f "$SCRIPT_DIR/cpu-exec.c" "$SCRIPT_DIR/translate-all.c"
}

build_linux() {
    local platform=$1
    local output_dir=$2

    echo "=== Building for $output_dir ($platform) ==="

    local docker_args="--build-arg UNICORN_COMMIT=$(get_unicorn_commit)"
    if $CLEAN; then
        docker_args="$docker_args --no-cache"
    fi

    docker build --platform "$platform" $docker_args -t "${IMAGE_NAME}-${output_dir}" .

    echo "Extracting libunicorn_java.so..."
    mkdir -p "$RESOURCES_DIR/$output_dir"
    CONTAINER_ID=$(docker create --platform "$platform" "${IMAGE_NAME}-${output_dir}")
    docker cp "$CONTAINER_ID:/build/jni/build/libunicorn_java.so" "$RESOURCES_DIR/$output_dir/libunicorn_java.so"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/$output_dir/libunicorn_java.so"
    ls -l "$RESOURCES_DIR/$output_dir/libunicorn_java.so"
    echo
}

build_windows() {
    local dockerfile=$1
    local output_dir=$2

    echo "=== Building for $output_dir (MinGW cross-compilation) ==="

    prepare_windows_sources
    trap cleanup_windows_sources EXIT

    local docker_args="--build-arg UNICORN_COMMIT=$(get_unicorn_commit)"
    if $CLEAN; then
        docker_args="$docker_args --no-cache"
    fi

    docker build $docker_args -f "$dockerfile" -t "${IMAGE_NAME}-${output_dir}" .

    cleanup_windows_sources
    trap - EXIT

    echo "Extracting unicorn_java.dll..."
    mkdir -p "$RESOURCES_DIR/$output_dir"
    CONTAINER_ID=$(docker create "${IMAGE_NAME}-${output_dir}")
    docker cp "$CONTAINER_ID:/build/jni/unicorn_java.dll" "$RESOURCES_DIR/$output_dir/unicorn_java.dll"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/$output_dir/unicorn_java.dll"
    ls -l "$RESOURCES_DIR/$output_dir/unicorn_java.dll"
    echo
}

# --- Main ---

TARGET=${1:-all}

case "$TARGET" in
    osx_arm64)
        build_osx arm64 11.0 osx_arm64
        ;;
    osx_64)
        build_osx x86_64 10.12 osx_64
        ;;
    osx)
        build_osx x86_64 10.12 osx_64
        build_osx arm64  11.0  osx_arm64
        ;;
    linux_arm64)
        build_linux linux/arm64 linux_arm64
        ;;
    linux_64)
        build_linux linux/amd64 linux_64
        ;;
    windows_64)
        build_windows Dockerfile.windows windows_64
        ;;
    windows_32)
        build_windows Dockerfile.windows32 windows_32
        ;;
    docker)
        build_linux linux/amd64 linux_64
        build_linux linux/arm64 linux_arm64
        build_windows Dockerfile.windows windows_64
        build_windows Dockerfile.windows32 windows_32
        ;;
    all)
        build_osx x86_64 10.12 osx_64
        build_osx arm64  11.0  osx_arm64
        build_linux linux/amd64 linux_64
        build_linux linux/arm64 linux_arm64
        build_windows Dockerfile.windows windows_64
        build_windows Dockerfile.windows32 windows_32
        ;;
    *)
        echo "Usage: $0 [--clean] [osx_arm64|osx_64|osx|linux_arm64|linux_64|windows_32|windows_64|docker|all]"
        echo ""
        echo "Options:"
        echo "  --clean      Clean build (Docker: --no-cache)"
        echo ""
        echo "Targets:"
        echo "  osx_arm64    - macOS ARM64 (native build)"
        echo "  osx_64       - macOS x86_64 (native build)"
        echo "  osx          - both macOS targets"
        echo "  linux_arm64  - Linux ARM64 (Docker)"
        echo "  linux_64     - Linux x86_64 (Docker)"
        echo "  windows_64   - Windows x86_64 (Docker + MinGW)"
        echo "  windows_32   - Windows x86 (Docker + MinGW)"
        echo "  docker       - all Docker targets (linux + windows)"
        echo "  all          - all platforms (default)"
        exit 1
        ;;
esac
