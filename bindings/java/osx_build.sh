#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/src/main/resources/natives"
UNICORN_HOME="${UNICORN_HOME:-$SCRIPT_DIR/../..}"

JAVA_INC="$(realpath "$JAVA_HOME/include")"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

build_arch() {
    local arch=$1
    local min_ver=$2
    local output_dir=$3

    echo "=== Building libunicorn.a for $arch ==="
    cd "$UNICORN_HOME"
    make clean 2>/dev/null || true
    CC="clang -arch $arch" UNICORN_ARCHS="arm aarch64" UNICORN_STATIC=yes ./make.sh
    cd "$SCRIPT_DIR"

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
}

build_arch x86_64 10.12 osx_64
build_arch arm64  11.0  osx_arm64

echo ""
echo "=== All macOS builds complete ==="
