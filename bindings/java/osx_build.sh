#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/src/main/resources/natives"
UNICORN_HOME="${UNICORN_HOME:-$SCRIPT_DIR/../..}"

JAVA_INC="$(realpath "$JAVA_HOME/include")"
JAVA_PLATFORM_INC="$(dirname "$(find "$JAVA_INC" -name jni_md.h)")"

if [ ! -f "$UNICORN_HOME/libunicorn.a" ]; then
    echo "libunicorn.a not found. Building unicorn..."
    cd "$UNICORN_HOME"
    UNICORN_ARCHS="arm aarch64" UNICORN_STATIC=yes ./make.sh
    cd "$SCRIPT_DIR"
fi

echo "=== Building for macOS arm64 ==="
xcrun -sdk macosx clang -o libunicorn_java.dylib -shared -O3 -DNDEBUG \
    -arch arm64 -mmacosx-version-min=11.0 \
    -I "$UNICORN_HOME/include" \
    -I "$JAVA_INC" -I "$JAVA_PLATFORM_INC" \
    -fPIC \
    unicorn_Unicorn.c \
    "$UNICORN_HOME/libunicorn.a"

mkdir -p "$RESOURCES_DIR/osx_arm64"
mv libunicorn_java.dylib "$RESOURCES_DIR/osx_arm64/"
echo "Done: $RESOURCES_DIR/osx_arm64/libunicorn_java.dylib"
ls -l "$RESOURCES_DIR/osx_arm64/libunicorn_java.dylib"
