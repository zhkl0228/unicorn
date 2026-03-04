#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/src/main/resources/natives"
IMAGE_NAME="unicorn-java-builder"

cd "$SCRIPT_DIR"

build_platform() {
    local platform=$1
    local output_dir=$2

    echo "=== Building for $platform ==="
    docker build --platform "$platform" -t "${IMAGE_NAME}-${output_dir}" .

    echo "Extracting libunicorn_java.so..."
    mkdir -p "$RESOURCES_DIR/$output_dir"
    CONTAINER_ID=$(docker create --platform "$platform" "${IMAGE_NAME}-${output_dir}")
    docker cp "$CONTAINER_ID:/build/jni/build/libunicorn_java.so" "$RESOURCES_DIR/$output_dir/libunicorn_java.so"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/$output_dir/libunicorn_java.so"
    ls -l "$RESOURCES_DIR/$output_dir/libunicorn_java.so"
    echo
}

prepare_windows_sources() {
    cp "$SCRIPT_DIR/../../qemu/cpu-exec.c" "$SCRIPT_DIR/cpu-exec.c"
    cp "$SCRIPT_DIR/../../qemu/translate-all.c" "$SCRIPT_DIR/translate-all.c"
}

cleanup_windows_sources() {
    rm -f "$SCRIPT_DIR/cpu-exec.c" "$SCRIPT_DIR/translate-all.c"
}

build_windows() {
    local dockerfile=$1
    local output_dir=$2

    echo "=== Building for $output_dir (MinGW cross-compilation) ==="

    prepare_windows_sources
    trap cleanup_windows_sources EXIT

    docker build -f "$dockerfile" -t "${IMAGE_NAME}-${output_dir}" .

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

TARGET=${1:-all}

case "$TARGET" in
    linux_arm64)
        build_platform linux/arm64 linux_arm64
        ;;
    linux_64)
        build_platform linux/amd64 linux_64
        ;;
    windows_32)
        build_windows Dockerfile.windows32 windows_32
        ;;
    windows_64)
        build_windows Dockerfile.windows windows_64
        ;;
    all)
        build_platform linux/amd64 linux_64
        build_platform linux/arm64 linux_arm64
        build_windows Dockerfile.windows windows_64
        build_windows Dockerfile.windows32 windows_32
        ;;
    *)
        echo "Usage: $0 [linux_64|linux_arm64|windows_32|windows_64|all]"
        exit 1
        ;;
esac
