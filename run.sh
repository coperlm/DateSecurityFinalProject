#!/usr/bin/env bash
set -euo pipefail

usage(){
  cat <<EOF
Usage: $0 [options]

Options:
  --faest      Rebuild FAEST C library (meson + ninja)
  --rust       Rebuild Rust project (cargo build)
  --no-wrapper Do not compile C wrapper (FAEST_BUILD_WRAPPER=0)
  --help       Show this help

If no options given, the script will run the project using existing build artifacts.
Example: $0 --faest --rust
EOF
}

REBUILD_FAEST=0
REBUILD_RUST=0
BUILD_WRAPPER=1

while [[ ${#} -gt 0 ]]; do
  case "$1" in
    --faest) REBUILD_FAEST=1; shift;;
    --rust)  REBUILD_RUST=1; shift;;
    --no-wrapper) BUILD_WRAPPER=0; shift;;
    --help) usage; exit 0;;
    *) echo "Unknown option: $1"; usage; exit 2;;
  esac
done

ROOT_DIR=$(dirname "$0")
cd "$ROOT_DIR"

if [ "$REBUILD_FAEST" -eq 1 ]; then
  echo "==> 构建 FAEST (meson + ninja)"
  if [ -d libs/FAEST ]; then
    meson setup --reconfigure libs/FAEST/builddir libs/FAEST
    ninja -C libs/FAEST/builddir
  else
    echo "错误：找不到 libs/FAEST 子模块，请先 git submodule update --init --recursive" >&2
    exit 1
  fi
fi

if [ "$REBUILD_RUST" -eq 1 ]; then
  echo "==> 构建 Rust 项目"
  FAEST_BUILD_WRAPPER=${BUILD_WRAPPER} cargo build
fi

# 运行（默认启用 wrapper）
export FAEST_BUILD_WRAPPER=${BUILD_WRAPPER}
export LD_LIBRARY_PATH="${ROOT_DIR}/libs/FAEST/builddir:${LD_LIBRARY_PATH:-}"

echo "==> 运行: LD_LIBRARY_PATH=libs/FAEST/builddir: FAEST_BUILD_WRAPPER=${FAEST_BUILD_WRAPPER} cargo run"
FAEST_BUILD_WRAPPER=${FAEST_BUILD_WRAPPER} LD_LIBRARY_PATH="${ROOT_DIR}/libs/FAEST/builddir:${LD_LIBRARY_PATH:-}" cargo run
