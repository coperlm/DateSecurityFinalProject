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

# 仅运行（不重建）：
# run.sh
# 先重建 FAEST，再运行：
# run.sh --faest --rust
# 只重建 Rust（不重建 FAEST）：
# run.sh --rust
# 运行时不编译 wrapper（若不需要编译 C wrapper）：
# run.sh --no-wrapper

REBUILD_FAEST=0
REBUILD_RUST=0
BUILD_WRAPPER=1

while [[ $# -gt 0 ]]; do
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

if command -v lsof >/dev/null 2>&1; then
  PIDS=$(lsof -ti tcp:8080 || true)
  if [ -n "${PIDS}" ]; then
    echo "发现占用 8080 的进程: ${PIDS}，发送 TERM 信号..."
    kill -TERM ${PIDS} || true
    sleep 1
    # 若仍然存在，强制杀死
    PIDS2=$(lsof -ti tcp:8080 || true)
    if [ -n "${PIDS2}" ]; then
      echo "进程仍然存在，发送 KILL 信号: ${PIDS2}"
      kill -KILL ${PIDS2} || true
      sleep 1
    fi
  fi
fi

FAEST_BUILD_WRAPPER=${FAEST_BUILD_WRAPPER} LD_LIBRARY_PATH="${ROOT_DIR}/libs/FAEST/builddir:${LD_LIBRARY_PATH:-}" cargo run
