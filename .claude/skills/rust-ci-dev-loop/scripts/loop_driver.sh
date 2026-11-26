#!/usr/bin/env bash
# =============================================================================
# loop_driver.sh —— Rust 云端构建闭环驱动脚本
#
# 子命令：
#   precheck                                   本地极速门禁（fmt/clippy/dev-release build/test）
#   watch                                      监控当前分支最近一次 build-loop 云端构建
#   fetch_run <artifact> <bin> <timeout_sec> [args...]
#                                              拉取云端产物并在超时保护下本地运行
#
# 安全红线：
#   - precheck 未返回 0 之前，禁止任何 git push（由调用方保证）
#   - 日志写入 .local-logs/，原始运行日志不全量打印，只输出结构化摘要 + 尾部
# =============================================================================
set -euo pipefail

# 定位仓库根（脚本位于 <root>/.claude/skills/rust-ci-dev-loop/scripts/）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
cd "$REPO_ROOT"

BIN_BASE="misc_killer_picsteg_rs"
WORKFLOW="build-loop.yml"
LOG_DIR="$REPO_ROOT/.local-logs"
mkdir -p "$LOG_DIR"

# 工具链探测：本机 WSL 的 /usr/bin/cargo 为 apt 独立版（无 rustup/rustfmt/clippy），
# 完整组件在 Windows 侧 /mnt/c/Users/<user>/.cargo/bin/cargo.exe。优先探测可用的 Windows cargo.exe。
detect_cargo() {
  local win_cargo
  for d in /mnt/c/Users/*/; do
    win_cargo="${d}.cargo/bin/cargo.exe"
    if [[ -x "$win_cargo" ]]; then echo "$win_cargo"; return 0; fi
  done
  if command -v cargo >/dev/null 2>&1; then
    command -v cargo
    return 0
  fi
  echo "[FATAL] 未找到可用 cargo（Windows cargo.exe 与 Linux cargo 均缺失）" >&2
  exit 127
}
CARGO="$(detect_cargo)"
echo "[i] 使用 cargo: $CARGO"
# Windows cargo.exe 在 WSL 下输出 Windows 路径，统一用正斜杠规避反斜杠转义
export CARGO_TERM_COLOR=always

# gh CLI 探测：WSL 默认 PATH 不含 Windows 侧 gh.exe（位于带空格的 Program Files）
detect_gh() {
  local win_gh="/mnt/c/Program Files/GitHub CLI/gh.exe"
  if [[ -x "$win_gh" ]]; then echo "$win_gh"; return 0; fi
  if command -v gh >/dev/null 2>&1; then command -v gh; return 0; fi
  echo "[FATAL] 未找到 gh CLI（Windows gh.exe 与 Linux gh 均缺失）" >&2
  exit 127
}
GH="$(detect_gh)"
echo "[i] 使用 gh: $GH"

# 当前平台 -> 对应 artifact 名
default_artifact() {
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) echo "${BIN_BASE}-windows-x86_64.exe" ;;
    Linux*)               echo "${BIN_BASE}-linux-x86_64" ;;
    Darwin*)
      case "$(uname -m)" in
        arm64) echo "${BIN_BASE}-macos-aarch64" ;;
        *)     echo "${BIN_BASE}-macos-x86_64" ;;
      esac ;;
    *) echo "${BIN_BASE}-linux-x86_64" ;;
  esac
}

current_branch() {
  git rev-parse --abbrev-ref HEAD
}

# 拒绝在主分支执行云端相关动作
guard_branch() {
  local b
  b="$(current_branch)"
  if [[ "$b" == "main" || "$b" == "master" ]]; then
    echo "[FATAL] 当前位于主分支 $b，禁止云端闭环操作。请先切出 dev/agent/* 分支。" >&2
    exit 2
  fi
}

cmd_precheck() {
  echo "==> [1/4] cargo fmt --check"
  "$CARGO" fmt --all -- --check

  echo "==> [2/4] cargo clippy (-D warnings)"
  "$CARGO" clippy --all-targets --all-features -- -D warnings

  echo "==> [3/4] cargo build --profile dev-release"
  "$CARGO" build --profile dev-release

  echo "==> [4/4] cargo test"
  "$CARGO" test --verbose

  echo "[OK] precheck passed on $(current_branch)"
}

cmd_watch() {
  guard_branch
  local branch run_id status conclusion
  branch="$(current_branch)"
  echo "==> 等待分支 $branch 的 workflow run 出队..."

  # 最多等待 30s 让 push 触发的 run 入队
  for _ in $(seq 1 15); do
    run_id="$("$GH" run list --workflow "$WORKFLOW" --branch "$branch" \
      --limit 1 --json databaseId --jq '.[0].databaseId // empty' || true)"
    [[ -n "$run_id" ]] && break
    sleep 2
  done

  if [[ -z "${run_id:-}" ]]; then
    echo "[FATAL] 未找到分支 $branch 的 $WORKFLOW 运行记录" >&2
    exit 3
  fi

  echo "==> 监控 run #$run_id"
  "$GH" run watch "$run_id" --exit-status --interval 15 || true

  read -r status conclusion < <("$GH" run view "$run_id" \
    --json status,conclusion --jq '"\(.status) \(.conclusion // "")"')
  echo "==> status=$status conclusion=$conclusion"

  if [[ "$conclusion" == "success" ]]; then
    echo "[OK] 云端构建成功 run #$run_id"
    return 0
  fi

  echo "[FAIL] 云端构建失败，提取失败作业核心日志（--log-failed）：" >&2
  "$GH" run view "$run_id" --log-failed 2>&1 | grep -Ei "error|panic|warning: unused|cannot|failed" | head -n 80 >&2 || true
  return 1
}

cmd_fetch_run() {
  guard_branch
  local artifact="${1:-dev-latest}" bin="${2:-$BIN_BASE}" timeout_sec="${3:-60}"
  shift "$(( $# >= 3 ? 3 : $# ))" || true
  local run_args=("$@")

  # dev-latest：自动选择当前平台对应的 artifact
  [[ "$artifact" == "dev-latest" ]] && artifact="$(default_artifact)"

  local branch run_id ts dl_dir exe logfile
  branch="$(current_branch)"
  run_id="$("$GH" run list --workflow "$WORKFLOW" --branch "$branch" \
    --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
  if [[ -z "${run_id:-}" ]]; then
    echo "[FATAL] 分支 $branch 无成功的云端运行，无法拉取产物" >&2
    exit 3
  fi

  ts="$(date +%Y%m%d_%H%M%S)"
  dl_dir="$(mktemp -d)"
  logfile="$LOG_DIR/run_${ts}.log"

  echo "==> 从 run #$run_id 下载 artifact: $artifact"
  "$GH" run download "$run_id" -n "$artifact" -D "$dl_dir"

  # 找到下载下来的可执行文件（artifact 内通常为单文件）
  exe="$(find "$dl_dir" -type f | head -n 1)"
  [[ -z "$exe" ]] && { echo "[FATAL] artifact $artifact 内无文件" >&2; exit 4; }
  chmod +x "$exe" 2>/dev/null || true

  echo "==> 运行（超时 ${timeout_sec}s，RUST_LOG=debug RUST_BACKTRACE=1）: $exe ${run_args[*]:-}"
  set +e
  RUST_LOG=debug RUST_BACKTRACE=1 \
    timeout "$timeout_sec" "$exe" "${run_args[@]}" >"$logfile" 2>&1
  local exit_code=$?
  set -e

  local elapsed="n/a"
  echo "----- 结构化摘要 -----"
  echo "Exit Code : $exit_code (124=超时)"
  echo "Artifact  : $artifact (run #$run_id)"
  echo "日志路径  : $logfile"
  echo "----- 报错摘要（PANIC/ERROR 精准检索）-----"
  grep -Ein "panic|error|failed|cannot" "$logfile" | head -n 30 || echo "(无 PANIC/ERROR 关键词)"
  echo "----- 日志尾部（最多 40 行）-----"
  tail -n 40 "$logfile"

  rm -rf "$dl_dir"
  return "$exit_code"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    precheck)   shift; cmd_precheck "$@" ;;
    watch)      shift; cmd_watch "$@" ;;
    fetch_run)  shift; cmd_fetch_run "$@" ;;
    *)
      cat >&2 <<EOF
用法:
  $0 precheck
  $0 watch
  $0 fetch_run <artifact|dev-latest> <bin_name> <timeout_sec> [program args...]
EOF
      exit 64 ;;
  esac
}

main "$@"
