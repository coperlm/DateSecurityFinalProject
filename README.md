# DateSecurityFinalProject
数据安全实训大作业 — 基于 AES / RSA 的加密加密工具

## 项目简介
这是一个教学与实验性质的服务，演示如何用对称加密（AES-GCM）、非对称加密（RSA）和后量子签名（FAEST）构建“可合规修订”的上链流程（变色龙哈希/陷门）。该服务同时提供简单前端页面用于交互演示。

## 要求
- Rust 1.65+（建议使用 rustup 管理）
- 网络端口 8080 可用

## 构建与运行
在项目根目录下执行：

```bash
# 构建
# 若使用 FAEST（推荐），请先在 libs/ 中构建 FAEST（需 meson + ninja），或在系统中安装可被 linker 识别的 libfaest:

# 在 libs/ 目录下（仓库已包含 FAEST 子模块），一次性构建 FAEST：
meson setup libs/builddir && ninja -C libs/builddir

# 构建并运行 Rust 项目（建议使用共享库路径）：
# 可选：构建并编译小 C wrapper（通过 build.rs），使用环境变量启用：
FAEST_BUILD_WRAPPER=1 cargo build

# 运行（确保动态库可被加载）：
LD_LIBRARY_PATH=libs/builddir: FAEST_BUILD_WRAPPER=1 cargo run

# 说明：
# - 需要在系统中安装 `meson` 和 `ninja`（例如通过 `pip install meson` / 包管理器安装或系统包）。
# - `LD_LIBRARY_PATH=libs/builddir:` 用于运行时找到 `libfaest.so`，也可将该路径加入系统链接器搜索路径（例如 `/etc/ld.so.conf.d/` 然后 `ldconfig`）。
# - 若不想使用共享库，可将 `libfaest.a` 静态库安装到系统链接路径并调整 `build.rs`，但仓库中默认推荐使用 `libfaest.so` 以避免 thin-archive 链接问题。
```

启动成功后服务监听：`http://0.0.0.0:8080/`，前端页面也可通过该地址访问。

## API 端点
- `GET /keys` — 生成临时 FAEST 密钥对与示例 RSA 公钥（Base64 / PEM）
- `GET /chain` — 返回当前链（JSON），包含完整性验证结果
- `POST /encrypt_and_mine` — 接收 JSON 请求，对明文进行数字信封加密、签名并打包上链
- `POST /redact` — 管理员使用陷门进行合规修订（区块内容替换但保持哈希不变）

### 示例：查询链
```bash
curl -s http://localhost:8080/chain | jq .
```

### 示例：生成临时密钥
```bash
curl http://localhost:8080/keys
```

## 注意事项
- 本项目为教学演示，包含“陷门”机制（变色龙哈希）——仅用于演示合规修订概念，勿在生产环境直接使用。
- 代码中可能包含未使用的辅助函数（编译时会有警告），不影响功能演示。

## 开发者提示
- 若遇到依赖或编译问题，先运行 `rustup update` 并检查 `cargo` 日志。

## 文件
- 前端页面位于 `static/index.html`。

---
许可证见项目根目录。
