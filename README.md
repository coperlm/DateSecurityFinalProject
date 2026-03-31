# DateSecurityFinalProject
企业级合规文件加密客户端（实验/教学版）

## 一、项目概览
本项目实现一个 Rust+Axum 的 Web 服务，演示以下技术组合：

- 对称加密：AES-256-GCM（文件/明文/二进制通用）
- 非对称加密：RSA-2048 + 数字信封（RSA 封装 AES key）
- 后量子签名：FAEST（通过 FAEST C-FFI 集成）
- 可修订区块链：变色龙哈希（Chameleon Hash + RSA 陷门）
- 前端演示：`static/index.html` 提供交互、进度和审计 UI

核心场景：
1. 数据加密并上链（`/encrypt_and_mine`）
2. 提供步骤级进度（`/progress/:id`）
3. 管理员合规修订（`/redact`）并保持区块 hash 不变

## 二、环境要求
- Rust 1.65+（推荐 `rustup toolchain install stable`）
- `meson`, `ninja`（用于 FAEST 库构建）
- 需要端口 `8080` 可用
- Linux/macOS 下建议设置 `LD_LIBRARY_PATH=libs/FAEST/builddir`（运行时加载 `libfaest.so`）

## 三、快速构建与运行
### 1. 构建 FAEST 依赖（仓库已包含子模块）
```bash
cd /home/coper/Projects/DateSecurityFinalProject
meson setup libs/FAEST/builddir && ninja -C libs/FAEST/builddir
```

### 2. 构建 Rust 项目
```bash
# 默认链接到FAEST共享库
FAEST_BUILD_WRAPPER=1 cargo build
```

### 3. 运行服务
```bash
LD_LIBRARY_PATH=libs/FAEST/builddir:$LD_LIBRARY_PATH ./run.sh
```

启动后访问 `http://0.0.0.0:8080/`。

## 四、核心 API
### 4.1 `GET /health`
基础健康检查，成功返回 200。

### 4.2 `GET /keys`
返回临时 FAEST 密钥（Base64） + RSA 公钥（PEM）

### 4.3 `GET /chain`
返回链数据与 `is_valid` 标记。

### 4.4 `POST /encrypt_and_mine`
异步任务提交，返回 `op_id`。
参数 JSON：
- `plaintext` (String)
- `plaintext_base64` (Boolean)
- `sender_private_key`, `sender_public_key`（FAEST，Base64）
- `filename`, `mime_type`（可选）

返回示例：
```json
{ "ok": true, "op_id": "..." }
```

### 4.5 `GET /progress/:id`
轮询进度：返回 `steps`、`done`、`success`、`result`。

### 4.6 `POST /redact`
合规修订入口（管理员）：
- `block_index` (number)
- `redaction_label` (string)
- `admin_public_key` (Base64)
- `admin_signature` (Base64)

返回 `op_id` 供进度轮询。

### 4.7 `POST /redact_prepare` + `POST /admin_sign`
前端演示流程：
- 生成待签名消息（`redact_prepare`）
- 生成管理员 FAEST 签名（`admin_sign`）
- 提交 `redact`

## 五、前端快速体验
入口文件：`static/index.html`
功能包括：
- 用户 FAEST 密钥自动生成
- 加密上链按钮 + 进度步骤（可视化）
- 链数据刷新与可视化
- 兼顾文件明文查看与合规修订结果展示

## 六、安全与警告
- 仅演示项目，不应直接用于生产系统。
- Admin 私钥仅用于演示，生产应存储在 KMS/安全硬件，绝不可暴露给终端。
- `redact` 机制是可修订演示，已保留可审计痕迹但仍需谨慎使用。

## 七、开发者建议
- `handlers.rs` 可拆分为按功能模块：`encrypt.rs`, `redact.rs`, `progress.rs`.
- 统一错误模型：实现 `AppError` + `IntoResponse`。
- 进度阶段 `ProgressStage` 枚举，减少硬编码字符串。
- 添加 CI：`cargo fmt`, `cargo clippy -- -D warnings`, `cargo test`。
- 加 Prometheus/metrics: `request_count`, `op_duration`, `failure_count`。

## 八、测试
```bash
LD_LIBRARY_PATH=libs/FAEST/builddir:$LD_LIBRARY_PATH cargo test -- --nocapture
```

## 九、目录说明
- `src/main.rs`: 服务入口与路由
- `src/handlers.rs`: API 业务逻辑
- `src/progress.rs`: 进度管理 + TTL 清理
- `src/crypto.rs`: 密码学函数（AES/GCM/RSA/FAEST/Chameleon）
- `src/faest_ffi.rs`: FAEST C-FFI 壳层
- `src/chain.rs`: 区块链结构、验证、修订
- `static/index.html`: Web UI + JS 交互

## 十、许可证
见根目录 LICENSE。
