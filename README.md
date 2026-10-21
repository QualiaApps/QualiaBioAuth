# QualiaBioAuth

English version: [README.en.md](README.en.md).

`qualia-bioauth` 是一个独立库：把一个 32 字节密钥包裹成「只有在平台完成用户认证之后
才能解开」的字节，供任何需要这种保护的应用使用。它不依赖 Qualia2FA 的保险库格式、协议
或核心库。

## 它解决什么问题

口令包裹能保护密钥，但口令可以被猜、被肩窥、被复用。这个库补上另一条路：让平台自己
持有解包的钥匙。

- **Android**：Keystore 中的 AES 密钥，`setUserAuthenticationRequired(true)`；解包时必须
  用 `BiometricPrompt` 的 `CryptoObject(Cipher)`，而不是「弹窗成功后无门槛解密」。
- **Windows**：Windows Hello 凭据的 `hmac-secret`（WebAuthn PRF）输出，只有完成 Hello
  手势才释放；输出的 32 字节作为包裹密钥。
- **Apple**：为 Secure Enclave 的 `.userPresence` 预留；尚未实现。
- **Linux**：没有后端，如实返回 `Unsupported`。

两种包裹互相独立：任何一条成功都能解出同一把密钥，因此忘记口令或重新录入指纹不会把用户
锁死；两条都不可用时失败关闭，不退回软件密钥。

## 当前状态

0.1.0 正在开发中。已经落地的是：

- 外层格式 `Q2FABIO1`（magic + 版本 + 后端 + 长度 + 平台私有载荷）；
- `MasterKey`（32 字节、`Zeroize`、`Debug` 不打印内容）；
- `AuthBoundKeyStore` trait 与 `Availability`；
- 测试用的 `MockKeyStore`（`mock` feature）与如实的 `UnsupportedKeyStore`；
- **Windows 后端**：Windows Hello 凭据 + WebAuthn `hmac-secret`，平台释放的 32 字节
  作为包裹密钥。

Windows 后端要求平台的认证器真的启用 PRF 扩展。**Windows 11 23H2（WebAuthn API 版本 7）
实测：凭据能创建，但 `bPrfEnabled = 0`、扩展输出为空；此时本库返回
`Unavailable`，不会退回软件密钥，口令路径不受影响。** 需要一台平台认证器启用 PRF 的
Windows 机器才能完成运行时验收。

Android Keystore 后端仍在实现中。**在它落地之前，Android 上不要把本库当成提供平台认证
保护的库**；`availability()` 会如实报告 `Unsupported`。

## 用法

```toml
[dependencies]
qualia-bioauth = { version = "0.1", features = ["mock"] }
```

```rust
use qualia_bioauth::{AuthBoundKeyStore, Availability, MasterKey, mock::MockKeyStore};

let store = MockKeyStore::new();
if store.availability().is_available() {
    let master = MasterKey::from_bytes(&[7_u8; 32]).expect("32 bytes");
    let blob = store.wrap(&master).expect("wrap");
    let restored = store.unwrap(&blob).expect("unwrap");
    assert_eq!(restored, master);
}
```

真实后端的使用方式相同：拿到实现 `AuthBoundKeyStore` 的值，调用 `availability()` 决定是否
向用户展示这条路，再用 `wrap` / `unwrap`。

## 接入约定

- 本库**不做 I/O**：`wrap` 返回完整的外层 blob，由调用方决定它写到哪里。
- 本库**不依赖 `qualia2fa-core`**：32 字节密钥类型是本地定义的，应用在边界上转换。
- 平台返回的载荷是私有的，外层格式只负责 magic、版本、后端与长度校验。
- 任何输入都不得导致 panic；错误信息与 `Debug` 不包含密钥或载荷字节。
- `unsafe` 只允许出现在平台后端，每个块都要写明 `// SAFETY:` 理由；CI 把
  `undocumented_unsafe_blocks` 上升为错误。

## 参与贡献

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --features mock -- -D warnings
cargo test --all-targets --features mock
cargo test --doc --features mock
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo deny check
```

平台后端在 Windows / Android 上各需要真机验证；没有真机时，`Availability` 必须报告
`Unavailable` 或 `Unsupported`，不得伪装成可用。

## 许可

GNU Lesser General Public License v3.0 or later（`LGPL-3.0-or-later`）。完整文本见
[COPYING.LESSER](COPYING.LESSER) 与 [LICENSE](LICENSE)。
