//! `lokal-core` —— Lokal 密码管理器的安全核心。
//!
//! 这个 crate **不依赖任何 GUI**。加密、存储、密码生成与强度评估全部在此，
//! Tauri（或将来的 Android 外壳）只是调用它的薄层。
//!
//! 这么分层有三个实际好处：
//! - 安全关键代码可以被单元测试直接覆盖，不需要起界面；
//! - 换前端、换平台时这部分一行不用改；
//! - 审计范围被压缩到一个小而封闭的模块。
//!
//! # 快速上手
//!
//! ```
//! use lokal_core::{Vault, Entry, Category, generator::{self, GenOptions}};
//!
//! # fn main() -> lokal_core::Result<()> {
//! let mut vault = Vault::create("一个足够长的主口令")?;
//!
//! let pw = generator::generate(GenOptions::default())?;
//! vault.add(Entry::new("Northwind Bank", "anna@mail.com", pw, Category::Banking));
//!
//! let bytes = vault.to_bytes()?;                            // 加密
//! let back = Vault::from_bytes(&bytes, "一个足够长的主口令")?; // 解密
//! assert_eq!(back.len(), 1);
//! # Ok(())
//! # }
//! ```
//!
//! # 安全边界（务必读一遍）
//!
//! - 保险库在**静态**时受主口令保护（Argon2id + XChaCha20-Poly1305）。
//! - 保险库**解锁期间**，VK 和条目明文都在进程内存里。任何能读取本进程内存的
//!   攻击者（同用户身份的恶意程序、root、内存转储）都能拿到它们。这是所有
//!   密码管理器的共同边界，不是本实现的缺陷。
//! - **4 位 PIN 不足以单独保护静态数据**：只有 10^4 种可能，离线暴力破解
//!   在任何 KDF 代价下都只是几小时的事。设计稿里的 PIN 只能作为
//!   *会话内快速解锁*，且必须由能强制限速的硬件（Android Keystore /
//!   Secure Enclave）托底。详见 README。

pub mod crypto;
pub mod error;
pub mod generator;
pub mod model;
pub mod secret;
pub mod strength;
pub mod vault;

pub use error::{Error, Result};
pub use generator::GenOptions;
pub use model::{Category, Entry, VaultData, VaultSettings};
pub use secret::{Key32, Secret};
pub use strength::{Assessment, Strength, assess};
pub use vault::Vault;
