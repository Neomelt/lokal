//! `lokal-core` —— Lokal 密码管理器的安全核心。
//!
//! 这个 crate **不依赖任何 GUI**。加密、存储、密码生成与强度评估全部在此，
//! Tauri（或将来的 Android 外壳）只是调用它的薄层。
//!
//! 这么分层有三个实际好处：
//! - 安全关键代码可以被单元测试直接覆盖，不需要起界面；
//! - 换前端、换平台时这部分一行不用改；
//! - 审计范围被压缩到一个小而封闭的模块。

pub mod crypto;
pub mod error;
pub mod secret;

pub use error::{Error, Result};
pub use secret::{Key32, Secret};
