//! 错误类型。
//!
//! 一条重要的安全约定：解密失败**不区分**「口令错」和「文件被篡改」。
//! 两者都返回 `Unauthenticated`。区分它们会给攻击者提供预言机
//! (oracle)，帮助他判断自己猜对了哪一半。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("不是有效的 Lokal 保险库文件")]
    BadMagic,

    #[error("保险库格式版本 {found} 不受支持（本程序支持 {supported}）")]
    UnsupportedVersion { found: u8, supported: u8 },

    #[error("保险库文件已损坏或被截断")]
    Truncated,

    /// 口令错误、文件被篡改、或头部参数被改动——三者故意不做区分。
    #[error("无法解锁保险库：口令错误或文件已被篡改")]
    Unauthenticated,

    #[error("KDF 参数非法：{0}")]
    BadKdfParams(String),

    #[error("找不到条目")]
    EntryNotFound,

    #[error("系统随机源不可用：{0}")]
    Random(String),

    #[error("保险库内容不是合法 JSON：{0}")]
    Json(#[from] serde_json::Error),

    #[error("文件读写失败：{0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
