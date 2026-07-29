//! 会在析构时被擦除的秘密数据。
//!
//! 为什么需要这个：Rust 的 `String` 被 drop 时只是把内存还给分配器，
//! **内容原样留在那里**。之后这块内存可能被再分配给别处、被写进 swap、
//! 或出现在 core dump 里。密码管理器必须主动把它清零。
//!
//! `zeroize` 用 volatile 写 + 编译屏障来保证这次清零不会被优化器删掉——
//! 普通的 `buf.fill(0)` 在「写完就不再读」时会被 LLVM 整段消除（dead store
//! elimination），这是自己写清零代码最常见的失败方式。

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// 一段明文秘密（条目密码、主口令）。Drop 时自动清零。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// 永不打印内容——防止密码从日志、`dbg!`、panic 信息里泄漏。
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// 32 字节对称密钥。Drop 时自动清零。
#[derive(Clone)]
pub struct Key32([u8; 32]);

impl Key32 {
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for Key32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32(***)")
    }
}
