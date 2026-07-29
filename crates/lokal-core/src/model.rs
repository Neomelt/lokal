//! 保险库的数据模型——也就是被加密的那部分内容。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secret::Secret;

/// 条目分类。沿用原型里的五类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Category {
    Social,
    Banking,
    Work,
    Shopping,
    Other,
}

impl Category {
    pub const ALL: [Category; 5] =
        [Category::Social, Category::Banking, Category::Work, Category::Shopping, Category::Other];
}

/// 一条密码记录。
///
/// `id` 用 UUIDv4 而不是自增整数：自增 id 在将来做多设备合并时必然冲突
/// （两台设备各自新建的条目都会是 7 号），而 UUID 天然全局唯一。
/// 现在用不上同步，但换 id 类型是破坏性改动，一开始选对成本为零。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub name: String,
    pub username: String,
    pub password: Secret,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    pub category: Category,
    /// Unix 毫秒时间戳。
    pub created_at: u64,
    pub updated_at: u64,
}

impl Entry {
    pub fn new(
        name: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<Secret>,
        category: Category,
    ) -> Self {
        let now = now_millis();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            username: username.into(),
            password: password.into(),
            url: String::new(),
            notes: String::new(),
            category,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    /// 大小写不敏感地匹配名称或用户名。
    pub fn matches(&self, query: &str) -> bool {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        self.name.to_lowercase().contains(&q) || self.username.to_lowercase().contains(&q)
    }
}

/// 保险库设置。
///
/// 存在保险库**里面**（跟着条目一起被加密），而不是旁边的明文配置文件。
/// 理由有两条：一是和"没有任何东西明文落地"这个产品原则一致——备份目录
/// 本身也会泄露信息（比如指向某个网盘账号的路径）；二是自动备份本来就只在
/// 保险库解锁时才可能发生，所以"要解锁才读得到设置"不构成限制。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSettings {
    /// 自动备份目录。`None` = 关闭。
    #[serde(default)]
    pub auto_backup_dir: Option<String>,
    /// 保留多少份自动备份。
    #[serde(default = "default_keep")]
    pub auto_backup_keep: usize,
}

fn default_keep() -> usize {
    24
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self { auto_backup_dir: None, auto_backup_keep: default_keep() }
    }
}

/// 保险库的明文内容。这个结构序列化成 JSON 后被整体加密。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultData {
    #[serde(default)]
    pub entries: Vec<Entry>,
    /// `serde(default)` 保证旧版本写的保险库（没有这个字段）仍能读——
    /// 加密文件是长期数据，向后兼容不是可选项。
    #[serde(default)]
    pub settings: VaultSettings,
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_matches_name_and_username_case_insensitively() {
        let e = Entry::new("Northwind Bank", "anna.k@mail.com", "pw", Category::Banking);
        assert!(e.matches("northwind"));
        assert!(e.matches("BANK"));
        assert!(e.matches("anna.k"));
        assert!(e.matches("")); // 空查询匹配全部
        assert!(!e.matches("pixelgram"));
    }

    #[test]
    fn search_never_matches_the_password() {
        // 如果搜索能命中密码，输入框就成了密码探测器。
        let e = Entry::new("Site", "user", "s3cr3t-unique-token", Category::Other);
        assert!(!e.matches("s3cr3t-unique-token"));
    }

    #[test]
    fn ids_are_unique() {
        let a = Entry::new("a", "u", "p", Category::Other);
        let b = Entry::new("a", "u", "p", Category::Other);
        assert_ne!(a.id, b.id);
    }
}
