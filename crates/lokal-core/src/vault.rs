//! 保险库：文件格式 + 增删改查。
//!
//! # 两级密钥结构
//!
//! ```text
//!   主口令 ──Argon2id(salt, params)──▶ KEK  (密钥加密密钥)
//!                                       │
//!            VK (32B, 来自 CSPRNG) ──被 KEK 加密──▶ wrapped_key（存进文件）
//!                                       │
//!            条目 JSON ──XChaCha20-Poly1305(VK)──▶ 密文（存进文件）
//! ```
//!
//! 为什么不直接用口令派生的密钥加密数据、非要中间隔一个 VK？
//!
//! 1. **改口令是 O(1) 而不是 O(数据量)**：只需用新 KEK 重新包一次 32 字节的
//!    VK，几百 MB 的密文一个字节都不用动。
//! 2. **多种解锁方式可以并存**：将来加指纹或 PIN 解锁时，让它们各自包一份
//!    同样的 VK 即可，不需要复制数据，也不需要它们互相知道。
//! 3. **保存时不需要主口令**：解锁后 VK 常驻内存，此后每次保存都不必再让
//!    用户输口令，也不必在内存里长期留着口令本身。
//!
//! # 文件布局
//!
//! ```text
//!   偏移   长度   字段
//!   0      6     magic "LOKAL1"
//!   6      1     格式版本 = 1
//!   7      1     KDF 标识 = 1 (argon2id)
//!   8      4     m_cost  (u32 小端)
//!   12     4     t_cost
//!   16     4     p_cost
//!   20     16    salt
//!   ├──────────── 以上 36 字节 = PREFIX，作 key-wrap 的 AAD
//!   36     24    wrap_nonce
//!   60     48    wrapped_key (32 密钥 + 16 标签)
//!   108    24    data_nonce
//!   ├──────────── 以上 132 字节 = HEADER，作 数据 的 AAD
//!   132    ...   密文 = AEAD(VK, VaultData 的 JSON)
//! ```
//!
//! 头部全部进 AAD，所以攻击者改不了里面任何一个字节——包括把 KDF 代价从
//! 64 MiB 调低到 8 KiB 好加速暴力破解。这种「参数降级攻击」在没把参数
//! 纳入认证的实现里是真实可行的。

use std::io::Write;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::crypto::{self, KdfParams, NONCE_LEN, SALT_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::model::{Category, Entry, VaultData, VaultSettings, now_millis};
use crate::secret::Key32;

const MAGIC: &[u8; 6] = b"LOKAL1";
const FORMAT_VERSION: u8 = 1;
const KDF_ARGON2ID: u8 = 1;

const PREFIX_LEN: usize = 36;
const WRAPPED_KEY_LEN: usize = 32 + TAG_LEN; // 48
const HEADER_LEN: usize = PREFIX_LEN + NONCE_LEN + WRAPPED_KEY_LEN + NONCE_LEN; // 132

/// 一个已解锁的保险库。
///
/// 只要它活着，VK 就在内存里；`lock()` 或 drop 会把它清零。
pub struct Vault {
    data: VaultData,
    vault_key: Key32,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    wrap_nonce: [u8; NONCE_LEN],
    wrapped_key: [u8; WRAPPED_KEY_LEN],
    path: Option<PathBuf>,
}

impl Vault {
    /// 新建一个空保险库（尚未落盘）。
    pub fn create(master_password: &str) -> Result<Self> {
        Self::create_with_params(master_password, KdfParams::default())
    }

    pub fn create_with_params(master_password: &str, kdf: KdfParams) -> Result<Self> {
        let salt = crypto::random_bytes::<SALT_LEN>()?;
        let vault_key = Key32::from_bytes(crypto::random_bytes::<32>()?);

        let kek = crypto::derive_kek(master_password.as_bytes(), &salt, kdf)?;
        let prefix = build_prefix(kdf, &salt);
        let wrap_nonce = crypto::random_bytes::<NONCE_LEN>()?;
        let wrapped = crypto::seal(&kek, &wrap_nonce, vault_key.as_bytes(), &prefix)?;

        let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
        if wrapped.len() != WRAPPED_KEY_LEN {
            return Err(Error::Truncated);
        }
        wrapped_key.copy_from_slice(&wrapped);

        Ok(Self {
            data: VaultData::default(),
            vault_key,
            kdf,
            salt,
            wrap_nonce,
            wrapped_key,
            path: None,
        })
    }

    // ── 序列化 ────────────────────────────────────────────────

    /// 加密成完整的文件字节。与文件系统无关，方便测试。
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&build_prefix(self.kdf, &self.salt));
        header.extend_from_slice(&self.wrap_nonce);
        header.extend_from_slice(&self.wrapped_key);
        let data_nonce = crypto::random_bytes::<NONCE_LEN>()?;
        header.extend_from_slice(&data_nonce);
        debug_assert_eq!(header.len(), HEADER_LEN);

        let mut plaintext = serde_json::to_vec(&self.data)?;
        let ciphertext = crypto::seal(&self.vault_key, &data_nonce, &plaintext, &header)?;
        // 明文 JSON 里含全部密码，用完立刻清零。
        use zeroize::Zeroize;
        plaintext.zeroize();

        let mut out = header;
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// 从文件字节解密。口令错和被篡改都返回同一个错误。
    pub fn from_bytes(bytes: &[u8], master_password: &str) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if &bytes[0..6] != MAGIC {
            return Err(Error::BadMagic);
        }
        let version = bytes[6];
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion { found: version, supported: FORMAT_VERSION });
        }
        if bytes[7] != KDF_ARGON2ID {
            return Err(Error::BadKdfParams(format!("未知 KDF 标识 {}", bytes[7])));
        }

        let kdf = KdfParams {
            m_cost: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            t_cost: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
            p_cost: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        };
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[20..36]);

        let mut wrap_nonce = [0u8; NONCE_LEN];
        wrap_nonce.copy_from_slice(&bytes[36..60]);
        let mut wrapped_key = [0u8; WRAPPED_KEY_LEN];
        wrapped_key.copy_from_slice(&bytes[60..108]);
        let mut data_nonce = [0u8; NONCE_LEN];
        data_nonce.copy_from_slice(&bytes[108..132]);

        let header = &bytes[..HEADER_LEN];
        let prefix = &bytes[..PREFIX_LEN];

        // 第一步：用主口令解开 VK。
        let kek = crypto::derive_kek(master_password.as_bytes(), &salt, kdf)?;
        let vk_bytes = crypto::open(&kek, &wrap_nonce, &wrapped_key, prefix)?;
        if vk_bytes.len() != 32 {
            return Err(Error::Unauthenticated);
        }
        let mut vk = [0u8; 32];
        vk.copy_from_slice(&vk_bytes);
        let vault_key = Key32::from_bytes(vk);

        // 第二步：用 VK 解开数据。
        let mut plaintext = crypto::open(&vault_key, &data_nonce, &bytes[HEADER_LEN..], header)?;
        let data: VaultData = serde_json::from_slice(&plaintext)?;
        use zeroize::Zeroize;
        plaintext.zeroize();

        Ok(Self { data, vault_key, kdf, salt, wrap_nonce, wrapped_key, path: None })
    }

    // ── 文件读写 ──────────────────────────────────────────────

    /// 原子写盘。
    ///
    /// 先写临时文件 → fsync → rename。`rename(2)` 在同一文件系统内是原子的，
    /// 所以断电或崩溃时要么是完整的旧版本、要么是完整的新版本，
    /// **不会**留下一个写了一半的保险库。直接覆写原文件则可能永久丢失全部密码。
    pub fn save_to(&mut self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let bytes = self.to_bytes()?;
        write_atomic(path, &bytes)?;
        self.path = Some(path.to_path_buf());
        Ok(())
    }

    /// 导出一份加密备份到别处。
    ///
    /// 与 `save_to` 的区别只有一点，但很关键：**不改变 `self.path`**。
    /// 用 `save_to` 做导出会让保险库从此指向备份文件，之后每次增删改都写进
    /// 备份而不是原库——一个静默的数据分叉。
    ///
    /// 备份内容就是完整的保险库文件：自包含、已加密、用同一个主口令打开。
    /// 因此把它放进网盘、U 盘、邮箱附件都不会泄露内容（安全性等同于你的主口令）。
    pub fn export_to(&self, path: impl AsRef<Path>) -> Result<()> {
        let bytes = self.to_bytes()?;
        write_atomic(path.as_ref(), &bytes)
    }

    /// 保存到上次打开/保存的位置。
    pub fn save(&mut self) -> Result<()> {
        let path = self.path.clone().ok_or_else(|| {
            Error::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "尚未指定保险库路径"))
        })?;
        self.save_to(path)
    }

    pub fn open(path: impl AsRef<Path>, master_password: &str) -> Result<Self> {
        let path = path.as_ref();
        let bytes = std::fs::read(path)?;
        let mut v = Self::from_bytes(&bytes, master_password)?;
        v.path = Some(path.to_path_buf());
        Ok(v)
    }

    // ── 主口令 ────────────────────────────────────────────────

    /// 更换主口令。
    ///
    /// 只重新包一次 VK——数据密文完全不动。这就是两级结构的直接回报。
    pub fn change_master_password(&mut self, new_password: &str) -> Result<()> {
        let salt = crypto::random_bytes::<SALT_LEN>()?; // 换口令必须换盐
        let kek = crypto::derive_kek(new_password.as_bytes(), &salt, self.kdf)?;
        let prefix = build_prefix(self.kdf, &salt);
        let wrap_nonce = crypto::random_bytes::<NONCE_LEN>()?;
        let wrapped = crypto::seal(&kek, &wrap_nonce, self.vault_key.as_bytes(), &prefix)?;

        self.salt = salt;
        self.wrap_nonce = wrap_nonce;
        self.wrapped_key.copy_from_slice(&wrapped);
        Ok(())
    }

    // ── 增删改查 ──────────────────────────────────────────────

    pub fn entries(&self) -> &[Entry] {
        &self.data.entries
    }

    pub fn len(&self) -> usize {
        self.data.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.entries.is_empty()
    }

    pub fn add(&mut self, entry: Entry) -> Uuid {
        let id = entry.id;
        self.data.entries.push(entry);
        id
    }

    pub fn get(&self, id: Uuid) -> Option<&Entry> {
        self.data.entries.iter().find(|e| e.id == id)
    }

    /// 取出可变引用以便修改；会自动更新 `updated_at`。
    pub fn update(&mut self, id: Uuid, f: impl FnOnce(&mut Entry)) -> Result<()> {
        let e = self.data.entries.iter_mut().find(|e| e.id == id).ok_or(Error::EntryNotFound)?;
        f(e);
        e.updated_at = now_millis();
        Ok(())
    }

    pub fn delete(&mut self, id: Uuid) -> Result<()> {
        let before = self.data.entries.len();
        self.data.entries.retain(|e| e.id != id);
        if self.data.entries.len() == before {
            return Err(Error::EntryNotFound);
        }
        Ok(())
    }

    /// 按分类 + 关键词筛选。`category` 为 `None` 表示全部。
    pub fn search(&self, query: &str, category: Option<Category>) -> Vec<&Entry> {
        self.data
            .entries
            .iter()
            .filter(|e| category.is_none_or(|c| e.category == c))
            .filter(|e| e.matches(query))
            .collect()
    }

    /// 清空全部条目（对应设计稿的「危险操作 / 清除所有数据」）。
    pub fn erase_all(&mut self) {
        self.data.entries.clear();
    }

    // ── 设置 ──────────────────────────────────────────────────

    pub fn settings(&self) -> &VaultSettings {
        &self.data.settings
    }

    pub fn settings_mut(&mut self) -> &mut VaultSettings {
        &mut self.data.settings
    }
}

/// 原子写文件：临时文件 → fsync → rename。
///
/// `rename(2)` 在同一文件系统内是原子的，所以断电或崩溃时要么是完整的旧版本、
/// 要么是完整的新版本，**不会**留下一个写了一半的保险库。直接覆写原文件
/// 则可能永久丢失全部密码。
///
/// fsync 不能省：没有它，rename 完成后数据可能仍只在页缓存里，
/// 此时掉电会得到一个文件名指向新数据、内容却是旧的（甚至是空的）的结果。
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("lokal.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        set_owner_only(&f)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn build_prefix(kdf: KdfParams, salt: &[u8; SALT_LEN]) -> [u8; PREFIX_LEN] {
    let mut p = [0u8; PREFIX_LEN];
    p[0..6].copy_from_slice(MAGIC);
    p[6] = FORMAT_VERSION;
    p[7] = KDF_ARGON2ID;
    p[8..12].copy_from_slice(&kdf.m_cost.to_le_bytes());
    p[12..16].copy_from_slice(&kdf.t_cost.to_le_bytes());
    p[16..20].copy_from_slice(&kdf.p_cost.to_le_bytes());
    p[20..36].copy_from_slice(salt);
    p
}

/// 文件权限设为 0600——同机器上的其他用户读不到。
#[cfg(unix)]
fn set_owner_only(f: &std::fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_f: &std::fs::File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Category;

    fn fast() -> KdfParams {
        KdfParams { m_cost: 8, t_cost: 1, p_cost: 1 }
    }

    fn seeded() -> Vault {
        let mut v = Vault::create_with_params("master-correct-horse", fast()).unwrap();
        v.add(
            Entry::new("Northwind Bank", "anna.k@mail.com", "K9#vLm2$pQx7!wRz", Category::Banking)
                .with_url("northwind.bank")
                .with_notes("Ask branch for wire limit increase."),
        );
        v.add(Entry::new("Pixelgram", "@anna.codes", "sunfl0wer-Dune-42", Category::Social));
        v.add(Entry::new("Mailbox Pro", "anna.k@mail.com", "Tr4in-Harbor-Lamp!", Category::Work));
        v
    }

    #[test]
    fn roundtrip_preserves_everything() {
        let v = seeded();
        let bytes = v.to_bytes().unwrap();
        let back = Vault::from_bytes(&bytes, "master-correct-horse").unwrap();

        assert_eq!(back.len(), 3);
        let bank = back.entries().iter().find(|e| e.name == "Northwind Bank").unwrap();
        assert_eq!(bank.password.expose(), "K9#vLm2$pQx7!wRz");
        assert_eq!(bank.url, "northwind.bank");
        assert_eq!(bank.category, Category::Banking);
        assert_eq!(bank.notes, "Ask branch for wire limit increase.");
    }

    #[test]
    fn wrong_password_fails() {
        let v = seeded();
        let bytes = v.to_bytes().unwrap();
        assert!(matches!(
            Vault::from_bytes(&bytes, "master-correct-hors"), // 少一个字母
            Err(Error::Unauthenticated)
        ));
    }

    #[test]
    fn plaintext_never_appears_in_the_file() {
        // 最直接的一条检查：把明文当子串在密文里搜一遍。
        let v = seeded();
        let bytes = v.to_bytes().unwrap();
        for needle in [
            "K9#vLm2$pQx7!wRz",
            "Northwind Bank",
            "anna.k@mail.com",
            "northwind.bank",
            "Ask branch for wire limit increase.",
            "master-correct-horse",
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "明文 {needle:?} 出现在了保险库文件里"
            );
        }
    }

    #[test]
    fn every_save_produces_different_bytes() {
        // nonce 每次重新随机 ⇒ 同样的内容两次保存密文不同。
        // 如果这条挂了，说明 nonce 被复用了——对 ChaCha 是灾难性的。
        let v = seeded();
        let a = v.to_bytes().unwrap();
        let b = v.to_bytes().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn tampering_with_ciphertext_is_detected() {
        let v = seeded();
        let mut bytes = v.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(Vault::from_bytes(&bytes, "master-correct-horse").is_err());
    }

    #[test]
    fn kdf_downgrade_attack_is_detected() {
        // 攻击者把 m_cost 从高改到 1 KiB,想让暴力破解快几个数量级。
        // 因为 KDF 参数进了 AAD、又参与密钥派生,改动必然导致解密失败。
        let v = Vault::create_with_params(
            "pw-under-test",
            KdfParams { m_cost: 64, t_cost: 2, p_cost: 1 },
        )
        .unwrap();
        let mut bytes = v.to_bytes().unwrap();
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes()); // m_cost := 1
        assert!(Vault::from_bytes(&bytes, "pw-under-test").is_err());
    }

    #[test]
    fn salt_tampering_is_detected() {
        let v = seeded();
        let mut bytes = v.to_bytes().unwrap();
        bytes[20] ^= 0xff;
        assert!(Vault::from_bytes(&bytes, "master-correct-horse").is_err());
    }

    #[test]
    fn bad_magic_and_version_are_reported_clearly() {
        let v = seeded();
        let bytes = v.to_bytes().unwrap();

        let mut wrong_magic = bytes.clone();
        wrong_magic[0] = b'X';
        assert!(matches!(Vault::from_bytes(&wrong_magic, "x"), Err(Error::BadMagic)));

        let mut wrong_ver = bytes.clone();
        wrong_ver[6] = 99;
        assert!(matches!(
            Vault::from_bytes(&wrong_ver, "x"),
            Err(Error::UnsupportedVersion { found: 99, supported: 1 })
        ));

        assert!(matches!(Vault::from_bytes(&bytes[..10], "x"), Err(Error::Truncated)));
    }

    #[test]
    fn changing_master_password_rewraps_only_the_key() {
        let mut v = seeded();
        let old = v.to_bytes().unwrap();

        v.change_master_password("a-brand-new-master").unwrap();
        let new = v.to_bytes().unwrap();

        // 旧口令再也打不开,新口令可以,内容一字不差。
        assert!(Vault::from_bytes(&new, "master-correct-horse").is_err());
        let back = Vault::from_bytes(&new, "a-brand-new-master").unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(
            back.entries().iter().find(|e| e.name == "Pixelgram").unwrap().password.expose(),
            "sunfl0wer-Dune-42"
        );

        // 换口令换了盐,所以头部必然变化。
        assert_ne!(&old[20..36], &new[20..36]);
    }

    #[test]
    fn crud_works() {
        let mut v = seeded();
        let id = v.add(Entry::new("ShopCart", "annak", "meadow77", Category::Shopping));
        assert_eq!(v.len(), 4);

        v.update(id, |e| e.password = "a-much-better-one".into()).unwrap();
        assert_eq!(v.get(id).unwrap().password.expose(), "a-much-better-one");

        v.delete(id).unwrap();
        assert_eq!(v.len(), 3);
        assert!(matches!(v.delete(id), Err(Error::EntryNotFound)));
    }

    #[test]
    fn search_filters_by_query_and_category() {
        let v = seeded();
        assert_eq!(v.search("", None).len(), 3);
        assert_eq!(v.search("", Some(Category::Work)).len(), 1);
        assert_eq!(v.search("mail", None).len(), 2); // 命中用户名 + 名称
        assert_eq!(v.search("mail", Some(Category::Banking)).len(), 1);
        assert_eq!(v.search("nonexistent", None).len(), 0);
    }

    #[test]
    fn export_does_not_repoint_the_vault() {
        // 这是 export_to 存在的唯一理由。用 save_to 做导出会让保险库改指向
        // 备份文件，之后 save() 全写进备份、原库停止更新——静默的数据分叉。
        let dir = std::env::temp_dir().join(format!("lokal-export-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("vault.lokal");
        let backup = dir.join("backup.lokal");

        let mut v = seeded();
        v.save_to(&live).unwrap();
        v.export_to(&backup).unwrap();

        // 导出后再加一条并 save()，必须落到原库、不能落到备份。
        v.add(Entry::new("AfterExport", "u", "p", Category::Other));
        v.save().unwrap();

        let live_back = Vault::open(&live, "master-correct-horse").unwrap();
        let backup_back = Vault::open(&backup, "master-correct-horse").unwrap();
        assert_eq!(live_back.len(), 4, "新条目应写进原库");
        assert_eq!(backup_back.len(), 3, "备份应停留在导出那一刻");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backup_opens_with_the_same_master_password() {
        let dir = std::env::temp_dir().join(format!("lokal-backup-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let backup = dir.join("backup.lokal");

        let v = seeded();
        v.export_to(&backup).unwrap();

        // 同口令能开，错口令不能。
        let back = Vault::open(&backup, "master-correct-horse").unwrap();
        assert_eq!(back.len(), 3);
        assert_eq!(
            back.entries().iter().find(|e| e.name == "Pixelgram").unwrap().password.expose(),
            "sunfl0wer-Dune-42"
        );
        assert!(Vault::open(&backup, "wrong").is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&backup).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "备份文件同样必须是 0600");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn backup_taken_before_password_change_still_opens_with_the_old_one() {
        // 换主口令只重包 VK,所以旧备份仍然只认旧口令。这不是 bug,
        // 是必须让用户知道的行为：换口令后要重新导出备份。
        let dir = std::env::temp_dir().join(format!("lokal-oldpw-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let backup = dir.join("backup.lokal");

        let mut v = seeded();
        v.export_to(&backup).unwrap();
        v.change_master_password("a-brand-new-master").unwrap();

        assert!(Vault::open(&backup, "a-brand-new-master").is_err(), "新口令开不了旧备份");
        assert!(Vault::open(&backup, "master-correct-horse").is_ok(), "旧备份仍认旧口令");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_roundtrip_is_atomic_and_private() {
        let dir = std::env::temp_dir().join(format!("lokal-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.lokal");

        let mut v = seeded();
        v.save_to(&path).unwrap();

        // 临时文件必须已被 rename 掉,不留残留。
        assert!(!dir.join("vault.lokal.tmp").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "保险库文件权限必须是 0600");
        }

        let back = Vault::open(&path, "master-correct-horse").unwrap();
        assert_eq!(back.len(), 3);

        std::fs::remove_dir_all(&dir).ok();
    }
}
