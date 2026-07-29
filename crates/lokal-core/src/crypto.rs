//! 密码学原语的薄封装。
//!
//! 选型理由（每一条都是可以被质疑和替换的工程决策，不是惯例）：
//!
//! **KDF：Argon2id**
//! 主口令的熵不够直接当密钥用，必须用 KDF 拉伸。选 Argon2id 是因为它
//! *内存硬* (memory-hard)：破解者想并行就得为每条流水线配等量内存，
//! 这直接压制 GPU/ASIC 的成本优势。PBKDF2 只吃算力不吃内存，正是
//! GPU 最擅长的形状。id 变体同时抵抗侧信道和 GPU 攻击。
//!
//! **AEAD：XChaCha20-Poly1305**
//! - 选 AEAD 而非纯加密：Poly1305 认证标签让「密文被改过」变成可检测的。
//!   没有认证的加密（如裸 CTR/CBC）攻击者可以翻转位来篡改明文。
//! - 选 X 变体（192-bit nonce）而非标准 ChaCha20-Poly1305（96-bit）：
//!   nonce 我们每次保存都随机生成。96 bit 下随机 nonce 在约 2^32 条消息后
//!   碰撞概率开始不可忽略（生日界），而 ChaCha 系列 nonce 复用是**灾难性**的
//!   ——两条密文异或就能消掉密钥流。192 bit 让随机 nonce 彻底安全，
//!   代价只是每条记录多 12 字节。
//! - 选 ChaCha 而非 AES-GCM：软件实现天然常数时间（不依赖 AES-NI 硬件指令），
//!   在没有硬件加速的平台上不会退化成有 cache 侧信道的查表实现。

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};

use crate::error::{Error, Result};
use crate::secret::Key32;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
/// Poly1305 认证标签长度。
pub const TAG_LEN: usize = 16;

/// Argon2id 代价参数。
///
/// 默认值参考 OWASP 建议（64 MiB / 3 轮 / 4 并行）。这些数字是
/// **安全与体验的权衡**：调高更难暴力破解，但用户每次解锁都要等更久。
/// 手机上通常要往下调（内存受限），所以参数写进文件头——换设备打开时
/// 用文件里记录的参数，而不是当前程序的默认值。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// 内存开销，单位 KiB。
    pub m_cost: u32,
    /// 迭代轮数。
    pub t_cost: u32,
    /// 并行度。
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 64 * 1024, // 64 MiB
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl KdfParams {
    /// 仅供测试使用的最低代价参数——正式代码路径绝不要用。
    #[cfg(test)]
    pub(crate) fn fast_for_tests() -> Self {
        Self {
            m_cost: 8, // 8 KiB
            t_cost: 1,
            p_cost: 1,
        }
    }
}

/// 用系统 CSPRNG 填充 N 字节。
///
/// 走的是 OS 的加密随机源（Linux 上是 `getrandom(2)`）。
/// **绝不能**用 `rand::random` 的默认 RNG 或任何 PRNG 来生成密钥/nonce/密码。
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| Error::Random(e.to_string()))?;
    Ok(buf)
}

/// 从主口令派生密钥加密密钥 (KEK)。
pub fn derive_kek(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key32> {
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::BadKdfParams(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);

    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| Error::BadKdfParams(e.to_string()))?;
    Ok(Key32::from_bytes(out))
}

/// 认证加密。返回 `密文 || 标签`。
///
/// `aad` 是附加认证数据：不加密，但参与认证。我们把文件头塞进去，
/// 于是任何对头部的改动（比如把 KDF 代价从 64 MiB 调到 8 KiB 来加速破解）
/// 都会让解密直接失败，而不是悄悄生效。
pub fn seal(key: &Key32, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| Error::BadKdfParams("密钥长度错误".into()))?;
    let nonce = XNonce::from(*nonce);
    cipher.encrypt(&nonce, Payload { msg: plaintext, aad }).map_err(|_| Error::Unauthenticated)
}

/// 认证解密。密文被改过一位就会失败。
pub fn open(
    key: &Key32,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|_| Error::BadKdfParams("密钥长度错误".into()))?;
    let nonce = XNonce::from(*nonce);
    cipher.decrypt(&nonce, Payload { msg: ciphertext, aad }).map_err(|_| Error::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = Key32::from_bytes(random_bytes::<32>().unwrap());
        let nonce = random_bytes::<NONCE_LEN>().unwrap();
        let msg = b"attack at dawn";
        let aad = b"header";

        let ct = seal(&key, &nonce, msg, aad).unwrap();
        assert_ne!(&ct[..msg.len()], msg, "密文不应等于明文");
        assert_eq!(ct.len(), msg.len() + TAG_LEN, "应为 密文||标签");

        let pt = open(&key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = Key32::from_bytes(random_bytes::<32>().unwrap());
        let nonce = random_bytes::<NONCE_LEN>().unwrap();
        let mut ct = seal(&key, &nonce, b"balance: 100", b"").unwrap();

        ct[0] ^= 0x01; // 只翻转一位
        assert!(open(&key, &nonce, &ct, b"").is_err(), "篡改必须被检测到");
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let key = Key32::from_bytes(random_bytes::<32>().unwrap());
        let nonce = random_bytes::<NONCE_LEN>().unwrap();
        let ct = seal(&key, &nonce, b"secret", b"header-v1").unwrap();

        assert!(open(&key, &nonce, &ct, b"header-v2").is_err(), "AAD 不符必须失败");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let k1 = Key32::from_bytes(random_bytes::<32>().unwrap());
        let k2 = Key32::from_bytes(random_bytes::<32>().unwrap());
        let nonce = random_bytes::<NONCE_LEN>().unwrap();
        let ct = seal(&k1, &nonce, b"secret", b"").unwrap();

        assert!(open(&k2, &nonce, &ct, b"").is_err());
    }

    #[test]
    fn kdf_is_deterministic_and_salt_dependent() {
        let p = KdfParams::fast_for_tests();
        let a = derive_kek(b"hunter2", b"salt-aaaaaaaaaaa", p).unwrap();
        let b = derive_kek(b"hunter2", b"salt-aaaaaaaaaaa", p).unwrap();
        let c = derive_kek(b"hunter2", b"salt-bbbbbbbbbbb", p).unwrap();

        assert_eq!(a.as_bytes(), b.as_bytes(), "同口令同盐必须得到同密钥");
        assert_ne!(a.as_bytes(), c.as_bytes(), "换盐必须换密钥（这就是盐的作用）");
    }

    #[test]
    fn kdf_params_change_the_key() {
        // 这条保证了「篡改文件头里的 KDF 参数」不可能得到同一个密钥。
        let salt = b"salt-aaaaaaaaaaa";
        let a = derive_kek(b"pw", salt, KdfParams { m_cost: 8, t_cost: 1, p_cost: 1 }).unwrap();
        let b = derive_kek(b"pw", salt, KdfParams { m_cost: 8, t_cost: 2, p_cost: 1 }).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn random_bytes_are_not_constant() {
        // 不是随机性检验，只是抓「忘了真正调用 CSPRNG」这类低级错误。
        let a = random_bytes::<32>().unwrap();
        let b = random_bytes::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
