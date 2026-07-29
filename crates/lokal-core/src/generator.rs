//! 密码生成器。
//!
//! 原型里这一步是 `Math.random()`——那是个可预测的 PRNG，
//! 用它生成的密码能被复现。这里全部走系统 CSPRNG。
//!
//! 第二个坑是**取模偏置** (modulo bias)：`rand_byte % pool_len` 在
//! `pool_len` 不整除 256 时，靠前的字符会比靠后的更容易被选中。
//! 比如 pool 长度 70 时，0..=185 映射到前 46 个字符各两次、
//! 剩下的只一次——熵实打实地降低了。这里用**拒绝采样**消除它。

use crate::error::Result;
use crate::secret::Secret;

/// 去掉了形近字符（l/I/1、O/0）——它们只会制造抄写错误，
/// 而少这几个字符带来的熵损失可以用长度补回来。
const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS: &str = "23456789";
const SYMBOLS: &str = "!@#$%&*?-";

#[derive(Debug, Clone, Copy)]
pub struct GenOptions {
    pub length: usize,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self { length: 20, digits: true, symbols: true }
    }
}

/// 无偏地从字符集里取一个字符。
///
/// 拒绝采样：把 0..=255 截断到 `pool_len` 的最大整数倍，
/// 落在尾巴上的随机字节直接丢弃重抽。丢弃率 < 50%，期望不到 2 次循环。
fn pick(pool: &[char]) -> Result<char> {
    let n = pool.len() as u32;
    debug_assert!(n > 0 && n <= 256);
    let limit = (256 / n) * n; // 可接受区间上界

    loop {
        let [b] = crate::crypto::random_bytes::<1>()?;
        if (b as u32) < limit {
            return Ok(pool[(b as u32 % n) as usize]);
        }
    }
}

/// 生成一个密码。
///
/// 若启用了数字/符号，保证**至少各出现一个**——很多站点强制要求。
/// 实现方式是整条重抽而非事后替换：事后往固定位置塞字符会破坏均匀性，
/// 整条重抽则保持在「满足约束的密码」这个集合上均匀分布。
pub fn generate(opts: GenOptions) -> Result<Secret> {
    let mut pool: Vec<char> = LOWER.chars().chain(UPPER.chars()).collect();
    if opts.digits {
        pool.extend(DIGITS.chars());
    }
    if opts.symbols {
        pool.extend(SYMBOLS.chars());
    }

    let len = opts.length.max(4);

    loop {
        let mut out = String::with_capacity(len);
        for _ in 0..len {
            out.push(pick(&pool)?);
        }
        let ok_digit = !opts.digits || out.chars().any(|c| DIGITS.contains(c));
        let ok_symbol = !opts.symbols || out.chars().any(|c| SYMBOLS.contains(c));
        if ok_digit && ok_symbol {
            return Ok(Secret::new(out));
        }
        // 约束不满足，整条丢弃重来。
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn respects_length() {
        for len in [8usize, 16, 32, 64] {
            let pw = generate(GenOptions { length: len, ..Default::default() }).unwrap();
            assert_eq!(pw.expose().chars().count(), len);
        }
    }

    #[test]
    fn honours_charset_toggles() {
        let pw = generate(GenOptions { length: 40, digits: false, symbols: false }).unwrap();
        assert!(
            pw.expose().chars().all(|c| c.is_ascii_alphabetic()),
            "关掉数字和符号后不应出现它们：{}",
            pw.expose()
        );
    }

    #[test]
    fn guarantees_required_classes() {
        // 长度取小值，让「碰巧没有数字」的概率足够高，能真正检验约束逻辑。
        for _ in 0..200 {
            let pw = generate(GenOptions { length: 6, digits: true, symbols: true }).unwrap();
            assert!(pw.expose().chars().any(|c| DIGITS.contains(c)), "缺数字：{}", pw.expose());
            assert!(pw.expose().chars().any(|c| SYMBOLS.contains(c)), "缺符号：{}", pw.expose());
        }
    }

    #[test]
    fn excludes_lookalike_characters() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let pw = generate(GenOptions { length: 32, ..Default::default() }).unwrap();
            seen.extend(pw.expose().chars());
        }
        for bad in ['l', 'I', '1', 'O', '0'] {
            assert!(!seen.contains(&bad), "形近字符 {bad} 不应出现");
        }
    }

    #[test]
    fn passwords_do_not_repeat() {
        let mut seen = HashSet::new();
        for _ in 0..500 {
            let pw = generate(GenOptions::default()).unwrap();
            assert!(seen.insert(pw.expose().to_string()), "生成了重复密码——随机源有问题");
        }
    }

    #[test]
    fn distribution_is_roughly_uniform() {
        // 拒绝采样若写错（退化成 % 取模），靠前字符会被显著偏爱。
        // 这里做个宽松的卡方式检查：抽样足够多时，最常见与最罕见字符
        // 的出现次数不应相差一倍以上。
        let opts = GenOptions { length: 64, digits: true, symbols: true };
        let pool_len = (LOWER.len() + UPPER.len() + DIGITS.len() + SYMBOLS.len()) as f64;
        let mut counts = std::collections::HashMap::<char, u32>::new();
        let samples = 400;
        for _ in 0..samples {
            let pw = generate(opts).unwrap();
            for c in pw.expose().chars() {
                *counts.entry(c).or_default() += 1;
            }
        }
        let total = (samples * opts.length) as f64;
        let expected = total / pool_len;
        let max = *counts.values().max().unwrap() as f64;
        let min = *counts.values().min().unwrap() as f64;
        assert!(
            max < expected * 1.5 && min > expected * 0.5,
            "分布偏斜：期望 {expected:.0}，实测 min={min} max={max}"
        );
    }
}
