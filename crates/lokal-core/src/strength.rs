//! 密码强度评估。
//!
//! 原型用的是「字符类打分法」：有大小写 +1、有数字 +1、有符号 +1……
//! 这个方法**是错的**，而且错得很典型——它会把 `P@ssw0rd!` 判成强密码
//! （四类字符全齐），却把 `correct horse battery staple` 判成弱密码
//! （只有小写）。而真实破解工具的字典和替换规则会在几秒内破掉前者，
//! 后者需要天文数字次猜测。
//!
//! 正确的度量是**攻击者需要猜多少次**。zxcvbn 用字典（常见密码、姓名、
//! 词表）、键盘序列（qwerty、1qaz）、日期、重复和 l33t 替换等模式去匹配，
//! 估计的是真实猜测次数，而不是字符集大小。

use zxcvbn::{Score, zxcvbn};

/// 三档强度——对应设计稿里的弱/中/强三色进度条。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    Weak,
    Fair,
    Strong,
}

impl Strength {
    /// 给 UI 用的进度条百分比。
    pub fn percent(self) -> u8 {
        match self {
            Strength::Weak => 30,
            Strength::Fair => 60,
            Strength::Strong => 100,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Assessment {
    pub strength: Strength,
    /// 估计的猜测次数（数量级参考，不是精确值）。
    pub guesses: u64,
    /// zxcvbn 原始 0–4 分。
    pub score: u8,
}

/// 把「Northwind Bank」「anna.k@mail.com」拆成可匹配的词。
///
/// **这一步不能省。** zxcvbn 把 `user_inputs` 的每个元素当作一个完整的
/// 词典词来匹配，不会自己分词——直接传 `"Northwind Bank"`（带空格）去比对
/// `"Northwind2024"`，永远匹配不上，这个防护就静默失效了。实测：
/// 传整串猜测次数 1.53e8，拆出 `"Northwind"` 后降到 1.5e4（一万倍）。
///
/// 短于 3 个字符的碎片（`co`、`k`）不要，它们只会误伤正常密码。
fn tokenize(inputs: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for raw in inputs {
        let raw = raw.trim();
        if raw.len() >= 3 {
            out.push(raw.to_string()); // 整串也留着,单词站点名靠它命中
        }
        for tok in raw.split(|c: char| !c.is_alphanumeric()) {
            if tok.len() >= 3 {
                out.push(tok.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// 评估一个密码。
///
/// `user_inputs` 传入该条目的名称、用户名、网址等——因为
/// 「用网站名当密码」是极常见且极易破解的做法，把这些喂给 zxcvbn
/// 它才能识别出来并扣分。传原始字符串即可，内部会自动分词。
pub fn assess(password: &str, user_inputs: &[&str]) -> Assessment {
    if password.is_empty() {
        return Assessment { strength: Strength::Weak, guesses: 0, score: 0 };
    }

    let tokens = tokenize(user_inputs);
    let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
    let entropy = zxcvbn(password, &refs);
    let score = entropy.score();

    // 门槛定得比 zxcvbn 默认严：密码管理器生成的密码轻松到 Four，
    // 所以只有 Four 才叫「强」，Three 只是「中」。
    let strength = match score {
        Score::Zero | Score::One => Strength::Weak,
        Score::Two | Score::Three => Strength::Fair,
        _ => Strength::Strong,
    };

    Assessment { strength, guesses: entropy.guesses(), score: u8::from(score) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::{GenOptions, generate};

    #[test]
    fn empty_password_is_weak() {
        assert_eq!(assess("", &[]).strength, Strength::Weak);
    }

    #[test]
    fn common_passwords_are_weak() {
        for pw in ["123456", "password", "qwerty", "letmein", "abc123"] {
            assert_eq!(assess(pw, &[]).strength, Strength::Weak, "{pw} 应判为弱");
        }
    }

    #[test]
    fn leetspeak_does_not_fool_it() {
        // 这正是字符类打分法失败的地方：四类字符齐全，但字典 + l33t
        // 规则一秒破解。这条测试锁住「我们没有退回旧方法」。
        let a = assess("P@ssw0rd!", &[]);
        assert_eq!(a.strength, Strength::Weak, "P@ssw0rd! 必须判为弱，实测 score={}", a.score);
    }

    #[test]
    fn long_passphrase_beats_short_complex_one() {
        let phrase = assess("correct horse battery staple", &[]);
        let complex = assess("P@ss1!", &[]);
        assert!(
            phrase.guesses > complex.guesses,
            "长短语应比短复杂密码更难猜：{} vs {}",
            phrase.guesses,
            complex.guesses
        );
    }

    #[test]
    fn reusing_the_site_name_is_penalised() {
        let blind = assess("Northwind2024", &[]);
        let aware = assess("Northwind2024", &["Northwind Bank"]);
        assert!(
            aware.guesses < blind.guesses,
            "知道站点名后应扣分：{} vs {}",
            aware.guesses,
            blind.guesses
        );
    }

    #[test]
    fn multiword_inputs_are_tokenized() {
        // 回归测试：曾经把整串直接丢给 zxcvbn，多词站点名一律匹配不上，
        // 防护静默失效。这条锁住分词行为。
        //
        // 用例一律选生造词。原因（实测得来）：user_inputs 只在词**不在**
        // zxcvbn 内置词典时才降分。拿 "anna.k@mail.com" 做用例会永远失败——
        // "anna" 已在内置人名词典里且猜测次数已到下限 50，再喂一遍不会更低。
        // 这不是分词的问题，是用例选错了。
        for (pw, inputs) in [
            ("Northwind2024", &["Northwind Bank"][..]),
            ("Vintrell99", &["Vintrell Holdings"][..]),
            ("zorbulon77", &["zorbulon@mail.com"][..]),
        ] {
            let blind = assess(pw, &[]);
            let aware = assess(pw, inputs);
            assert!(
                aware.guesses < blind.guesses,
                "{pw} 配 {inputs:?} 应被扣分：{} vs {}",
                aware.guesses,
                blind.guesses
            );
        }
    }

    #[test]
    fn short_fragments_do_not_cause_false_penalties() {
        // 分词不能碎到 1-2 个字母,否则任何密码都会被误判。
        let pw = "Zt7#qWm4$xLp9!";
        let blind = assess(pw, &[]);
        let aware = assess(pw, &["a.b@c.io", "x"]);
        assert_eq!(aware.guesses, blind.guesses, "短碎片不应影响评分");
    }

    #[test]
    fn generated_passwords_are_strong() {
        // 端到端约束：我们自己生成器的默认输出必须过「强」这一档，
        // 否则要么生成器太弱，要么门槛定错了。
        for _ in 0..20 {
            let pw = generate(GenOptions::default()).unwrap();
            let a = assess(pw.expose(), &[]);
            assert_eq!(
                a.strength,
                Strength::Strong,
                "生成的密码判为 {:?}：{}",
                a.strength,
                pw.expose()
            );
        }
    }
}
