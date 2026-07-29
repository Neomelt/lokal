//! 校验一份备份还能不能打开。
//!
//! 备份最坏的失败方式是**沉默**：文件一直在，你一直以为它有效，
//! 等真需要恢复的那天才发现口令记错了、或者文件在同步过程中被截断了。
//! 定期跑一次这个，把"我有备份"变成"我验过备份"。
//!
//! ```text
//! cargo run --release --example verify_backup -- <备份文件> [主口令]
//! ```
//!
//! 不传口令时会从标准输入读一行。推荐这样用：`ps` 能看到任何进程的完整
//! 命令行（包括别的用户跑的），口令写在参数里等于公开广播一次。

use std::io::Write;

use lokal_core::Vault;

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("用法: verify_backup <备份文件> [主口令]");
        eprintln!("      省略口令则从标准输入读取（推荐，不会留在 shell 历史和 ps 里）");
        return std::process::ExitCode::from(2);
    };

    let password = match args.next() {
        Some(p) => p,
        None => {
            eprint!("主口令: ");
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            if std::io::stdin().read_line(&mut line).is_err() {
                eprintln!("读取口令失败");
                return std::process::ExitCode::from(2);
            }
            line.trim_end_matches(['\r', '\n']).to_string()
        }
    };

    match Vault::open(&path, &password) {
        Ok(v) => {
            println!("✓ 解密成功 — {} 条条目", v.len());
            for e in v.entries() {
                let user = if e.username.is_empty() { "—" } else { e.username.as_str() };
                println!(
                    "   {:<24} {:<28} {:?}  密码 {} 位",
                    e.name,
                    user,
                    e.category,
                    e.password.expose().chars().count()
                );
            }
            println!("\n这份备份是好的。");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            println!("✗ 打不开：{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
