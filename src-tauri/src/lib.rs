//! Tauri 外壳：把 `lokal-core` 暴露给界面。
//!
//! # 这一层的安全约定
//!
//! **密码默认不下发到前端。** 列表和详情返回的 `EntryView` 里没有密码字段——
//! 强度是在 Rust 侧算好后只把结果传过去的。只有用户明确点「显示」或「复制」时，
//! 才通过 `reveal_password` 单独取一次。
//!
//! 为什么较真这一点：WebView 里的任何 XSS、任何一个被注入的脚本、
//! 任何一次 DevTools 打开，都能把 JS 堆里的东西读走。把整库明文一次性
//! 灌进前端，等于把加密核心的努力在最后一米全部作废。
//!
//! 保险库本身（VK 和全部明文）只存在于 Rust 侧的 `VaultState` 里。

use std::sync::Mutex;

use lokal_core::{
    Category, Entry, Secret, Strength, Vault, assess,
    generator::{self, GenOptions},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 已解锁的保险库。`None` 表示锁定状态。
#[derive(Default)]
struct VaultState(Mutex<Option<Vault>>);

// ── 传给前端的视图类型 ──────────────────────────────────────

/// 列表/详情用。**没有密码字段**——这是刻意的。
#[derive(Serialize)]
struct EntryView {
    id: String,
    name: String,
    username: String,
    url: String,
    notes: String,
    category: Category,
    /// 名称首字母，给列表的方块头像用。
    initial: String,
    strength: StrengthView,
}

#[derive(Serialize)]
struct StrengthView {
    /// "weak" | "fair" | "strong"
    level: &'static str,
    percent: u8,
    /// zxcvbn 原始 0–4 分。
    score: u8,
}

impl From<Strength> for StrengthView {
    fn from(s: Strength) -> Self {
        Self {
            level: match s {
                Strength::Weak => "weak",
                Strength::Fair => "fair",
                Strength::Strong => "strong",
            },
            percent: s.percent(),
            score: 0,
        }
    }
}

fn view_of(e: &Entry) -> EntryView {
    // 把名称/用户名/网址喂给 zxcvbn，它才能识别「拿站点名当密码」。
    let a = assess(e.password.expose(), &[&e.name, &e.username, &e.url]);
    EntryView {
        id: e.id.to_string(),
        name: e.name.clone(),
        username: e.username.clone(),
        url: e.url.clone(),
        notes: e.notes.clone(),
        category: e.category,
        initial: e.name.chars().next().map(|c| c.to_uppercase().to_string()).unwrap_or_default(),
        strength: StrengthView { score: a.score, ..a.strength.into() },
    }
}

#[derive(Deserialize)]
struct EntryInput {
    /// `None` = 新建；`Some(uuid)` = 编辑。
    id: Option<String>,
    name: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    category: Category,
}

#[derive(Serialize)]
struct VaultStats {
    count: usize,
    /// 加密后的文件字节数。
    size_bytes: u64,
    /// 自动备份目录；`None` = 未开启。
    auto_backup_dir: Option<String>,
    /// 该目录下现有的自动备份份数。
    auto_backup_count: usize,
    /// 最新一份的时间戳（文件名里那段）。
    auto_backup_latest: Option<String>,
    /// 最近一次自动备份的失败原因。备份坏了必须让用户看见。
    auto_backup_error: Option<String>,
}

// ── 辅助 ────────────────────────────────────────────────────

fn vault_path(app: &tauri::AppHandle) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;
    let dir = app.path().app_data_dir().map_err(|e| format!("找不到应用数据目录：{e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("无法创建数据目录：{e}"))?;
    Ok(dir.join("vault.lokal"))
}

/// 取出已解锁的保险库；锁定时返回统一错误。
fn with_vault<T>(
    state: &tauri::State<VaultState>,
    f: impl FnOnce(&mut Vault) -> Result<T, String>,
) -> Result<T, String> {
    let mut guard = state.0.lock().map_err(|_| "内部状态已损坏".to_string())?;
    let vault = guard.as_mut().ok_or_else(|| "保险库已锁定".to_string())?;
    f(vault)
}

fn parse_id(id: &str) -> Result<Uuid, String> {
    Uuid::parse_str(id).map_err(|_| "条目 id 非法".to_string())
}

/// 最近一次自动备份的失败原因。
///
/// 用全局而非 `VaultState`，是因为保存发生在 `with_vault` 的闭包里、
/// 那里拿不到 `State`。范围很小、只写一个字符串，代价可接受。
static LAST_BACKUP_ERROR: Mutex<Option<String>> = Mutex::new(None);

/// 保存保险库，顺手做一次自动备份。
///
/// **备份失败绝不让保存失败。** 备份盘拔了、网盘没挂上，用户也必须能继续
/// 存密码——把两者绑死只会让人在最需要记密码的时候用不了软件。
/// 失败原因记下来由设置页显示，而不是静默吞掉：一个没人知道它坏了的备份，
/// 比没有备份更危险。
fn save_and_backup(v: &mut Vault, path: &std::path::Path) -> Result<(), String> {
    v.save_to(path).map_err(|e| e.to_string())?;
    if let Ok(mut slot) = LAST_BACKUP_ERROR.lock() {
        *slot = auto_backup_after_save(v);
    }
    Ok(())
}

// ── 命令 ────────────────────────────────────────────────────

#[tauri::command]
fn vault_exists(app: tauri::AppHandle) -> Result<bool, String> {
    Ok(vault_path(&app)?.exists())
}

#[tauri::command]
fn is_unlocked(state: tauri::State<VaultState>) -> bool {
    state.0.lock().map(|g| g.is_some()).unwrap_or(false)
}

#[tauri::command]
fn create_vault(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
    master_password: String,
) -> Result<(), String> {
    // 包一层 Secret，让它在本函数结束时被清零，而不是等分配器回收。
    let pw = Secret::new(master_password);
    if pw.expose().chars().count() < 8 {
        return Err("主口令至少 8 个字符".into());
    }
    let path = vault_path(&app)?;
    if path.exists() {
        return Err("此设备上已存在保险库".into());
    }

    let mut vault = Vault::create(pw.expose()).map_err(|e| e.to_string())?;
    vault.save_to(&path).map_err(|e| e.to_string())?;
    *state.0.lock().map_err(|_| "内部状态已损坏")? = Some(vault);
    Ok(())
}

#[tauri::command]
fn unlock(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
    master_password: String,
) -> Result<(), String> {
    let pw = Secret::new(master_password);
    let path = vault_path(&app)?;
    let vault = Vault::open(&path, pw.expose()).map_err(|e| e.to_string())?;
    *state.0.lock().map_err(|_| "内部状态已损坏")? = Some(vault);
    Ok(())
}

/// 上锁——丢弃 `Vault`，`Key32`/`Secret` 的 `Drop` 会把密钥和明文清零。
#[tauri::command]
fn lock(state: tauri::State<VaultState>) -> Result<(), String> {
    *state.0.lock().map_err(|_| "内部状态已损坏")? = None;
    Ok(())
}

#[tauri::command]
fn list_entries(
    state: tauri::State<VaultState>,
    query: String,
    category: Option<Category>,
) -> Result<Vec<EntryView>, String> {
    with_vault(&state, |v| Ok(v.search(&query, category).into_iter().map(view_of).collect()))
}

#[tauri::command]
fn get_entry(state: tauri::State<VaultState>, id: String) -> Result<EntryView, String> {
    let id = parse_id(&id)?;
    with_vault(&state, |v| v.get(id).map(view_of).ok_or_else(|| "找不到条目".to_string()))
}

/// 单独取一条密码的明文。前端只在用户点「显示」或「复制」时调用。
#[tauri::command]
fn reveal_password(state: tauri::State<VaultState>, id: String) -> Result<String, String> {
    let id = parse_id(&id)?;
    with_vault(&state, |v| {
        v.get(id).map(|e| e.password.expose().to_string()).ok_or_else(|| "找不到条目".to_string())
    })
}

#[tauri::command]
fn save_entry(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
    input: EntryInput,
) -> Result<String, String> {
    if input.name.trim().is_empty() || input.password.is_empty() {
        return Err("名称和密码为必填项".into());
    }
    let path = vault_path(&app)?;

    with_vault(&state, |v| {
        let id = match &input.id {
            Some(raw) => {
                let id = parse_id(raw)?;
                v.update(id, |e| {
                    e.name = input.name.clone();
                    e.username = input.username.clone();
                    e.password = Secret::new(input.password.clone());
                    e.url = input.url.clone();
                    e.notes = input.notes.clone();
                    e.category = input.category;
                })
                .map_err(|e| e.to_string())?;
                id
            }
            None => v.add(
                Entry::new(
                    input.name.clone(),
                    input.username.clone(),
                    Secret::new(input.password.clone()),
                    input.category,
                )
                .with_url(input.url.clone())
                .with_notes(input.notes.clone()),
            ),
        };
        save_and_backup(v, &path)?;
        Ok(id.to_string())
    })
}

#[tauri::command]
fn delete_entry(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
    id: String,
) -> Result<(), String> {
    let id = parse_id(&id)?;
    let path = vault_path(&app)?;
    with_vault(&state, |v| {
        v.delete(id).map_err(|e| e.to_string())?;
        save_and_backup(v, &path)
    })
}

#[tauri::command]
fn erase_all(app: tauri::AppHandle, state: tauri::State<VaultState>) -> Result<(), String> {
    let path = vault_path(&app)?;
    with_vault(&state, |v| {
        v.erase_all();
        save_and_backup(v, &path)
    })
}

#[tauri::command]
fn change_master_password(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
    new_password: String,
) -> Result<(), String> {
    let pw = Secret::new(new_password);
    if pw.expose().chars().count() < 8 {
        return Err("主口令至少 8 个字符".into());
    }
    let path = vault_path(&app)?;
    with_vault(&state, |v| {
        v.change_master_password(pw.expose()).map_err(|e| e.to_string())?;
        save_and_backup(v, &path)
    })
}

#[tauri::command]
fn generate_password(length: usize, digits: bool, symbols: bool) -> Result<String, String> {
    generator::generate(GenOptions { length, digits, symbols })
        .map(|s| s.expose().to_string())
        .map_err(|e| e.to_string())
}

/// 给新建/编辑界面的实时强度条用。
#[tauri::command]
fn assess_password(password: String, context: Vec<String>) -> StrengthView {
    let refs: Vec<&str> = context.iter().map(String::as_str).collect();
    let a = assess(&password, &refs);
    StrengthView { score: a.score, ..a.strength.into() }
}

// ── 备份 ────────────────────────────────────────────────────

/// 由 unix 秒生成 `YYYYMMDD-HHMMSSZ`。
///
/// 手写而不是引入日期库：只需要给备份文件取个人类能排序的名字，
/// 为此拉一个依赖不划算。用 UTC 并在末尾标 `Z`，避免跨时区时
/// 「昨天的备份看起来比今天的新」这种歧义。
///
/// 日期部分用的是 Howard Hinnant 的 civil-from-days 算法：把纪元平移到
/// 3 月 1 日，闰日就落在 400 年周期的末尾，于是整个换算没有分支。
fn stamp(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days as i64 + 719_468; // 纪元移到 0000-03-01
    let era = z / 146_097; // 一个 era = 400 年 = 146097 天
    let doe = z - era * 146_097; // day-of-era
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 以 3 月 1 日为起点
    let mp = (5 * doy + 2) / 153; // 月份（3 月 = 0）
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);

    format!("{y:04}{m:02}{d:02}-{h:02}{mi:02}{s:02}Z")
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Serialize)]
struct BackupPreview {
    path: String,
    count: usize,
}

const AUTO_PREFIX: &str = "lokal-auto-";

/// 自动备份的文件名：`lokal-auto-YYYYMMDD-HHZ.lokal`。
///
/// 精确到**小时**是刻意的，它同时解决了两个问题：
/// - **去抖**：同一小时内改十次只写同一个文件，不会刷屏；
/// - **时间深度**：保留 24 份就等于覆盖 24 个不同的小时，而不是
///   "最近 24 次改动"——后者可能只跨越几分钟，一点用都没有。
///
/// 名字里的时间戳是零填充的定长 UTC，所以**字典序等于时间序**，
/// 轮转时直接按文件名排序即可，不必读 mtime（mtime 会被复制、同步工具改掉）。
fn auto_backup_name(secs: u64) -> String {
    let s = stamp(secs); // YYYYMMDD-HHMMSSZ
    format!("{}{}Z.lokal", AUTO_PREFIX, &s[..11])
}

/// 写一份自动备份并把旧的轮转掉。
///
/// **绝不能因为备份失败就让保存失败**：备份盘拔了、网盘没挂上，
/// 用户也必须能继续存密码。所以调用方只记录错误，不向上传播。
fn auto_backup(vault: &Vault, dir: &std::path::Path, keep: usize) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("无法创建备份目录：{e}"))?;
    vault
        .export_to(dir.join(auto_backup_name(now_secs())))
        .map_err(|e| format!("写备份失败：{e}"))?;
    prune_auto_backups(dir, keep.max(1));
    Ok(())
}

/// 只删我们自己写的文件——前缀和扩展名都要对上。
///
/// 轮转代码是会删用户文件的代码，宁可漏删也不能误删：任何不匹配
/// `lokal-auto-*.lokal` 的东西一律不碰，读目录失败就整个放弃。
fn prune_auto_backups(dir: &std::path::Path, keep: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut ours: Vec<_> = rd
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            (name.starts_with(AUTO_PREFIX) && name.ends_with(".lokal")).then(|| (name, e.path()))
        })
        .collect();
    if ours.len() <= keep {
        return;
    }
    ours.sort_by(|a, b| a.0.cmp(&b.0)); // 定长时间戳 ⇒ 字典序即时间序
    let doomed = ours.len() - keep;
    for (_, path) in ours.into_iter().take(doomed) {
        let _ = std::fs::remove_file(path);
    }
}

/// 保存之后顺手做一次自动备份。失败只记录，不影响保存本身。
fn auto_backup_after_save(vault: &Vault) -> Option<String> {
    let s = vault.settings();
    let dir = s.auto_backup_dir.as_ref()?;
    auto_backup(vault, std::path::Path::new(dir), s.auto_backup_keep).err()
}

/// 列出目录里我们自己的自动备份，按文件名（= 时间）升序。
fn list_auto_backups(dir: &std::path::Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut v: Vec<String> = rd
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(AUTO_PREFIX) && n.ends_with(".lokal"))
        .collect();
    v.sort();
    v
}

/// 开启自动备份：选一个目录，存进设置，并**立刻**先备份一份。
///
/// 立刻备份是有意的：如果等到下次改动才写第一份，用户点完开关看到
/// 目录里空空如也，无从判断到底配好没有。
#[tauri::command]
async fn set_auto_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<String, String> {
    use tauri_plugin_dialog::DialogExt;

    let picked = app
        .dialog()
        .file()
        .set_title("选择自动备份目录（建议选网盘或移动硬盘上的文件夹）")
        .blocking_pick_folder();

    let Some(fp) = picked else {
        return Err("已取消".into());
    };
    let dir = fp.into_path().map_err(|e| format!("路径无效：{e}"))?;
    let path = vault_path(&app)?;

    with_vault(&state, |v| {
        v.settings_mut().auto_backup_dir = Some(dir.display().to_string());
        v.save_to(&path).map_err(|e| e.to_string())?;
        auto_backup(v, &dir, v.settings().auto_backup_keep)
    })?;
    Ok(dir.display().to_string())
}

/// 关闭自动备份。**不删已有的备份文件**——那是用户的数据，不是我们的缓存。
#[tauri::command]
fn disable_auto_backup(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
) -> Result<(), String> {
    let path = vault_path(&app)?;
    with_vault(&state, |v| {
        v.settings_mut().auto_backup_dir = None;
        v.save_to(&path).map_err(|e| e.to_string())
    })?;
    if let Ok(mut slot) = LAST_BACKUP_ERROR.lock() {
        *slot = None;
    }
    Ok(())
}

/// 导出一份加密备份。弹原生保存对话框，用户选位置。
///
/// 备份就是完整的保险库文件：自包含、已加密、用**当前**主口令打开。
/// 放网盘或 U 盘都不泄露内容——安全性等同于主口令本身。
///
/// **必须是 `async fn`。** Tauri 的同步命令跑在主线程上，而
/// `blocking_save_file` 需要主线程去泵事件循环才能弹出对话框——
/// 在主线程上调用它会直接死锁（进程停在 futex 等待，对话框永远不出现）。
/// 异步命令跑在 async runtime 的线程上，才是安全的。
#[tauri::command]
async fn export_backup(
    app: tauri::AppHandle,
    state: tauri::State<'_, VaultState>,
) -> Result<String, String> {
    use tauri_plugin_dialog::DialogExt;

    let name = format!("lokal-backup-{}.lokal", stamp(now_secs()));
    let picked = app
        .dialog()
        .file()
        .set_title("导出加密备份")
        .set_file_name(&name)
        .add_filter("Lokal 备份", &["lokal"])
        .blocking_save_file();

    let Some(fp) = picked else {
        return Err("已取消".into());
    };
    let dest = fp.into_path().map_err(|e| format!("路径无效：{e}"))?;

    with_vault(&state, |v| {
        // export_to 而非 save_to：后者会把保险库改指向备份文件。
        v.export_to(&dest).map_err(|e| e.to_string())
    })?;
    Ok(dest.display().to_string())
}

/// 选一个备份文件（只选，不做任何事）。同样必须 async，理由见 `export_backup`。
#[tauri::command]
async fn pick_backup_file(app: tauri::AppHandle) -> Result<String, String> {
    use tauri_plugin_dialog::DialogExt;

    let picked = app
        .dialog()
        .file()
        .set_title("选择要恢复的备份")
        .add_filter("Lokal 备份", &["lokal"])
        .blocking_pick_file();

    let Some(fp) = picked else {
        return Err("已取消".into());
    };
    Ok(fp.into_path().map_err(|e| format!("路径无效：{e}"))?.display().to_string())
}

/// 试开备份，报告里面有多少条——**不改动任何东西**。
///
/// 这一步存在的意义是让用户在覆盖之前看清楚将要换成什么。
/// 备份的主口令可能与当前保险库不同（比如导出后换过口令），所以单独要一次。
#[tauri::command]
fn preview_backup(path: String, password: String) -> Result<BackupPreview, String> {
    let pw = Secret::new(password);
    let v = Vault::open(&path, pw.expose()).map_err(|e| e.to_string())?;
    Ok(BackupPreview { path, count: v.len() })
}

/// 用备份替换当前保险库。
///
/// 顺序是这个功能里唯一要紧的东西：
/// 1. **先完整解密备份**，失败就直接返回，一个文件都不碰；
/// 2. 把现有保险库改名为 `vault.lokal.prev`，留一次反悔的机会；
/// 3. 原子写入新保险库；
/// 4. 替换内存状态。
///
/// 反过来写——先删后验——只要备份有问题就会永久毁掉用户的全部密码。
#[tauri::command]
fn import_backup(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
    path: String,
    password: String,
) -> Result<usize, String> {
    let pw = Secret::new(password);

    // 1. 验证。这一步失败，下面什么都不会发生。
    let mut restored = Vault::open(&path, pw.expose()).map_err(|e| e.to_string())?;
    let count = restored.len();

    let live = vault_path(&app)?;

    // 2~3. 换文件。抽成独立函数是为了能被测试——这几行一旦写错，
    // 后果是用户全部密码永久丢失，不能只靠"看着对"。
    install_vault(&live, &mut restored)?;

    // 4. 换掉内存里的保险库。
    *state.0.lock().map_err(|_| "内部状态已损坏")? = Some(restored);
    Ok(count)
}

/// 把 `restored` 装到 `live` 位置，旧文件留一份 `.prev` 作为反悔余地。
///
/// 失败时必须让用户回到原状，而不是两头落空：所以写入失败要把 `.prev`
/// 换回去。调用方保证 `restored` 已经完整解密过——本函数不做验证。
fn install_vault(live: &std::path::Path, restored: &mut Vault) -> Result<(), String> {
    let prev = live.with_extension("lokal.prev");

    let had_old = live.exists();
    if had_old {
        std::fs::rename(live, &prev).map_err(|e| format!("无法备份当前保险库：{e}"))?;
    }

    if let Err(e) = restored.save_to(live) {
        if had_old {
            let _ = std::fs::rename(&prev, live); // 尽力还原
        }
        return Err(format!("写入失败，已还原原保险库：{e}"));
    }
    Ok(())
}

#[tauri::command]
fn vault_stats(
    app: tauri::AppHandle,
    state: tauri::State<VaultState>,
) -> Result<VaultStats, String> {
    let size_bytes = std::fs::metadata(vault_path(&app)?).map(|m| m.len()).unwrap_or(0);
    let auto_backup_error = LAST_BACKUP_ERROR.lock().ok().and_then(|g| g.clone());
    with_vault(&state, |v| {
        let dir = v.settings().auto_backup_dir.clone();
        let names = dir.as_ref().map(|d| list_auto_backups(std::path::Path::new(d)));
        Ok(VaultStats {
            count: v.len(),
            size_bytes,
            auto_backup_dir: dir,
            auto_backup_count: names.as_ref().map_or(0, Vec::len),
            // 文件名形如 lokal-auto-YYYYMMDD-HHZ.lokal，切掉前缀和扩展名。
            auto_backup_latest: names
                .and_then(|n| n.last().cloned())
                .map(|n| n.trim_start_matches(AUTO_PREFIX).trim_end_matches(".lokal").to_string()),
            auto_backup_error,
        })
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(VaultState::default())
        .invoke_handler(tauri::generate_handler![
            vault_exists,
            is_unlocked,
            create_vault,
            unlock,
            lock,
            list_entries,
            get_entry,
            reveal_password,
            save_entry,
            delete_entry,
            erase_all,
            change_master_password,
            generate_password,
            assess_password,
            vault_stats,
            export_backup,
            pick_backup_file,
            preview_backup,
            import_backup,
            set_auto_backup,
            disable_auto_backup,
        ])
        .run(tauri::generate_context!())
        .expect("Tauri 启动失败");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_matches_known_utc_values() {
        // 期望值取自 `date -u -d @<secs> +%Y%m%d-%H%M%SZ`，不是手算的。
        for (secs, want) in [
            (0u64, "19700101-000000Z"),
            (951_782_400, "20000229-000000Z"), // 2000 年闰日：能被 400 整除,是闰年
            (1_709_164_800, "20240229-000000Z"), // 普通闰年
            (1_234_567_890, "20090213-233130Z"),
            (4_102_444_799, "20991231-235959Z"), // 2100 不是闰年,跨年边界
            (1_753_800_000, "20250729-144000Z"),
        ] {
            assert_eq!(stamp(secs), want, "secs={secs}");
        }
    }

    #[test]
    fn stamp_is_lexicographically_sortable() {
        // 备份文件名靠字典序排出先后,所以这条性质必须成立。
        let a = stamp(1_700_000_000);
        let b = stamp(1_800_000_000);
        assert!(a < b, "{a} 应排在 {b} 之前");
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("lokal-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 建一个含 n 条条目的保险库，主口令固定，KDF 用最低代价（测试要快）。
    fn vault_with(n: usize, pw: &str) -> Vault {
        use lokal_core::crypto::KdfParams;
        let mut v =
            Vault::create_with_params(pw, KdfParams { m_cost: 8, t_cost: 1, p_cost: 1 }).unwrap();
        for i in 0..n {
            v.add(Entry::new(format!("Site{i}"), "u", "p", Category::Other));
        }
        v
    }

    #[test]
    fn install_keeps_the_old_vault_as_prev() {
        // 用户依赖的反悔路径：恢复错了备份，旧库还能从 .prev 找回来。
        let dir = tmpdir("install");
        let live = dir.join("vault.lokal");
        let prev = dir.join("vault.lokal.prev");

        vault_with(3, "old-master-pw").save_to(&live).unwrap();
        let mut incoming = vault_with(1, "backup-master-pw");
        install_vault(&live, &mut incoming).unwrap();

        // 新的装上了。
        assert_eq!(Vault::open(&live, "backup-master-pw").unwrap().len(), 1);
        // 旧的还在 .prev 里，而且仍认旧口令。
        assert!(prev.exists(), ".prev 必须存在,否则用户无法反悔");
        assert_eq!(Vault::open(&prev, "old-master-pw").unwrap().len(), 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn install_rolls_back_when_the_write_fails() {
        // 故障注入：在临时文件的路径上先建一个**目录**，让 save_to 的
        // File::create 必然失败。此时旧保险库必须被换回原位——
        // 否则用户既没拿到备份，又丢了原来的全部密码。
        let dir = tmpdir("rollback");
        let live = dir.join("vault.lokal");
        vault_with(3, "old-master-pw").save_to(&live).unwrap();

        std::fs::create_dir_all(live.with_extension("lokal.tmp")).unwrap();

        let mut incoming = vault_with(1, "backup-master-pw");
        let err = install_vault(&live, &mut incoming).unwrap_err();
        assert!(err.contains("已还原"), "错误信息应说明已还原：{err}");

        // 原库必须完好无损地回到原位。
        assert!(live.exists(), "原保险库必须被还原");
        assert_eq!(Vault::open(&live, "old-master-pw").unwrap().len(), 3);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn full_backup_cycle_restores_exactly() {
        // 端到端：导出 → 改动 → 恢复，必须精确回到导出那一刻。
        let dir = tmpdir("cycle");
        let live = dir.join("vault.lokal");
        let backup = dir.join("backup.lokal");
        let pw = "cycle-master-pw";

        let mut v = vault_with(2, pw);
        v.save_to(&live).unwrap();
        v.export_to(&backup).unwrap(); // 备份此刻：2 条

        // 之后又加了 3 条,现在是 5 条。
        for i in 0..3 {
            v.add(Entry::new(format!("Later{i}"), "u", "p", Category::Work));
        }
        v.save().unwrap();
        assert_eq!(Vault::open(&live, pw).unwrap().len(), 5);

        // 从备份恢复 → 回到 2 条。
        let mut restored = Vault::open(&backup, pw).unwrap();
        install_vault(&live, &mut restored).unwrap();

        let after = Vault::open(&live, pw).unwrap();
        assert_eq!(after.len(), 2, "应精确回到导出那一刻");
        assert!(after.entries().iter().all(|e| e.name.starts_with("Site")), "不该残留后加的条目");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn entry_view_never_carries_a_password() {
        // 这一层的核心安全约定：下发给前端的对象里不能有密码。
        // 用序列化后的 JSON 直接检查,而不是靠「我记得没写那个字段」。
        let e = Entry::new("Site", "user@example.com", "s3cr3t-unique-token", Category::Work);
        let json = serde_json::to_string(&view_of(&e)).unwrap();

        assert!(!json.contains("s3cr3t-unique-token"), "密码泄漏进了 EntryView：{json}");
        assert!(!json.contains("password"), "EntryView 不应有 password 字段：{json}");
        assert!(json.contains("Site") && json.contains("strength"));
    }

    // ── 自动备份 ──────────────────────────────────────────────

    #[test]
    fn auto_backup_name_is_hourly_and_sorts_by_time() {
        let h = 3600;
        let a = auto_backup_name(1_753_800_000); // 2025-07-29 14:40Z
        let b = auto_backup_name(1_753_800_000 + 600); // 同一小时,+10 分钟
        let c = auto_backup_name(1_753_800_000 + h); // 下一小时

        assert_eq!(a, b, "同一小时内必须是同一个文件名——这就是去抖机制");
        assert_ne!(a, c, "跨小时必须换文件,否则没有时间深度");
        assert!(a < c, "字典序必须等于时间序：{a} vs {c}");
        assert_eq!(a, "lokal-auto-20250729-14Z.lokal");
    }

    #[test]
    fn prune_keeps_the_newest_and_never_touches_other_files() {
        let dir = tmpdir("prune");

        // 我们的备份：10 份,跨 10 个小时。
        for h in 0..10u32 {
            std::fs::write(dir.join(format!("lokal-auto-20260729-{h:02}Z.lokal")), b"x").unwrap();
        }
        // 目录里别人的东西——一个都不许动。
        let bystanders = [
            "vault.lokal",                         // 手动备份
            "lokal-backup-20260729-000000Z.lokal", // 手动导出,不是 auto 前缀
            "lokal-auto-notes.txt",                // 前缀像但扩展名不对
            "important.txt",
        ];
        for f in bystanders {
            std::fs::write(dir.join(f), b"keep me").unwrap();
        }

        prune_auto_backups(&dir, 3);

        let left = list_auto_backups(&dir);
        assert_eq!(left.len(), 3, "应只保留 3 份");
        assert_eq!(
            left,
            vec![
                "lokal-auto-20260729-07Z.lokal".to_string(),
                "lokal-auto-20260729-08Z.lokal".to_string(),
                "lokal-auto-20260729-09Z.lokal".to_string(),
            ],
            "保留的必须是最新的三份"
        );
        for f in bystanders {
            assert!(dir.join(f).exists(), "误删了不属于我们的文件：{f}");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prune_is_a_noop_when_under_the_limit() {
        let dir = tmpdir("prune-noop");
        for h in 0..3u32 {
            std::fs::write(dir.join(format!("lokal-auto-20260729-{h:02}Z.lokal")), b"x").unwrap();
        }
        prune_auto_backups(&dir, 24);
        assert_eq!(list_auto_backups(&dir).len(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn auto_backup_writes_a_readable_vault() {
        let dir = tmpdir("autobk");
        let v = vault_with(2, "auto-master-pw");

        auto_backup(&v, &dir, 24).unwrap();

        let names = list_auto_backups(&dir);
        assert_eq!(names.len(), 1);
        let back = Vault::open(dir.join(&names[0]), "auto-master-pw").unwrap();
        assert_eq!(back.len(), 2, "自动备份必须是能真正打开的完整保险库");

        // 同一小时再备份一次：覆盖，不新增。
        auto_backup(&v, &dir, 24).unwrap();
        assert_eq!(list_auto_backups(&dir).len(), 1, "同一小时应覆盖而非累积");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn erasing_everything_does_not_destroy_older_backups() {
        // 这是「自动备份必须保留多份」的全部理由：
        // 误删全部条目后,上一小时那份完好的备份必须还在。
        let dir = tmpdir("erase");
        let mut v = vault_with(5, "erase-master-pw");

        // 假装上一小时已经备份过一份好的。
        v.export_to(dir.join("lokal-auto-20260728-10Z.lokal")).unwrap();

        v.erase_all();
        auto_backup(&v, &dir, 24).unwrap(); // 本小时备份了空库

        let names = list_auto_backups(&dir);
        assert_eq!(names.len(), 2, "旧备份必须还在");
        let old =
            Vault::open(dir.join("lokal-auto-20260728-10Z.lokal"), "erase-master-pw").unwrap();
        assert_eq!(old.len(), 5, "旧备份里的 5 条必须完好");

        std::fs::remove_dir_all(&dir).ok();
    }
}
