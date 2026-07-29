# Lokal

> ## ⚠️ 这是学习项目，**没有经过任何安全审计**
>
> **不要把真实密码放进去。**
>
> 加密方案是认真设计的（Argon2id + XChaCha20-Poly1305，理由见下文），也有 51 个测试覆盖，
> 但「认真写的密码学」和「被人认真攻击过的密码学」是两回事。真正能托付密码的工具，
> 差别不在算法选型，而在于它被多少人试图攻破过。
>
> 需要能用的：[Bitwarden](https://bitwarden.com)、[KeePassXC](https://keepassxc.org)、1Password。
>
> 这个仓库的价值在于**它是怎么被做出来的**——每一个密码学选择都写了理由，
> 每一条安全性质都有对应的测试。拿来读、拿来学、拿来批评，都欢迎。

一个本地优先的密码管理器。无账号、无云端、不同步。

- **`crates/lokal-core`** — 安全核心：加密、存储、密码生成、强度评估。纯 Rust，不依赖 GUI，可独立测试。
- **`src-tauri`** — Tauri 外壳：把核心暴露给界面的命令层，密码默认不下发到前端。
- **`ui`** — 界面：Nocturne 设计系统的七屏，纯 HTML/CSS/JS，无构建步骤。

设计稿来自 Claude Design 的 Nocturne 主题原型（7 屏：引导 → 创建 PIN → 解锁 → 密码库 → 详情 → 编辑 → 设置）。

---

## 当前状态

| 部分 | 状态 |
|---|---|
| 加密核心（Argon2id + XChaCha20-Poly1305） | ✅ 完成，39 个单元测试通过 |
| 加密备份导出 / 恢复 | ✅ 完成，导出经真实 GUI 验证 |
| 自动备份（每小时一份，轮转保留 24 份） | ✅ 完成，端到端验证 |
| 保险库文件格式 v1（原子写盘、0600 权限） | ✅ 完成 |
| 密码生成器（CSPRNG + 拒绝采样） | ✅ 完成 |
| 强度评估（zxcvbn） | ✅ 完成 |
| Tauri 外壳（15 个命令） | ✅ 完成 |
| 界面：7 屏 + 生成器 + 确认框 | ✅ 完成，端到端实机验证通过 |
| 自动锁定（5 分钟无操作） | ✅ 完成 |
| 剪贴板 30 秒自动清空 | ✅ 完成 |
| Android 打包（APK） | ✅ 完成，实测 15 MB / arm64 |
| CI（fmt / clippy / test / Android check） | ✅ 完成 |
| Release 流程（打 v* 标签 → 草稿 release） | ✅ 完成，Linux 产物 |
| PIN / 生物识别解锁 | ⬜ 未开始，需硬件托底，见「安全边界」 |
| APK 签名 | ⬜ 未开始，需 keystore |
| 浏览器自动填充 | ⬜ 未开始 |

```bash
cargo test --workspace   # 39 核心 + 11 外壳 + 1 文档测试
cargo clippy --workspace --all-targets
cargo run -p lokal       # 启动应用
cargo run --release --example kdf_bench      # 在你的硬件上重新测 KDF 耗时
cargo run --release --example verify_backup -- <备份文件>   # 校验一份备份还能不能打开
```

保险库文件位置：`~/.local/share/app.lokal.vault/vault.lokal`

## 备份怎么用

设置 →「导出备份…」，选个位置。导出的是**完整保险库**：自包含、已加密、用当前主口令打开，
所以放网盘、U 盘、邮箱附件都不泄露内容（安全性等同于你的主口令）。

两条容易踩的：

1. **换过主口令要重新导出。** 换口令只重包 VK，旧备份仍然只认旧口令——这不是 bug，
   但你得知道。测试 `backup_taken_before_password_change_still_opens_with_the_old_one` 锁住了这个行为。
2. **定期验一次备份。** 备份最坏的失败方式是沉默：文件一直在，等真要恢复那天才发现口令记错了。
   用 `verify_backup` 把"我有备份"变成"我验过备份"。

恢复走两步：先「校验备份」看清里面有多少条，确认后才「覆盖并恢复」。旧库会留一份
`vault.lokal.prev`，恢复错了可以手动换回来。

### 自动备份

设置 →「开启自动备份…」选一个目录，此后**每次改动都会自动留一份**，开启时就先写第一份。

命名 `lokal-auto-YYYYMMDD-HHZ.lokal`，**精确到小时**，这一个选择同时解决两件事：

- **去抖**：同一小时内改十次只写同一个文件，不会刷屏；
- **时间深度**：保留 24 份 = 覆盖 24 个不同的小时，而不是"最近 24 次改动"——
  后者可能只跨越几分钟，一点用都没有。

时间戳是定长 UTC，所以字典序等于时间序，轮转直接按文件名排序，不依赖 mtime
（mtime 会被复制和同步工具改掉）。

三条设计约束，都有测试锁住：

1. **必须保留多份。** 只覆盖一个文件的"自动备份"不是备份——你误删了全部条目，
   下一次备份就会用空库盖掉你唯一的副本。测试 `erasing_everything_does_not_destroy_older_backups`。
2. **轮转只删自己写的文件。** 严格匹配 `lokal-auto-*.lokal` 前缀和扩展名，其余一律不碰，
   读目录失败就整个放弃。测试 `prune_keeps_the_newest_and_never_touches_other_files`。
3. **备份失败绝不让保存失败。** 备份盘拔了、网盘没挂上，也必须能继续存密码。
   失败原因显示在设置页——一个没人知道它坏了的备份，比没有备份更危险。

**它防不住什么**：备份到同一块硬盘只能挡住"误删条目"，挡不住"硬盘挂了"。
真要防硬件故障，目录得选在网盘同步文件夹或移动硬盘上。

---

## 密钥结构

```
主口令 ──Argon2id(salt, params)──▶ KEK  (密钥加密密钥)
                                    │
         VK (32B, 来自 CSPRNG) ──被 KEK 加密──▶ wrapped_key（存进文件）
                                    │
         条目 JSON ──XChaCha20-Poly1305(VK)──▶ 密文（存进文件）
```

**为什么中间要隔一个 VK，而不是直接用口令派生的密钥加密数据？**

1. 改主口令是 O(1)：只需用新 KEK 重新包一次 32 字节的 VK，密文一个字节都不用动。
2. 多种解锁方式可以并存：将来加 PIN 或指纹，让它们各自包一份同样的 VK 即可。
3. 保存时不需要主口令：解锁后 VK 常驻内存，口令本身不必长期留在内存里。

## 文件格式 v1

```
偏移   长度   字段
0      6     magic "LOKAL1"
6      1     格式版本 = 1
7      1     KDF 标识 = 1 (argon2id)
8      4     m_cost  (u32 小端)
12     4     t_cost
16     4     p_cost
20     16    salt
├──────────── 以上 36 字节 = PREFIX，作 key-wrap 的 AAD
36     24    wrap_nonce
60     48    wrapped_key (32 密钥 + 16 标签)
108    24    data_nonce
├──────────── 以上 132 字节 = HEADER，作 数据 的 AAD
132    ...   密文 = AEAD(VK, VaultData 的 JSON)
```

整个头部都进 AAD，因此任何字节被改动都会导致解密失败——包括把 KDF 代价从
64 MiB 降到 1 KiB 来加速暴力破解（**参数降级攻击**，在不认证参数的实现里是真实可行的）。
测试 `kdf_downgrade_attack_is_detected` 锁住这一点。

## 算法选型

| 选择 | 理由 |
|---|---|
| **Argon2id** 而非 PBKDF2 | 内存硬：破解者并行就得配等量内存，压制 GPU/ASIC 成本优势。PBKDF2 只吃算力，正是 GPU 最擅长的形状 |
| **AEAD** 而非裸加密 | 没有认证标签，攻击者可以翻转密文位来篡改明文，且不可检测 |
| **XChaCha20**（192-bit nonce）而非 ChaCha20（96-bit） | nonce 每次保存随机生成；96 bit 在约 2⁶⁴ 条消息后碰撞不可忽略，而 ChaCha 系列 nonce 复用是灾难性的（两条密文异或消掉密钥流）。192 bit 让随机 nonce 彻底安全，代价每条多 12 字节 |
| **ChaCha** 而非 AES-GCM | 软件实现天然常数时间，不依赖 AES-NI；没有硬件加速时不会退化成有 cache 侧信道的查表实现 |
| **UUIDv4** 而非自增 id | 自增 id 在多设备合并时必然冲突。现在用不上同步，但换 id 类型是破坏性改动，一开始选对成本为零 |

### KDF 参数

默认 **64 MiB / t=3 / p=4**。本机实测（release）：

| 参数 | 耗时 |
|---|---|
| 32 MiB / t=2 / p=4 | 35 ms |
| **64 MiB / t=3 / p=4（默认）** | **98 ms** |
| 128 MiB / t=4 / p=4 | 291 ms |

98 ms 解锁无感。没有调更高，是因为要保证将来在手机上也能打开同一个保险库——
手机内存和主频都更紧张。参数写在文件头里，所以换设备打开时用的是**文件记录的参数**，
而不是当前程序的默认值。换硬件后可用 `cargo run --release --example kdf_bench` 重测。

---

## 安全边界

**必须清楚的三条：**

1. **静态受保护**。保险库文件在磁盘上受主口令保护。文件权限 0600，原子写盘（临时文件 → fsync → rename），断电不会留下写坏的保险库。

2. **解锁期间不受保护**。VK 和条目明文都在进程内存里。任何能读本进程内存的攻击者（同用户身份的恶意程序、root、内存转储）都能拿到。这是**所有**密码管理器的共同边界，不是本实现的缺陷。`Secret` / `Key32` 在 drop 时会用 `zeroize` 清零（volatile 写 + 编译屏障，防止 LLVM 把「写完不再读」的清零当死代码删掉），但这只缩短暴露窗口，不消除它。

3. **4 位 PIN 不能单独保护静态数据**。这是与设计稿的一处**实质性偏离**，必须说明：

   4 位 PIN 只有 10⁴ 种可能。如果保险库文件由 PIN 派生的密钥加密，攻击者只要拷走文件就能离线穷举——即使每次尝试要 100 ms，全部试完也不到 20 分钟。**任何 KDF 代价都救不了 4 位 PIN**，因为代价对防守方和攻击方是等比放大的。

   手机上的密码管理器能用 PIN，靠的不是密码学而是**硬件**：Android Keystore / Secure Enclave 把密钥锁在安全芯片里，由硬件强制限速并在 N 次失败后擦除。攻击者拿不到可离线穷举的材料。

   所以本实现的安全边界是**主口令**。PIN 将来会作为*会话内快速解锁*加入（第二个 wrap slot），且仅在有硬件托底的平台上启用。文件格式已为此预留——加 slot 不需要改动数据密文。

**还有一条使用建议**：在这个项目被真正审计之前，别把真实密码放进去。用它学工程，用假数据。

---

## 开发

### 桌面（Ubuntu / Debian）

```bash
sudo apt install -y libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev
cargo install tauri-cli --version "^2.0"
cargo run -p lokal
```

工具链版本由 `rust-toolchain.toml` 钉死，本地和 CI 用的是同一个。

### Android

`lokal-core` 一行不用改就能跑在 Android 上——安全核心不依赖 GUI 的分层在这里兑现了。

前置（Ubuntu）：

```bash
sudo apt install -y openjdk-21-jdk
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
```

再装 Android SDK（[命令行工具](https://developer.android.com/studio#command-line-tools-only)解压到
`~/Android/sdk/cmdline-tools/latest`），然后：

```bash
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;28.2.13676358"
```

构建：

```bash
export ANDROID_HOME=~/Android/sdk
export NDK_HOME=$ANDROID_HOME/ndk/28.2.13676358
cargo tauri android init      # 只需一次
cargo tauri android build --apk --target aarch64
```

产物在 `src-tauri/gen/android/app/build/outputs/apk/`，实测 15 MB，
包名 `app.lokal.vault`，minSdk 24 / targetSdk 36。

**Android 上的差异**：自动备份不可用。dialog 插件的 `pick_folder` 是 `#[cfg(desktop)]` 的，
Android 拿不到任意目录的持久写权限（需要 Storage Access Framework 的 persistable URI 授权）。
这里选择明确报错，而不是退而求其次写进应用私有目录——那个目录随卸载消失、又和保险库同在一块存储上，
挡不住任何一种真实的数据丢失。**一个让人以为自己有备份、实际什么都没保护的功能，比没有这个功能更糟。**
手动「导出备份…」在 Android 上是可用的。

**APK 未签名**，装不上真机。要发布得先建 keystore 并配 `key.properties`
（已在 `.gitignore` 里）——目前 release 流程只出 Linux 产物。

## 路线图

- **APK 签名** — 建 keystore、配 `key.properties`，release 流程才能出可安装的 Android 产物
- **PIN / 生物识别解锁** — 第二个 wrap slot，仅在有硬件限速托底的平台上启用（见「安全边界」第 3 条）
- **浏览器自动填充** — 扩展 + 本地通信协议。用起来最舒服，但会显著扩大攻击面，值得单独做一轮安全设计
- **Android 上的自动备份** — 需要 Storage Access Framework 的 persistable URI 授权
