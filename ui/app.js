// Lokal 界面逻辑。
//
// 两条贯穿全文件的安全约定：
//
// 1. **一律用 textContent，绝不用 innerHTML。** 条目名称、用户名、备注都是
//    用户可控内容。用 innerHTML 拼接等于给自己开一个 XSS 口子——而在密码
//    管理器里，一次 XSS 就能把整个已解锁的库读走。CSP 里也禁掉了 inline
//    script，两道防线。
//
// 2. **密码不留在 JS 里。** 列表和详情从后端拿到的对象没有密码字段；
//    只有用户点「显示」或「复制」时才单独取一次，用完即清。

const { invoke } = window.__TAURI__.core;

const CAT_LABEL = {
  Social: '社交', Banking: '银行', Work: '工作', Shopping: '购物', Other: '其他',
};
const CATS = Object.keys(CAT_LABEL);
const CLIPBOARD_CLEAR_MS = 30_000;
const AUTO_LOCK_MS = 5 * 60_000;

const $ = (id) => document.getElementById(id);
const SCREENS = ['s-onboard', 's-setup', 's-unlock', 's-vault', 's-detail', 's-edit', 's-settings'];

const state = {
  entries: [],
  query: '',
  category: null,      // null = 全部
  selectedId: null,
  editingId: null,
  editCategory: 'Social',
  revealed: false,
  genOpts: { length: 20, digits: true, symbols: true },
  genValue: '',
};

let clipboardTimer = null;
let autoLockTimer = null;
let restorePath = null;

// ── 基础 ────────────────────────────────────────────────────

function show(id) {
  SCREENS.forEach((s) => $(s).classList.toggle('hidden', s !== id));
}

let toastTimer = null;
function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 2200);
}

function setMeter(barEl, labelEl, strength) {
  const level = strength ? strength.level : 'weak';
  const pct = strength ? strength.percent : 0;
  barEl.className = 'meter-fill s-' + level;
  barEl.style.width = strength && strength.percent ? pct + '%' : '0';
  labelEl.className = 'meter-label t-' + level;
  labelEl.textContent = strength && strength.percent
    ? { weak: '弱', fair: '中', strong: '强' }[level]
    : '';
}

/** 后端错误统一走这里，避免把 Rust 的 Debug 串直接甩给用户。 */
function fail(el, e) {
  const msg = typeof e === 'string' ? e : (e && e.message) || '操作失败';
  if (el) el.textContent = msg;
  else toast(msg);
}

// ── 自动锁定 ────────────────────────────────────────────────

function touchActivity() {
  clearTimeout(autoLockTimer);
  autoLockTimer = setTimeout(doLock, AUTO_LOCK_MS);
}

async function doLock() {
  clearTimeout(autoLockTimer);
  await invoke('lock').catch(() => {});
  state.entries = [];
  state.selectedId = null;
  state.revealed = false;
  $('unlock-pw').value = '';
  $('unlock-err').textContent = '';
  show('s-unlock');
  $('unlock-pw').focus();
}

// ── 启动 ────────────────────────────────────────────────────

async function boot() {
  wireUp();
  renderChips();
  renderCatPicks();
  const exists = await invoke('vault_exists').catch(() => false);
  if (exists) {
    show('s-unlock');
    $('unlock-pw').focus();
  } else {
    show('s-onboard');
  }
}

// ── 密码库列表 ──────────────────────────────────────────────

async function refreshList() {
  try {
    state.entries = await invoke('list_entries', {
      query: state.query,
      category: state.category,
    });
  } catch (e) {
    fail(null, e);
    return;
  }

  const list = $('entry-list');
  list.replaceChildren();

  for (const e of state.entries) {
    const btn = document.createElement('button');
    btn.className = 'item';
    btn.addEventListener('click', () => openDetail(e.id));

    const av = document.createElement('div');
    av.className = 'avatar';
    av.textContent = e.initial;

    const mid = document.createElement('div');
    mid.className = 'grow';
    const n = document.createElement('div');
    n.className = 'item-name';
    n.textContent = e.name;                    // textContent，不是 innerHTML
    const u = document.createElement('div');
    u.className = 'item-user';
    u.textContent = e.username || '—';
    mid.append(n, u);

    const dot = document.createElement('div');
    dot.className = 'dot s-' + e.strength.level;
    dot.title = '密码强度：' + { weak: '弱', fair: '中', strong: '强' }[e.strength.level];

    btn.append(av, mid, dot);
    list.append(btn);
  }

  $('empty-msg').classList.toggle('hidden', state.entries.length > 0);
  $('vault-count').textContent = `${state.entries.length} 个密码 · 仅保存在本机`;
}

function renderChips() {
  const wrap = $('chips');
  wrap.replaceChildren();
  const mk = (label, value) => {
    const b = document.createElement('button');
    b.className = 'chip' + (state.category === value ? ' on' : '');
    b.textContent = label;
    b.addEventListener('click', () => {
      state.category = value;
      renderChips();
      refreshList();
    });
    return b;
  };
  wrap.append(mk('全部', null));
  CATS.forEach((c) => wrap.append(mk(CAT_LABEL[c], c)));
}

function renderCatPicks() {
  const wrap = $('cat-picks');
  wrap.replaceChildren();
  CATS.forEach((c) => {
    const b = document.createElement('button');
    b.className = 'chip' + (state.editCategory === c ? ' on' : '');
    b.textContent = CAT_LABEL[c];
    b.addEventListener('click', () => {
      state.editCategory = c;
      renderCatPicks();
    });
    wrap.append(b);
  });
}

// ── 详情 ────────────────────────────────────────────────────

async function openDetail(id) {
  let e;
  try {
    e = await invoke('get_entry', { id });
  } catch (err) {
    return fail(null, err);
  }
  state.selectedId = id;
  state.revealed = false;

  $('d-initial').textContent = e.initial;
  $('d-name').textContent = e.name;
  $('d-cat').textContent = CAT_LABEL[e.category] || e.category;
  $('d-user').textContent = e.username || '—';
  $('d-url').textContent = e.url || '—';
  $('d-pw').textContent = '••••••••••••';
  $('btn-reveal').textContent = '显示';
  setMeter($('d-bar'), $('d-str'), e.strength);

  const hasNotes = !!(e.notes && e.notes.trim());
  $('d-notes-wrap').classList.toggle('hidden', !hasNotes);
  if (hasNotes) $('d-notes').textContent = e.notes;

  show('s-detail');
}

async function toggleReveal() {
  if (state.revealed) {
    $('d-pw').textContent = '••••••••••••';
    $('btn-reveal').textContent = '显示';
    state.revealed = false;
    return;
  }
  try {
    // 只有此刻才把明文取到前端。
    const pw = await invoke('reveal_password', { id: state.selectedId });
    $('d-pw').textContent = pw;
    $('btn-reveal').textContent = '隐藏';
    state.revealed = true;
  } catch (e) {
    fail(null, e);
  }
}

async function copyField(which) {
  const e = state.entries.find((x) => x.id === state.selectedId);
  let text, label;
  if (which === 'pw') {
    text = await invoke('reveal_password', { id: state.selectedId }).catch(() => null);
    label = '密码';
  } else if (which === 'user') {
    text = e ? e.username : $('d-user').textContent;
    label = '用户名';
  } else {
    text = e ? e.url : $('d-url').textContent;
    label = '网站';
  }
  if (!text) return toast('没有可复制的内容');

  try {
    await navigator.clipboard.writeText(text);
  } catch {
    return toast('剪贴板不可用');
  }

  if (which === 'pw') {
    // 30 秒后清空——密码留在剪贴板里，任何程序都能读走。
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => {
      navigator.clipboard.writeText('').catch(() => {});
    }, CLIPBOARD_CLEAR_MS);
    toast('密码已复制 — 30 秒后自动清除');
  } else {
    toast(label + '已复制');
  }
}

// ── 新建 / 编辑 ─────────────────────────────────────────────

async function openEdit(id) {
  state.editingId = id;
  $('edit-err').textContent = '';
  $('edit-title').textContent = id ? '编辑条目' : '新建条目';

  if (id) {
    const e = await invoke('get_entry', { id }).catch(() => null);
    if (!e) return fail(null, '找不到条目');
    $('f-name').value = e.name;
    $('f-user').value = e.username;
    $('f-url').value = e.url;
    $('f-notes').value = e.notes;
    state.editCategory = e.category;
    // 编辑时才把明文取过来填进输入框。
    $('f-pw').value = await invoke('reveal_password', { id }).catch(() => '');
  } else {
    ['f-name', 'f-user', 'f-url', 'f-notes', 'f-pw'].forEach((k) => ($(k).value = ''));
    state.editCategory = 'Social';
  }
  renderCatPicks();
  await updateEditMeter();
  show('s-edit');
}

async function updateEditMeter() {
  const pw = $('f-pw').value;
  if (!pw) return setMeter($('f-bar'), $('f-str'), null);
  const context = [$('f-name').value, $('f-user').value, $('f-url').value].filter(Boolean);
  const s = await invoke('assess_password', { password: pw, context }).catch(() => null);
  setMeter($('f-bar'), $('f-str'), s);
}

async function saveEntry() {
  const input = {
    id: state.editingId,
    name: $('f-name').value.trim(),
    username: $('f-user').value.trim(),
    password: $('f-pw').value,
    url: $('f-url').value.trim(),
    notes: $('f-notes').value,
    category: state.editCategory,
  };
  try {
    const id = await invoke('save_entry', { input });
    $('f-pw').value = '';                    // 别把明文留在 DOM 里
    await refreshList();
    toast(state.editingId ? '已保存到本地' : '已添加到密码库');
    if (state.editingId) await openDetail(id);
    else show('s-vault');
  } catch (e) {
    fail($('edit-err'), e);
  }
}

// ── 生成器 ──────────────────────────────────────────────────

async function regen() {
  try {
    state.genValue = await invoke('generate_password', {
      length: state.genOpts.length,
      digits: state.genOpts.digits,
      symbols: state.genOpts.symbols,
    });
    $('gen-out').textContent = state.genValue;
  } catch (e) {
    fail(null, e);
  }
}

function openGen() {
  $('gen-len').value = state.genOpts.length;
  $('gen-len-val').textContent = state.genOpts.length;
  $('gen-num').classList.toggle('on', state.genOpts.digits);
  $('gen-sym').classList.toggle('on', state.genOpts.symbols);
  $('gen-modal').classList.remove('hidden');
  regen();
}

// ── 确认对话框 ──────────────────────────────────────────────

let confirmResolve = null;
function confirmAction(title, msg) {
  $('confirm-title').textContent = title;
  $('confirm-msg').textContent = msg;
  $('confirm-modal').classList.remove('hidden');
  return new Promise((res) => (confirmResolve = res));
}
function closeConfirm(v) {
  $('confirm-modal').classList.add('hidden');
  if (confirmResolve) confirmResolve(v);
  confirmResolve = null;
}

// ── 设置 ────────────────────────────────────────────────────

async function openSettings() {
  const s = await invoke('vault_stats').catch(() => null);
  if (s) {
    $('st-count').textContent = `${s.count} 条`;
    $('st-size').textContent = `${(s.size_bytes / 1024).toFixed(1)} KiB`;
    renderAutoBackup(s);
  }
  $('set-newpw').value = '';
  show('s-settings');
}

function renderAutoBackup(s) {
  const on = !!s.auto_backup_dir;
  $('btn-auto-on').classList.toggle('hidden', on);
  $('btn-auto-off').classList.toggle('hidden', !on);
  $('auto-dir').classList.toggle('hidden', !on);

  if (on) {
    $('auto-dir').textContent = s.auto_backup_dir;
    const latest = s.auto_backup_latest ? `最新 ${s.auto_backup_latest}（UTC）` : '尚未写入';
    $('auto-status').textContent = `已开启 · 现有 ${s.auto_backup_count} 份 · ${latest}`;
  } else {
    $('auto-status').textContent =
      '未开启。开启后每次改动都会自动留一份：每小时一份、最多 24 份，所以误删条目后还能从上一小时的备份找回。';
  }

  // 备份坏了必须让人看见——沉默失败的备份比没有备份更危险。
  $('auto-error').textContent = s.auto_backup_error
    ? `上次自动备份失败：${s.auto_backup_error}`
    : '';
}

// ── 事件绑定 ────────────────────────────────────────────────

function wireUp() {
  // 引导 → 创建
  $('btn-start').addEventListener('click', () => {
    show('s-setup');
    $('setup-pw').focus();
  });

  $('setup-pw').addEventListener('input', async () => {
    const pw = $('setup-pw').value;
    if (!pw) return setMeter($('setup-bar'), $('setup-lbl'), null);
    const s = await invoke('assess_password', { password: pw, context: [] }).catch(() => null);
    setMeter($('setup-bar'), $('setup-lbl'), s);
  });

  $('btn-create').addEventListener('click', async () => {
    const pw = $('setup-pw').value;
    const pw2 = $('setup-pw2').value;
    $('setup-err').textContent = '';
    if (pw !== pw2) return fail($('setup-err'), '两次输入不一致');
    try {
      await invoke('create_vault', { masterPassword: pw });
      $('setup-pw').value = '';
      $('setup-pw2').value = '';
      await refreshList();
      touchActivity();
      show('s-vault');
      toast('密码库已创建 — 已保存到本机');
    } catch (e) {
      fail($('setup-err'), e);
    }
  });

  // 解锁
  $('unlock-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    $('unlock-err').textContent = '';
    try {
      await invoke('unlock', { masterPassword: $('unlock-pw').value });
      $('unlock-pw').value = '';
      await refreshList();
      touchActivity();
      show('s-vault');
    } catch (e) {
      fail($('unlock-err'), e);
    }
  });

  // 密码库
  $('btn-lock').addEventListener('click', doLock);
  $('btn-settings').addEventListener('click', openSettings);
  $('btn-add').addEventListener('click', () => openEdit(null));
  $('search').addEventListener('input', (ev) => {
    state.query = ev.target.value;
    refreshList();
  });

  // 详情
  $('btn-back-detail').addEventListener('click', () => show('s-vault'));
  $('btn-reveal').addEventListener('click', toggleReveal);
  $('btn-edit').addEventListener('click', () => openEdit(state.selectedId));
  $('btn-delete').addEventListener('click', async () => {
    const name = $('d-name').textContent;
    if (!(await confirmAction('删除条目', `确定删除「${name}」？此操作不可撤销。`))) return;
    try {
      await invoke('delete_entry', { id: state.selectedId });
      await refreshList();
      show('s-vault');
      toast('已从本机删除');
    } catch (e) {
      fail(null, e);
    }
  });
  document.querySelectorAll('[data-copy]').forEach((b) =>
    b.addEventListener('click', () => copyField(b.dataset.copy)),
  );

  // 编辑
  $('btn-back-edit').addEventListener('click', () => {
    $('f-pw').value = '';
    show(state.editingId ? 's-detail' : 's-vault');
  });
  $('btn-save').addEventListener('click', saveEntry);
  ['f-pw', 'f-name', 'f-user', 'f-url'].forEach((k) =>
    $(k).addEventListener('input', updateEditMeter),
  );
  $('btn-gen').addEventListener('click', openGen);

  // 生成器
  $('gen-len').addEventListener('input', (ev) => {
    state.genOpts.length = +ev.target.value;
    $('gen-len-val').textContent = ev.target.value;
    regen();
  });
  $('gen-num').addEventListener('click', () => {
    state.genOpts.digits = !state.genOpts.digits;
    $('gen-num').classList.toggle('on', state.genOpts.digits);
    regen();
  });
  $('gen-sym').addEventListener('click', () => {
    state.genOpts.symbols = !state.genOpts.symbols;
    $('gen-sym').classList.toggle('on', state.genOpts.symbols);
    regen();
  });
  $('gen-again').addEventListener('click', regen);
  $('gen-cancel').addEventListener('click', () => $('gen-modal').classList.add('hidden'));
  $('gen-use').addEventListener('click', () => {
    $('f-pw').value = state.genValue;
    state.genValue = '';
    $('gen-modal').classList.add('hidden');
    updateEditMeter();
  });

  // 设置
  $('btn-back-settings').addEventListener('click', () => show('s-vault'));
  $('btn-chpw').addEventListener('click', async () => {
    const pw = $('set-newpw').value;
    try {
      await invoke('change_master_password', { newPassword: pw });
      $('set-newpw').value = '';
      toast('主口令已更换');
    } catch (e) {
      fail(null, e);
    }
  });
  // 备份：导出
  $('btn-export').addEventListener('click', async () => {
    try {
      const path = await invoke('export_backup');
      toast('备份已导出：' + path.split('/').pop());
    } catch (e) {
      if (e !== '已取消') fail(null, e);
    }
  });

  // 自动备份
  $('btn-auto-on').addEventListener('click', async () => {
    try {
      await invoke('set_auto_backup');
      await openSettings();
      toast('自动备份已开启，并已写入第一份');
    } catch (e) {
      if (e !== '已取消') fail(null, e);
    }
  });

  $('btn-auto-off').addEventListener('click', async () => {
    if (!(await confirmAction('关闭自动备份', '已经备份好的文件不会被删除，只是不再新增。确定？'))) {
      return;
    }
    try {
      await invoke('disable_auto_backup');
      await openSettings();
      toast('自动备份已关闭');
    } catch (e) {
      fail(null, e);
    }
  });

  // 备份：恢复（两步——先校验看清内容，再决定是否覆盖）
  $('btn-import').addEventListener('click', async () => {
    let path;
    try {
      path = await invoke('pick_backup_file');
    } catch (e) {
      if (e !== '已取消') fail(null, e);
      return;
    }
    restorePath = path;
    $('restore-path').textContent = path;
    $('restore-pw').value = '';
    $('restore-err').textContent = '';
    $('restore-summary').classList.add('hidden');
    $('restore-check').classList.remove('hidden');
    $('restore-confirm').classList.add('hidden');
    $('restore-modal').classList.remove('hidden');
    $('restore-pw').focus();
  });

  $('restore-check').addEventListener('click', async () => {
    $('restore-err').textContent = '';
    try {
      const p = await invoke('preview_backup', {
        path: restorePath,
        password: $('restore-pw').value,
      });
      const cur = await invoke('vault_stats').catch(() => ({ count: '?' }));
      $('restore-summary').textContent =
        `这份备份含 ${p.count} 条；当前保险库有 ${cur.count} 条。恢复后当前内容会被完全替换（旧库会另存为 vault.lokal.prev，可手动找回）。`;
      $('restore-summary').classList.remove('hidden');
      $('restore-check').classList.add('hidden');
      $('restore-confirm').classList.remove('hidden');
    } catch (e) {
      fail($('restore-err'), e);
    }
  });

  $('restore-confirm').addEventListener('click', async () => {
    try {
      const n = await invoke('import_backup', {
        path: restorePath,
        password: $('restore-pw').value,
      });
      $('restore-pw').value = '';
      $('restore-modal').classList.add('hidden');
      state.query = '';
      $('search').value = '';
      await refreshList();
      await openSettings();
      toast(`已恢复 ${n} 条`);
    } catch (e) {
      fail($('restore-err'), e);
    }
  });

  $('restore-cancel').addEventListener('click', () => {
    $('restore-pw').value = '';
    $('restore-modal').classList.add('hidden');
  });

  $('btn-erase').addEventListener('click', async () => {
    if (!(await confirmAction('清除所有数据', '将永久删除本机上的全部条目，无法撤销。确定？'))) return;
    try {
      await invoke('erase_all');
      await refreshList();
      await openSettings();
      toast('所有条目已清除');
    } catch (e) {
      fail(null, e);
    }
  });

  // 确认框
  $('confirm-yes').addEventListener('click', () => closeConfirm(true));
  $('confirm-no').addEventListener('click', () => closeConfirm(false));

  // 活动即重置自动锁定计时
  ['click', 'keydown', 'input'].forEach((ev) =>
    document.addEventListener(ev, touchActivity, { passive: true }),
  );

  // Esc 关闭弹层
  document.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Escape') return;
    if (!$('gen-modal').classList.contains('hidden')) $('gen-modal').classList.add('hidden');
    else if (!$('restore-modal').classList.contains('hidden')) {
      $('restore-pw').value = '';
      $('restore-modal').classList.add('hidden');
    } else if (!$('confirm-modal').classList.contains('hidden')) closeConfirm(false);
  });
}

boot();
