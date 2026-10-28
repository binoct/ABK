#!/usr/bin/env python3
"""让 SUSFS 补丁所需的 KSU 侧符号真正存在，避免链接期 undefined symbol。

背景（根因）
------------
simonpunk 的 `50_add_susfs_in_gki-*.patch` 直接在**内核侧**调用 KSU 实现的
selinux_hide / preinit 助手：

    security/selinux/selinuxfs.c : my_write_context() / my_write_access()
    security/selinux/hooks.c     : my_setprocattr()
    fs/exec.c                    : ksu_setup_preinit_file() /
                                   ksu_preinit_handle_post_execveat()   (受 KSU_NO_PREINIT 控制)

BakaSU 9dbce02（2026-10-05，当前 pin 的 Dev/Stable 提交）有两个自身缺口，
两者都会让 `ld.lld` 报 undefined symbol：

1. selinux_hide 导出
   `kernel/tools/susfs_compat.mk` 只要发现 `security/selinux/hooks.c` 里有
   `ksu_selinux_hide_running` 就定义 `KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE`，
   而旧版 `feature/selinux_hide.c` 里 `my_write_context` / `my_write_access` /
   `ksu_handle_selinux_setprocattr` 全在 `#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE`
   块内 —— 宏一旦定义，这些实现整段被裁掉；旧版也根本没有 `my_setprocattr` 这个别名。
   新版 BakaSU 用 `__maybe_static` + `#define ksu_handle_selinux_setprocattr my_setprocattr`
   才让两种模式都成立。

2. preinit
   旧版没有 `kernel/preinit/`，而 SUSFS 的 fs/exec.c hunk 按 `#ifndef KSU_NO_PREINIT`
   去调用 preinit 助手。新版由
   `tools/code_generation/preinit_runner/preinit_runner.mk` 在缺少 UAPI 头时自己补
   `-DKSU_NO_PREINIT`，旧版没有这套逻辑。

修复策略
--------
按「源码能力」而不是版本号判定，三处都幂等：

  a. `tools/susfs_compat.mk`：只有 KSU 侧真的能导出（源码里出现
     `__maybe_static ssize_t my_write_context`）才让 SUSFS 接管 selinux_hide，
     否则回退到 KSU 自带实现 —— 这样 `#ifndef` 块照常编译，符号自然存在。
  b. `feature/selinux_hide.c`：把 `static ssize_t my_write_context/my_write_access`
     的 static 去掉；若该版本没有 `my_setprocattr` 别名，补一个转发到
     `ksu_handle_selinux_setprocattr()` 的全局函数。
  c. `fs/Makefile`：KSU 树没有把 `preinit/preinit.o` 接进构建时追加
     `-DKSU_NO_PREINIT`。守卫写在 fs/exec.c 里，所以开关必须落在 fs/ 上，
     KSU 目录自己的 ccflags-y 管不到。

用法
----
    fix-susfs-ksu-symbols.py <kernel-root>
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


KSU_DIR_CANDIDATES = (
    "common/drivers/kernelsu",
    "drivers/kernelsu",
    "KernelSU/kernel",
    "kernel",
)

WRITE_FUNCS = ("my_write_context", "my_write_access")

SUSFS_COMPAT_MARKER = 'grep -q "__maybe_static ssize_t my_write_context"'
SUSFS_COMPAT_OLD_LINE = (
    'ifeq ($(shell grep -q "ksu_selinux_hide_running" '
    "$(srctree)/security/selinux/hooks.c; echo $$?),0)"
)
SUSFS_COMPAT_NEW_LINE = (
    'ifeq ($(shell grep -q "ksu_selinux_hide_running" '
    "$(srctree)/security/selinux/hooks.c && "
    'grep -q "__maybe_static ssize_t my_write_context" '
    "$(KSU_SRC)/feature/selinux_hide.c; echo $$?),0)"
)
SUSFS_COMPAT_NOTE = (
    "# ABK: 只有 KSU 侧能把 my_write_context/my_write_access 导出成全局符号时，\n"
    "#      才让 SUSFS 接管 selinux_hide（新版用 __maybe_static 让两种模式共存）。\n"
    "#      旧版 BakaSU 在该宏下会整段裁掉这些实现，security/selinux/*.c 的调用\n"
    "#      就会在链接期报 undefined symbol，因此这里追加能力检查。\n"
)

MYSETPROCATTR_MARKER = "ABK: simonpunk SUSFS GKI patch 在 security/selinux/hooks.c 里调用"
MYSETPROCATTR_BLOCK = """
#ifdef CONFIG_KSU_SUSFS
/* ABK: simonpunk SUSFS GKI patch 在 security/selinux/hooks.c 里调用 my_setprocattr()，
 * 而本版 BakaSU 只提供 ksu_handle_selinux_setprocattr()，这里补一个导出别名。 */
int my_setprocattr(const char *name, void *value, size_t size)
{
    return ksu_handle_selinux_setprocattr(name, value, size);
}
#endif // #ifdef CONFIG_KSU_SUSFS
"""

NO_PREINIT_MARKER = "ABK: 该 KSU 版本没有 preinit 实现"
NO_PREINIT_BLOCK = """
# ABK: 该 KSU 版本没有 preinit 实现，而 SUSFS 的 fs/exec.c hunk 会按
#      `#ifndef KSU_NO_PREINIT` 调用 ksu_setup_preinit_file()/
#      ksu_preinit_handle_post_execveat()，符号不存在就是链接期 undefined symbol。
#      守卫写在 fs/exec.c 里，所以开关必须落在 fs/ 的 ccflags 上，
#      KSU 目录自己的 ccflags-y 影响不到它。
ccflags-y += -DKSU_NO_PREINIT
"""

# 定义形态：`ssize_t my_write_context(` 或新版 `__maybe_static ssize_t my_write_context(`
DEFINE_RE = r"(?m)^(?:__maybe_static[ \t]+)?ssize_t[ \t]+{name}[ \t]*\("
STATIC_DEFINE_RE = r"(?m)^static[ \t]+ssize_t[ \t]+{name}[ \t]*\("


class RepairError(RuntimeError):
    pass


def read_text(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def write_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def find_ksu_dirs(root: Path) -> list[Path]:
    """按候选路径找出真实存在的 KSU 源码目录（软链接去重）。"""
    found: list[Path] = []
    seen: set[Path] = set()
    for rel in KSU_DIR_CANDIDATES:
        base = root / rel
        if not base.is_dir():
            continue
        try:
            resolved = base.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        if not (base / "Kbuild").is_file() and not (base / "Makefile").is_file():
            continue
        seen.add(resolved)
        found.append(base)
    return found


def tighten_susfs_compat(ksu_dir: Path, log: list[str]) -> None:
    """只有 KSU 侧真的能导出 my_* 时才让 SUSFS 接管 selinux_hide。"""
    path = ksu_dir / "tools/susfs_compat.mk"
    if not path.is_file():
        return

    text = read_text(path)
    if SUSFS_COMPAT_MARKER in text:
        return
    if SUSFS_COMPAT_OLD_LINE not in text:
        raise RepairError(
            f"{path}: 找不到 selinux_hide 的自动探测行，susfs_compat.mk 结构已变化"
        )

    text = text.replace(
        SUSFS_COMPAT_OLD_LINE, SUSFS_COMPAT_NOTE + SUSFS_COMPAT_NEW_LINE, 1
    )
    write_text(path, text)
    log.append(f"{path}: selinux_hide 自动探测追加「KSU 侧可导出」能力检查")


def export_selinux_hide_symbols(ksu_dir: Path, log: list[str]) -> None:
    """去掉 my_write_* 的 static，并在需要时补 my_setprocattr 导出别名。"""
    path = ksu_dir / "feature/selinux_hide.c"
    if not path.is_file():
        return

    text = read_text(path)
    original = text

    for name in WRITE_FUNCS:
        text, count = re.subn(
            rf"(?m)^static[ \t]+(ssize_t[ \t]+{name}[ \t]*\()", r"\1", text
        )
        if count:
            log.append(f"{path}: 导出 {name}()（去掉 static）")

    # 新版 BakaSU 用 `__maybe_static ssize_t my_write_context(...)`，两种形态都认
    if not re.search(DEFINE_RE.format(name=WRITE_FUNCS[0]), text):
        raise RepairError(f"{path}: 找不到 {WRITE_FUNCS[0]} 的定义")

    provides_alias = (
        "define ksu_handle_selinux_setprocattr my_setprocattr" in text
        or re.search(r"(?m)^(?:int|ssize_t)[^\n]*\bmy_setprocattr\s*\(", text)
        or MYSETPROCATTR_MARKER in text
    )
    if not provides_alias:
        if not re.search(
            r"(?m)^(?:int|ssize_t)[^\n]*\bksu_handle_selinux_setprocattr\s*\(", text
        ):
            raise RepairError(
                f"{path}: 既没有 my_setprocattr 别名，也没有 "
                "ksu_handle_selinux_setprocattr 实现，无法补导出别名"
            )
        text = text.rstrip("\n") + "\n" + MYSETPROCATTR_BLOCK
        log.append(
            f"{path}: 补 my_setprocattr() 导出别名（转发 ksu_handle_selinux_setprocattr）"
        )

    if text != original:
        write_text(path, text)

    final = read_text(path)
    for name in WRITE_FUNCS:
        if re.search(STATIC_DEFINE_RE.format(name=name), final):
            raise RepairError(f"{path}: {name}() 仍是 static，SUSFS 侧仍会链接失败")
        if not re.search(DEFINE_RE.format(name=name), final):
            raise RepairError(f"{path}: 找不到全局 {name}() 定义")


def ensure_no_preinit_flag(
    kernel_root: Path, ksu_dirs: list[Path], log: list[str]
) -> None:
    """KSU 树没有把 preinit 接进构建时，在 fs/ 上显式关掉 SUSFS 的 preinit 调用。"""
    build_files: list[Path] = []
    for ksu_dir in ksu_dirs:
        for path in (ksu_dir / "Kbuild", ksu_dir / "Makefile"):
            if path.is_file():
                build_files.append(path)
        tools_dir = ksu_dir / "tools"
        if tools_dir.is_dir():
            build_files.extend(sorted(tools_dir.rglob("*.mk")))

    if any("preinit/preinit.o" in read_text(path) for path in build_files):
        # KSU 侧真的会编译 preinit，保留 SUSFS 的 preinit 调用
        return

    fs_makefile = kernel_root / "common/fs/Makefile"
    if not fs_makefile.is_file():
        fs_makefile = kernel_root / "fs/Makefile"
    if not fs_makefile.is_file():
        raise RepairError(f"{kernel_root} 下找不到 fs/Makefile，无法关闭 SUSFS preinit 调用")

    text = read_text(fs_makefile)
    if NO_PREINIT_MARKER in text or "KSU_NO_PREINIT" in text:
        return

    write_text(fs_makefile, text.rstrip("\n") + "\n" + NO_PREINIT_BLOCK)
    log.append(f"{fs_makefile}: 追加 -DKSU_NO_PREINIT（KSU 树没有 preinit 实现）")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: fix-susfs-ksu-symbols.py <kernel-root>", file=sys.stderr)
        return 2

    root = Path(argv[1]).resolve()
    ksu_dirs = find_ksu_dirs(root)
    if not ksu_dirs:
        print(
            f"::warning::{root} 下找不到 KSU 源码目录，跳过 SUSFS 符号修复",
            file=sys.stderr,
        )
        return 0

    log: list[str] = []
    try:
        for ksu_dir in ksu_dirs:
            tighten_susfs_compat(ksu_dir, log)
            export_selinux_hide_symbols(ksu_dir, log)
        ensure_no_preinit_flag(root, ksu_dirs, log)
    except RepairError as error:
        print(f"::error::SUSFS↔KSU 符号修复失败: {error}", file=sys.stderr)
        return 1

    if log:
        print("SUSFS↔KSU 符号修复：")
        for line in log:
            print(f"  {line}")
    else:
        print("SUSFS↔KSU 符号无需修复。")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
