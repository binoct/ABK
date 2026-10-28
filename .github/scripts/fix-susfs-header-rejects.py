#!/usr/bin/env python3
"""修复因缺少 trace/hooks 上下文行而被 patch 拒绝的 SUSFS 头部 hunk。

背景（根因）
------------
simonpunk/susfs4ksu 的 `50_add_susfs_in_gki-<android>-<kernel>.patch` 是在「带
vendor hook 的 GKI 树」上生成的，所以 fs/namespace.c 与 fs/proc/task_mmu.c 的
**首个 hunk 把下面两行当作上下文行**：

    fs/namespace.c      : #include <trace/hooks/blk.h>
    fs/proc/task_mmu.c  : #include <trace/hooks/mm.h>

ABK 从 AOSP common（repo manifest `common-android13-5.15-*`）拉取的树里没有这两行，
于是该 hunk 被 patch 判为 reject（生成 .rej），而补丁其余 hunk 照常应用。
结果是文件里开始使用 SUSFS 符号，却没有对应的头文件 / 前置声明，编译报：

    fs/namespace.c      : error: 'CL_COPY_MNT_NS' undeclared
                          error: implicit declaration of 'susfs_is_current_ksu_domain'
                          error: 'DEFAULT_KSU_MNT_ID' undeclared
    fs/proc/task_mmu.c  : error: implicit declaration of 'SUSFS_IS_INODE_SUS_MAP'

本脚本按「符号是否被使用」而不是按 sub_level 白名单判定（5.15.178 这类新 LTS
点版本没有历史兜底补丁可用），幂等补齐：

    fs/namespace.c      : <linux/susfs_def.h> + susfs_is_current_ksu_domain() 与
                          susfs_is_sdcard_android_data_not_decrypted 的 extern +
                          CL_COPY_MNT_NS 定义（内容与上游被拒 hunk 一致）
    fs/proc/task_mmu.c  : <linux/susfs_def.h>（SUSFS_IS_INODE_SUS_MAP /
                          SUSFS_IS_INODE_OPEN_REDIRECT 等宏的来源）

补齐并校验通过后删除对应的 .rej，避免已修复的冲突继续被当作冲突上报。

用法
----
    fix-susfs-header-rejects.py <kernel-root>

<kernel-root> 可以是含 fs/ 的 common 目录，也可以是它的父目录（如
$KERNEL_ROOT，脚本会自动下探 common/）。
"""

from __future__ import annotations

import sys
from pathlib import Path


SUSFS_DEF_INCLUDE = "#include <linux/susfs_def.h>"

# 与上游 50_add_susfs_in_gki-*.patch 中 namespace.c 头部 hunk 完全一致
NAMESPACE_INCLUDE_BLOCK = (
    "#ifdef CONFIG_KSU_SUSFS\n"
    "#include <linux/susfs_def.h>\n"
    "#endif // #ifdef CONFIG_KSU_SUSFS\n"
)

NAMESPACE_EXTERN_LINES = (
    "",
    "#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT",
    "/* upstream 靠 fs/namespace.c 里的 <trace/hooks/blk.h> 间接引入 jump_label.h，",
    " * 而 AOSP common 树没有该头文件，这里显式引入，避免 struct static_key_true 未定义。 */",
    "#include <linux/jump_label.h>",
    "extern bool susfs_is_current_ksu_domain(void);",
    "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;",
)
NAMESPACE_EXTERN_TAIL = "#endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT\n"
NAMESPACE_INCLUDE_ANCHOR = NAMESPACE_INCLUDE_BLOCK.rstrip("\n")
NAMESPACE_MNT_NS_DEFINE = "#define CL_COPY_MNT_NS BIT(25) /* used by copy_mnt_ns() */\n"

TASK_MMU_INCLUDE_BLOCK = (
    "#if defined(CONFIG_KSU_SUSFS_SUS_KSTAT) || defined(CONFIG_KSU_SUSFS_SUS_MAP)"
    " || defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)\n"
    "#include <linux/susfs_def.h>\n"
    "#endif // #if defined(CONFIG_KSU_SUSFS_SUS_KSTAT) || defined(CONFIG_KSU_SUSFS_SUS_MAP)"
    " || defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)\n"
)

# 只要文件用到其中之一，就必须能见到 <linux/susfs_def.h>
NAMESPACE_DEF_SYMBOLS = (
    "DEFAULT_KSU_MNT_ID",
    "DEFAULT_KSU_MNT_GROUP_ID",
    "VFSMOUNT_MNT_FLAGS_KSU_UNSHARED_MNT",
    "susfs_is_current_proc_umounted",
)

TASK_MMU_DEF_SYMBOLS = (
    "SUSFS_IS_INODE_SUS_MAP",
    "SUSFS_IS_INODE_OPEN_REDIRECT",
    "SUSFS_IS_INODE_OPEN_REDIRECT_WITHOUT_UID_CHECK",
)

EXTERN_KSK_DOMAIN = "extern bool susfs_is_current_ksu_domain(void);"
DEFINE_CL_COPY_MNT_NS = "#define CL_COPY_MNT_NS"


class RepairError(RuntimeError):
    pass


def read_text(path: Path) -> str:
    # newline="" 保留原始换行，避免在 Windows 上把内核源码写成 CRLF
    with path.open("r", encoding="utf-8", newline="") as handle:
        return handle.read()


def write_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def insert_after(text: str, block: str, anchors: tuple[str, ...], what: str) -> str:
    """把 block 插到第一个命中的 anchor 所在行的行尾之后（anchor 不带换行符）。"""
    for anchor in anchors:
        index = text.find(anchor)
        if index < 0:
            continue
        end = index + len(anchor)
        while end < len(text) and text[end] not in "\r\n":
            end += 1
        if text.startswith("\r\n", end):
            end += 2
        elif end < len(text) and text[end] == "\n":
            end += 1
        return text[:end] + block + text[end:]
    raise RepairError(f"{what}: 找不到插入锚点，候选锚点 = {list(anchors)}")


def uses_any(text: str, symbols: tuple[str, ...]) -> bool:
    return any(symbol in text for symbol in symbols)


def needs_namespace_include(text: str) -> bool:
    return uses_any(text, NAMESPACE_DEF_SYMBOLS) or "CL_COPY_MNT_NS" in text


def needs_namespace_externs(text: str) -> bool:
    return (
        "susfs_is_current_ksu_domain(" in text
        or "susfs_is_sdcard_android_data_not_decrypted" in text
    )


def namespace_extern_block(text: str) -> str:
    lines = list(NAMESPACE_EXTERN_LINES)
    if "CL_COPY_MNT_NS" in text and DEFINE_CL_COPY_MNT_NS not in text:
        lines.append("")
        lines.append(NAMESPACE_MNT_NS_DEFINE.rstrip("\n"))
    return "\n".join(lines) + "\n" + NAMESPACE_EXTERN_TAIL


def repair_namespace(path: Path, changed: list[str], log: list[str]) -> bool:
    """返回 True 表示本次真的改动了文件（此时它的 .rej 才算已修复）。"""
    text = read_text(path)
    original = text
    want_include = needs_namespace_include(text)

    if want_include and SUSFS_DEF_INCLUDE not in text:
        text = insert_after(
            text,
            NAMESPACE_INCLUDE_BLOCK,
            (
                "#include <linux/mnt_idmapping.h>",
                "#include <linux/shmem_fs.h>",
                "#include <linux/fs_context.h>",
                '#include "pnode.h"',
            ),
            f"{path} 的 {SUSFS_DEF_INCLUDE}",
        )
        log.append(f"{path}: 注入 {SUSFS_DEF_INCLUDE}（CONFIG_KSU_SUSFS 保护）")

    if needs_namespace_externs(text) and EXTERN_KSK_DOMAIN not in text:
        block = namespace_extern_block(text)
        text = insert_after(
            text,
            block,
            (
                NAMESPACE_INCLUDE_ANCHOR,
                '#include "internal.h"',
                "#include <linux/mnt_idmapping.h>",
            ),
            f"{path} 的 SUSFS 前置声明",
        )
        log.append(
            f"{path}: 注入 susfs_is_current_ksu_domain()/static key extern"
            + (" 与 CL_COPY_MNT_NS 定义" if DEFINE_CL_COPY_MNT_NS not in original else "")
        )

    if text != original:
        write_text(path, text)
        changed.append(str(path))

    final = read_text(path)
    if want_include and SUSFS_DEF_INCLUDE not in final:
        raise RepairError(f"{path}: 注入后仍缺少 {SUSFS_DEF_INCLUDE}")
    if "CL_COPY_MNT_NS" in final and DEFINE_CL_COPY_MNT_NS not in final:
        raise RepairError(f"{path}: 使用了 CL_COPY_MNT_NS 但没有定义")
    if needs_namespace_externs(final) and EXTERN_KSK_DOMAIN not in final:
        raise RepairError(f"{path}: 使用了 susfs_is_current_ksu_domain() 但没有 extern 声明")
    return text != original


def repair_task_mmu(path: Path, changed: list[str], log: list[str]) -> bool:
    """返回 True 表示本次真的改动了文件（此时它的 .rej 才算已修复）。"""
    text = read_text(path)
    original = text

    if uses_any(text, TASK_MMU_DEF_SYMBOLS) and SUSFS_DEF_INCLUDE not in text:
        text = insert_after(
            text,
            TASK_MMU_INCLUDE_BLOCK,
            (
                "#include <linux/pkeys.h>",
                "#include <linux/uaccess.h>",
                '#include "internal.h"',
            ),
            f"{path} 的 {SUSFS_DEF_INCLUDE}",
        )
        log.append(
            f"{path}: 注入 {SUSFS_DEF_INCLUDE}（SUS_KSTAT/SUS_MAP/OPEN_REDIRECT 保护）"
        )

    if text != original:
        write_text(path, text)
        changed.append(str(path))

    final = read_text(path)
    if uses_any(final, TASK_MMU_DEF_SYMBOLS) and SUSFS_DEF_INCLUDE not in final:
        raise RepairError(f"{path}: 注入后仍缺少 {SUSFS_DEF_INCLUDE}")
    return text != original


def resolve_common_root(root: Path) -> Path | None:
    if (root / "fs" / "namespace.c").is_file():
        return root
    if (root / "common" / "fs" / "namespace.c").is_file():
        return root / "common"
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: fix-susfs-header-rejects.py <kernel-root>", file=sys.stderr)
        return 2

    root = Path(argv[1]).resolve()
    common = resolve_common_root(root)
    if common is None:
        print(
            f"::warning::{root} 下找不到 fs/namespace.c（既不是 common 目录也不是它的父目录），跳过",
            file=sys.stderr,
        )
        return 0

    changed: list[str] = []
    log: list[str] = []
    removed_rejects: list[str] = []
    repairs = {
        "fs/namespace.c": repair_namespace,
        "fs/proc/task_mmu.c": repair_task_mmu,
    }

    try:
        for rel_path, repair in repairs.items():
            target = common / rel_path
            if not target.is_file():
                continue
            touched = repair(target, changed, log)
            reject = target.with_name(target.name + ".rej")
            # 只有本次真的补齐了该文件，它的 .rej 才算「已修复」；否则保留，
            # 避免把尚未处理的其他 hunk 冲突一起吞掉。
            if touched and reject.is_file():
                reject.unlink()
                removed_rejects.append(str(reject))
    except RepairError as error:
        print(f"::error::SUSFS 头部修复失败: {error}", file=sys.stderr)
        return 1

    if log:
        print("SUSFS 头部 include/声明修复：")
        for line in log:
            print(f"  {line}")
    else:
        print("SUSFS 头部 include/声明无需修复。")

    if removed_rejects:
        print("已清理被修复的 reject 文件：")
        for line in removed_rejects:
            print(f"  {line}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
