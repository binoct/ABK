"""Regression tests for the SUSFS header-hunk repair used by the kernel workflow.

上游 50_add_susfs_in_gki-*.patch 把 `#include <trace/hooks/blk.h>` /
`#include <trace/hooks/mm.h>` 当作 fs/namespace.c、fs/proc/task_mmu.c 首个 hunk 的
上下文行，而 AOSP common 树没有这两行，hunk 被拒后补丁其余部分照常应用，文件开始
使用 SUSFS 符号却没有头文件/声明。这里固定住「补齐 + 幂等 + 清理 .rej」的行为。
"""

import importlib.util
import io
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/fix-susfs-header-rejects.py"


NAMESPACE_SOURCE = textwrap.dedent(
    """\
    // SPDX-License-Identifier: GPL-2.0-only
    #include <linux/syscalls.h>
    #include <linux/fs_context.h>
    #include <linux/shmem_fs.h>
    #include <linux/mnt_idmapping.h>

    #include "pnode.h"
    #include "internal.h"

    /* Maximum number of mounts in a mount namespace */
    unsigned int sysctl_mount_max __read_mostly = 100000;

    static int mnt_alloc_group_id(struct mount *mnt)
    {
    #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    	int res;

    	if (susfs_is_current_ksu_domain()) {
    		res = ida_alloc_min(&mnt_group_ida, DEFAULT_KSU_MNT_GROUP_ID, GFP_KERNEL);
    		goto bypass_orig_flow;
    	}
    	res = ida_alloc_min(&mnt_group_ida, 1, GFP_KERNEL);
    bypass_orig_flow:
    #else
    	int res = ida_alloc_min(&mnt_group_ida, 1, GFP_KERNEL);
    #endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT

    	if (res < 0)
    		return res;
    	mnt->mnt_group_id = res;
    	return 0;
    }

    static struct mount *copy_tree(struct mount *mnt, struct dentry *dentry, int flag)
    {
    #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    	if (static_branch_unlikely(&susfs_is_sdcard_android_data_not_decrypted)) {
    		if (flag & CL_COPY_MNT_NS)
    			return NULL;
    	}
    #endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    	return NULL;
    }
    """
)

TASK_MMU_SOURCE = textwrap.dedent(
    """\
    // SPDX-License-Identifier: GPL-2.0
    #include <linux/pagewalk.h>
    #include <linux/shmem_fs.h>
    #include <linux/uaccess.h>
    #include <linux/pkeys.h>

    #include <asm/elf.h>
    #include <asm/tlb.h>
    #include "internal.h"

    static void show_map_vma(struct seq_file *m, struct vm_area_struct *vma)
    {
    	struct inode *inode = file_inode(vma->vm_file);

    #ifdef CONFIG_KSU_SUSFS_SUS_MAP
    	if (SUSFS_IS_INODE_SUS_MAP(inode))
    		return;
    #endif // #ifdef CONFIG_KSU_SUSFS_SUS_MAP
    }
    """
)

CLEAN_NAMESPACE_SOURCE = textwrap.dedent(
    """\
    // SPDX-License-Identifier: GPL-2.0-only
    #include <linux/syscalls.h>
    #include <linux/mnt_idmapping.h>

    #include "pnode.h"
    #include "internal.h"

    static int mnt_alloc_id(struct mount *mnt)
    {
    	return ida_alloc(&mnt_id_ida, GFP_KERNEL);
    }
    """
)


class SusfsHeaderRepairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "fix_susfs_header_rejects", SCRIPT
        )
        cls.patcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.patcher)

    def run_repair(self, common):
        """在进程内跑一遍 main()，返回 (exit_code, stdout, stderr)。"""
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = self.patcher.main(["fix-susfs-header-rejects.py", str(common.parent)])
        return code, stdout.getvalue(), stderr.getvalue()

    def build_tree(self, root, namespace=None, task_mmu=None):
        common = root / "common"
        (common / "fs" / "proc").mkdir(parents=True)
        if namespace is not None:
            (common / "fs" / "namespace.c").write_text(namespace, encoding="utf-8")
            (common / "fs" / "namespace.c.rej").write_text("rej", encoding="utf-8")
        if task_mmu is not None:
            (common / "fs" / "proc" / "task_mmu.c").write_text(task_mmu, encoding="utf-8")
            (common / "fs" / "proc" / "task_mmu.c.rej").write_text("rej", encoding="utf-8")
        return common

    def test_repairs_rejected_header_hunks_and_clears_rejects(self):
        with tempfile.TemporaryDirectory() as temp:
            common = self.build_tree(
                Path(temp), NAMESPACE_SOURCE, TASK_MMU_SOURCE
            )

            code, out, err = self.run_repair(common)

            self.assertEqual(code, 0, err)
            namespace = (common / "fs" / "namespace.c").read_text(encoding="utf-8")
            task_mmu = (common / "fs" / "proc" / "task_mmu.c").read_text(encoding="utf-8")

            self.assertIn("#include <linux/susfs_def.h>", namespace)
            self.assertIn("extern bool susfs_is_current_ksu_domain(void);", namespace)
            self.assertIn(
                "extern struct static_key_true susfs_is_sdcard_android_data_not_decrypted;",
                namespace,
            )
            self.assertIn("#define CL_COPY_MNT_NS BIT(25)", namespace)
            self.assertIn("#include <linux/jump_label.h>", namespace)
            # 注入点必须在 #include "pnode.h" 之前，且不破坏原有 include 顺序
            self.assertLess(
                namespace.index("#include <linux/susfs_def.h>"),
                namespace.index('#include "pnode.h"'),
            )

            self.assertIn("#include <linux/susfs_def.h>", task_mmu)
            self.assertLess(
                task_mmu.index("#include <linux/susfs_def.h>"),
                task_mmu.index("#include <asm/elf.h>"),
            )

            self.assertFalse((common / "fs" / "namespace.c.rej").exists())
            self.assertFalse((common / "fs" / "proc" / "task_mmu.c.rej").exists())

    def test_second_pass_is_noop(self):
        with tempfile.TemporaryDirectory() as temp:
            common = self.build_tree(
                Path(temp), NAMESPACE_SOURCE, TASK_MMU_SOURCE
            )
            self.run_repair(common)
            first_namespace = (common / "fs" / "namespace.c").read_text(encoding="utf-8")
            first_task_mmu = (common / "fs" / "proc" / "task_mmu.c").read_text(encoding="utf-8")

            code, out, err = self.run_repair(common)

            self.assertEqual(code, 0, err)
            self.assertEqual(
                (common / "fs" / "namespace.c").read_text(encoding="utf-8"),
                first_namespace,
            )
            self.assertEqual(
                (common / "fs" / "proc" / "task_mmu.c").read_text(encoding="utf-8"),
                first_task_mmu,
            )
            self.assertEqual(first_namespace.count("#include <linux/susfs_def.h>"), 1)
            self.assertEqual(first_namespace.count("#define CL_COPY_MNT_NS BIT(25)"), 1)
            self.assertIn("无需修复", out)

    def test_clean_tree_is_left_untouched(self):
        with tempfile.TemporaryDirectory() as temp:
            common = self.build_tree(Path(temp), CLEAN_NAMESPACE_SOURCE)

            code, out, err = self.run_repair(common)

            self.assertEqual(code, 0, err)
            self.assertEqual(
                (common / "fs" / "namespace.c").read_text(encoding="utf-8"),
                CLEAN_NAMESPACE_SOURCE,
            )
            # 没有 SUSFS 符号时不动文件，也不碰 .rej
            self.assertTrue((common / "fs" / "namespace.c.rej").exists())

    def test_missing_anchor_fails_loudly(self):
        broken = textwrap.dedent(
            """\
            // SPDX-License-Identifier: GPL-2.0-only
            #include <linux/syscalls.h>

            static int mnt_alloc_group_id(struct mount *mnt)
            {
            #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
            	return ida_alloc_min(&mnt_group_ida, DEFAULT_KSU_MNT_GROUP_ID, GFP_KERNEL);
            #else
            	return ida_alloc_min(&mnt_group_ida, 1, GFP_KERNEL);
            #endif // #ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
            }
            """
        )

        with tempfile.TemporaryDirectory() as temp:
            common = self.build_tree(Path(temp), broken)

            code, out, err = self.run_repair(common)

            self.assertEqual(code, 1)
            self.assertIn("SUSFS 头部修复失败", err)

    def test_missing_common_dir_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            code, out, err = self.run_repair(Path(temp))

            self.assertEqual(code, 0)
            self.assertIn("跳过", err)


if __name__ == "__main__":
    unittest.main()
