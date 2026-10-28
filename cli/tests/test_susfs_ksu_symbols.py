"""Regression tests for the SUSFS↔KSU symbol-export repair.

上游 SUSFS 补丁在内核侧直接调用 KSU 的 selinux_hide / preinit 助手；旧版 KSU
（BakaSU 9dbce02）把这些实现关在 `#ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE`
里、也没有 preinit，链接期就报 undefined symbol。这里固定住修复行为。
"""

import importlib.util
import io
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/fix-susfs-ksu-symbols.py"


SUSFS_COMPAT_MK = textwrap.dedent(
    """\
    # susfs selinux_hide feature
    # old susfs won't have this manual hook
    ifeq ($(shell grep -q "ksu_selinux_hide_running" $(srctree)/security/selinux/hooks.c; echo $$?),0)
    $(info -- $(REPO_NAME)/susfs_feature_check: selinux_hide manual hook found)
    ccflags-y += -DKSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    endif
    """
)

# 旧版形态：实现在 #ifndef 里且是 static，没有 my_setprocattr
OLD_SELINUX_HIDE = textwrap.dedent(
    """\
    #include <linux/cred.h>

    #ifdef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    #define __maybe_static
    #else
    #define __maybe_static static
    #endif

    #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    static write_op_fn *context_write, *access_write;
    static write_op_fn orig_context_write, orig_access_write;

    static ssize_t my_write_context(struct file *file, char *buf, size_t size)
    {
        return orig_context_write(file, buf, size);
    }

    static ssize_t my_write_access(struct file *file, char *buf, size_t size)
    {
        return orig_access_write(file, buf, size);
    }

    int __nocfi ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size)
    {
        return 0;
    }
    #endif // #ifndef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    """
)

# 新版形态：__maybe_static + #define 别名
NEW_SELINUX_HIDE = textwrap.dedent(
    """\
    #ifdef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    #define __maybe_static
    #else
    #define __maybe_static static
    #endif

    __maybe_static ssize_t my_write_context(struct file *file, char *buf, size_t size)
    {
        return 0;
    }

    __maybe_static ssize_t my_write_access(struct file *file, char *buf, size_t size)
    {
        return 0;
    }

    #ifdef KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
    #define ksu_handle_selinux_setprocattr my_setprocattr
    #endif
    int __nocfi ksu_handle_selinux_setprocattr(const char *name, void *value, size_t size)
    {
        return 0;
    }
    """
)

KBUILD = "kernelsu-objs := core/init.o\nkernelsu-objs += feature/selinux_hide.o\n"

PREINIT_MK = "kernelsu-objs += preinit/preinit.o\nkernelsu-objs += preinit/blob.o\n"


class SusfsKsuSymbolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "fix_susfs_ksu_symbols", SCRIPT
        )
        cls.patcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.patcher)

    def build_tree(self, root, selinux_hide=OLD_SELINUX_HIDE, preinit=False, compat_mk=SUSFS_COMPAT_MK):
        ksu = root / "KernelSU" / "kernel"
        (ksu / "feature").mkdir(parents=True)
        (ksu / "tools").mkdir(parents=True)
        (ksu / "Kbuild").write_text(KBUILD, encoding="utf-8", newline="\n")
        (ksu / "feature" / "selinux_hide.c").write_text(
            selinux_hide, encoding="utf-8", newline="\n"
        )
        if compat_mk is not None:
            (ksu / "tools" / "susfs_compat.mk").write_text(
                compat_mk, encoding="utf-8", newline="\n"
            )
        if preinit:
            (ksu / "tools" / "preinit_runner.mk").write_text(
                PREINIT_MK, encoding="utf-8", newline="\n"
            )
        fs = root / "common" / "fs"
        fs.mkdir(parents=True)
        (fs / "Makefile").write_text(
            "obj-y += exec.o\n", encoding="utf-8", newline="\n"
        )
        return ksu, fs

    def run_repair(self, root):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = self.patcher.main(["fix-susfs-ksu-symbols.py", str(root)])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_exports_symbols_for_old_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ksu, fs = self.build_tree(root)

            code, out, err = self.run_repair(root)

            self.assertEqual(code, 0, err)
            hide = (ksu / "feature" / "selinux_hide.c").read_text(encoding="utf-8")
            self.assertIn("ssize_t my_write_context(struct file *file", hide)
            self.assertIn("ssize_t my_write_access(struct file *file", hide)
            self.assertNotIn("static ssize_t my_write_context(", hide)
            self.assertIn("int my_setprocattr(const char *name, void *value, size_t size)", hide)
            self.assertIn("return ksu_handle_selinux_setprocattr(name, value, size);", hide)

            # SUSFS 接管 selinux_hide 的探测必须带上 KSU 侧能力检查
            compat = (ksu / "tools" / "susfs_compat.mk").read_text(encoding="utf-8")
            self.assertIn('grep -q "__maybe_static ssize_t my_write_context"', compat)
            self.assertIn("$(KSU_SRC)/feature/selinux_hide.c", compat)
            self.assertIn("ccflags-y += -DKSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE", compat)

            # preinit 开关必须落在 fs/ 上（fs/exec.c 的守卫在 fs/ 编译单元）
            makefile = (fs / "Makefile").read_text(encoding="utf-8")
            self.assertIn("ccflags-y += -DKSU_NO_PREINIT", makefile)

    def test_second_pass_is_noop(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ksu, fs = self.build_tree(root)
            self.run_repair(root)
            hide_first = (ksu / "feature" / "selinux_hide.c").read_text(encoding="utf-8")
            makefile_first = (fs / "Makefile").read_text(encoding="utf-8")
            compat_first = (ksu / "tools" / "susfs_compat.mk").read_text(encoding="utf-8")

            code, out, err = self.run_repair(root)

            self.assertEqual(code, 0, err)
            self.assertEqual(
                (ksu / "feature" / "selinux_hide.c").read_text(encoding="utf-8"),
                hide_first,
            )
            self.assertEqual(
                (fs / "Makefile").read_text(encoding="utf-8"), makefile_first
            )
            self.assertEqual(
                (ksu / "tools" / "susfs_compat.mk").read_text(encoding="utf-8"),
                compat_first,
            )
            self.assertEqual(hide_first.count("int my_setprocattr("), 1)
            self.assertEqual(makefile_first.count("-DKSU_NO_PREINIT"), 1)
            self.assertIn("无需修复", out)

    def test_new_layout_only_tightens_detection(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ksu, fs = self.build_tree(root, selinux_hide=NEW_SELINUX_HIDE, preinit=True)

            code, out, err = self.run_repair(root)

            self.assertEqual(code, 0, err)
            hide = (ksu / "feature" / "selinux_hide.c").read_text(encoding="utf-8")
            # 新版自带 __maybe_static + #define 别名，不能再插一个同名函数
            self.assertEqual(hide, NEW_SELINUX_HIDE)
            # preinit 已接进构建，不能关掉它
            self.assertEqual(
                (fs / "Makefile").read_text(encoding="utf-8"), "obj-y += exec.o\n"
            )

    def test_missing_preinit_wiring_disables_susfs_preinit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _, fs = self.build_tree(root, preinit=False)

            code, _, err = self.run_repair(root)

            self.assertEqual(code, 0, err)
            self.assertIn(
                "ccflags-y += -DKSU_NO_PREINIT",
                (fs / "Makefile").read_text(encoding="utf-8"),
            )

    def test_unknown_susfs_compat_layout_fails_loudly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.build_tree(root, compat_mk="# nothing to see here\n")

            code, _, err = self.run_repair(root)

            self.assertEqual(code, 1)
            self.assertIn("susfs_compat.mk 结构已变化", err)

    def test_missing_ksu_tree_is_skipped(self):
        with tempfile.TemporaryDirectory() as temp:
            code, _, err = self.run_repair(Path(temp))

            self.assertEqual(code, 0)
            self.assertIn("跳过", err)


if __name__ == "__main__":
    unittest.main()
