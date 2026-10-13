/*
 * mount_filter — hide keyword-matching mount records from /proc mounts views.
 *
 * KernelPatch Module (KPM), ARM64. Targets Android GKI kernels (audited on
 * 5.10.269-gki; seq_file layout stable from 3.17 through 6.x).
 *
 * What it does
 * ------------
 * Hooks the seq_file show handlers that render:
 *   - show_vfsmnt()   -> /proc/mounts, /proc/self/mounts, /proc/<pid>/mounts
 *   - show_mountinfo()-> /proc/self/mountinfo, /proc/<pid>/mountinfo
 * and, for third-party app callers with uid >= 10000 (isolated/zygote_next
 * processes at 99000+ are included; system 0/1000, shell 2000 and the system
 * AID range 1001..1099 are never affected),
 * drops any rendered line containing one of the built-in keywords:
 *   "/adb/modules/zygisk_lsposed", "dex2oat64", "dex2oat32"
 * plus any keyword added at runtime through the control interface.
 *
 * Hook strategy (pattern: kernel/patch/common/selinux_hide.c):
 *   1. preferred: inline hook (hook_wrap2) on the resolved show function
 *      symbol (exact name -> LTO suffix walk -> numbered suffix);
 *   2. fallback:  fp_hook_wrap2 on the `.show` pointer slot of the resolved
 *      mounts_op / mountinfo_op data symbol (no kernel text is modified);
 *   Both paths share the same before/after callbacks; installation fails
 *   (module refuses to load) only when neither path can be set up for either
 *   target at all.
 *
 * Filter mechanics
 * ----------------
 * before: if enabled && uid >= 1000, remember m->count in fargs->local.data0
 *         (sentinel value otherwise).
 * after:  if the original show() returned 0 and appended bytes
 *         [buf+count0, m->count) contain a keyword, rewind m->count back to
 *         count0 — the whole mount line vanishes from the read result and
 *         seq_read_iter simply continues with the next record.
 *
 * Usage (via KernelPatch supercall, see user/supercall.h and doc/zh-CN/module.md)
 * ---------------------------------------------------------------------------
 *   long rc = sc_kpm_load(key, "/data/local/tmp/mount_filter_1.0.0.kpm", "", NULL);
 *   char msg[256];
 *   sc_kpm_control(key, "mount_filter", "status", msg, sizeof(msg));
 *   sc_kpm_control(key, "mount_filter", "on",  msg, sizeof(msg));
 *   sc_kpm_control(key, "mount_filter", "off", msg, sizeof(msg));
 *   sc_kpm_control(key, "mount_filter", "list", msg, sizeof(msg));
 *   sc_kpm_control(key, "mount_filter", "add <keyword>", msg, sizeof(msg));
 *   sc_kpm_control(key, "mount_filter", "del <keyword>", msg, sizeof(msg));
 *   sc_kpm_unload(key, "mount_filter", NULL);
 *
 * Build
 * -----
 *   export TARGET_COMPILE=aarch64-none-elf-
 *   make          # silent release image (no log strings inside)
 *   make DEBUG=1  # verbose image for troubleshooting
 *
 * 修改历史: 2026-10-13 23:30 — initial version (v1.0.0)
 */

#include <compiler.h>
#include <common.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <ksyms.h>
#include <kputils.h>
#include <kconfig.h>

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <asm/cmpxchg.h>
#include <asm-generic/rwonce.h>
#include <uapi/asm-generic/errno.h>

#include "mount_filter.h"

#ifndef MOUNT_FILTER_VERSION
#define MOUNT_FILTER_VERSION "1.0.1"
#endif

KPM_NAME("mount_filter");
KPM_VERSION(MOUNT_FILTER_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("nmb");
KPM_DESCRIPTION("Hide keyword-matching mount records from /proc mounts views for third-party apps (uid>=10000)");

/* ============================ constants ============================ */

/*
 * Only third-party apps are filtered: Android allocates application uids from
 * FIRST_APPLICATION_UID (10000), so this boundary matches the framework's own
 * convention (selinux_hide.c: "Apps (uid >= 10000)", selinux_hook bypass:
 * uid < 10000). Isolated processes (99000..99999) — including the zygote_next
 * native helpers detectors use — are >= 10000 and therefore covered, while
 * system(0/1000), shell(2000) and the system AID range (1001..1099) keep the
 * untouched mount table and never observe the filter.
 */
#define MF_FILTER_UID_MIN 10000

/* Sentinel kept in fargs->local.data0 meaning "filtering not armed for this
 * call" — the after callback must leave everything untouched. */
#define MF_SKIP_SENTINEL ((uint64_t)0xFFFFFFFFFFFFFFFFull)

/* Built-in keywords (compiled in, cannot be removed at runtime). */
#define MF_KW_STATIC_NUM 3
static const char *const g_static_kw[MF_KW_STATIC_NUM] = {
    "/adb/modules/zygisk_lsposed",
    "dex2oat64",
    "dex2oat32",
};

/* Runtime keyword slots. slot[0] == '\0' means empty; publishers write bytes
 * [1..len] first and slot[0] last so lock-free readers never observe a
 * half-written keyword (any intermediate state is either empty or a complete
 * older keyword — both safe to match against). */
#define MF_KW_DYN_NUM 8
#define MF_KW_DYN_LEN 64 /* 63 content bytes + NUL */
static char g_dyn_kw[MF_KW_DYN_NUM][MF_KW_DYN_LEN];

/* Two filter paths: index 0 = mounts (show_vfsmnt/mounts_op),
 * index 1 = mountinfo (show_mountinfo/mountinfo_op). */
#define MF_PATH_MOUNTS 0
#define MF_PATH_MOUNTINFO 1
#define MF_PATH_NUM 2

/* ===================== minimal kernel structure views ===================== */

/*
 * Minimal view of struct seq_file (fs/seq_file.c). The leading fields
 * buf/size/from/count/pad_until have kept this exact layout since v3.17,
 * including the target 5.10 GKI kernel; only buf and count are touched here.
 */
struct seq_file_view {
    char *buf;   /* +0  */
    size_t size; /* +8  */
    size_t from; /* +16 */
    size_t count; /* +24: bytes written into buf */
};

/*
 * Minimal view of struct seq_operations (include/linux/seq_file.h):
 * { start; stop; next; show; } — show is the 4th pointer, offset 24 on every
 * kernel generation. Used only to locate/validate the `.show` slot address.
 */
struct seq_ops_view {
    void *start; /* +0  */
    void *stop;  /* +8  */
    void *next;  /* +16 */
    void *show;  /* +24 */
};
#define MF_SEQ_OPS_SHOW_OFF 24

/* ================================ state ================================ */

/* Whole-literal reply helper: copy a compile-time-known string and set len. */
#define MF_SET_REPLY(b, l, s)                            \
    do {                                                 \
        mf_copy_bytes((b), (s), sizeof(s) - 1);          \
        (l) = (int)(sizeof(s) - 1);                      \
    } while (0)

/* Master switch (ctl0 on/off). */
static bool g_enabled;

/* Per-path hook mode: 0 = not installed, 1 = inline hook, 2 = fp slot hook. */
static int g_mode[MF_PATH_NUM];

/* Hook bookkeeping (pattern: selinux_hide.c g_hooked[] / g_fp_slot[]). */
#define MF_HOOK_MAX 4
static void *g_inline_fn[MF_HOOK_MAX];   /* inline-track hooked functions */
static int g_inline_cnt;
static uintptr_t g_fp_slot[MF_HOOK_MAX]; /* fp: pointer-slot addresses */
static int g_fp_cnt;

/* Statistics (relaxed; observation only). */
static u32 g_show_calls[MF_PATH_NUM];
static u32 g_hits[MF_PATH_NUM];

/* kfunc(strnstr) availability, checked once at init. */
static bool g_strnstr_native;

/* ======================= KP-owned spinlock (kp_spinlock.c pattern) =======
 *
 * kp_private_spin_lock()/kp_private_spin_unlock() themselves are not exported
 * to KPMs, so this reproduces their exact strategy: use the target kernel's
 * _raw_spin_lock_irqsave/_raw_spin_unlock_irqrestore pair when resolvable,
 * otherwise fall back to a local 0/1 test-and-set with IRQs masked in DAIF.
 * The lock is zero-initialized and KP-owned, which is the only supported use.
 */

typedef unsigned long (*raw_spin_lock_irqsave_fn_t)(raw_spinlock_t *lock);
typedef void (*raw_spin_unlock_irqrestore_fn_t)(raw_spinlock_t *lock, unsigned long flags);
static raw_spin_lock_irqsave_fn_t g_spin_lock_fn;
static raw_spin_unlock_irqrestore_fn_t g_spin_unlock_fn;
static bool g_spin_native;

static spinlock_t g_kw_lock = { .rlock = { .raw_lock = ATOMIC_INIT(0) } };

/* Save DAIF and mask interrupts (kp_spinlock.c kp_local_irq_save pattern). */
static inline unsigned long mf_local_irq_save(void)
{
    unsigned long flags;
    asm volatile("mrs %0, daif\n\t"
                 "msr daifset, #2"
                 : "=r"(flags)
                 :
                 : "memory");
    return flags;
}

/* Restore DAIF (kp_spinlock.c kp_local_irq_restore pattern). */
static inline void mf_local_irq_restore(unsigned long flags)
{
    asm volatile("msr daif, %0" : : "r"(flags) : "memory");
}

/* Local test-and-set spin (kp_spinlock.c kp_local_raw_spin_lock pattern). */
static inline void mf_local_spin_lock(raw_spinlock_t *lock)
{
    while (cmpxchg(&lock->raw_lock.counter, 0, 1) != 0) {
        while (__atomic_load_n(&lock->raw_lock.counter, __ATOMIC_RELAXED))
            asm volatile("yield" ::: "memory");
    }
}

/**
 * @brief take the keyword-table lock (used only on the ctl0 write path)
 * @return flags to pass to mf_kw_unlock()
 */
static unsigned long mf_kw_lock(void)
{
    unsigned long flags;

    if (likely(g_spin_native)) return g_spin_lock_fn(&g_kw_lock.rlock);
    flags = mf_local_irq_save();
    mf_local_spin_lock(&g_kw_lock.rlock);
    return flags;
}

/**
 * @brief release the keyword-table lock
 * @param flags value returned by the matching mf_kw_lock()
 */
static void mf_kw_unlock(unsigned long flags)
{
    if (likely(g_spin_native)) {
        g_spin_unlock_fn(&g_kw_lock.rlock, flags);
        return;
    }
    smp_store_release(&g_kw_lock.rlock.raw_lock.counter, 0);
    mf_local_irq_restore(flags);
}

/* ==================== freestanding byte/string helpers ==================== */
/* Explicit volatile byte walks keep clang from folding these into
 * out-of-line strlen/memcpy libcalls, which do not exist in the KPM loader
 * (pattern: selinux_hook str_len_safe/copy_bytes). */

static size_t mf_strnlen_safe(const char *s, size_t max)
{
    const volatile char *p = (const volatile char *)s;
    size_t len = 0;

    if (!s) return 0;
    while (len < max && p[len]) len++;
    return len;
}

static void mf_copy_bytes(void *dst, const void *src, size_t n)
{
    volatile char *d = (volatile char *)dst;
    const volatile char *s = (const volatile char *)src;
    size_t i;

    if (!d || !s) return;
    for (i = 0; i < n; i++) d[i] = s[i];
}

/** Fixed-length equality, no NUL requirement on either side. */
static bool mf_bytes_eq(const char *a, const char *b, size_t n)
{
    size_t i;

    if (!a || !b) return false;
    for (i = 0; i < n; i++)
        if (a[i] != b[i]) return false;
    return true;
}

/** Hand-rolled substring search used when kfunc(strnstr) is unavailable.
 * Pure memcmp-style comparison, hay does not need NUL termination. */
static bool mf_strnstr_fallback(const char *hay, size_t hay_len, const char *needle, size_t needle_len)
{
    size_t i, j;

    if (!needle_len || hay_len < needle_len) return false;
    for (i = 0; i + needle_len <= hay_len; i++) {
        for (j = 0; j < needle_len; j++)
            if (hay[i + j] != needle[j]) break;
        if (j == needle_len) return true;
    }
    return false;
}

/* ============================ keyword matching ============================ */

/**
 * @brief test whether one rendered mount line contains an active keyword
 * @param line pointer into m->buf (not NUL terminated)
 * @param len  number of bytes appended by the original show() for this line
 * @return true when the line must be dropped
 *
 * Uses the exported kfunc strnstr when available (kernel strnstr is a pure
 * byte-wise search bounded by len, so no NUL is required in `line`),
 * otherwise falls back to the hand-rolled matcher above.
 */
static bool mf_line_hit(const char *line, size_t len)
{
    int i;

    for (i = 0; i < MF_KW_STATIC_NUM; i++) {
        const char *kw = g_static_kw[i];
        size_t klen = mf_strnlen_safe(kw, MF_KW_DYN_LEN - 1);

        if (!klen || klen > len) continue;
        if (g_strnstr_native) {
            if (kfunc(strnstr)(line, kw, len)) return true;
        } else if (mf_strnstr_fallback(line, len, kw, klen)) {
            return true;
        }
    }

    for (i = 0; i < MF_KW_DYN_NUM; i++) {
        /* slot[0] == '\0' publishes emptiness; see the slot protocol above. */
        if (!g_dyn_kw[i][0]) continue;
        {
            const char *kw = g_dyn_kw[i];
            size_t klen = mf_strnlen_safe(kw, MF_KW_DYN_LEN - 1);

            if (!klen || klen > len) continue;
            if (g_strnstr_native) {
                if (kfunc(strnstr)(line, kw, len)) return true;
            } else if (mf_strnstr_fallback(line, len, kw, klen)) {
                return true;
            }
        }
    }
    return false;
}

/* ========================= hook before/after callbacks ==================== */
/*
 * Execution context (kernel/base/hook.c _transit4 / fphook.c _fp_transit4):
 * the callbacks run in the original caller's context of the hooked show()
 * — inside seq_read_iter() while holding the seq_file mutex. Therefore they
 * stay O(1), never sleep, never allocate, and only touch the seq_file fields
 * owned by that same mutex. fargs (and fargs->local) live on the transit
 * stack and die with the call, which is exactly the data0 lifetime we need.
 */

/**
 * @brief before-callback shared by both hook paths
 * @param udata (void*)(uintptr_t)path id (MF_PATH_MOUNTS / MF_PATH_MOUNTINFO)
 */
static void mf_show_before(hook_fargs2_t *a, void *udata)
{
    struct seq_file_view *m;

    (void)udata;
    a->local.data0 = MF_SKIP_SENTINEL;

    if (!READ_ONCE(g_enabled)) return;
    if (current_uid() < MF_FILTER_UID_MIN) return;

    m = (struct seq_file_view *)(void *)(uintptr_t)a->arg0;
    if (!m || !m->buf) return;

    a->local.data0 = (uint64_t)m->count;
}

/**
 * @brief after-callback shared by both hook paths: rewind m->count to drop
 *        the rendered line when a keyword matched.
 */
static void mf_show_after(hook_fargs2_t *a, void *udata)
{
    int path = (int)(uintptr_t)udata;
    struct seq_file_view *m;
    size_t c0, c1;

    if (a->local.data0 == MF_SKIP_SENTINEL) return;

    if (path >= 0 && path < MF_PATH_NUM)
        WRITE_ONCE(g_show_calls[path], g_show_calls[path] + 1);

    /* Only undo a successful render; error codes keep stock behaviour. */
    if ((int)a->ret != 0) return;

    m = (struct seq_file_view *)(void *)(uintptr_t)a->arg0;
    if (!m || !m->buf) return;

    c0 = (size_t)a->local.data0;
    c1 = (size_t)m->count;
    if (c1 <= c0) return;       /* nothing appended */
    if (c1 > m->size) return;   /* defensive: impossible layout, keep stock */

    if (!mf_line_hit(m->buf + c0, c1 - c0)) return;

    /* Drop the whole line; seq_read_iter continues with the next record. */
    m->count = c0;
    if (path >= 0 && path < MF_PATH_NUM)
        WRITE_ONCE(g_hits[path], g_hits[path] + 1);
}

/* ======================= symbol resolution (3 stages) ===================== */
/* Pattern: selinux_hook resolve_required_symbols_once / lookup_name_numbered_
 * suffix, plus the selinux_hide.c note that one kallsyms_on_each_symbol walk
 * covers every LTO mangling form (`.N`, `.llvm.<hash>`, `$...`). */

struct mf_sym {
    const char *name;
    size_t name_len;
    unsigned long addr;
    bool exact;
};

/* [0]=show_vfsmnt [1]=show_mountinfo [2]=mounts_op [3]=mountinfo_op */
static struct mf_sym g_syms[] = {
    { "show_vfsmnt", 0, 0, false },
    { "show_mountinfo", 0, 0, false },
    { "mounts_op", 0, 0, false },
    { "mountinfo_op", 0, 0, false },
};
#define MF_SYM_NUM (sizeof(g_syms) / sizeof(g_syms[0]))
static bool g_syms_walked;

static bool mf_name_is_exact(const char *name, const char *base, size_t blen)
{
    size_t i;

    if (!name) return false;
    for (i = 0; i < blen; i++)
        if (name[i] != base[i]) return false;
    return name[blen] == '\0';
}

/* base + '.'/'$' + non-empty suffix, skipping CFI-jump-table clones
 * (selinux_hook symbol_has_compiler_suffix / suffix_contains_cfi pattern). */
static bool mf_name_is_suffixed(const char *name, const char *base, size_t blen)
{
    const char *suf;
    size_t i;

    if (!name) return false;
    for (i = 0; i < blen; i++)
        if (name[i] != base[i]) return false;
    if (!(name[blen] == '.' || name[blen] == '$') || !name[blen + 1]) return false;

    suf = &name[blen + 1];
    for (i = 0; suf[i]; i++) {
        if (suf[i] == 'c' && suf[i + 1] == 'f' && suf[i + 2] == 'i' &&
            (i == 0 || suf[i - 1] == '.' || suf[i - 1] == '$') &&
            (!suf[i + 3] || suf[i + 3] == '.' || suf[i + 3] == '$'))
            return false;
    }
    return true;
}

/* kallsyms_on_each_symbol callback: kernel <= 6.1 signature (with module). */
static int mf_sym_cb(void *data, const char *name, struct module *module, unsigned long addr)
{
    size_t i;

    (void)data;
    (void)module;
    if (!name || !addr) return 0;
    for (i = 0; i < MF_SYM_NUM; i++) {
        struct mf_sym *s = &g_syms[i];

        if (s->exact) continue;
        if (mf_name_is_exact(name, s->name, s->name_len)) {
            s->addr = addr;
            s->exact = true;
        } else if (!s->addr && mf_name_is_suffixed(name, s->name, s->name_len)) {
            s->addr = addr;
        }
    }
    return 0;
}

/* kallsyms_on_each_symbol callback: kernel > 6.1 signature (no module arg). */
typedef int (*kallsyms_on_each_symbol_nomod_fn_t)(int (*fn)(void *, const char *, unsigned long), void *data);

static int mf_sym_cb_nomod(void *data, const char *name, unsigned long addr)
{
    return mf_sym_cb(data, name, NULL, addr);
}

/* Numbered-suffix probe (show_vfsmnt.0 .. .255) — only used when the symbol
 * walk is unavailable, because a completed walk already sees those names. */
static unsigned long mf_lookup_numbered(const char *base, size_t base_len)
{
    char name[48];
    volatile char *nb = (volatile char *)name;
    const volatile char *bb = (const volatile char *)base;
    unsigned long addr;
    size_t pos;
    u32 n;
    size_t i;

    if (!base || !base_len || base_len + 5 > sizeof(name)) return 0;

    for (i = 0; i < base_len; i++) nb[i] = bb[i];

    for (n = 0; n < 256; n++) {
        pos = base_len;
        name[pos++] = '.';
        if (n >= 100) name[pos++] = '0' + (n / 100) % 10;
        if (n >= 10) name[pos++] = '0' + (n / 10) % 10;
        name[pos++] = '0' + n % 10;
        name[pos] = '\0';

        addr = kallsyms_lookup_name(name);
        if (addr) return addr;
    }
    return 0;
}

/** Resolve all four symbols: exact -> one walk -> numbered fallback. */
static void mf_resolve_symbols_once(void)
{
    size_t i;
    bool need_walk = false;

    for (i = 0; i < MF_SYM_NUM; i++) {
        g_syms[i].name_len = mf_strnlen_safe(g_syms[i].name, 47);
        if (!g_syms[i].addr) {
            g_syms[i].addr = kallsyms_lookup_name(g_syms[i].name);
            g_syms[i].exact = !!g_syms[i].addr;
        }
        if (!g_syms[i].addr) need_walk = true;
    }

    if (need_walk && kallsyms_on_each_symbol) {
        int rc;

        if (kver <= VERSION(6, 1, 0)) {
            rc = kallsyms_on_each_symbol(mf_sym_cb, NULL);
        } else {
            kallsyms_on_each_symbol_nomod_fn_t walk;

            walk = (kallsyms_on_each_symbol_nomod_fn_t)kallsyms_on_each_symbol;
            rc = walk(mf_sym_cb_nomod, NULL);
        }
        g_syms_walked = (rc == 0);
    }

    if (!g_syms_walked) {
        for (i = 0; i < MF_SYM_NUM; i++)
            if (!g_syms[i].addr)
                g_syms[i].addr = mf_lookup_numbered(g_syms[i].name, g_syms[i].name_len);
    }
}

/* ======================= dual-track hook install/uninstall ================ */

/**
 * @brief install the filter for one path (inline preferred, fp slot fallback)
 * @param path MF_PATH_MOUNTS or MF_PATH_MOUNTINFO
 * @return 0 on success, negative errno when neither track could be set up
 */
static int mf_install_path(int path)
{
    struct mf_sym *show_sym = &g_syms[path];
    struct mf_sym *ops_sym = &g_syms[2 + path];
    const char *__maybe_unused tag = (path == MF_PATH_MOUNTINFO) ? "mountinfo" : "mounts";
    void *udata = (void *)(uintptr_t)path;

    /* Track 1: inline hook on the show function symbol. */
    if (show_sym->addr && !is_bad_address((void *)show_sym->addr)) {
        hook_err_t err = hook_wrap2((void *)show_sym->addr, mf_show_before, mf_show_after, udata);

        if (err == HOOK_NO_ERR) {
            g_inline_fn[g_inline_cnt++] = (void *)show_sym->addr;
            g_mode[path] = 1;
            mf_dbg("hooked show_%s inline @%llx\n", tag, show_sym->addr);
            return 0;
        }
        mf_warn("inline hook on %s failed err=%d, trying fp slot\n", tag, (int)err);
    }

    /* Track 2: fp slot hook on ops->show (mounts_op / mountinfo_op). */
    if (ops_sym->addr && !is_bad_address((void *)ops_sym->addr)) {
        struct seq_ops_view *ops = (struct seq_ops_view *)ops_sym->addr;
        void *show_fp = ops->show;

        if (show_fp && !is_bad_address(show_fp)) {
            hook_err_t err = fp_hook_wrap2((uintptr_t)((char *)ops + MF_SEQ_OPS_SHOW_OFF), mf_show_before,
                                           mf_show_after, udata);

            if (err == HOOK_NO_ERR) {
                g_fp_slot[g_fp_cnt++] = (uintptr_t)((char *)ops + MF_SEQ_OPS_SHOW_OFF);
                g_mode[path] = 2;
                mf_dbg("hooked %s ops .show slot @%llx (show=%llx)\n", tag, (unsigned long)ops,
                       (unsigned long)show_fp);
                return 0;
            }
            mf_warn("fp slot hook on %s failed err=%d\n", tag, (int)err);
        } else {
            mf_warn("%s ops->show slot unusable ops=%llx show=%llx\n", tag, (unsigned long)ops,
                    (unsigned long)(uintptr_t)show_fp);
        }
    }

    mf_err("no usable hook point for %s (show=%llx ops=%llx)\n", tag, show_sym->addr, ops_sym->addr);
    return -ENOENT;
}

/**
 * @brief remove every installed hook (reverse order, idempotent)
 *
 * Note (framework-known): hook_unwrap_remove/fp_hook_unwrap free the chain
 * when the last item goes away while concurrent callers may still be inside
 * the transit code — the same exposure every in-tree KPM (selinux_hook,
 * selinux_hide) accepts; unload is a user-triggered, one-shot event.
 */
static void mf_uninstall_all(void)
{
    while (g_inline_cnt > 0) {
        g_inline_cnt--;
        if (g_inline_fn[g_inline_cnt])
            hook_unwrap(g_inline_fn[g_inline_cnt], mf_show_before, mf_show_after);
        g_inline_fn[g_inline_cnt] = NULL;
    }
    while (g_fp_cnt > 0) {
        g_fp_cnt--;
        if (g_fp_slot[g_fp_cnt])
            fp_hook_unwrap(g_fp_slot[g_fp_cnt], mf_show_before, mf_show_after);
        g_fp_slot[g_fp_cnt] = 0;
    }
    g_mode[MF_PATH_MOUNTS] = 0;
    g_mode[MF_PATH_MOUNTINFO] = 0;
}

/* ============================ ctl0 helpers ============================ */

/** Whole-word command match: args equals cmd, followed by '\0' or ' '. */
static bool mf_word_match(const char *args, const char *word)
{
    size_t i = 0;

    if (!args || !word) return false;
    while (word[i]) {
        if (args[i] != word[i]) return false;
        i++;
    }
    return args[i] == '\0' || args[i] == ' ';
}

/** Skip the command word and blanks; NULL when no argument follows. */
static const char *mf_arg_of(const char *args)
{
    size_t i = 0;

    if (!args) return NULL;
    while (args[i] && args[i] != ' ') i++;
    while (args[i] == ' ') i++;
    return args[i] ? &args[i] : NULL;
}

static const char *mf_mode_name(int path)
{
    switch (g_mode[path]) {
    case 1:
        return "inline";
    case 2:
        return "fp_slot";
    default:
        return "none";
    }
}

/** Count occupied dynamic slots (lock-free read: slot[0] protocol). */
static int mf_dyn_kw_count(void)
{
    int i, n = 0;

    for (i = 0; i < MF_KW_DYN_NUM; i++)
        if (g_dyn_kw[i][0]) n++;
    return n;
}

/**
 * @brief KPM_CTL0 control interface
 * @param ctl_args kernel-side NUL-terminated command string (module.c copy)
 * @param out_msg user buffer for the reply
 * @param outlen  size of out_msg
 * @return 0 on success (including "not found"/"full" style user errors that
 *         are reported through the reply text), negative errno on hard errors
 *
 * Commands: status | on | off | list | add <keyword> | del <keyword>
 */
static long control(const char *ctl_args, char *__user out_msg, int outlen)
{
    char buf[256];
    const char *arg;
    int len = 0;
    int rc = 0;
    int i;

    if (!ctl_args || !ctl_args[0]) return -EINVAL;
    buf[0] = '\0';

    if (mf_word_match(ctl_args, "status")) {
        if (kfunc(snprintf)) {
            len = kfunc(snprintf)(buf, sizeof(buf),
                                  "enabled=%u mounts=%s mountinfo=%s kw=%d+%d calls=%u,%u hits=%u,%u "
                                  "strnstr=%u spin=%u",
                                  READ_ONCE(g_enabled) ? 1 : 0, mf_mode_name(MF_PATH_MOUNTS),
                                  mf_mode_name(MF_PATH_MOUNTINFO), MF_KW_STATIC_NUM, mf_dyn_kw_count(),
                                  READ_ONCE(g_show_calls[MF_PATH_MOUNTS]), READ_ONCE(g_show_calls[MF_PATH_MOUNTINFO]),
                                  READ_ONCE(g_hits[MF_PATH_MOUNTS]), READ_ONCE(g_hits[MF_PATH_MOUNTINFO]),
                                  g_strnstr_native ? 1 : 0, g_spin_native ? 1 : 0);
            if (len < 0) len = 0;
            if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
        } else {
            /* snprintf unexported on this kernel: degrade to a terse reply. */
            MF_SET_REPLY(buf, len, "status: snprintf unavailable\n");
        }
    } else if (mf_word_match(ctl_args, "on")) {
        WRITE_ONCE(g_enabled, true);
        MF_SET_REPLY(buf, len, "filter enabled\n");
    } else if (mf_word_match(ctl_args, "off")) {
        WRITE_ONCE(g_enabled, false);
        MF_SET_REPLY(buf, len, "filter disabled\n");
    } else if (mf_word_match(ctl_args, "list")) {
        int off = 0;

        for (i = 0; i < MF_KW_STATIC_NUM && off < (int)sizeof(buf) - 1; i++) {
            const char *kw = g_static_kw[i];

            if (kfunc(snprintf)) {
                int n = kfunc(snprintf)(buf + off, sizeof(buf) - off, "[%s]\n", kw);

                if (n <= 0 || n >= (int)(sizeof(buf) - off)) {
                    off = mf_strnlen_safe(buf, sizeof(buf) - 1);
                    goto list_trunc;
                }
                off += n;
            } else {
                goto list_trunc;
            }
        }
        for (i = 0; i < MF_KW_DYN_NUM && off < (int)sizeof(buf) - 1; i++) {
            const char *kw = g_dyn_kw[i];
            int n;

            if (!kw[0]) continue;
            n = kfunc(snprintf) ? kfunc(snprintf)(buf + off, sizeof(buf) - off, "%s\n", kw) : -1;
            if (n <= 0 || n >= (int)(sizeof(buf) - off)) {
                off = mf_strnlen_safe(buf, sizeof(buf) - 1);
                goto list_trunc;
            }
            off += n;
        }
        len = off;
        goto reply;
list_trunc:
        if (off < (int)sizeof(buf) - 5) {
            buf[off++] = '.';
            buf[off++] = '.';
            buf[off++] = '.';
            buf[off++] = '\n';
            buf[off] = '\0';
        }
        len = off;
    } else if (mf_word_match(ctl_args, "add")) {
        size_t klen;
        unsigned long flags;
        int slot = -1;

        arg = mf_arg_of(ctl_args);
        if (!arg) {
            MF_SET_REPLY(buf, len, "add: missing keyword\n");
            goto reply;
        }
        klen = mf_strnlen_safe(arg, MF_KW_DYN_LEN - 1);
        if (klen == 0) {
            MF_SET_REPLY(buf, len, "add: empty keyword\n");
            goto reply;
        }
        if (klen == MF_KW_DYN_LEN - 1 && arg[klen] != '\0') {
            MF_SET_REPLY(buf, len, "add: keyword too long (max 63)\n");
            goto reply;
        }

        flags = mf_kw_lock();
        for (i = 0; i < MF_KW_DYN_NUM; i++) {
            if (!g_dyn_kw[i][0]) {
                slot = i;
                break;
            }
            if (mf_bytes_eq(g_dyn_kw[i], arg, klen) && g_dyn_kw[i][klen] == '\0') {
                slot = -2; /* duplicate */
                break;
            }
        }
        if (slot >= 0) {
            char *dst = g_dyn_kw[slot];

            /* publish protocol: tail bytes first, slot[0] last */
            if (klen > 1) mf_copy_bytes(&dst[1], &arg[1], klen - 1);
            dst[klen] = '\0';
            WRITE_ONCE(dst[0], arg[0]);
        }
        mf_kw_unlock(flags);

        if (slot == -2) {
            MF_SET_REPLY(buf, len, "add: duplicate keyword\n");
        } else if (slot < 0) {
            MF_SET_REPLY(buf, len, "add: dynamic slots full\n");
        } else {
            MF_SET_REPLY(buf, len, "add: ok\n");
        }
    } else if (mf_word_match(ctl_args, "del")) {
        size_t klen;
        unsigned long flags;
        bool removed = false;

        arg = mf_arg_of(ctl_args);
        if (!arg) {
            MF_SET_REPLY(buf, len, "del: missing keyword\n");
            goto reply;
        }
        for (i = 0; i < MF_KW_STATIC_NUM; i++) {
            if (mf_bytes_eq(g_static_kw[i], arg, mf_strnlen_safe(g_static_kw[i], MF_KW_DYN_LEN - 1)) &&
                arg[mf_strnlen_safe(g_static_kw[i], MF_KW_DYN_LEN - 1)] == '\0') {
                MF_SET_REPLY(buf, len, "del: built-in keyword is read-only\n");
                goto reply;
            }
        }
        klen = mf_strnlen_safe(arg, MF_KW_DYN_LEN - 1);

        flags = mf_kw_lock();
        for (i = 0; i < MF_KW_DYN_NUM; i++) {
            if (g_dyn_kw[i][0] && klen && mf_bytes_eq(g_dyn_kw[i], arg, klen) && g_dyn_kw[i][klen] == '\0') {
                WRITE_ONCE(g_dyn_kw[i][0], '\0');
                removed = true;
                break;
            }
        }
        mf_kw_unlock(flags);

        if (removed) {
            MF_SET_REPLY(buf, len, "del: ok\n");
        } else {
            MF_SET_REPLY(buf, len, "del: not found\n");
        }
    } else {
        if (kfunc(snprintf)) {
            len = kfunc(snprintf)(buf, sizeof(buf), "unknown command: %.32s\n", ctl_args);
            if (len < 0) len = 0;
            if (len >= (int)sizeof(buf)) len = (int)sizeof(buf) - 1;
        } else {
            MF_SET_REPLY(buf, len, "unknown command\n");
        }
        rc = -EINVAL;
    }

reply:
    if (out_msg && outlen > 0 && len > 0) {
        if (compat_copy_to_user(out_msg, buf, len) != len) rc = -EFAULT;
    }
    return rc;
}

/* ============================ init / exit ============================ */

/**
 * @brief module init: resolve symbols, install both hook paths
 * @return 0 on success; negative when neither path could be hooked at all
 *         (the KPM loader then calls exit and drops the image — module.c).
 */
static long mf_init(const char *args, const char *event, void *reserved)
{
    int rc_mounts;
    int rc_mountinfo;

    (void)args;
    (void)event; /* consumed by mf_dbg only in DEBUG builds */
    (void)reserved;

    /* Re-entry guard (the loader already rejects duplicate module names). */
    if (g_inline_cnt || g_fp_cnt) return 0;

    mf_dbg("init event=%s version=%s\n", event ? event : "(null)", MOUNT_FILTER_VERSION);

    /* Diagnostics only: CONFIG_KALLSYMS_ALL explains symbol visibility. */
    if (kp_kconfig_available())
        mf_dbg("CONFIG_KALLSYMS_ALL=%d\n", kp_kconfig_enabled("KALLSYMS_ALL"));

    /* Runtime capability probes. */
    g_strnstr_native = !!kfunc(strnstr);
    g_spin_lock_fn = (raw_spin_lock_irqsave_fn_t)kallsyms_lookup_name("_raw_spin_lock_irqsave");
    g_spin_unlock_fn = (raw_spin_unlock_irqrestore_fn_t)kallsyms_lookup_name("_raw_spin_unlock_irqrestore");
    g_spin_native = !!g_spin_lock_fn && !!g_spin_unlock_fn;
    if (!g_strnstr_native) mf_warn("kfunc strnstr unavailable, using fallback matcher\n");
    if (!g_spin_native) mf_warn("native spinlock pair unavailable, using local cmpxchg lock\n");

    /* Resolve the four targets, then install per path (best track wins). */
    mf_resolve_symbols_once();
    rc_mounts = mf_install_path(MF_PATH_MOUNTS);
    rc_mountinfo = mf_install_path(MF_PATH_MOUNTINFO);

    if (rc_mounts && rc_mountinfo) {
        mf_err("no hook point on either path, refusing to load\n");
        mf_uninstall_all();
        return -ENOENT;
    }
    if (rc_mounts) mf_warn("mounts path not covered (mountinfo active only)\n");
    if (rc_mountinfo) mf_warn("mountinfo path not covered (mounts active only)\n");

    WRITE_ONCE(g_enabled, true);
    mf_dbg("init ok: mounts=%s mountinfo=%s\n", mf_mode_name(MF_PATH_MOUNTS), mf_mode_name(MF_PATH_MOUNTINFO));
    return 0;
}

/**
 * @brief module exit: remove every hook and reset state (idempotent)
 */
static long mf_exit(void *reserved)
{
    (void)reserved;
    WRITE_ONCE(g_enabled, false);
    mf_uninstall_all();
    mf_dbg("exit done\n");
    return 0;
}

KPM_INIT(mf_init);
KPM_CTL0(control);
KPM_EXIT(mf_exit);
