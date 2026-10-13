/*
 * mount_filter — KernelPatch Module (KPM) header
 *
 * Gated logging macros (pattern: kpms/selinux_hook v1.1.8+).
 *
 * Default builds are fully silent: the macros expand to no-ops so neither the
 * "[mount_filter] " prefix nor any format string lands in the .kpm image
 * (prevents `strings` based fingerprinting and logd forwarding of kernel
 * printk into logcat where detectors scan for known tags).
 * Build with `make DEBUG=1` (-DMOUNT_FILTER_DEBUG=1) to re-enable all logs.
 *
 * 修改历史: 2026-10-13 23:30 — initial version (v1.0.0)
 */

#ifndef __MOUNT_FILTER_H
#define __MOUNT_FILTER_H

#include <linux/printk.h>

#ifdef MOUNT_FILTER_DEBUG
#define mf_dbg(fmt, ...) pr_info("[mount_filter] " fmt, ##__VA_ARGS__)
#define mf_warn(fmt, ...) pr_warn("[mount_filter] " fmt, ##__VA_ARGS__)
#define mf_err(fmt, ...) pr_err("[mount_filter] " fmt, ##__VA_ARGS__)
#else
#define mf_dbg(fmt, ...) do { } while (0)
#define mf_warn(fmt, ...) do { } while (0)
#define mf_err(fmt, ...) do { } while (0)
#endif

#endif /* __MOUNT_FILTER_H */
