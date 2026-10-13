# mount_filter — KPM 挂载记录过滤器

**A KernelPatch Module (KPM) that hides keyword-matching mount records from `/proc` mounts views — only for third-party apps.**

在内核层拦截 `/proc/mounts`、`/proc/self/mounts`、`/proc/self/mountinfo`（及全部 `/proc/<pid>/` 变体）的读取内容，按关键词删除整行挂载记录。第三方应用与 isolated 进程（含 zygote_next 原生隔离进程）看不到被过滤的挂载；root / system / shell 等系统侧永远看到完整真实视图，系统运行零干扰。

## 它解决什么问题

Zygisk 类模块通过 bind mount 注入文件（例如把 `/apex/com.android.art/bin/dex2oat64` 替换为模块目录内的副本）。应用层的 unmount/挂载命名空间隐藏通常覆盖普通 app 进程，但 Android 的 **zygote_next 原生隔离进程**（isolated UID 99000–99999）走的是 init 管理的默认命名空间路径，仍能在 `/proc/self/mountinfo` 里读到这些 root 管理的挂载记录——这正是现代安全检测（如 Duck Detector 的 "Zygote next mount view" 探针）定位 root 框架的核心证据。

mount_filter 在内核 show 层直接删除这些行，让上述探针无迹可寻。

## 工作原理

```text
读取方 read → seq_read_iter → m->op->show(m, mnt)   ← 被 hook 拦截
  before: uid >= 10000 且过滤开启 → 记录 m->count
  原函数: 渲染一整行挂载记录
  after :  增量区间 [buf+count0, m->count) 命中关键词
          → 回退 m->count，该行从读取结果中消失
```

- **双轨 hook**（[selinux_hide](https://github.com/bmax121/KernelPatch) 官方范式）：优先对 `show_vfsmnt` / `show_mountinfo` 函数符号做 inline hook（`hook_wrap2`）；符号被 LTO 混淆无法解析时，自动降级为 `mounts_op` / `mountinfo_op` 数据结构的 `.show` 指针槽替换（`fp_hook_wrap2`，不修改内核文本）。两轨共用同一对回调。
- **三级符号解析**：精确名 → `kallsyms_on_each_symbol` 后缀匹配（`.N` / `.llvm.<hash>` / `$`，排除 CFI 克隆）→ 编号后缀探测。
- **UID 门控**：以 `FIRST_APPLICATION_UID`（10000）为界，与 KernelPatch 内置 selinux_hide 的应用边界一致。isolated（99000+）自然覆盖；system(0/1000)、系统 AID 段(1001–1099)、shell(2000) 直通真实视图。
- **匹配引擎**：优先使用框架导出的 kfunc `strnstr`（纯字节受限匹配），不可用时回退内置手写匹配器；关键词匹配精确大小写。
- **静默构建**：默认产物零日志字符串（不进二进制，防 `strings` 指纹与 logd 转发），`make DEBUG=1` 恢复全量日志。
- **卸载安全**：倒序完整还原全部 hook；init 失败自动回滚并拒绝加载，内核不留残留。

## 内置关键词

```text
/adb/modules/zygisk_lsposed
dex2oat64
dex2oat32
```

另支持 8 个运行时动态关键词（每个 ≤63 字节），经控制接口增删。

## 构建

依赖任意 aarch64 交叉工具链（裸机或 Linux 目标均可），并需要本仓库依赖的 [KernelPatch](https://github.com/bmax121/KernelPatch) 内核头（`KP_DIR` 指向其根目录）：

```shell
export TARGET_COMPILE=aarch64-none-elf-    # 或 aarch64-linux-gnu-
make                                        # 静默发行版 mount_filter_<ver>.kpm
make DEBUG=1                                # 排查版（全量日志）
```

编译参数 `-Wall -Wextra -Werror -O2`，自有代码零告警。

## 使用

以 APatch 管理器为例：模块页安装 `mount_filter_<ver>.kpm` 即生效；或通过 supercall 接口（见 KernelPatch `user/supercall.h`）：

```c
sc_kpm_load(key, "/data/local/tmp/mount_filter_1.0.1.kpm", "", NULL);
sc_kpm_control(key, "mount_filter", "status", buf, sizeof(buf));
sc_kpm_control(key, "mount_filter", "off", buf, sizeof(buf));   // 停用（hook 在位，零过滤）
sc_kpm_unload(key, "mount_filter", NULL);                        // 彻底卸载还原
```

### 控制命令（KPM_CTL0）

| 命令 | 功能 |
|---|---|
| `status` | 过滤开关、两路 hook 模式（inline / fp_slot）、关键词数量、各路径调用与命中计数 |
| `on` / `off` | 启用 / 停用过滤 |
| `list` | 列出全部生效关键词 |
| `add <keyword>` | 追加动态关键词（≤63 字节，上限 8 个） |
| `del <keyword>` | 删除动态关键词（内置三项只读） |

## 兼容性

- KernelPatch / APatch 0.13.x，ARM64
- `struct seq_file` 视图布局适用 Linux 3.18–6.x（buf@0 / count@24，自 3.17 起稳定）
- 实测环境：Redmi marble / Android 17（LineageOS）/ GKI 5.10.269 / KernelPatch 0.13.9

## 实测（Duck Detector 前后对比）

| 指标 | 加载前 | 加载后 |
|---|---|---|
| 总体评级 | ✖ Danger | ▲ Warning |
| Mount 卡片 | ROOT_MOUNT_EXPOSURE（2 条 root 挂载） | **CLEAR** |
| Zygote next mount view | 命中 dex2oat64 / dex2oat32 | Clean |
| isolated 进程可见挂载数 | 159 | **157（精确 −2，零误删）** |
| 其余全部挂载探针（statx 交叉校验等） | — | 与加载前逐项一致，无副作用 |

剩余 Warning（Custom ROM / 已安装的 root 类应用 / Xposed 模块包名）属于包管理器与 ROM 层面的客观事实，不在挂载层职责内。

## 已知边界

- 仅过滤 mounts / mountinfo 渲染层；`/proc/self/mountstats`（`show_vfsstat`）未覆盖。
- 关键词精确大小写匹配（路径场景）；不支持通配符。
- 检测方若改用 `statx` 逐路径探测 bind mount 本身（而非读挂载表），不在本模块拦截范围。

## 免责声明

本项目仅供安全研究与学习目的。修改内核行为可能违反设备保修条款或当地法律，因使用本模块造成的任何后果由使用者自行承担。

## 致谢

- [KernelPatch](https://github.com/bmax121/KernelPatch) / [APatch](https://github.com/bmax121/APatch) — bmax121 的 KPM 框架与 hook 基础设施
- 框架内置 `selinux_hide` 的双轨 hook 范式与 `kp_spinlock` 锁模式

## 许可

GPL-2.0，与 KernelPatch 上游一致。
