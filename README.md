# 🛡️ HyperGuard92

> A friendly Windows 11 utility that prepares your system to run applications which rely on **hypervisor bypass** techniques — custom hypervisors, research drivers, kernel debuggers, reverse-engineering tools, and similar low-level software.

![HyperGuard92 Control Panel](.images/hyperguard92.png)

## ✨ What does this app do?

By default, Windows 11 enables several security layers (VBS, HVCI, Credential Guard, Memory Integrity, Hyper-V, and more) that **block third-party hypervisors and unsigned drivers** from running.

**HyperGuard92** lets you toggle those layers safely from a single screen:

- Click **PIRATE MODE** when you need to run a hypervisor-bypass tool — Windows is reconfigured to allow it.
- Click **DEFENDER MODE** to put every protection back exactly the way it was — your system returns to its original secure state.

Everything is backed up before it changes, so you can always revert with one click.

> 📚 For the full technical breakdown — service layers, registry keys, BCD edits, build/run commands, and contribution guidelines — see [`TECHNICAL.md`](TECHNICAL.md).

---

## 🖥️ The Interface, Explained

The window is split into a **left sidebar** (control & diagnostics) and a **main panel** (the feature matrix or logs).

### 🎛️ Left Sidebar

| Section | What it shows |
| :--- | :--- |
| **Brand header** | App title and "Control Panel" subtitle. |
| **Navigation** | Two tabs: `Features` (default) and `Execution Logs`. |
| **System Profile** | The current mode of the machine — `Defender Mode` (secure, default Windows) or `Pirate Mode` (relaxed, ready for hypervisor-bypass tools). |
| **Optimization Engine** | Two main action buttons: <br>• **PIRATE MODE** — disables conflicting protections in the right sequence. <br>• **DEFENDER MODE** — restores everything from backup. |
| **Diagnostics** | Live health checks: `Admin Privileges`, `BIOS VT-x/SVM`, `WMI Health`. A green ✓ means you are good to go. |
| **Banner** | Contextual warnings such as *"Smart App Control is currently in Evaluation Mode"*. |

### 🧩 Main Panel — Features Tab

The **Feature Matrix** is a grid of cards, one per managed Windows security feature. Each card has the same shape:

- **Title** — the feature name (e.g., `Memory Integrity (HVCI)`, `Credential Guard`).
- **Info icon (ℹ️)** — hover to read a plain-English explanation of what the feature does and why it might block a hypervisor.
- **Toggle switch** — enable or disable that single feature without running the whole pipeline.
- **Scope tag** — where the feature lives: `BIOS`, `REGISTRY`, `BCD`, `SERVICE`, `REGISTRY/UEFI`, `REGISTRY/TPM`, `BOOT`, `SYSTEM`.
- **Target State** — what HyperGuard92 wants this feature to be (e.g., `Disabled`, `Enabled`, `Removed`, `Functional`).
- **Current State** — what the feature is right now on your machine (`ACTIVE`, `DISABLED`, `LOCKED`, …).

Top-right of the matrix shows a counter like **`0 / 11 Optimizations Applied`** so you can see progress at a glance.

#### Features you can manage
| # | Feature | Why it matters |
| :--- | :--- | :--- |
| 1 | Virtualization (VT-x/SVM) | Required by every hypervisor — must stay **enabled**. |
| 2 | WMI (WinMgmt) | Used internally by HyperGuard92 to read system state. |
| 3 | VBS (Virtualization-Based Security) | The main blocker; disabling it unlocks everything below. |
| 4 | HVCI (Memory Integrity) | Blocks unsigned drivers. |
| 5 | Credential Guard | Isolates LSA secrets inside VBS. |
| 6 | Driver Signature Enforcement | Blocks unsigned/research drivers. |
| 7 | KVA Shadow (Meltdown) | Interferes with syscall hooks. |
| 8 | Windows Hypervisor (Hyper-V) | Holds VT-x exclusively if running. |
| 9 | FACEIT Anti-Cheat | Kernel filter that blocks unapproved drivers. |
| 10 | Windows Hello Protection | Tied to VBS keys — must be reset before disabling VBS. |
| 11 | Secure Biometrics | Enhanced sign-in security uses VBS. |
| 12 | HyperGuard / System Guard | SMM and boot-integrity protections. |
| 13 | Smart App Control | Can block the app itself. |
| 14 | BitLocker | Suspended automatically while boot settings change. |

### 📜 Main Panel — Execution Logs Tab

A terminal-styled view that streams real-time messages while HyperGuard92 works:
- `[SYSTEM]` lines — app lifecycle events.
- `[INFO]` lines — successful operations.
- `[WARN]` lines — non-fatal issues (e.g., a feature is locked by UEFI).
- `[USER]` lines — actions you triggered (PIRATE / DEFENDER / individual toggles).
- Each entry is timestamped so you can correlate it with system reboots.

---

## ⚠️ Important Warnings

- **Run as Administrator.** Without admin rights, the app refuses to make changes.
- **A reboot is usually required** after PIRATE MODE so registry/BCD/EFI changes take effect.
- **Windows Hello PIN & biometrics are reset** when VBS is disabled. You will need your Microsoft account password on next login.
- **BitLocker is briefly suspended** to let boot parameters change, then automatically resumed.
- **Use only on machines you own.** This tool deliberately weakens Windows protections.
