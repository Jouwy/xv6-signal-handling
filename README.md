# Project Signal - xv6 Kernel Signal Implementation

[*[Original README]*](https://github.com/Layheng-Hok/xv6-signal-handling/blob/signals-6969/OG-README.md)

[*[Project Requirements]*](https://github.com/Layheng-Hok/xv6-signal-handling/blob/signals-6969/docs/Project_Signal_Requirements.pdf)

[*[Project Report]*](https://github.com/Layheng-Hok/xv6-signal-handling/blob/signals-6969/docs/Final_Report.pdf)

## Overview
**Project Signal** extends the xv6 operating system kernel with a **POSIX-style signal handling mechanism**, enabling asynchronous communication between processes. This implementation supports sending, receiving, masking, and handling signals, as well as default and custom signal actions.

The project draws inspiration from **POSIX.1-2008** and parts of the Linux signal implementation, with integration tailored to xv6's architecture. It includes base functionality plus several optional features.

## Features Implemented

### **Base Checkpoints**
1. **Signal Handling Core (`sigaction`, `sigreturn`, `sigkill`)**
   - Allows processes to register handlers, ignore, or use default actions.
   - Proper context saving and restoration for signal handlers.
   - Masking support via `sigset_t` to block specific signals during handler execution.

2. **`SIGKILL`**
   - Uncatchable, unignorable.
   - Terminates process with exit code `-10 - SIGKILL`.

3. **Signal Behavior Across `fork` and `exec`**
   - **Fork:** Child inherits parent’s signal mask and handlers but clears pending signals.
   - **Exec:** Resets handlers to default except for explicitly ignored signals; preserves mask and pending signals.

### **Optional Checkpoints**
- **`SIGALRM`** – Timer-based signal delivery after a specified duration via `alarm(seconds)`.
- **`siginfo_t` Support** – Metadata passed to handlers, including:
  - `si_signo` (signal number)  
  - `si_pid` (sender PID)  
  - `si_code` (reason/metadata)
- **`SIGCHLD`** – Delivered to parent when a child process exits, with exit info.

## Architecture & Design

### **Core Components**
- **Signal Table (per-process)**  
  Stores registered handlers, pending signals, and masks.
  
- **Kernel Modifications**
  - `syscall.c` – Added system call support for signals.
  - `trap.c` – Integrated signal delivery checks on kernel-to-user transitions.
  - `proc.c` – Managed inheritance of signal state across `fork` and `exec`.
  - `ksignal.c` – Core signal implementation logic.

- **Lazy Delivery Mechanism**  
  Signals are delivered during safe user–kernel transitions (syscall return, timer interrupt) to avoid reentrancy.

- **Context Handling**  
  - `ucontext_t` and `siginfo_t` structures built on user stack before handler execution.
  - Original register state and signal mask restored via `sigreturn`.

## Challenges & Solutions

1. **Inline Stack Setup Complexity**  
   → Merged stack setup logic directly into `do_signal()` to avoid duplication.

2. **Mask & Nesting Management**  
   → Stored old mask in `ucontext` and restored it in `sigreturn()`; blocked current signal during handler execution.

3. **Race Conditions in Signal Delivery**  
   → Enforced lock ordering (`p->lock` before `mm->lock`) and disabled interrupts during pending-check phase.

4. **Default Action Duplication**  
   → Consolidated into a single switch block used for both direct default execution and fallback.

5. **Cross-File Alarm Implementation**  
   → Carefully integrated alarm logic across multiple files (`ksignal.c`, `proc.c`, `syscall.c`) while keeping changes modular.
   
## Testing & Validation

### **Test Suites**
- **Provided Tests:** `basic1`–`basic7`, `basic10`, `basic11`, `basic20`  
- **Custom Tests:**
  - `siginfo`
  - `sigchld`
  - `alarm1`, `alarm2`, `alarm3`

**All tests passed**, confirming:

- Correct signal delivery & masking
- Handler invocation order & nesting behavior
- Signal inheritance across `fork` and `exec`
- Accurate `siginfo_t` metadata
- Proper `SIGALRM` scheduling & cancellation
- Correct `SIGCHLD` behavior on child termination

## How to Run

```bash
# Clone and switch to your branch
git clone https://github.com/Layheng-Hok/xv6-signal-handling
git checkout signals-6969

# Build & run xv6
make run 				# Starts a single-core
make runsmp				# Starts a multi-core

# In xv6 shell
$ signal             # Runs provided tests
```
