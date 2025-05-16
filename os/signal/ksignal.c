#include "ksignal.h"
#include <proc.h>
#include <defs.h>
#include <trap.h>
/**
 * @brief init the signal struct inside a PCB.
 *
 * @param p
 * @return int
 */
 static int setup_signal_stack(struct proc *p, int signo, void (*handler)(int, siginfo_t*, void*)) {
    struct trapframe *tf = p->trapframe;
    struct mm *mm = p->mm;
    uint64 sp = tf->sp;
    tracef("setup_signal_stack: pid %d, signo %d, handler %p, sp %p, sigmask %x, sigpending %x",
           p->pid, signo, handler, sp, p->signal.sigmask, p->signal.sigpending);

    // Align stack to 16 bytes
    sp = sp & ~0xf;

    // Allocate space for ucontext
    sp -= sizeof(struct ucontext);
    struct ucontext uc;
    uc.uc_sigmask = p->signal.sigmask;
    uc.uc_mcontext.epc = tf->epc;
    uc.uc_mcontext.regs[0] = tf->ra;
    uc.uc_mcontext.regs[1] = tf->sp;
    uc.uc_mcontext.regs[2] = tf->gp;
    uc.uc_mcontext.regs[3] = tf->tp;
    uc.uc_mcontext.regs[4] = tf->t0;
    uc.uc_mcontext.regs[5] = tf->t1;
    uc.uc_mcontext.regs[6] = tf->t2;
    uc.uc_mcontext.regs[7] = tf->s0;
    uc.uc_mcontext.regs[8] = tf->s1;
    uc.uc_mcontext.regs[9] = tf->a0;
    uc.uc_mcontext.regs[10] = tf->a1;
    uc.uc_mcontext.regs[11] = tf->a2;
    uc.uc_mcontext.regs[12] = tf->a3;
    uc.uc_mcontext.regs[13] = tf->a4;
    uc.uc_mcontext.regs[14] = tf->a5;
    uc.uc_mcontext.regs[15] = tf->a6;
    uc.uc_mcontext.regs[16] = tf->a7;
    uc.uc_mcontext.regs[17] = tf->s2;
    uc.uc_mcontext.regs[18] = tf->s3;
    uc.uc_mcontext.regs[19] = tf->s4;
    uc.uc_mcontext.regs[20] = tf->s5;
    uc.uc_mcontext.regs[21] = tf->s6;
    uc.uc_mcontext.regs[22] = tf->s7;
    uc.uc_mcontext.regs[23] = tf->s8;
    uc.uc_mcontext.regs[24] = tf->s9;
    uc.uc_mcontext.regs[25] = tf->s10;
    uc.uc_mcontext.regs[26] = tf->s11;
    uc.uc_mcontext.regs[27] = tf->t3;
    uc.uc_mcontext.regs[28] = tf->t4;
    uc.uc_mcontext.regs[29] = tf->t5;
    uc.uc_mcontext.regs[30] = tf->t6;

    // Allocate space for siginfo
    sp -= sizeof(siginfo_t);
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));

    // Copy to user stack
    acquire(&mm->lock);
    if (copy_to_user(mm, sp, (char*)&si, sizeof(siginfo_t)) < 0 ||
        copy_to_user(mm, sp + sizeof(siginfo_t), (char*)&uc, sizeof(struct ucontext)) < 0) {
        release(&mm->lock);
        tracef("setup_signal_stack: failed to copy to user stack");
        return -1;
    }
    release(&mm->lock);

    // Update trapframe
    tf->sp = sp;
    tf->epc = (uint64)handler;
    tf->a0 = signo;
    tf->a1 = sp;
    tf->a2 = sp + sizeof(siginfo_t);
    tf->ra = (uint64)p->signal.sa[signo].sa_restorer;

    // Update signal mask
    //p->signal.sigmask |= p->signal.sa[signo].sa_mask;
    p->signal.sigmask |= p->signal.sa[signo].sa_mask | sigmask(signo);
    // p->signal.sigmask |= sigmask(signo);

    // Clear pending signal
    // p->signal.sigpending &= ~sigmask(signo);

    // Defensive: Clear unexpected SIGUSR1
    //if (p->signal.sigpending & sigmask(SIGUSR1)) {
    //    tracef("setup_signal_stack: clearing unexpected SIGUSR1, sigpending %x", p->signal.sigpending);
    //    p->signal.sigpending &= ~sigmask(SIGUSR1);
    //}
    p->signal.handling_depth++;
    tracef("setup_signal_stack: success, new sp %p, epc %p, new sigmask %x, sigpending %x, saved sigmask %x",
           tf->sp, tf->epc, p->signal.sigmask, p->signal.sigpending, uc.uc_sigmask);
    return 0;
}

/**
 * @brief Handle default action for a signal.
 *
 * @param p Process
 * @param signo Signal number
 */
static void handle_default(struct proc *p, int signo) {
    tracef("handle_default: pid %d, signo %d, sigpending %x, sigmask %x",
           p->pid, signo, p->signal.sigpending, p->signal.sigmask);
    switch (signo) {
        case SIGUSR0:
        case SIGUSR1:
        case SIGUSR2:
        case SIGTERM:
        case SIGSEGV:
        case SIGINT:
            setkilled(p, -10 - signo);
            break;
        case SIGCHLD:
        case SIGCONT:
            break;
        case SIGKILL:
        case SIGSTOP:
            break; // Checkpoint 2
    }
    p->signal.sigpending &= ~sigmask(signo);
}

// static int valid_signal(int signo) {
//    return signo >= SIGMIN && signo <= SIGMAX;
//}

int siginit(struct proc *p) {
    // Initialize default signal handlers
    memset(&p->signal, 0, sizeof(struct ksignal));
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = NULL;
    }

    // Initialize signal masks and pending signals
    sigemptyset(&p->signal.sigmask);
    sigemptyset(&p->signal.sigpending);

    p->signal.handling_depth = 0;

    return 0;
}

int siginit_fork(struct proc *parent, struct proc *child) {
    // Copy parent's sigactions and signal mask
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        child->signal.sa[i] = parent->signal.sa[i];
    }

    // Copy parent's signal mask
    child->signal.sigmask = parent->signal.sigmask;

    // Clear all pending signals in child
    child->signal.sigpending = 0;

    return 0;
}

int siginit_exec(struct proc *p) {
    // Remember which signals were ignored
    sigset_t ignored = 0;
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        if (p->signal.sa[i].sa_sigaction == SIG_IGN) {
            sigaddset(&ignored, i);
        }
    }

    // Reset all sigactions to default
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = 0;
    }

    // Restore ignored signals
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        if (sigismember(&ignored, i)) {
            p->signal.sa[i].sa_sigaction = SIG_IGN;
        }
    }

    // Inherit signal mask and pending signals
    // (They remain unchanged)

    return 0;
}

int do_signal(void) {
    struct proc *p = curr_proc();
    intr_off(); // Ensure atomicity
    //if (p->signal.handling_signo != -1) {
    //    tracef("do_signal: already handling signo %d, skipping", p->signal.handling_signo);
    //    return 0;
    //}
    tracef("do_signal: pid %d, sigpending %x, sigmask %x",
           p->pid, p->signal.sigpending, p->signal.sigmask);
    // p->signal.sigmask = 1;
    //if (p->signal.in_handler) {
    //    tracef("do_signal: already in handler, skipping");
    //    return 0;
    //}
    if ((p->signal.sigmask & p->signal.sigpending) == p->signal.sigpending) {
        tracef("do_signal: all pending signals masked, skipping");
        return 0;
    }

    // Defensive: Clear unexpected SIGUSR1
    //if (p->signal.sigpending & sigmask(SIGUSR1)) {
    //    tracef("do_signal: clearing unexpected SIGUSR1, sigpending %x", p->signal.sigpending);
    //    p->signal.sigpending &= ~sigmask(SIGUSR1);
    //}

    for (int signo = SIGMIN; signo <= SIGMAX; signo++) {
        if (!(p->signal.sigpending & sigmask(signo)))
            continue;
        if (p->signal.sigmask & sigmask(signo)) {
            tracef("do_signal: signo %d blocked by sigmask %x", signo, p->signal.sigmask);
            continue;
        }

        sigaction_t *sa = &p->signal.sa[signo];
        tracef("do_signal: handling signo %d, action %p", signo, sa->sa_sigaction);
        if (sa->sa_sigaction == SIG_IGN) {
            sigdelset(&p->signal.sigpending, signo);
            tracef("do_signal: ignored signo %d", signo);
        } else if (sa->sa_sigaction == SIG_DFL) {
            handle_default(p, signo);
        } else {
            if (setup_signal_stack(p, signo, sa->sa_sigaction) == 0) {
                sigdelset(&p->signal.sigpending, signo);
                tracef("do_signal: handled signo %d, returning to handler", signo);
                return 1;
            }
            tracef("do_signal: setup failed for signo %d, using default", signo);
            handle_default(p, signo);
        }
    }
    return 0;
}

// syscall handlers:
//  sys_* functions are called by syscall.c

int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    struct proc *p = curr_proc();


    if (signo < SIGMIN || signo > SIGMAX) {
        return -EINVAL;
    }


    if (signo == SIGKILL) {
        return -EINVAL;
    }

    if (oldact) {
        acquire(&p->mm->lock);
        if (copy_to_user(p->mm, (uint64)oldact, (char *)&p->signal.sa[signo], sizeof(sigaction_t)) < 0) {
            release(&p->mm->lock);
            return -1;
        }
        release(&p->mm->lock);
    }

    if (act) {
        sigaction_t kact;
        acquire(&p->mm->lock);
        if (copy_from_user(p->mm, (char *)&kact, (uint64)act, sizeof(sigaction_t)) < 0) {
            release(&p->mm->lock);
            return -1;
        }
        release(&p->mm->lock);

        p->signal.sa[signo] = kact;
    }

    return 0;
}


int sys_sigreturn() {
    struct proc *p = curr_proc();
    assert(!holding(&p->lock));
    acquire(&p->lock);
    struct mm *mm = p->mm;
    struct trapframe *tf = p->trapframe;
    struct ucontext uc;

    tracef("sys_sigreturn: pid %d, sp %p, sigmask %x, sigpending %x",
           p->pid, tf->sp, p->signal.sigmask, p->signal.sigpending);
    acquire(&mm->lock);
    if (copy_from_user(mm, (char*)&uc, tf->sp + sizeof(siginfo_t), sizeof(struct ucontext)) < 0) {
        release(&mm->lock);
        release(&p->lock);
        tracef("sys_sigreturn: failed to copy ucontext");
        return -1;
    }
    release(&mm->lock);

    // Validate sigmask
    sigset_t valid_mask = (1ULL << (SIGMAX + 1)) - 1;
    if (uc.uc_sigmask & ~valid_mask) {
        tracef("sys_sigreturn: invalid sigmask %x, masking to %x", uc.uc_sigmask, uc.uc_sigmask & valid_mask);
        uc.uc_sigmask &= valid_mask;
    }

    p->signal.sigmask = uc.uc_sigmask;
    tf->epc = uc.uc_mcontext.epc;
    tf->ra = uc.uc_mcontext.regs[0];
    tf->sp = uc.uc_mcontext.regs[1];
    tf->gp = uc.uc_mcontext.regs[2];
    tf->tp = uc.uc_mcontext.regs[3];
    tf->t0 = uc.uc_mcontext.regs[4];
    tf->t1 = uc.uc_mcontext.regs[5];
    tf->t2 = uc.uc_mcontext.regs[6];
    tf->s0 = uc.uc_mcontext.regs[7];
    tf->s1 = uc.uc_mcontext.regs[8];
    tf->a0 = uc.uc_mcontext.regs[9];
    tf->a1 = uc.uc_mcontext.regs[10];
    tf->a2 = uc.uc_mcontext.regs[11];
    tf->a3 = uc.uc_mcontext.regs[12];
    tf->a4 = uc.uc_mcontext.regs[13];
    tf->a5 = uc.uc_mcontext.regs[14];
    tf->a6 = uc.uc_mcontext.regs[15];
    tf->a7 = uc.uc_mcontext.regs[16];
    tf->s2 = uc.uc_mcontext.regs[17];
    tf->s3 = uc.uc_mcontext.regs[18];
    tf->s4 = uc.uc_mcontext.regs[19];
    tf->s5 = uc.uc_mcontext.regs[20];
    tf->s6 = uc.uc_mcontext.regs[21];
    tf->s7 = uc.uc_mcontext.regs[22];
    tf->s8 = uc.uc_mcontext.regs[23];
    tf->s9 = uc.uc_mcontext.regs[24];
    tf->s10 = uc.uc_mcontext.regs[25];
    tf->s11 = uc.uc_mcontext.regs[26];
    tf->t3 = uc.uc_mcontext.regs[27];
    tf->t4 = uc.uc_mcontext.regs[28];
    tf->t5 = uc.uc_mcontext.regs[29];
    tf->t6 = uc.uc_mcontext.regs[30];

    // Restore stack pointer
    //tf->sp += sizeof(siginfo_t) + sizeof(struct ucontext);

    // Clear the signal that was being handled
    //if (p->signal.handling_signo != -1) {
    //    //sigdelset(&p->signal.sigpending, p->signal.handling_signo);
    //    tracef("sys_sigreturn: cleared pending signal %d", p->signal.handling_signo);
    //    p->signal.handling_signo = -1;
    //}
    if (p->signal.handling_depth > 0) {
        p->signal.handling_depth--;
    }

    // Restore signal mask from saved context
    p->signal.sigmask = uc.uc_sigmask;

    release(&p->lock);
    tracef("sys_sigreturn: restored, epc %p, sp %p, new sigmask %x, sigpending %x",
           tf->epc, tf->sp, p->signal.sigmask, p->signal.sigpending);
    return 0;
}


int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    struct proc *p = curr_proc();
    assert(!holding(&p->lock));
    acquire(&p->lock);
    struct mm *mm = p->mm;
    sigset_t temp;

    tracef("sys_sigprocmask: pid %d, how %d, sigmask %x, sigpending %x",
           p->pid, how, p->signal.sigmask, p->signal.sigpending);

    if (oldset) {
        acquire(&mm->lock);
        if (copy_to_user(mm, (uint64)oldset, (char*)&p->signal.sigmask, sizeof(sigset_t)) < 0) {
            release(&mm->lock);
            release(&p->lock);
            tracef("sys_sigprocmask: failed to copy oldset");
            return -1;
        }
        release(&mm->lock);
    }

    if (set) {
        acquire(&mm->lock);
        if (copy_from_user(mm, (char*)&temp, (uint64)set, sizeof(sigset_t)) < 0) {
            release(&mm->lock);
            release(&p->lock);
            tracef("sys_sigprocmask: failed to copy set");
            return -1;
        }
        release(&mm->lock);
        switch (how) {
            case SIG_BLOCK:
                p->signal.sigmask |= temp;
                break;
            case SIG_UNBLOCK:
                p->signal.sigmask &= ~temp;
                break;
            case SIG_SETMASK:
                p->signal.sigmask = temp;
                break;
            default:
                release(&p->lock);
                tracef("sys_sigprocmask: invalid how %d", how);
                return -1;
        }
    }

    release(&p->lock);
    tracef("sys_sigprocmask: new sigmask %x, sigpending %x",
           p->signal.sigmask, p->signal.sigpending);
    return 0;
}

int sys_sigpending(sigset_t __user *set) {
    struct proc *p = curr_proc();

    if (set == NULL) {
        return -1;
    }

    acquire(&p->mm->lock);  
    int res = copy_to_user(p->mm, (uint64)set, (char *)&p->signal.sigpending, sizeof(sigset_t));
    release(&p->mm->lock); 

    if (res < 0) {
        return -1;
    }

    return 0;
}

int sys_sigkill(int pid, int signo, int code) {
    // 检查信号编号是否有效
    if (signo < SIGMIN || signo > SIGMAX) {
        return -1;
    }

    // 查找目标进程
    struct proc *target = NULL;
    for (int i = 0; i < NPROC; i++) {
        struct proc *p = pool[i];
        acquire(&p->lock);
        if (p->state != UNUSED && p->pid == pid) {
            target = p;
            break;
        }
        release(&p->lock);
    }

    if (target == NULL) {
        return -1;
    }

    // 设置信号的待处理状态
    sigaddset(&target->signal.sigpending, signo);

    // 设置信号信息
    target->signal.siginfos[signo].si_signo = signo;
    target->signal.siginfos[signo].si_code = code;
    target->signal.siginfos[signo].si_pid = curr_proc()->pid;


    // 如果目标进程正在睡眠，唤醒它
    if (target->state == SLEEPING) {
        wakeup(target->sleep_chan);
    }

    release(&target->lock);

    return 0;
}
