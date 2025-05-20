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
static int handle_stack(struct proc *p, int signo, void (*handler)(int, siginfo_t*, void*)) {
    struct trapframe *tf = p->trapframe;
    struct mm *mm = p->mm;
    uint64 sp = tf->sp;

    sp = sp & ~0xf;

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

    sp -= sizeof(siginfo_t);
    siginfo_t si;
    memset(&si, 0, sizeof(siginfo_t));

    acquire(&mm->lock);
    if (copy_to_user(mm, sp, (char*)&si, sizeof(siginfo_t)) < 0 ||
        copy_to_user(mm, sp + sizeof(siginfo_t), (char*)&uc, sizeof(struct ucontext)) < 0) {
        release(&mm->lock);
        return -1;
    }
    release(&mm->lock);

    tf->sp = sp;
    tf->epc = (uint64)handler;
    tf->a0 = signo;
    tf->a1 = sp;
    tf->a2 = sp + sizeof(siginfo_t);
    tf->ra = (uint64)p->signal.sa[signo].sa_restorer;
    p->signal.sigmask |= p->signal.sa[signo].sa_mask | sigmask(signo);
    p->signal.handling_depth++;
    return 0;
}

/**
 * @brief Handle default action for a signal.
 *
 * @param p Process
 * @param signo Signal number
 */

int siginit(struct proc *p) {
    memset(&p->signal, 0, sizeof(struct ksignal));
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = NULL;
    }

    sigemptyset(&p->signal.sigmask);
    sigemptyset(&p->signal.sigpending);
    p->signal.handling_depth = 0;
    return 0;
}

int siginit_fork(struct proc *parent, struct proc *child) {
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        child->signal.sa[i] = parent->signal.sa[i];
    }
    child->signal.sigmask = parent->signal.sigmask;
    child->signal.sigpending = 0;
    return 0;
}

int siginit_exec(struct proc *p) {
    sigset_t ignored = 0;
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        if (p->signal.sa[i].sa_sigaction == SIG_IGN) {
            sigaddset(&ignored, i);
        }
    }

    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = 0;
    }

    for (int i = SIGMIN; i <= SIGMAX; i++) {
        if (sigismember(&ignored, i)) {
            p->signal.sa[i].sa_sigaction = SIG_IGN;
        }
    }

    return 0;
}

int do_signal(void) {
    struct proc *p = curr_proc();
    intr_off();

    if ((p->signal.sigmask & p->signal.sigpending) == p->signal.sigpending) {
        return 0;
    }

    for (int signo = SIGMIN; signo <= SIGMAX; signo++) {
        if (!(p->signal.sigpending & sigmask(signo)))
            continue;
        if (p->signal.sigmask & sigmask(signo)) {
            continue;
        }

        sigaction_t *sa = &p->signal.sa[signo];
        if (sa->sa_sigaction == SIG_IGN) {
            sigdelset(&p->signal.sigpending, signo);
        } else if (sa->sa_sigaction == SIG_DFL) {
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
        } else {
            if (handle_stack(p, signo, sa->sa_sigaction) == 0) {
                sigdelset(&p->signal.sigpending, signo);
                return 1;
            }
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
    acquire(&mm->lock);
    if (copy_from_user(mm, (char*)&uc, tf->sp + sizeof(siginfo_t), sizeof(struct ucontext)) < 0) {
        release(&p->mm->lock);
        return -1;
    }
    release(&p->mm->lock);

    sigset_t valid_mask = (1ULL << (SIGMAX + 1)) - 1;
    if (uc.uc_sigmask & ~valid_mask) {
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

    if (p->signal.handling_depth > 0) {
        p->signal.handling_depth--;
    }

    p->signal.sigmask = uc.uc_sigmask;

    release(&p->lock);
    return 0;
}


int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
return 0;
}

int sys_sigpending(sigset_t __user *set) {
struct proc *p = curr_proc();
if (set == NULL) {
return -1;
}
acquire(&p->mm->lock);
int err = copy_to_user(p->mm, (uint64)set, (char *)&p->signal.sigpending, sizeof(sigset_t));
release(&p->mm->lock);
if (err < 0) {
return -1;
}
return 0;
}

int sys_sigkill(int pid, int signo, int code) {
    if (signo < SIGMIN || signo > SIGMAX) {
        return -1;
    }

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

    sigaddset(&target->signal.sigpending, signo);

    target->signal.siginfos[signo].si_signo = signo;
    target->signal.siginfos[signo].si_code = code;
    target->signal.siginfos[signo].si_pid = curr_proc()->pid;


    if (target->state == SLEEPING) {
        wakeup(target->sleep_chan);
    }

    release(&target->lock);

    return 0;
}
