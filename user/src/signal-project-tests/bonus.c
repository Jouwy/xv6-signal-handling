#include "../../os/ktest/ktest.h"
#include "../lib/user.h"

void handler_siginfo(int signo, siginfo_t *info, void *ctx) {
    assert(info != 0);

    if (signo == SIGUSR1) {
        assert(info->si_signo == SIGUSR1);
        assert(info->si_pid == getppid());
        assert(info->si_code == 42);
        assert(info->si_status == 0);
        assert(info->addr == 0);
        //fprintf(1, "SIGUSR1 fields are correct!\n");
    } else if (signo == SIGUSR2) {
        assert(info->si_signo == SIGUSR2);
        assert(info->si_pid == -1);
        assert(info->si_code == 0);
        assert(info->si_status == 0);
        assert(info->addr == 0);
        //fprintf(1, "SIGUSR2 (kernel-emulated) fields are correct!\n");
    } else {
        assert(0 && "Unexpected signal");
    }

    // Exit only after both have been received.
    static int received = 0;
    received++;
    if (received == 2) {
        exit(200);
    }
}

void siginfo(char *s) {
    int pid = fork();
    if (pid == 0) {
        // child registers handlers for both signals
        sigaction_t sa;
        sa.sa_sigaction = handler_siginfo;
        sa.sa_restorer = sigreturn;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, 0);
        sigaction(SIGUSR2, &sa, 0);  // kernel-emulated

        while (1);
        exit(1);
    } else {
        // parent
        sleep(5);
        sigkill(pid, SIGUSR1, 42);
        sleep(5);
        sigkill(pid, SIGUSR2, 0);
        int status;
        wait(0, &status);
        assert_eq(status, 200);
    }
}

volatile int handler_done = 0;
void handler_sigchld(int signo, siginfo_t *info, void *ctx) {
    assert(signo == SIGCHLD);
    assert(info != 0);

    int status;
    int pid = wait(-1, &status);

    assert(info->si_signo == SIGCHLD);
    assert(info->si_pid == pid);
    assert(info->si_code == 123);

    //fprintf(1, "SIGCHLD handler received. Child PID: %d Exit code: %d\n",
            info->si_pid, info->si_code);

    handler_done = 1;
}

void sigchld(char *s) {
    sigaction_t sa;
    sa.sa_sigaction = handler_sigchld;
    sa.sa_restorer = sigreturn;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, 0);

    int pid = fork();
    if (pid == 0) {
        exit(123);
    }

    while (!handler_done) {
    }

    //fprintf(1, "sigchld_bonus exiting with code 200\n");
    exit(0);
}
