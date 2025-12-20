#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <mntent.h>
#include <errno.h>
#include <string.h>
#include <seccomp.h>
#include <fcntl.h>

#define PAGE_SIZE 4096
#define NUM_PAGES 256

typedef struct { int frame[NUM_PAGES]; } PageTable;

void init_page_table(PageTable *pt) { for (int i = 0; i < NUM_PAGES; ++i) pt->frame[i] = -1; }
int allocate_page(PageTable *pt, int page, int frame) { if (page < 0 || page >= NUM_PAGES) return -1; pt->frame[page] = frame; return 0; }
int access_memory(PageTable *pt, unsigned int vaddr) {
    unsigned int page = vaddr / PAGE_SIZE;
    if (page >= NUM_PAGES || pt->frame[page] == -1) { printf("Segmentation fault: illegal access to page %u\n", page); return -1; }
    unsigned int paddr = pt->frame[page] * PAGE_SIZE + (vaddr % PAGE_SIZE);
    printf("Access OK: virtual 0x%x -> physical 0x%x\n", vaddr, paddr);
    return 0;
}

void test_memory_manager() {
    printf("[Memory Manager] Starting memory simulation\n");
    PageTable pt;
    init_page_table(&pt);
    allocate_page(&pt, 0, 9); allocate_page(&pt, 1, 10); allocate_page(&pt, 2, 11);
    access_memory(&pt, 4096); access_memory(&pt, 8192); access_memory(&pt, 0);
    printf("[Memory Manager] Finished test\n");
}

static char child_stack[1048576];
static const char *rootfs_path = "/home/kumari-shreya/sandbox_rootfs";

int mount_proc(const char *target) {
    if (mount("proc", target, "proc", 0, "") != 0) { perror("mount proc failed"); return -1; }
    return 0;
}

int setup_sandbox_environment() {
    if (sethostname("sandbox", 7) != 0) { perror("sethostname failed"); return -1; }
    char proc_path[256]; snprintf(proc_path, sizeof(proc_path), "%s/proc", rootfs_path);
    if (mount_proc(proc_path) != 0) return -1;
    if (chroot(rootfs_path) != 0) { perror("chroot failed"); return -1; }
    if (chdir("/") != 0) { perror("chdir failed"); return -1; }
    return 0;
}

void cleanup_sandbox() {
    char proc_path[256]; snprintf(proc_path, sizeof(proc_path), "%s/proc", rootfs_path);
    if (umount(proc_path) != 0 && errno != EINVAL) perror("umount proc failed");
}

void sandbox_file_access() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(open), 1, SCMP_CMP(1, SCMP_CMP_MASKED_EQ, O_WRONLY|O_RDWR, O_WRONLY|O_RDWR));
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(openat), 1, SCMP_CMP(2, SCMP_CMP_MASKED_EQ, O_WRONLY|O_RDWR, O_WRONLY|O_RDWR));
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unlink), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(creat), 0);
    seccomp_load(ctx); seccomp_release(ctx);
}

void sandbox_network_security() {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(connect), 0);
    seccomp_load(ctx); seccomp_release(ctx);
}

int child_fn(void *arg) {
    char **child_argv = (char **)arg;

    if (setup_sandbox_environment() != 0) exit(1);
    sandbox_file_access();
    sandbox_network_security();

    if (!child_argv || !child_argv[0]) {
        execlp("/bin/sh", "/bin/sh", NULL);
        perror("execlp sh failed"); exit(1);
    }

    execvp(child_argv[0], child_argv);
    perror("execvp failed");
    exit(1);
}

int main(int argc, char *argv[]) {
    test_memory_manager();

    char proc_path[256]; snprintf(proc_path, sizeof(proc_path), "%s/proc", rootfs_path);
    FILE *m = setmntent("/proc/mounts", "r");
    if (m) { struct mntent *ent; while ((ent = getmntent(m))) if (strcmp(ent->mnt_dir, proc_path) == 0) { endmntent(m); return 0; } endmntent(m); }

    int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD;
    pid_t p = clone(child_fn, child_stack + sizeof(child_stack), flags, argv + 1);
    if (p == -1) { perror("clone failed"); return 1; }
    waitpid(p, NULL, 0);
    printf("[Process Manager] Sandbox exited.\n");
    cleanup_sandbox();
    return 0;
}
