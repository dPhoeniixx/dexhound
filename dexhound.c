// dexdump.c — scan a process for DEX magic, dump each hit
// build: aarch64-linux-android30-clang dexdump.c -o dexdump
// run (as root): ./dexdump <pid|package> <outdir>

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <ctype.h>
#include <dirent.h>

static int is_dex_magic(const uint8_t *p) {
    if (memcmp(p, "dex\n", 4) != 0) return 0;
    if (p[4] < '0' || p[4] > '9') return 0;
    if (p[5] < '0' || p[5] > '9') return 0;
    if (p[6] < '0' || p[6] > '9') return 0;
    if (p[7] != 0) return 0;
    return 1;
}

// Adler-32 over [0x0C .. file_size]. DEX stores it at offset 0x08.
static uint32_t adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a)       % 65521;
    }
    return (b << 16) | a;
}

// Read /proc/<pid>/cmdline into out (NUL-terminated, ":subproc" stripped).
static int read_cmdline_pkg(const char *pid, char *out, size_t outsz) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, out, outsz - 1);
    close(fd);
    if (r <= 0) return -1;
    out[r] = '\0';
    char *colon = strchr(out, ':');
    if (colon) *colon = '\0';
    return 0;
}

// Search /proc for a process whose cmdline matches `pkg`. Returns 0 on success.
static int find_pid_for_package(const char *pkg, char *pid_out, size_t pid_sz) {
    DIR *d = opendir("/proc");
    if (!d) { perror("/proc"); return -1; }
    struct dirent *de;
    int found = 0;
    while ((de = readdir(d))) {
        const char *n = de->d_name;
        int all_digit = 1;
        for (const char *c = n; *c; c++) if (!isdigit((unsigned char)*c)) { all_digit = 0; break; }
        if (!all_digit) continue;
        char cmd[128];
        if (read_cmdline_pkg(n, cmd, sizeof(cmd)) != 0) continue;
        if (strcmp(cmd, pkg) != 0) continue;
        snprintf(pid_out, pid_sz, "%s", n);
        found = 1;
        break;
    }
    closedir(d);
    return found ? 0 : -1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "usage: %s <pid|package> <outdir>\n"
        "  if the first argument is all digits it is treated as a pid,\n"
        "  otherwise it is resolved as a package name via /proc/*/cmdline\n",
        prog);
}

int main(int argc, char **argv) {
    if (argc != 3) { usage(argv[0]); return 1; }
    const char *target = argv[1];
    const char *outdir = argv[2];

    int is_numeric = target[0] != '\0';
    for (const char *c = target; *c; c++) {
        if (!isdigit((unsigned char)*c)) { is_numeric = 0; break; }
    }

    char pid_buf[16];
    const char *pid;

    if (is_numeric) {
        pid = target;
    } else {
        if (find_pid_for_package(target, pid_buf, sizeof(pid_buf)) != 0) {
            fprintf(stderr, "[-] no running process matches package '%s'\n", target);
            return 1;
        }
        pid = pid_buf;
        fprintf(stderr, "[*] resolved package '%s' -> pid %s\n", target, pid);
    }

    char path[256];

    // auto-detect package name from /proc/<pid>/cmdline (NUL-terminated)
    char pkg[128] = "";
    if (read_cmdline_pkg(pid, pkg, sizeof(pkg)) != 0 || !pkg[0]) {
        fprintf(stderr, "could not read package from cmdline\n");
        return 1;
    }
    fprintf(stderr, "[*] target package: %s\n", pkg);

    snprintf(path, sizeof(path), "/proc/%s/maps", pid);
    FILE *maps = fopen(path, "r");
    if (!maps) { perror("maps"); return 1; }

    snprintf(path, sizeof(path), "/proc/%s/mem", pid);
    int mem = open(path, O_RDONLY | O_LARGEFILE);
    if (mem < 0) { perror("mem"); return 1; }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        uint64_t start, end;
        char perms[5];
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s", &start, &end, perms) != 3) continue;
        if (perms[0] != 'r') continue;
        if (strstr(line, "/dev/")) continue;
        uint64_t size = end - start;
        if (size > (1ULL << 30)) continue;

        // capture region path: starts with '/' (file-backed) or '[' (anon labels)
        char src[256] = "[anon]";
        const char *sp = strchr(line, '/');
        if (!sp) sp = strchr(line, '[');
        if (sp) {
            size_t n = strcspn(sp, "\n");
            if (n >= sizeof(src)) n = sizeof(src) - 1;
            memcpy(src, sp, n); src[n] = '\0';
        }

        // filter: drop system/framework and other apps' data dirs
        if (strncmp(src, "/system/", 8) == 0)     continue;
        if (strncmp(src, "/system_ext/", 12) == 0) continue;
        if (strncmp(src, "/apex/", 6) == 0)        continue;
        if (strncmp(src, "/data/", 6) == 0 && !strstr(src, pkg)) continue;

        uint8_t *buf = malloc(size);
        if (!buf) continue;
        if (pread(mem, buf, size, start) != (ssize_t)size) { free(buf); continue; }

        for (uint64_t i = 0; i + 0x70 < size; i++) {
            if (!is_dex_magic(buf + i)) continue;

            uint32_t fsz, hsz, endian, stored_adler;
            memcpy(&stored_adler, buf + i + 0x08, 4);
            memcpy(&fsz,          buf + i + 0x20, 4);
            memcpy(&hsz,          buf + i + 0x24, 4);
            memcpy(&endian,       buf + i + 0x28, 4);

            if (hsz != 0x70) continue;
            if (endian != 0x12345678) continue;
            if (fsz < 0x70 || fsz > size - i) continue;

            uint32_t calc_adler = adler32(buf + i + 0x0C, fsz - 0x0C);
            const char *tag = (calc_adler == stored_adler) ? "OK" : "MISMATCH";

            char out[320];
            snprintf(out, sizeof(out), "%s/dump_%016" PRIx64 "_%s.dex",
                     outdir, start + i, tag);
            int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                write(fd, buf + i, fsz);
                close(fd);
                printf("[+] %s  (%u bytes)  adler32=%08x stored=%08x [%s]  src=%s\n",
                       out, fsz, calc_adler, stored_adler, tag, src);
                found++;
            }
            i += fsz - 1;
        }
        free(buf);
    }
    fclose(maps);
    close(mem);
    printf("done, %d dex dumped\n", found);
    return 0;
}
