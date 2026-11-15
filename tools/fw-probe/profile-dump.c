/*
 * Blackwire profile dump — read instruction bytes at resolved export
 * addresses for fw 8.00 native_profile.c port.
 * Serves JSON on port 5922. Requires a game running.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

#include <sys/types.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#ifndef SYS___sysctl
#define SYS___sysctl 202
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ps5/kernel.h>

#define LISTEN_PORT 5922
#define BUF_SIZE (512 * 1024)

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char     title_id[10];
    char     unknown2[0x3c];
} app_info_t;
__attribute__((weak)) int sceKernelGetAppInfo(pid_t pid, app_info_t *info);

static pid_t find_game(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t sz = 0;
    if (sysctl(mib, 4, NULL, &sz, NULL, 0)) return -1;
    void *buf = malloc(sz);
    if (!buf || sysctl(mib, 4, buf, &sz, NULL, 0)) { free(buf); return -1; }
    pid_t best = -1;
    for (void *p = buf; p < buf + sz;) {
        struct kinfo_proc *ki = (struct kinfo_proc *)p;
        if (ki->ki_structsize <= 0) break;
        p += ki->ki_structsize;
        if (ki->ki_pid <= 1) continue;
        if (strstr(ki->ki_comm, "eboot")) { best = ki->ki_pid; break; }
        if (sceKernelGetAppInfo) {
            app_info_t ai = {0};
            sceKernelGetAppInfo(ki->ki_pid, &ai);
            if (ai.title_id[0] == 'C' || ai.title_id[0] == 'P')
                { best = ki->ki_pid; break; }
        }
    }
    free(buf);
    return best;
}

static void hex_bytes(char *out, size_t cap, const unsigned char *d, size_t len) {
    size_t pos = 0;
    for (size_t i = 0; i < len && pos + 6 < cap; i++) {
        if (i) out[pos++] = ',';
        pos += snprintf(out + pos, cap - pos, "0x%02x", d[i]);
    }
    out[pos] = '\0';
}

struct sym_entry {
    const char *name;
    const char *nid_name;
    size_t dump_len;
};

static const struct sym_entry lk_syms[] = {
    {"sceKernelAioSubmitReadCommands", NULL, 48},
    {"sceKernelAioSubmitReadCommandsMultiple", NULL, 48},
    {"sceKernelAioPollRequest", NULL, 48},
    {"sceKernelPread", NULL, 48},
    {"preadv", NULL, 48},
    {"read", NULL, 48},
    {"readv", NULL, 48},
    {"lseek", NULL, 48},
    {"close", NULL, 48},
    {"fstat", NULL, 48},
    {"sceKernelOpen", NULL, 48},
    {"__error", NULL, 128},
};
#define LK_SYM_COUNT (sizeof(lk_syms)/sizeof(lk_syms[0]))

/* Ampr PRX: scan for recognizable instruction patterns */
struct scan_region {
    uint64_t start;
    uint64_t length;
    const char *label;
};

static const struct scan_region ampr_scans[] = {
    /* Text segment regions where hook points typically live */
    {0x0f000, 0x2000, "ampr_text_0f000"},
    {0x12000, 0x2000, "ampr_text_12000"},
    {0x1b000, 0x3000, "ampr_text_1b000"},
    {0x1f000, 0x4000, "ampr_text_1f000"},
    {0x42000, 0x2000, "ampr_text_42000"},
    {0x4a000, 0x2000, "ampr_text_4a000"},
    {0x0e000, 0x1000, "ampr_text_0e000"},
};

static int gather(char *out, size_t cap, pid_t pid) {
    int n = 0;
    uint32_t lk_h = 0, ampr_h = 0;
    intptr_t lk_base = 0, ampr_base = 0;

    kernel_dynlib_handle(pid, "libkernel.sprx", &lk_h);
    lk_base = kernel_dynlib_mapbase_addr(pid, lk_h);
    kernel_dynlib_handle(pid, "libSceAmpr.sprx", &ampr_h);
    ampr_base = kernel_dynlib_mapbase_addr(pid, ampr_h);

    n += snprintf(out + n, cap - n,
        "{\n  \"firmware\": \"0x%08x\",\n  \"game_pid\": %d,\n"
        "  \"libkernel_base\": \"0x%lx\",\n  \"ampr_base\": \"0x%lx\",\n"
        "  \"exports\": [\n",
        kernel_get_fw_version(), pid,
        (unsigned long)lk_base, (unsigned long)ampr_base);

    unsigned char bytes[256];
    char hex[2048];

    for (size_t i = 0; i < LK_SYM_COUNT; i++) {
        intptr_t addr = kernel_dynlib_dlsym(pid, lk_h, lk_syms[i].name);
        uint64_t offset = addr ? (uint64_t)(addr - lk_base) : 0;
        size_t dlen = lk_syms[i].dump_len;
        if (dlen > sizeof(bytes)) dlen = sizeof(bytes);

        int ok = -1;
        memset(bytes, 0xcc, sizeof(bytes));
        if (addr)
            ok = kernel_proc_copyout(pid, addr, bytes, dlen);

        hex_bytes(hex, sizeof(hex), bytes, dlen);
        n += snprintf(out + n, cap - n,
            "    {\"symbol\": \"%s\", \"addr\": \"0x%lx\", \"offset\": \"0x%lx\", "
            "\"read_ok\": %s, \"bytes\": [%s]}%s\n",
            lk_syms[i].name, (unsigned long)addr, (unsigned long)offset,
            ok == 0 ? "true" : "false", hex,
            (i + 1 < LK_SYM_COUNT) ? "," : "");
    }
    n += snprintf(out + n, cap - n, "  ],\n");

    /* Also dump pread raw stub and lseek raw stub at known offsets */
    n += snprintf(out + n, cap - n, "  \"raw_stubs\": [\n");
    struct { const char *name; uint64_t off; size_t len; } stubs[] = {
        {"pread_raw_0x1820", 0x1820, 32},
        {"lseek_raw_0x1880", 0x1880, 32},
    };
    for (size_t i = 0; i < 2; i++) {
        memset(bytes, 0xcc, sizeof(bytes));
        int ok = kernel_proc_copyout(pid, lk_base + stubs[i].off, bytes, stubs[i].len);
        hex_bytes(hex, sizeof(hex), bytes, stubs[i].len);
        n += snprintf(out + n, cap - n,
            "    {\"label\": \"%s\", \"offset\": \"0x%lx\", \"read_ok\": %s, \"bytes\": [%s]}%s\n",
            stubs[i].name, (unsigned long)stubs[i].off,
            ok == 0 ? "true" : "false", hex, i < 1 ? "," : "");
    }
    n += snprintf(out + n, cap - n, "  ],\n");

    /* Ampr: dump the RW data region to find slot layout */
    n += snprintf(out + n, cap - n, "  \"ampr_slot_scan\": {\n    \"base\": \"0x%lx\",\n    \"regions\": [\n",
        (unsigned long)ampr_base);
    /* Scan the slot table area (0x64000-0x68000) to find where slots are */
    struct { const char *label; uint64_t off; size_t len; } slot_scans[] = {
        {"slots_64800_64ac0", 0x64800, 0x2c0},
        {"aio_state_67200_67400", 0x67200, 0x200},
    };
    for (size_t i = 0; i < 2; i++) {
        size_t slen = slot_scans[i].len;
        unsigned char *sbuf = malloc(slen);
        memset(sbuf, 0xcc, slen);
        int ok = ampr_base ? kernel_proc_copyout(pid, ampr_base + slot_scans[i].off, sbuf, slen) : -1;
        n += snprintf(out + n, cap - n,
            "      {\"label\": \"%s\", \"offset\": \"0x%lx\", \"length\": %zu, \"read_ok\": %s, \"bytes\": [",
            slot_scans[i].label, (unsigned long)slot_scans[i].off, slen,
            ok == 0 ? "true" : "false");
        if (ok == 0) hex_bytes(out + n, cap - n, sbuf, slen);
        n += strlen(out + n);
        n += snprintf(out + n, cap - n, "]}%s\n", i < 1 ? "," : "");
        free(sbuf);
    }
    n += snprintf(out + n, cap - n, "    ]\n  },\n");

    /* Ampr: dump broader code regions to find hook entry points */
    n += snprintf(out + n, cap - n, "  \"ampr_code_scan\": {\n    \"base\": \"0x%lx\",\n    \"regions\": [\n",
        (unsigned long)ampr_base);
    size_t scan_count = sizeof(ampr_scans)/sizeof(ampr_scans[0]);
    for (size_t i = 0; i < scan_count; i++) {
        /* Only dump first 128 bytes of each region as a fingerprint */
        size_t dlen = 128;
        memset(bytes, 0xcc, sizeof(bytes));
        int ok = ampr_base ? kernel_proc_copyout(pid, ampr_base + ampr_scans[i].start, bytes, dlen) : -1;
        hex_bytes(hex, sizeof(hex), bytes, dlen);
        n += snprintf(out + n, cap - n,
            "      {\"label\": \"%s\", \"offset\": \"0x%lx\", \"full_size\": %lu, \"read_ok\": %s, \"first_128\": [%s]}%s\n",
            ampr_scans[i].label, (unsigned long)ampr_scans[i].start,
            (unsigned long)ampr_scans[i].length,
            ok == 0 ? "true" : "false", hex,
            (i + 1 < scan_count) ? "," : "");
    }
    n += snprintf(out + n, cap - n, "    ]\n  }\n}\n");
    return n;
}

static void serve(int fd, const char *j, int len) {
    char h[256];
    int hl = snprintf(h, sizeof(h),
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
        "Content-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n", len);
    write(fd, h, hl);
    write(fd, j, len);
}

int main(void) {
    char *json = malloc(BUF_SIZE);
    if (!json) return 1;

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return 1;
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(LISTEN_PORT), .sin_addr.s_addr = INADDR_ANY };
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    listen(sfd, 4);

    for (;;) {
        struct sockaddr_in ca; socklen_t cl = sizeof(ca);
        int cfd = accept(sfd, (struct sockaddr *)&ca, &cl);
        if (cfd < 0) continue;
        char req[1024] = {0};
        read(cfd, req, sizeof(req) - 1);

        if (strstr(req, "GET /")) {
            pid_t gpid = find_game();
            if (gpid <= 0) {
                const char *e = "{\"error\":\"No game found\"}";
                serve(cfd, e, strlen(e));
            } else {
                int len = gather(json, BUF_SIZE, gpid);
                serve(cfd, json, len);
            }
        }
        close(cfd);
    }
}
