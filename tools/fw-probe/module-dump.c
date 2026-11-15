/*
 * Blackwire module dump probe — discover Ampr PRX and libkernel byte windows
 * from a running game process on fw 8.00.
 * Requires a game to be running. Serves JSON on port 5921.
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

#define LOG_PATH "/data/blackwire/module-dump.log"
#define LISTEN_PORT 5921
#define BUF_SIZE (1024 * 1024)

static FILE *logfp;

static void logmsg(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fflush(stdout);
    if (logfp) {
        va_start(ap, fmt);
        vfprintf(logfp, fmt, ap);
        va_end(ap);
        fflush(logfp);
    }
}

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char     title_id[10];
    char     unknown2[0x3c];
} app_info_t;

__attribute__((weak)) int sceKernelGetAppInfo(pid_t pid, app_info_t *info);

struct dump_request {
    uint64_t offset;
    size_t   length;
    const char *label;
};

/* Ampr instruction windows from native_profile.c */
static const struct dump_request ampr_windows[] = {
    {0x0fb00, 17, "main_entry"},
    {0x1f7f2,  7, "lseek"},
    {0x1fb96,  7, "pread"},
    {0x1fd8d,  7, "preadv"},
    {0x20114,  7, "read"},
    {0x20421,  7, "readv"},
    {0x2124c,  7, "aio_single"},
    {0x0fb7c,  7, "aio_multiple"},
    {0x12fd4,  7, "aio_poll"},
    {0x1d5ab,  7, "close"},
    {0x1d6ee,  7, "fstat"},
    {0x1bf4b,  7, "open"},
};

/* Ampr runtime windows */
static const struct dump_request ampr_runtime[] = {
    {0x42d3f,  11, "rt_init_flag"},
    {0x42d88,  10, "rt_check"},
    {0x43144,  17, "rt_refresh"},
    {0x4b040, 378, "rt_installer"},
    {0x0e43f,  10, "rt_mask"},
};

/* Ampr RW data region offsets */
static const struct dump_request ampr_rw_data[] = {
    {0x60000,   8, "rw_first_8bytes"},
    {0x64850,   8, "open_slot"},
    {0x64a58,   8, "close_slot"},
    {0x64a60,   8, "fstat_slot"},
    {0x64a68,   8, "lseek_slot"},
    {0x64a80,   8, "pread_slot"},
    {0x64a88,   8, "preadv_slot"},
    {0x64a90,   8, "read_slot"},
    {0x64a98,   8, "readv_slot"},
    {0x64aa0,   8, "aio_single_slot"},
    {0x64aa8,   8, "aio_multiple_slot"},
    {0x64ab0,   8, "aio_poll_slot"},
    {0x672f8,   8, "aio_trampoline"},
    {0x67348,   1, "aio_installed"},
};

/* Libkernel export entry points to dump */
static const struct dump_request lk_exports[] = {
    {0x168d0, 32, "AioSubmitReadCommands"},
    {0x16910, 32, "AioSubmitReadCommandsMultiple"},
    {0x167b0, 32, "AioPollRequest"},
    {0x12910, 32, "pread_export"},
    {0x011c0, 32, "preadv_export"},
    {0x0e370, 32, "read_export"},
    {0x0e3d0, 32, "readv_export"},
    {0x128f0, 32, "lseek_export"},
    {0x0dc40, 32, "close_export"},
    {0x00e60, 32, "fstat_export"},
    {0x0e020, 32, "open_export"},
    {0x02e00, 110, "__error_export"},
    {0x01820, 32, "pread_raw"},
    {0x01880, 32, "lseek_raw"},
};

static pid_t find_game_pid(char *out_comm, size_t comm_size) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t buf_size = 0;
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) != 0 || buf_size == 0)
        return -1;
    void *buf = malloc(buf_size);
    if (!buf || sysctl(mib, 4, buf, &buf_size, NULL, 0) != 0) {
        free(buf);
        return -1;
    }
    pid_t best = -1;
    for (void *ptr = buf; ptr < buf + buf_size;) {
        struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
        if (ki->ki_structsize <= 0) break;
        ptr += ki->ki_structsize;
        if (ki->ki_pid <= 1) continue;

        /* Try app info if available */
        if (sceKernelGetAppInfo) {
            app_info_t ai = {0};
            sceKernelGetAppInfo(ki->ki_pid, &ai);
            if (ai.title_id[0] == 'C' || ai.title_id[0] == 'P') {
                best = ki->ki_pid;
                strncpy(out_comm, ki->ki_comm, comm_size - 1);
                out_comm[comm_size - 1] = '\0';
                break;
            }
        }

        /* Fallback: look for eboot.bin which is the game executable */
        if (best < 0 && strstr(ki->ki_comm, "eboot")) {
            best = ki->ki_pid;
            strncpy(out_comm, ki->ki_comm, comm_size - 1);
            out_comm[comm_size - 1] = '\0';
        }
    }
    free(buf);
    return best;
}

static int list_all_processes(char *out, size_t cap) {
    int n = 0;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t buf_size = 0;
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) != 0 || buf_size == 0)
        return snprintf(out, cap, "{\"error\":\"sysctl failed\"}");

    void *buf = malloc(buf_size);
    if (!buf || sysctl(mib, 4, buf, &buf_size, NULL, 0) != 0) {
        free(buf);
        return snprintf(out, cap, "{\"error\":\"sysctl alloc/read failed\"}");
    }

    n += snprintf(out + n, cap - n,
        "{\"sceKernelGetAppInfo_available\": %s,\n \"processes\": [\n",
        sceKernelGetAppInfo ? "true" : "false");

    int first = 1;
    for (void *ptr = buf; ptr < buf + buf_size;) {
        struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
        if (ki->ki_structsize <= 0) break;
        ptr += ki->ki_structsize;

        app_info_t ai = {0};
        int has_ai = 0;
        if (sceKernelGetAppInfo && ki->ki_pid > 0) {
            has_ai = (sceKernelGetAppInfo(ki->ki_pid, &ai) == 0);
        }

        /* Try to find Ampr in this process */
        uint32_t ampr_h = 0;
        int has_ampr = (ki->ki_pid > 1 &&
            kernel_dynlib_handle(ki->ki_pid, "libSceAmpr.sprx", &ampr_h) == 0);

        if (!first) n += snprintf(out + n, cap - n, ",\n");
        first = 0;
        n += snprintf(out + n, cap - n,
            "  {\"pid\": %d, \"ppid\": %d, \"uid\": %u, \"comm\": \"%.19s\", "
            "\"stat\": %d, \"app_id\": %u, \"title_id\": \"%.9s\", "
            "\"has_app_info\": %s, \"has_ampr\": %s}",
            ki->ki_pid, ki->ki_ppid, ki->ki_uid, ki->ki_comm,
            (int)ki->ki_stat, ai.app_id, ai.title_id,
            has_ai ? "true" : "false",
            has_ampr ? "true" : "false");
    }
    n += snprintf(out + n, cap - n, "\n],\n\"hint\": \"Find the process with has_ampr=true, "
        "then use GET /dump?pid=<that_pid>\"}\n");

    free(buf);
    return n;
}

static void hex_append(char *out, size_t cap, int *n,
                       const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len && (size_t)*n + 6 < cap; i++) {
        if (i > 0) *n += snprintf(out + *n, cap - *n, ",");
        *n += snprintf(out + *n, cap - *n, "0x%02x", data[i]);
    }
}

static void dump_section(char *out, size_t cap, int *n,
                         pid_t pid, uint64_t base, const char *name,
                         const struct dump_request *reqs, size_t count) {
    unsigned char buf[512];
    *n += snprintf(out + *n, cap - *n,
        "  \"%s\": {\n    \"base\": \"0x%lx\",\n    \"regions\": [\n",
        name, (unsigned long)base);

    for (size_t i = 0; i < count; i++) {
        size_t len = reqs[i].length;
        if (len > sizeof(buf)) len = sizeof(buf);
        memset(buf, 0, sizeof(buf));

        int ok = -1;
        if (base != 0 && pid > 0)
            ok = kernel_proc_copyout(pid, (intptr_t)(base + reqs[i].offset), buf, len);

        *n += snprintf(out + *n, cap - *n,
            "      {\"label\": \"%s\", \"offset\": \"0x%lx\", \"length\": %zu, "
            "\"read_ok\": %s, \"bytes\": [",
            reqs[i].label, (unsigned long)reqs[i].offset, len,
            ok == 0 ? "true" : "false");
        if (ok == 0)
            hex_append(out, cap, n, buf, len);
        *n += snprintf(out + *n, cap - *n, "]}%s\n",
            (i + 1 < count) ? "," : "");
    }
    *n += snprintf(out + *n, cap - *n, "    ]\n  }");
}

static int gather_dump(char *out, size_t cap, pid_t game_pid, const char *comm) {
    int n = 0;
    uint32_t ampr_handle = 0, lk_handle = 0;
    intptr_t ampr_base = 0, lk_base = 0;

    int ampr_ok = kernel_dynlib_handle(game_pid, "libSceAmpr.sprx", &ampr_handle);
    if (ampr_ok == 0)
        ampr_base = kernel_dynlib_mapbase_addr(game_pid, ampr_handle);

    int lk_ok = kernel_dynlib_handle(game_pid, "libkernel.sprx", &lk_handle);
    if (lk_ok == 0)
        lk_base = kernel_dynlib_mapbase_addr(game_pid, lk_handle);

    /* Also try resolving key symbols to get their actual offsets */
    intptr_t sym_pread = 0, sym_open = 0, sym_error = 0;
    if (lk_ok == 0) {
        sym_pread = kernel_dynlib_dlsym(game_pid, lk_handle, "sceKernelPread");
        sym_open  = kernel_dynlib_dlsym(game_pid, lk_handle, "sceKernelOpen");
        sym_error = kernel_dynlib_dlsym(game_pid, lk_handle, "__error");
    }

    intptr_t sym_aio_single = 0, sym_aio_multi = 0, sym_aio_poll = 0;
    intptr_t sym_read = 0, sym_readv = 0, sym_preadv = 0;
    intptr_t sym_lseek = 0, sym_close = 0, sym_fstat = 0;
    if (lk_ok == 0) {
        sym_aio_single = kernel_dynlib_dlsym(game_pid, lk_handle, "sceKernelAioSubmitReadCommands");
        sym_aio_multi  = kernel_dynlib_dlsym(game_pid, lk_handle, "sceKernelAioSubmitReadCommandsMultiple");
        sym_aio_poll   = kernel_dynlib_dlsym(game_pid, lk_handle, "sceKernelAioPollRequest");
        sym_read       = kernel_dynlib_dlsym(game_pid, lk_handle, "read");
        sym_readv      = kernel_dynlib_dlsym(game_pid, lk_handle, "readv");
        sym_preadv     = kernel_dynlib_dlsym(game_pid, lk_handle, "preadv");
        sym_lseek      = kernel_dynlib_dlsym(game_pid, lk_handle, "lseek");
        sym_close      = kernel_dynlib_dlsym(game_pid, lk_handle, "close");
        sym_fstat      = kernel_dynlib_dlsym(game_pid, lk_handle, "fstat");
    }

    n += snprintf(out + n, cap - n,
        "{\n"
        "  \"probe\": \"blackwire-module-dump-v1\",\n"
        "  \"firmware\": \"0x%08x\",\n"
        "  \"game_pid\": %d,\n"
        "  \"game_comm\": \"%s\",\n"
        "  \"ampr_found\": %s,\n"
        "  \"ampr_base\": \"0x%lx\",\n"
        "  \"ampr_handle\": %u,\n"
        "  \"libkernel_found\": %s,\n"
        "  \"libkernel_base\": \"0x%lx\",\n"
        "  \"libkernel_handle\": %u,\n"
        "  \"resolved_symbols\": {\n"
        "    \"sceKernelPread\": \"0x%lx\",\n"
        "    \"sceKernelOpen\": \"0x%lx\",\n"
        "    \"__error\": \"0x%lx\",\n"
        "    \"sceKernelAioSubmitReadCommands\": \"0x%lx\",\n"
        "    \"sceKernelAioSubmitReadCommandsMultiple\": \"0x%lx\",\n"
        "    \"sceKernelAioPollRequest\": \"0x%lx\",\n"
        "    \"read\": \"0x%lx\",\n"
        "    \"readv\": \"0x%lx\",\n"
        "    \"preadv\": \"0x%lx\",\n"
        "    \"lseek\": \"0x%lx\",\n"
        "    \"close\": \"0x%lx\",\n"
        "    \"fstat\": \"0x%lx\"\n"
        "  },\n"
        "  \"computed_offsets\": {\n"
        "    \"pread\": \"0x%lx\",\n"
        "    \"open\": \"0x%lx\",\n"
        "    \"__error\": \"0x%lx\",\n"
        "    \"aio_single\": \"0x%lx\",\n"
        "    \"aio_multi\": \"0x%lx\",\n"
        "    \"aio_poll\": \"0x%lx\",\n"
        "    \"read\": \"0x%lx\",\n"
        "    \"readv\": \"0x%lx\",\n"
        "    \"preadv\": \"0x%lx\",\n"
        "    \"lseek\": \"0x%lx\",\n"
        "    \"close\": \"0x%lx\",\n"
        "    \"fstat\": \"0x%lx\"\n"
        "  },\n",
        kernel_get_fw_version(), game_pid, comm,
        ampr_ok == 0 ? "true" : "false", (unsigned long)ampr_base, ampr_handle,
        lk_ok == 0 ? "true" : "false", (unsigned long)lk_base, lk_handle,
        (unsigned long)sym_pread, (unsigned long)sym_open, (unsigned long)sym_error,
        (unsigned long)sym_aio_single, (unsigned long)sym_aio_multi, (unsigned long)sym_aio_poll,
        (unsigned long)sym_read, (unsigned long)sym_readv, (unsigned long)sym_preadv,
        (unsigned long)sym_lseek, (unsigned long)sym_close, (unsigned long)sym_fstat,
        lk_base ? (unsigned long)(sym_pread - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_open - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_error - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_aio_single - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_aio_multi - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_aio_poll - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_read - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_readv - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_preadv - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_lseek - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_close - lk_base) : 0UL,
        lk_base ? (unsigned long)(sym_fstat - lk_base) : 0UL);

    dump_section(out, cap, &n, game_pid, (uint64_t)ampr_base, "ampr_windows",
                 ampr_windows, sizeof(ampr_windows)/sizeof(ampr_windows[0]));
    n += snprintf(out + n, cap - n, ",\n");

    dump_section(out, cap, &n, game_pid, (uint64_t)ampr_base, "ampr_runtime",
                 ampr_runtime, sizeof(ampr_runtime)/sizeof(ampr_runtime[0]));
    n += snprintf(out + n, cap - n, ",\n");

    dump_section(out, cap, &n, game_pid, (uint64_t)ampr_base, "ampr_rw_data",
                 ampr_rw_data, sizeof(ampr_rw_data)/sizeof(ampr_rw_data[0]));
    n += snprintf(out + n, cap - n, ",\n");

    dump_section(out, cap, &n, game_pid, (uint64_t)lk_base, "libkernel_exports",
                 lk_exports, sizeof(lk_exports)/sizeof(lk_exports[0]));
    n += snprintf(out + n, cap - n, "\n}\n");

    return n;
}

static void serve_http(int fd, const char *json, int len) {
    char hdr[512];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n\r\n", len);
    write(fd, hdr, hlen);
    write(fd, json, len);
}

int main(void) {
    mkdir("/data/blackwire", 0755);
    logfp = fopen(LOG_PATH, "w");

    logmsg("=== Blackwire Module Dump v1 ===\n");
    logmsg("FW: 0x%08x\n", kernel_get_fw_version());
    logmsg("Port: %d\n\n", LISTEN_PORT);
    logmsg("Endpoints:\n");
    logmsg("  GET /list         -> all processes + which have Ampr loaded\n");
    logmsg("  GET /dump?pid=N   -> dump module data from process N\n");
    logmsg("  GET /             -> auto-detect game and dump\n\n");

    char *json = malloc(BUF_SIZE);
    if (!json) { logmsg("FATAL: malloc\n"); return 1; }

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) { logmsg("FATAL: socket: %s\n", strerror(errno)); return 1; }
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(LISTEN_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logmsg("FATAL: bind: %s\n", strerror(errno));
        return 1;
    }
    listen(sfd, 4);
    logmsg("Ready.\n");

    for (;;) {
        struct sockaddr_in ca;
        socklen_t cl = sizeof(ca);
        int cfd = accept(sfd, (struct sockaddr *)&ca, &cl);
        if (cfd < 0) continue;

        char req[4096] = {0};
        read(cfd, req, sizeof(req) - 1);

        if (strstr(req, "GET /list")) {
            int len = list_all_processes(json, BUF_SIZE);
            logmsg("[list] %d bytes\n", len);
            serve_http(cfd, json, len);
        } else if (strstr(req, "GET /dump")) {
            /* Parse ?pid=N from request */
            pid_t target = 0;
            const char *pp = strstr(req, "pid=");
            if (pp) target = (pid_t)atoi(pp + 4);

            if (target <= 0) {
                /* Auto-detect */
                char comm[20] = "none";
                target = find_game_pid(comm, sizeof(comm));
                if (target <= 0) {
                    const char *err = "{\"error\":\"No game auto-detected. Use GET /list to find the PID, then GET /dump?pid=N\"}";
                    serve_http(cfd, err, strlen(err));
                    close(cfd);
                    continue;
                }
                logmsg("[dump] auto pid=%d comm=%s\n", target, comm);
                int len = gather_dump(json, BUF_SIZE, target, comm);
                serve_http(cfd, json, len);
            } else {
                char label[32];
                snprintf(label, sizeof(label), "pid_%d", target);
                logmsg("[dump] manual pid=%d\n", target);
                int len = gather_dump(json, BUF_SIZE, target, label);
                serve_http(cfd, json, len);
            }
        } else if (strstr(req, "GET /")) {
            /* Root: same as auto-detect dump */
            char comm[20] = "none";
            pid_t gpid = find_game_pid(comm, sizeof(comm));
            if (gpid <= 0) {
                const char *err = "{\"error\":\"No game auto-detected. "
                    "Try: GET /list to see all processes, then GET /dump?pid=N\"}";
                serve_http(cfd, err, strlen(err));
            } else {
                logmsg("[dump] game pid=%d comm=%s\n", gpid, comm);
                int len = gather_dump(json, BUF_SIZE, gpid, comm);
                serve_http(cfd, json, len);
            }
        } else {
            const char *r = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
            write(cfd, r, strlen(r));
        }
        close(cfd);
    }
}
