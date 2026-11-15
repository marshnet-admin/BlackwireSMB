/*
 * Blackwire firmware probe — discover FW 8.00 environment for porting.
 * Loads via Payload Manager, serves diagnostic JSON on port 5920.
 * Writes /data/blackwire/fw-probe.log for offline collection.
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
#include <time.h>

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

__attribute__((weak)) int sceKernelGetHwModelName(char *);

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char     title_id[10];
    char     unknown2[0x3c];
} app_info_t;

__attribute__((weak)) int sceKernelGetAppInfo(pid_t pid, app_info_t *info);

#define LOG_PATH "/data/blackwire/fw-probe.log"
#define LISTEN_PORT 5920
#define BUF_SIZE (256 * 1024)

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

static int gather_diagnostics(char *out, size_t cap) {
    int n = 0;
    uint32_t fw = kernel_get_fw_version();
    uint32_t fw_major = (fw >> 24) & 0xFF;
    uint32_t fw_minor = (fw >> 16) & 0xFF;
    uint32_t fw_patch = (fw >> 8) & 0xFF;
    uint32_t fw_build = fw & 0xFF;

    n += snprintf(out + n, cap - n,
        "{\n"
        "  \"probe\": \"blackwire-fw-probe-v1\",\n"
        "  \"firmware_raw\": \"0x%08x\",\n"
        "  \"firmware_display\": \"%u.%02u.%02u.%02u\",\n"
        "  \"kinfo_proc_size\": %zu,\n"
        "  \"kinfo_proc_offsets\": {\n"
        "    \"ki_structsize\": %zu,\n"
        "    \"ki_pid\": %zu,\n"
        "    \"ki_ppid\": %zu,\n"
        "    \"ki_pgid\": %zu,\n"
        "    \"ki_uid\": %zu,\n"
        "    \"ki_comm\": %zu,\n"
        "    \"ki_comm_size\": %zu,\n"
        "    \"ki_stat\": %zu,\n"
        "    \"ki_rssize\": %zu,\n"
        "    \"ki_start\": %zu,\n"
        "    \"ki_size\": %zu\n"
        "  },\n",
        fw, fw_major, fw_minor, fw_patch, fw_build,
        sizeof(struct kinfo_proc),
        offsetof(struct kinfo_proc, ki_structsize),
        offsetof(struct kinfo_proc, ki_pid),
        offsetof(struct kinfo_proc, ki_ppid),
        offsetof(struct kinfo_proc, ki_pgid),
        offsetof(struct kinfo_proc, ki_uid),
        offsetof(struct kinfo_proc, ki_comm),
        sizeof(((struct kinfo_proc *)0)->ki_comm),
        offsetof(struct kinfo_proc, ki_stat),
        offsetof(struct kinfo_proc, ki_rssize),
        offsetof(struct kinfo_proc, ki_start),
        offsetof(struct kinfo_proc, ki_size));

    char model[256] = "unavailable";
    if (sceKernelGetHwModelName)
        if (sceKernelGetHwModelName(model))
            strcpy(model, "unknown");

    n += snprintf(out + n, cap - n,
        "  \"model\": \"%s\",\n"
        "  \"pid\": %d,\n",
        model, getpid());

    /* Process list */
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t buf_size = 0;
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) == 0 && buf_size > 0) {
        void *buf = malloc(buf_size);
        if (buf && sysctl(mib, 4, buf, &buf_size, NULL, 0) == 0) {
            n += snprintf(out + n, cap - n, "  \"processes\": [\n");
            int first = 1;
            for (void *ptr = buf; ptr < (buf + buf_size);) {
                struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
                if (ki->ki_structsize <= 0) break;
                ptr += ki->ki_structsize;
                app_info_t ai = {0};
                if (sceKernelGetAppInfo)
                    sceKernelGetAppInfo(ki->ki_pid, &ai);
                if (!first) n += snprintf(out + n, cap - n, ",\n");
                first = 0;
                n += snprintf(out + n, cap - n,
                    "    {\"pid\": %d, \"ppid\": %d, \"uid\": %u, "
                    "\"comm\": \"%.19s\", \"stat\": %d, "
                    "\"structsize\": %d, \"app_id\": %u, \"title_id\": \"%.9s\"}",
                    ki->ki_pid, ki->ki_ppid, ki->ki_uid,
                    ki->ki_comm, (int)ki->ki_stat,
                    ki->ki_structsize, ai.app_id, ai.title_id);
            }
            n += snprintf(out + n, cap - n, "\n  ],\n");
            n += snprintf(out + n, cap - n,
                "  \"process_buf_bytes\": %zu,\n"
                "  \"first_ki_structsize\": %d,\n",
                buf_size,
                buf_size >= sizeof(struct kinfo_proc)
                    ? ((struct kinfo_proc *)buf)->ki_structsize : -1);
        }
        free(buf);
    } else {
        n += snprintf(out + n, cap - n,
            "  \"processes\": [],\n"
            "  \"sysctl_error\": \"%s\",\n", strerror(errno));
    }

    /* Module info — try to discover libkernel base for native profile */
    n += snprintf(out + n, cap - n,
        "  \"SYS___sysctl\": %d,\n"
        "  \"PAGE_SIZE\": %d\n"
        "}\n",
        SYS___sysctl, PAGE_SIZE);

    return n;
}

static void serve_http(int client_fd, const char *json, int json_len) {
    char header[512];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n", json_len);
    write(client_fd, header, hlen);
    write(client_fd, json, json_len);
}

static void serve_health(int client_fd) {
    const char *body = "{\"buildId\":\"blackwire-fw-probe-v1\",\"status\":\"ok\"}";
    int blen = strlen(body);
    char header[256];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
        "\r\n", blen);
    write(client_fd, header, hlen);
    write(client_fd, body, blen);
}

int main(void) {
    mkdir("/data/blackwire", 0755);
    logfp = fopen(LOG_PATH, "w");

    logmsg("=== Blackwire FW Probe v1 ===\n");
    logmsg("PID: %d\n", getpid());

    uint32_t fw = kernel_get_fw_version();
    logmsg("Firmware raw: 0x%08x\n", fw);
    logmsg("Firmware display: %u.%02u\n", (fw >> 24) & 0xFF, (fw >> 16) & 0xFF);
    logmsg("sizeof(struct kinfo_proc): %zu\n", sizeof(struct kinfo_proc));
    logmsg("Expected by Blackwire (BW_STOP_PROFILE_RECORD): 1096\n");
    logmsg("Match: %s\n", sizeof(struct kinfo_proc) == 1096 ? "YES" : "NO");

    char *json = malloc(BUF_SIZE);
    if (!json) {
        logmsg("FATAL: malloc failed\n");
        return 1;
    }
    int json_len = gather_diagnostics(json, BUF_SIZE);
    logmsg("\n--- Full diagnostic JSON ---\n%.*s\n", json_len, json);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        logmsg("FATAL: socket: %s\n", strerror(errno));
        return 1;
    }
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(LISTEN_PORT),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        logmsg("FATAL: bind port %d: %s\n", LISTEN_PORT, strerror(errno));
        close(server_fd);
        return 1;
    }
    if (listen(server_fd, 4) < 0) {
        logmsg("FATAL: listen: %s\n", strerror(errno));
        close(server_fd);
        return 1;
    }

    logmsg("Listening on http://0.0.0.0:%d/\n", LISTEN_PORT);
    logmsg("  GET /         -> full diagnostics JSON\n");
    logmsg("  GET /health   -> probe health check\n");
    logmsg("  GET /refresh  -> re-gather and return diagnostics\n");
    logmsg("Log: %s\n\n", LOG_PATH);

    for (;;) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        char req[4096] = {0};
        read(client_fd, req, sizeof(req) - 1);

        if (strstr(req, "GET /health")) {
            serve_health(client_fd);
        } else if (strstr(req, "GET /refresh")) {
            json_len = gather_diagnostics(json, BUF_SIZE);
            logmsg("[refresh] re-gathered %d bytes\n", json_len);
            serve_http(client_fd, json, json_len);
        } else if (strstr(req, "GET /")) {
            serve_http(client_fd, json, json_len);
        } else {
            const char *r404 = "HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n";
            write(client_fd, r404, strlen(r404));
        }
        close(client_fd);
    }
}
