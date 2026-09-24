#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define TOKEN_HEX_LENGTH 48U
#define UUID_TEXT_LENGTH 36U
#define MAX_OPTIONS_LENGTH 512U
#define MAX_CHILDREN 32
#define TUNNEL_BUFFER_SIZE 16384U
#define MAX_HTTP_LINE_LENGTH 1024U
#define MAX_HTTP_HEADER_BYTES 8192U

static char session_token[TOKEN_HEX_LENGTH + 1U];
static char job_id[UUID_TEXT_LENGTH + 1U];
static char target_host[INET_ADDRSTRLEN];
static struct in_addr target_address;
static uint16_t target_port;
static char options_raw[MAX_OPTIONS_LENGTH + 1U];
static unsigned int lifetime_seconds;
static int legacy_mode;
static volatile sig_atomic_t child_count;

struct debug_frame {
    unsigned char data[128];
    void (*next)(int);
};

_Static_assert(offsetof(struct debug_frame, next) == 128U, "callback offset must stay stable");
_Static_assert(sizeof(void *) == 8U, "RelayForge requires a 64-bit target");
_Static_assert(sizeof(struct debug_frame) == 136U, "unexpected debug frame padding");

static void set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
}

static ssize_t read_line(int fd, char *buffer, size_t capacity) {
    size_t used = 0U;
    char byte = '\0';
    if (capacity < 2U) {
        return -2;
    }
    for (;;) {
        ssize_t received = recv(fd, &byte, 1U, 0);
        if (received <= 0) {
            return received;
        }
        if (byte == '\n') {
            buffer[used] = '\0';
            return (ssize_t)used;
        }
        if (byte == '\r') {
            continue;
        }
        if (used + 1U >= capacity) {
            while (byte != '\n') {
                received = recv(fd, &byte, 1U, 0);
                if (received <= 0) {
                    break;
                }
            }
            buffer[0] = '\0';
            return -2;
        }
        buffer[used++] = byte;
    }
}

static int recv_exact(int fd, unsigned char *buffer, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ssize_t received = recv(fd, buffer + offset, length - offset, 0);
        if (received <= 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 0;
}

static int send_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    while (length > 0U) {
        ssize_t sent = send(fd, cursor, length, 0);
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent <= 0) {
            return -1;
        }
        cursor += (size_t)sent;
        length -= (size_t)sent;
    }
    return 0;
}

static int constant_time_equal(const char *left, const char *right) {
    size_t left_length = strlen(left);
    size_t right_length = strlen(right);
    size_t maximum = left_length > right_length ? left_length : right_length;
    unsigned char difference = (unsigned char)(left_length ^ right_length);
    for (size_t index = 0U; index < maximum; index++) {
        unsigned char lvalue = index < left_length ? (unsigned char)left[index] : 0U;
        unsigned char rvalue = index < right_length ? (unsigned char)right[index] : 0U;
        difference = (unsigned char)(difference | (unsigned char)(lvalue ^ rvalue));
    }
    return difference == 0U;
}

static int valid_uuid(const char *value) {
    if (strlen(value) != UUID_TEXT_LENGTH || value[14] != '4' ||
        strchr("89ab", value[19]) == NULL) {
        return 0;
    }
    for (size_t index = 0U; index < UUID_TEXT_LENGTH; index++) {
        if (index == 8U || index == 13U || index == 18U || index == 23U) {
            if (value[index] != '-') {
                return 0;
            }
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

static int copy_config_value(FILE *stream, const char *prefix, char *destination, size_t capacity) {
    char line[1024];
    size_t prefix_length = strlen(prefix);
    if (fgets(line, sizeof(line), stream) == NULL) {
        return -1;
    }
    size_t length = strlen(line);
    if (length == 0U || line[length - 1U] != '\n') {
        return -1;
    }
    line[--length] = '\0';
    if (length > 0U && line[length - 1U] == '\r') {
        line[--length] = '\0';
    }
    if (strncmp(line, prefix, prefix_length) != 0 || length < prefix_length ||
        length - prefix_length >= capacity) {
        return -1;
    }
    memcpy(destination, line + prefix_length, length - prefix_length + 1U);
    return 0;
}

static int exact_slice(const char *start, size_t length, const char *expected) {
    return strlen(expected) == length && memcmp(start, expected, length) == 0;
}

static int valid_note(const char *start, size_t length) {
    if (length == 0U || length > 32U) {
        return 0;
    }
    for (size_t index = 0U; index < length; index++) {
        unsigned char byte = (unsigned char)start[index];
        if (!((byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9') ||
              byte == '.' || byte == '_' || byte == '-')) {
            return 0;
        }
    }
    return 1;
}

static int parse_options_last_wins(const char *raw, int *is_legacy) {
    const char *cursor = raw;
    unsigned int profile_count = 0U;
    unsigned int note_count = 0U;
    unsigned int pair_count = 0U;
    int last_legacy = 0;

    if (*cursor == '\0' || strlen(raw) > MAX_OPTIONS_LENGTH) {
        return -1;
    }
    for (;;) {
        const char *end = strchr(cursor, '&');
        size_t pair_length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        const char *equals = memchr(cursor, '=', pair_length);
        if (pair_length == 0U || equals == NULL ||
            memchr(equals + 1, '=', pair_length - (size_t)(equals + 1 - cursor)) != NULL) {
            return -1;
        }
        size_t key_length = (size_t)(equals - cursor);
        const char *value = equals + 1;
        size_t value_length = pair_length - key_length - 1U;
        pair_count++;

        if (exact_slice(cursor, key_length, "profile")) {
            profile_count++;
            if (profile_count > 2U ||
                !(exact_slice(value, value_length, "safe") ||
                  exact_slice(value, value_length, "legacy"))) {
                return -1;
            }
            last_legacy = exact_slice(value, value_length, "legacy");
        } else if (exact_slice(cursor, key_length, "note")) {
            note_count++;
            if (note_count > 1U || !valid_note(value, value_length)) {
                return -1;
            }
        } else {
            return -1;
        }

        if (end == NULL) {
            break;
        }
        cursor = end + 1;
    }
    if ((pair_count != 2U && pair_count != 3U) ||
        profile_count < 1U || profile_count > 2U || note_count != 1U) {
        return -1;
    }
    *is_legacy = last_legacy; /* INTENTIONAL-VULNERABILITY RF-PARSE-02: last profile wins. */
    return 0;
}

static int load_config(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        return -1;
    }
    set_cloexec(descriptor);
    struct stat metadata;
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        (metadata.st_uid != 0U && metadata.st_uid != getuid()) ||
        (metadata.st_mode & 0022U) != 0U || metadata.st_size > 1024) {
        close(descriptor);
        return -1;
    }
    FILE *stream = fdopen(descriptor, "r");
    if (stream == NULL) {
        close(descriptor);
        return -1;
    }
    char duration_text[16];
    char target_port_text[16];
    int failed = copy_config_value(stream, "token=", session_token, sizeof(session_token)) ||
                 copy_config_value(stream, "job=", job_id, sizeof(job_id)) ||
                 copy_config_value(stream, "duration=", duration_text, sizeof(duration_text)) ||
                 copy_config_value(stream, "target_host=", target_host, sizeof(target_host)) ||
                 copy_config_value(stream, "target_port=", target_port_text, sizeof(target_port_text)) ||
                 copy_config_value(stream, "options=", options_raw, sizeof(options_raw));
    if (!failed && fgetc(stream) != EOF) {
        failed = 1;
    }
    (void)fclose(stream);
    if (failed || strlen(session_token) != TOKEN_HEX_LENGTH || !valid_uuid(job_id)) {
        return -1;
    }
    for (size_t index = 0U; index < TOKEN_HEX_LENGTH; index++) {
        if (!((session_token[index] >= '0' && session_token[index] <= '9') ||
              (session_token[index] >= 'a' && session_token[index] <= 'f'))) {
            return -1;
        }
    }
    char canonical_address[INET_ADDRSTRLEN];
    if (inet_pton(AF_INET, target_host, &target_address) != 1 ||
        inet_ntop(AF_INET, &target_address, canonical_address, sizeof(canonical_address)) == NULL ||
        strcmp(target_host, canonical_address) != 0) {
        return -1;
    }
    uint32_t target_numeric = ntohl(target_address.s_addr);
    if (target_numeric == 0U || target_numeric == UINT32_MAX ||
        (target_numeric & 0xF0000000U) == 0xE0000000U) {
        return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long parsed_duration = strtoul(duration_text, &end, 10);
    if (errno != 0 || end == duration_text || *end != '\0' ||
        parsed_duration < 30UL || parsed_duration > 420UL) {
        return -1;
    }
    lifetime_seconds = (unsigned int)parsed_duration;
    for (const char *cursor = target_port_text; *cursor != '\0'; cursor++) {
        if (!isdigit((unsigned char)*cursor)) {
            return -1;
        }
    }
    errno = 0;
    end = NULL;
    unsigned long parsed_target_port = strtoul(target_port_text, &end, 10);
    if (errno != 0 || end == target_port_text || *end != '\0' ||
        parsed_target_port < 1UL || parsed_target_port > 65535UL) {
        return -1;
    }
    target_port = (uint16_t)parsed_target_port;
    return parse_options_last_wins(options_raw, &legacy_mode);
}

static void normal_action(int fd) {
    (void)dprintf(fd, "worker: request rejected\n");
}

__attribute__((noinline, used))
static void worker_shell(int fd) {
    (void)dprintf(fd, "relay shell opened (uid=%ld)\n", (long)getuid());
    (void)dup2(fd, STDIN_FILENO);
    (void)dup2(fd, STDOUT_FILENO);
    (void)dup2(fd, STDERR_FILENO);
    execl("/bin/sh", "sh", "-i", (char *)NULL);
    _exit(127);
}

__attribute__((noinline))
static void vulnerable_debug(int fd, const unsigned char *payload, size_t length) {
    volatile struct debug_frame frame;
    frame.next = normal_action;
    /* INTENTIONAL-VULNERABILITY RF-WORKER-01: bounded copy may overwrite only callback. */
    for (size_t index = 0U; index < length; index++) {
        ((volatile unsigned char *)&frame)[index] = payload[index];
    }
    void (*next)(int) = frame.next;
    next(fd);
}

static void set_receive_timeout(int fd, long seconds) {
    struct timeval timeout = {.tv_sec = seconds, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

static int forward_tunnel(int client_fd, int target_fd) {
    struct pollfd sockets[2] = {
        {.fd = client_fd, .events = POLLIN, .revents = 0},
        {.fd = target_fd, .events = POLLIN, .revents = 0},
    };
    const int descriptors[2] = {client_fd, target_fd};
    unsigned int open_readers = 2U;
    unsigned char buffer[TUNNEL_BUFFER_SIZE];

    while (open_readers > 0U) {
        int ready = poll(sockets, 2U, -1);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready < 0) {
            return -1;
        }
        for (size_t index = 0U; index < 2U; index++) {
            if (sockets[index].fd < 0 || sockets[index].revents == 0) {
                continue;
            }
            if ((sockets[index].revents & (POLLERR | POLLNVAL)) != 0) {
                return -1;
            }
            if ((sockets[index].revents & (POLLIN | POLLHUP)) != 0) {
                ssize_t received = recv(descriptors[index], buffer, sizeof(buffer), 0);
                if (received < 0 && errno == EINTR) {
                    continue;
                }
                if (received < 0) {
                    return -1;
                }
                if (received == 0) {
                    sockets[index].fd = -1;
                    open_readers--;
                    (void)shutdown(descriptors[1U - index], SHUT_WR);
                } else if (send_all(descriptors[1U - index], buffer, (size_t)received) != 0) {
                    return -1;
                }
            }
            sockets[index].revents = 0;
        }
    }
    return 0;
}

static int open_target(void) {
    int target = socket(AF_INET, SOCK_STREAM, 0);
    if (target < 0) {
        return -1;
    }
    set_cloexec(target);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(target_port);
    address.sin_addr = target_address;
    if (connect(target, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(target);
        return -1;
    }
    return target;
}

static void connect_target(int client_fd) {
    int target = open_target();
    if (target < 0) {
        (void)dprintf(client_fd, "ERR connect\n");
        return;
    }
    static const char connected[] = "CONNECTED\n";
    if (send_all(client_fd, connected, sizeof(connected) - 1U) != 0) {
        close(target);
        return;
    }
    set_receive_timeout(client_fd, 0L);
    (void)forward_tunnel(client_fd, target);
    close(target);
}

static void send_http_error(int fd, const char *status, const char *body) {
    (void)dprintf(
        fd,
        "HTTP/1.1 %s\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "Connection: close\r\n\r\n",
        status,
        strlen(body));
    (void)send_all(fd, body, strlen(body));
}

static int drain_http_headers(int fd) {
    char header[MAX_HTTP_LINE_LENGTH];
    size_t total = 0U;
    for (;;) {
        ssize_t length = read_line(fd, header, sizeof(header));
        if (length < 0) {
            return -1;
        }
        if (length == 0) {
            return 0;
        }
        total += (size_t)length + 2U;
        if (total > MAX_HTTP_HEADER_BYTES) {
            return -1;
        }
    }
}

static void serve_browser_client(int fd, char *request_line) {
    if (drain_http_headers(fd) != 0) {
        send_http_error(fd, "431 Request Header Fields Too Large", "Request headers are too large.\n");
        return;
    }
    char *method_end = strchr(request_line, ' ');
    if (method_end == NULL) {
        send_http_error(fd, "400 Bad Request", "Malformed request.\n");
        return;
    }
    *method_end = '\0';
    char *request_target = method_end + 1;
    char *version = strchr(request_target, ' ');
    if (version == NULL || strchr(version + 1, ' ') != NULL) {
        send_http_error(fd, "400 Bad Request", "Malformed request.\n");
        return;
    }
    *version++ = '\0';
    if (strcmp(request_line, "GET") != 0) {
        send_http_error(fd, "405 Method Not Allowed", "Only GET is supported.\n");
        return;
    }
    if (strcmp(version, "HTTP/1.1") != 0 && strcmp(version, "HTTP/1.0") != 0) {
        send_http_error(fd, "400 Bad Request", "Unsupported HTTP version.\n");
        return;
    }

    static const char prefix[] = "/relay/";
    size_t prefix_length = sizeof(prefix) - 1U;
    size_t target_length = strlen(request_target);
    if (target_length < prefix_length + TOKEN_HEX_LENGTH ||
        memcmp(request_target, prefix, prefix_length) != 0) {
        send_http_error(fd, "403 Forbidden", "A valid temporary relay URL is required.\n");
        return;
    }
    char supplied[TOKEN_HEX_LENGTH + 1U];
    memcpy(supplied, request_target + prefix_length, TOKEN_HEX_LENGTH);
    supplied[TOKEN_HEX_LENGTH] = '\0';
    if (!constant_time_equal(supplied, session_token)) {
        send_http_error(fd, "403 Forbidden", "A valid temporary relay URL is required.\n");
        return;
    }
    const char *upstream_path = request_target + prefix_length + TOKEN_HEX_LENGTH;
    if (*upstream_path == '\0') {
        upstream_path = "/";
    } else if (*upstream_path != '/') {
        send_http_error(fd, "400 Bad Request", "Malformed relay path.\n");
        return;
    }
    for (const unsigned char *cursor = (const unsigned char *)upstream_path; *cursor != '\0'; cursor++) {
        if (*cursor < 0x21U || *cursor > 0x7eU || *cursor == '#') {
            send_http_error(fd, "400 Bad Request", "Malformed relay path.\n");
            return;
        }
    }

    int target = open_target();
    if (target < 0) {
        send_http_error(fd, "502 Bad Gateway", "The private endpoint is unavailable.\n");
        return;
    }
    if (dprintf(
            target,
            "GET %s HTTP/1.1\r\nHost: %s:%u\r\nConnection: close\r\n\r\n",
            upstream_path,
            target_host,
            (unsigned int)target_port) < 0) {
        close(target);
        send_http_error(fd, "502 Bad Gateway", "The private endpoint is unavailable.\n");
        return;
    }
    set_receive_timeout(fd, 0L);
    (void)forward_tunnel(fd, target);
    close(target);
}

static void serve_command_client(int fd, char *line, size_t line_capacity) {
    if (strncmp(line, "TOKEN ", 6U) != 0 || !constant_time_equal(line + 6, session_token)) {
        (void)dprintf(fd, "ERR auth\n");
        return;
    }
    set_receive_timeout(fd, 120L);
    (void)dprintf(fd, "RelayForge worker job=%s\n", job_id);
    (void)dprintf(fd, "OK\n");
    for (;;) {
        ssize_t line_length = read_line(fd, line, line_capacity);
        if (line_length == 0) {
            continue;
        }
        if (line_length < 0) {
            return;
        }
        if (strcmp(line, "LEAK") == 0 && legacy_mode) {
            /* INTENTIONAL-VULNERABILITY RF-WORKER-02: live PIE address disclosure. */
            (void)dprintf(fd, "worker_shell=%p\n", (void *)worker_shell);
        } else if (strncmp(line, "OVERFLOW ", 9U) == 0 && legacy_mode) {
            char *end = NULL;
            errno = 0;
            unsigned long requested = strtoul(line + 9, &end, 10);
            if (errno != 0 || end == line + 9 || *end != '\0' ||
                requested > (unsigned long)sizeof(struct debug_frame)) {
                (void)dprintf(fd, "ERR size\n");
                continue;
            }
            unsigned char payload[sizeof(struct debug_frame)];
            if (recv_exact(fd, payload, (size_t)requested) != 0) {
                return;
            }
            vulnerable_debug(fd, payload, (size_t)requested);
        } else if (strcmp(line, "CONNECT") == 0) {
            connect_target(fd);
            return;
        } else if (strcmp(line, "QUIT") == 0) {
            return;
        } else {
            (void)dprintf(fd, "ERR command\n");
        }
    }
}

static void serve_client(int fd) {
    char line[MAX_HTTP_LINE_LENGTH];
    set_receive_timeout(fd, 10L);
    ssize_t line_length = read_line(fd, line, sizeof(line));
    if (line_length <= 0) {
        return;
    }
    if (strstr(line, " HTTP/") != NULL) {
        serve_browser_client(fd, line);
    } else {
        serve_command_client(fd, line, sizeof(line));
    }
}

static void reap_children(int signal_number) {
    (void)signal_number;
    int saved_errno = errno;
    while (waitpid(-1, NULL, WNOHANG) > 0) {
        if (child_count > 0) {
            child_count--;
        }
    }
    errno = saved_errno;
}

static int write_ready_file(void) {
    int descriptor = open("ready", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return -1;
    }
    static const char ready[] = "ready\n";
    int result = write(descriptor, ready, sizeof(ready) - 1U) == (ssize_t)(sizeof(ready) - 1U) ? 0 : -1;
    close(descriptor);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        (void)fprintf(stderr, "usage: relay-worker PORT CONFIG\n");
        return 64;
    }
    if (load_config(argv[2]) != 0) {
        (void)fprintf(stderr, "invalid worker configuration\n");
        return 65;
    }
    errno = 0;
    char *end = NULL;
    unsigned long parsed_port = strtoul(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' ||
        parsed_port < 25000UL || parsed_port > 25099UL) {
        (void)fprintf(stderr, "invalid worker port\n");
        return 65;
    }

    (void)signal(SIGPIPE, SIG_IGN);
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = reap_children;
    action.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    (void)sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) != 0) {
        return 70;
    }
    (void)alarm(lifetime_seconds);

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return 71;
    }
    set_cloexec(listener);
    int one = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)parsed_port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 16) != 0 || write_ready_file() != 0) {
        perror("worker startup");
        close(listener);
        return 71;
    }

    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        set_cloexec(client);
        if (child_count >= MAX_CHILDREN) {
            static const char busy[] = "ERR busy\n";
            (void)send_all(client, busy, sizeof(busy) - 1U);
            close(client);
            continue;
        }
        pid_t child = fork();
        if (child == 0) {
            close(listener);
            (void)alarm(lifetime_seconds);
            serve_client(client);
            close(client);
            _exit(0);
        }
        if (child < 0) {
            static const char busy[] = "ERR busy\n";
            (void)send_all(client, busy, sizeof(busy) - 1U);
        } else {
            child_count++;
        }
        close(client);
    }
    close(listener);
    return 0;
}
