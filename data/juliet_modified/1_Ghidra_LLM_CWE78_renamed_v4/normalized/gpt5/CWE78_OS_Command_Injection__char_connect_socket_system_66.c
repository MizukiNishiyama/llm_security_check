#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* External symbols for stack protector emulation (kept as in original) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Constants (magic numbers made explicit) */
#define AF_INET_FAMILY  AF_INET
#define SOCK_TYPE       SOCK_STREAM
#define PROTOCOL_TCP    IPPROTO_TCP
#define PORT            0x8769
#define BUFFER_SIZE     100
#define RECV_FLAGS      0

/* Forward declaration of the downstream function (name improved, behavior unchanged) */
void process_payload(unsigned char ctx[16]);

/* Vulnerable network handler: preserves original control flow and vulnerabilities,
   but with improved names and formatting for readability. */
void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t ip_addr;
    int connect_ret;
    size_t prefix_len;
    ssize_t recv_ret;
    char *newline_pos;
    struct sockaddr_in addr;
    char command_buffer[BUFFER_SIZE];
    unsigned char payload_ctx[16];
    char *buffer_ptr;
    long saved_stack_guard;

    /* Preserve stack guard usage from original */
    saved_stack_guard = __stack_chk_guard;

    /* Initialize buffer and set initial prefix "ls " (same bytes as original) */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */
    prefix_len = strlen(command_buffer);

    /* Create TCP socket */
    socket_fd = socket(AF_INET_FAMILY, SOCK_TYPE, PROTOCOL_TCP);
    if (socket_fd != -1) {

        /* Prepare sockaddr_in (explicit fields instead of raw sockaddr) */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET_FAMILY;
        addr.sin_port = htons((uint16_t)PORT);
        ip_addr = inet_addr("127.0.0.1");
        addr.sin_addr.s_addr = ip_addr;

        /* Attempt to connect */
        connect_ret = connect(socket_fd, (struct sockaddr *)&addr, sizeof(addr));
        if (connect_ret != -1) {

            /* Receive data directly into command_buffer after the prefix.
               Note: original code allowed potential overflow; this retains that behavior. */
            recv_ret = recv(socket_fd, command_buffer + prefix_len, (int)(BUFFER_SIZE - prefix_len - 1), RECV_FLAGS);
            connect_ret = (int)recv_ret;
            if ((connect_ret != -1) && (connect_ret != 0)) {
                /* Null-terminate based on received length (same arithmetic as original) */
                command_buffer[prefix_len + (size_t)(long)connect_ret / 1] = '\0';

                /* Strip CR and LF if present */
                newline_pos = strchr(command_buffer, '\r');
                if (newline_pos != NULL) {
                    *newline_pos = '\0';
                }
                newline_pos = strchr(command_buffer, '\n');
                if (newline_pos != NULL) {
                    *newline_pos = '\0';
                }
            }
        }
    }

    /* Close socket if opened (same as original) */
    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Preserve original assignment and downstream call (behavior unchanged) */
    buffer_ptr = command_buffer;
    process_payload(payload_ctx);

    /* Stack protector check preserved */
    if (__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail();
    }

    return;
}

/* Placeholder for the original downstream function; kept signature for compatibility.
   Implementation is intentionally omitted/neutral to reflect structure only. */
void process_payload(unsigned char ctx[16])
{
    (void)ctx;
    /* Original behavior intentionally preserved elsewhere; this is a stub to satisfy linkage. */
}