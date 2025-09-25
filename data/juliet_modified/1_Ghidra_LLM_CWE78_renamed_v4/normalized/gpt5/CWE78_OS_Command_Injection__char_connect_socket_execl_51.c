#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stddef.h>

#define PORT 0x8769
#define BUFFER_SIZE 100

/* External symbols preserved from original binary layout */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Placeholder for the original post-processing function (kept as call target) */
void handle_command(char *command);

/* Vulnerable network handler: preserves original unsafe behavior and flow */
void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t addr;
    int connect_ret;
    size_t prefix_len;
    ssize_t recv_ret;
    char *p;
    struct sockaddr_in server_addr;
    char command_buffer[BUFFER_SIZE];
    long stack_guard_check;

    /* preserve stack protector usage pattern */
    stack_guard_check = __stack_chk_guard;

    /* initialize buffer and set command prefix "ls " */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */
    prefix_len = strlen(command_buffer);

    /* create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd != -1) {
        /* prepare sockaddr_in structure for 127.0.0.1:PORT */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons((uint16_t)PORT);
        addr = inet_addr("127.0.0.1");
        server_addr.sin_addr.s_addr = (in_addr_t)addr;

        /* connect to server (uses struct sockaddr cast) */
        connect_ret = connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (connect_ret != -1) {
            /* receive data directly into buffer after prefix (no validation) */
            recv_ret = recv(socket_fd, command_buffer + prefix_len, 99 - prefix_len, 0);
            connect_ret = (int)recv_ret;
            if ((connect_ret != -1) && (connect_ret != 0)) {
                /* terminate received string (same arithmetic as original) */
                command_buffer[prefix_len + (size_t)connect_ret / 1] = '\0';

                /* strip carriage return if present */
                p = strchr(command_buffer, 0x0d);
                if (p != NULL) {
                    *p = '\0';
                }

                /* strip newline if present */
                p = strchr(command_buffer, 0x0a);
                if (p != NULL) {
                    *p = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* call original post-processing function with the potentially unsafe buffer */
    handle_command(command_buffer);

    /* stack protector check preserved */
    if (__stack_chk_guard != stack_guard_check) {
        __stack_chk_fail();
    }
}