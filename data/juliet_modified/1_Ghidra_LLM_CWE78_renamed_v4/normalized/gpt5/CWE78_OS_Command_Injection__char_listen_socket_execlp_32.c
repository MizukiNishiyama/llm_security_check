#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Constants (magic numbers from original) */
#define AF_INET_VAL 2
#define SOCK_STREAM_VAL 1
#define IPPROTO_TCP_VAL 6
#define BIND_ADDR_LEN 16
#define BACKLOG 5
#define COMMAND_BUFFER_SIZE 100
#define PORT 0x8769

/* External/placeholder for stack protector behavior replicated from original */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Vulnerable network handler: retains original unsafe behavior and flow */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t base_cmd_len;
    ssize_t recv_len;
    char *newline_pos;
    int saved_client_fd;
    struct sockaddr_in bind_addr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_guard_saved;

    /* save stack guard (replicates original stack check pattern) */
    stack_guard_saved = __stack_chk_guard;

    /* initialize command buffer and set initial "ls " */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */

    saved_client_fd = -1;

    base_cmd_len = strlen(command_buffer);

    /* create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET_VAL, SOCK_STREAM_VAL, IPPROTO_TCP_VAL);

    if (listen_fd != -1) {

        /* prepare sockaddr_in equivalent to original byte manipulations */
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET;                    /* AF_INET */
        bind_addr.sin_port = htons((unsigned short)PORT);  /* port 0x8769 */
        bind_addr.sin_addr.s_addr = INADDR_ANY;            /* any address */

        /* bind/listen/accept sequence (no additional checks or protections added) */
        if (bind(listen_fd, (struct sockaddr *)&bind_addr, BIND_ADDR_LEN) != -1
            && listen(listen_fd, BACKLOG) != -1
            && (saved_client_fd = accept(listen_fd, NULL, NULL)) != -1) {

            /* receive into buffer after the existing "ls " contents */
            recv_len = recv(saved_client_fd,
                            command_buffer + base_cmd_len,
                            (int)(COMMAND_BUFFER_SIZE - 1) - (int)base_cmd_len,
                            0);

            client_fd = (int)recv_len;
            if (client_fd != -1 && client_fd != 0) {
                /* null-terminate based on received length (preserve original arithmetic) */
                command_buffer[base_cmd_len + (size_t)(long)client_fd / 1] = '\0';

                /* strip CR and LF if present */
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

    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (saved_client_fd != -1) {
        close(saved_client_fd);
    }

    /* execute shell (kept identical to original call signature) */
    int execlp_result = execlp("sh", "sh");

    /* final stack check (replicated) */
    if (__stack_chk_guard != stack_guard_saved) {
        __stack_chk_fail(execlp_result);
    }

    return;
}