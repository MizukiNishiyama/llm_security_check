#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* External helpers from original binary (preserve calls and semantics) */
extern char *func_1(char *s, int c); /* likely strchr-like */
extern void func_3(const char *msg);
extern void ___stack_chk_fail(void);
extern long __stack_chk_guard;

/* Constants from original code expressed as named constants */
#define COMMAND_BUFFER_SIZE 100
#define LISTEN_BACKLOG 5
#define DEFAULT_PORT 0x8769  /* preserved magic number as constant */

/* Vulnerable function: keeps original unsafe behavior and calls */
void vulnerable_network_handler(void)
{
    int listen_fd = -1;
    int client_fd = -1;
    size_t prefix_len;
    ssize_t recv_len;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long stack_guard_check;

    /* stack protector value capture (preserve original check) */
    stack_guard_check = __stack_chk_guard;

    /* initialize command buffer and set prefix "ls " (same bytes as original) */
    memset(command_buffer, 0, sizeof(command_buffer));
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* compute existing length of the prefix */
    prefix_len = strlen(command_buffer);

    /* create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {
        struct sockaddr_in addr;

        /* prepare sockaddr_in using explicit fields (mirrors original raw sockaddr usage) */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        /* preserve original magic port by using htons of the constant */
        addr.sin_port = htons((unsigned short)DEFAULT_PORT);
        addr.sin_addr.s_addr = INADDR_ANY;

        /* bind, listen, accept sequence (preserve lack of extra validation) */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 &&
            listen(listen_fd, LISTEN_BACKLOG) != -1) {

            client_fd = accept(listen_fd, (struct sockaddr *)NULL, (socklen_t *)NULL);
            if (client_fd != -1) {
                /* receive data directly into the command buffer after the prefix */
                recv_len = recv(client_fd, command_buffer + prefix_len,
                                (int)(COMMAND_BUFFER_SIZE - 1 - prefix_len), 0);
                if (recv_len != -1 && recv_len != 0) {
                    /* null-terminate based on received length (preserve original math) */
                    command_buffer[prefix_len + (size_t)recv_len] = '\0';

                    /* remove specific bytes (preserve original calls to func_1) */
                    char *p;
                    p = func_1(command_buffer, 0x0d); /* 0x0d == CR */
                    if (p != NULL) {
                        *p = 0;
                    }
                    p = func_1(command_buffer, 0x0a); /* 0x0a == LF */
                    if (p != NULL) {
                        *p = 0;
                    }
                }
            }
        }
    }

    /* close sockets if opened (preserve original cleanup behavior) */
    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (client_fd != -1) {
        close(client_fd);
    }

    /* execute the received command (unsafe, preserved) */
    if (system(command_buffer) != 0) {
        func_3("command execution failed!");
        _exit(1);
    }

    /* stack protector check (preserve original behavior) */
    if (__stack_chk_guard != stack_guard_check) {
        ___stack_chk_fail();
    }

    return;
}