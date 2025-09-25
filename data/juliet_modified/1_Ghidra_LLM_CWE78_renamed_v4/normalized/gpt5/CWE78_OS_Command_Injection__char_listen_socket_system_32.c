#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* External symbols used for stack check consistency with original binary */
extern long __stack_chk_guard;
void ___stack_chk_fail(void);
void func_2(const char *); /* original diagnostics function preserved */

/* Constants to replace magic numbers */
#define BUFFER_SIZE 100
#define LISTEN_BACKLOG 5
#define SOCK_FAMILY AF_INET
#define SOCK_TYPE SOCK_STREAM
#define PROTOCOL_IP 6

/* Vulnerable function: preserves original control flow and unsafe operations */
void vulnerable_network_handler(void)
{
    int server_fd;
    int client_fd;
    size_t prefix_len;
    ssize_t recv_len;
    char *newline_ptr;
    char command_buffer[BUFFER_SIZE];
    long local_stack_guard = __stack_chk_guard;

    /* Initialize command buffer and set initial bytes ("ls ") */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;     /* 's' */
    command_buffer[2] = 0x20;     /* ' ' */

    client_fd = -1;
    prefix_len = strlen(command_buffer);

    server_fd = socket(SOCK_FAMILY, SOCK_TYPE, PROTOCOL_IP);
    if (server_fd != -1) {
        struct sockaddr_in addr;
        unsigned char port_bytes[2];

        /* Construct sockaddr_in using raw bytes to match original layout */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = SOCK_FAMILY;

        /* Preserve original byte values placed in sa_data[0]..[1] */
        /* sa_data[0] = 'i' (0x69), sa_data[1] = -0x79 (0x87) */
        port_bytes[0] = 0x69;
        port_bytes[1] = (unsigned char)(-0x79);
        /* Copy raw bytes into sin_port (network byte order) */
        memcpy(&addr.sin_port, port_bytes, 2);

        bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));

        if (listen(server_fd, LISTEN_BACKLOG) != -1) {
            client_fd = accept(server_fd, NULL, NULL);
            if (client_fd != -1) {
                recv_len = recv(client_fd, command_buffer + prefix_len, BUFFER_SIZE - prefix_len - 1, 0);
                if (recv_len != -1 && recv_len != 0) {
                    /* Null-terminate based on received length (preserve original arithmetic) */
                    command_buffer[prefix_len + (size_t)((long)recv_len / 1)] = '\0';

                    newline_ptr = strchr(command_buffer, '\r');
                    if (newline_ptr != NULL) {
                        *newline_ptr = '\0';
                    }
                    newline_ptr = strchr(command_buffer, '\n');
                    if (newline_ptr != NULL) {
                        *newline_ptr = '\0';
                    }
                }
            }
        }

        close(server_fd);
    }

    if (client_fd != -1) {
        close(client_fd);
    }

    /* Execute command buffer using system (unsafe behavior preserved) */
    if (system(command_buffer) != 0) {
        func_2("command execution failed!");
        exit(1);
    }

    if (__stack_chk_guard != local_stack_guard) {
        ___stack_chk_fail();
    }
}