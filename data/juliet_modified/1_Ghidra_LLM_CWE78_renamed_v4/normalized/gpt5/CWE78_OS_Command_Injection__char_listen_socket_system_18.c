#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Constants for clarity */
#define COMMAND_BUFFER_SIZE 100
#define BACKLOG 5
#define PORT 0x8769  /* 0x8769 matches original byte sequence used for port */

/* External functions retained as in original binary */
extern void func_2(const char *msg);
extern void ___stack_chk_fail(void);

/* Vulnerable network handler: preserves original unsafe behavior */
void vulnerable_network_handler(void)
{
    int listen_fd = -1;
    int client_fd = -1;
    size_t prefix_len;
    ssize_t recv_len;
    char *cr_pos;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize command buffer and set initial command prefix */
    memset(command_buffer, 0, sizeof(command_buffer));
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    /* Measure current length to append incoming data after the prefix */
    prefix_len = strlen(command_buffer);

    /* Create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {
        struct sockaddr_in addr;

        /* Prepare sockaddr_in structure corresponding to original bytes:
           family AF_INET, port 0x8769, address INADDR_ANY */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        /* Bind, listen, and accept a single connection */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 &&
            listen(listen_fd, BACKLOG) != -1) {
            client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd != -1) {
                /* Receive data directly into the command buffer after the prefix.
                   Note: buffer boundaries are unchanged from original. */
                recv_len = recv(client_fd,
                                command_buffer + prefix_len,
                                (int)(COMMAND_BUFFER_SIZE - prefix_len - 1),
                                0);
                if (recv_len != -1 && recv_len != 0) {
                    /* Null-terminate based on received length (mimics original integer cast) */
                    command_buffer[prefix_len + (size_t)((int)recv_len)] = '\0';

                    /* Strip CR and LF if present */
                    cr_pos = strchr(command_buffer, '\r');
                    if (cr_pos != NULL) {
                        *cr_pos = '\0';
                    }
                    cr_pos = strchr(command_buffer, '\n');
                    if (cr_pos != NULL) {
                        *cr_pos = '\0';
                    }
                }
            }
        }
    }

    /* Close descriptors if opened (preserve original flow) */
    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (client_fd != -1) {
        close(client_fd);
    }

    /* Execute the command buffer using system() as in original (vulnerable) */
    if (system(command_buffer) != 0) {
        func_2("command execution failed!");
        _exit(1);
    }

    /* Preserve potential stack check failure call site (kept as external) */
    /* Note: original stack guard checks removed for portability; call preserved if needed */
    /* If a stack check were to fail, the original binary would call ___stack_chk_fail(). */
}