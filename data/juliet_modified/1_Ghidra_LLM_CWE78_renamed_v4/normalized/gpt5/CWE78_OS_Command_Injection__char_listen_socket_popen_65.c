#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* External stack protector symbols kept for parity with original binary */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Preserved magic number as a named constant */
#define LISTEN_PORT 0x8769
#define BACKLOG 5
#define BUFFER_SIZE 100

/* Prototype for external function retained as in original code */
void func_2(char *data);

/* A clearer name for the original function while preserving behavior and vulnerabilities */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t prefix_len;
    ssize_t received_len;
    char *ptr;
    int placeholder_fd;
    struct sockaddr_in addr;
    char command_buffer[BUFFER_SIZE];
    long local_canary;

    /* Preserve stack guard check semantics */
    local_canary = __stack_chk_guard;

    /* Initialize buffer and set an initial command prefix ("ls ") as in original */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' (space) */

    placeholder_fd = -1;

    /* compute current length of the prefix in the buffer */
    prefix_len = strlen(command_buffer);

    /* create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (listen_fd != -1) {
        /* Prepare sockaddr_in structure for bind (INADDR_ANY, LISTEN_PORT) */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((unsigned short)LISTEN_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        /* bind the listening socket */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != -1 &&
            listen(listen_fd, BACKLOG) != -1 &&
            (client_fd = accept(listen_fd, NULL, NULL)) != -1) {

            /* receive data directly into the command_buffer after the existing prefix
               Note: buffer size and lack of bounds checks are preserved as in original */
            received_len = recv(client_fd,
                                command_buffer + prefix_len,
                                (BUFFER_SIZE - 1) - prefix_len,
                                0);

            if ((int)received_len != -1 && (int)received_len != 0) {
                /* Null-terminate based on received length (preserving original arithmetic) */
                command_buffer[prefix_len + (ulong)(long)received_len / 1] = '\0';

                /* Strip CR and LF if present (in-place) */
                ptr = strchr(command_buffer, '\r');
                if (ptr != NULL) {
                    *ptr = '\0';
                }
                ptr = strchr(command_buffer, '\n');
                if (ptr != NULL) {
                    *ptr = '\0';
                }

                /* preserve the accepted client fd for later close */
                placeholder_fd = client_fd;
            }
        } else {
            /* original code did not add extra error handling here */
        }
    }

    /* Close descriptors if opened (preserve original close behavior/order) */
    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (placeholder_fd != -1) {
        close(placeholder_fd);
    }

    /* Call to external function with the assembled command (vulnerability preserved) */
    func_2(command_buffer);

    /* Final stack check as in original */
    if (__stack_chk_guard != local_canary) {
        __stack_chk_fail();
    }

    return;
}