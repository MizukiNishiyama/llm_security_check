#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Constants (magic numbers made explicit) */
#define LISTEN_BACKLOG 5
#define COMMAND_BUF_SIZE 100
#define PORT 0x8769  /* network byte order will be handled via htons */

/* External symbols used to preserve original control flow checks */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* External global used elsewhere in original program */
extern char * _CWE78_OS_Command_Injection__char_listen_socket_execl_68_badData;

/* Forward declaration of external function called at end */
void func_2(char *arg);

/* Readable version of the original vulnerable function.
   Note: Vulnerabilities (no input validation, potential buffer overflow,
   use of sockets with direct recv into buffer, assignment to global) are
   intentionally preserved. */
void vulnerable_network_handler(void)
{
    long stack_guard_value;
    int listen_fd;
    int client_fd;
    struct sockaddr_in addr;
    char command_buffer[COMMAND_BUF_SIZE];
    size_t prefix_len;
    ssize_t recv_ret;
    char *found;

    /* preserve original stack guard check usage */
    stack_guard_value = __stack_chk_guard;

    /* initialize buffer and set a short command prefix */
    memset(command_buffer, 0, COMMAND_BUF_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    listen_fd = -1;
    prefix_len = strlen(command_buffer);

    /* create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {
        /* prepare sockaddr_in structure */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        /* bind to the port */
        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != -1) {
            /* start listening */
            if (listen(listen_fd, LISTEN_BACKLOG) != -1) {
                /* accept an incoming connection */
                client_fd = accept(listen_fd, NULL, NULL);
                if (client_fd != -1) {
                    /* receive data directly into the buffer after the prefix
                       NOTE: No bounds checking beyond original recv size */
                    recv_ret = recv(client_fd,
                                    command_buffer + prefix_len,
                                    (COMMAND_BUF_SIZE - 1) - prefix_len,
                                    0);
                    if ((recv_ret != -1) && (recv_ret != 0)) {
                        /* null-terminate at the received length */
                        command_buffer[prefix_len + (size_t)recv_ret] = '\0';

                        /* strip CR and LF if present */
                        found = strchr(command_buffer, '\r');
                        if (found != NULL) {
                            *found = '\0';
                        }
                        found = strchr(command_buffer, '\n');
                        if (found != NULL) {
                            *found = '\0';
                        }
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

    /* assign the received command buffer to the global used by the rest of program */
    _CWE78_OS_Command_Injection__char_listen_socket_execl_68_badData = command_buffer;

    /* continue original control flow */
    func_2(NULL);

    /* stack guard check as in original */
    if (__stack_chk_guard != stack_guard_value) {
        __stack_chk_fail();
    }
}