#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SOCKET_DOMAIN 2       /* AF_INET */
#define SOCKET_TYPE 1         /* SOCK_STREAM */
#define SOCKET_PROTOCOL 6     /* IPPROTO_TCP */
#define BIND_ADDR_LEN 0x10
#define LISTEN_BACKLOG 5
#define COMMAND_BUFFER_LEN 100
#define PORT 0x8769           /* retained magic port value */

/* Vulnerable network handler (preserves original unsafe behavior) */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t init_len;
    ssize_t recv_len;
    char *ptr;
    char command_buffer[COMMAND_BUFFER_LEN];

    /* Initialize command buffer with a short prefix ("ls ") */
    memset(command_buffer, 0, COMMAND_BUFFER_LEN);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* space */

    listen_fd = -1;
    client_fd = -1;

    /* Calculate current length of the command prefix */
    init_len = strlen(command_buffer);

    /* Create TCP socket */
    listen_fd = socket(SOCKET_DOMAIN, SOCKET_TYPE, SOCKET_PROTOCOL);

    if (listen_fd != -1) {
        struct sockaddr_in addr;

        /* Prepare IPv4 socket address structure */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = (short)SOCKET_DOMAIN;
        addr.sin_port = htons((unsigned short)PORT);
        addr.sin_addr.s_addr = 0; /* INADDR_ANY */

        /* Bind, listen, accept sequence (no error handling added) */
        if (bind(listen_fd, (struct sockaddr *)&addr, BIND_ADDR_LEN) != -1 &&
            listen(listen_fd, LISTEN_BACKLOG) != -1) {
            client_fd = accept(listen_fd, NULL, NULL);

            if (client_fd != -1) {
                /* Receive data appended to the existing command prefix */
                recv_len = recv(client_fd, command_buffer + init_len,
                                COMMAND_BUFFER_LEN - init_len - 1, 0);
                if (recv_len != -1 && recv_len != 0) {
                    /* Null-terminate based on received length */
                    command_buffer[init_len + (size_t)recv_len] = '\0';

                    /* Strip carriage return if present */
                    ptr = strchr(command_buffer, '\r');
                    if (ptr != NULL) {
                        *ptr = '\0';
                    }

                    /* Strip newline if present */
                    ptr = strchr(command_buffer, '\n');
                    if (ptr != NULL) {
                        *ptr = '\0';
                    }
                }
            }
        }
    }

    /* Close descriptors if opened (original behavior retained) */
    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (client_fd != -1) {
        close(client_fd);
    }

    /* Execute shell (call preserved as in original code) */
    execlp("sh", "sh");

    return;
}