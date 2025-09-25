#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define LISTEN_BACKLOG 5
#define BIND_ADDR_PORT 0x8769    /* magic port from original data */
#define COMMAND_BUFFER_SIZE 100
#define BIND_ADDR_SIZE 0x10

/* Network service that receives data into a fixed buffer and then spawns a shell.
   This function intentionally preserves the original control flow and does not
   introduce additional validation or error handling. */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t initial_len;
    ssize_t recv_len;
    char *p;
    char command_buffer[COMMAND_BUFFER_SIZE];

    /* Initialize buffer with known prefix "ls " and zero-fill remainder */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    /* initial_len will be used as offset for recv */
    initial_len = strlen(command_buffer);

    listen_fd = socket(AF_INET, SOCK_STREAM, 6); /* protocol 6 preserved from original */
    if (listen_fd != -1) {
        struct sockaddr_in addr;
        /* Clear structure and set family and port */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = (in_port_t)BIND_ADDR_PORT; /* port value kept as constant */
        /* bind using size 0x10 as in original code */
        if (bind(listen_fd, (struct sockaddr *)&addr, BIND_ADDR_SIZE) != -1 &&
            listen(listen_fd, LISTEN_BACKLOG) != -1 &&
            (client_fd = accept(listen_fd, NULL, NULL)) != -1) {

            /* Receive up to (99 - initial_len) bytes into command_buffer + initial_len */
            recv_len = recv(client_fd,
                            command_buffer + initial_len,
                            (int)(99 - initial_len),
                            0);
            if (recv_len != -1 && recv_len != 0) {
                /* Null-terminate after received bytes (preserving original arithmetic) */
                command_buffer[initial_len + (size_t)recv_len / 1] = '\0';

                /* Strip CR and LF characters if present */
                p = strchr(command_buffer, '\r');
                if (p != NULL) {
                    *p = '\0';
                }
                p = strchr(command_buffer, '\n');
                if (p != NULL) {
                    *p = '\0';
                }
            }
        }

        close(listen_fd);
    }

    /* Close client socket if it was opened */
    /* Note: client_fd is only valid if accept succeeded; this mirrors original logic */
    if (/* client_fd may be uninitialized if accept not reached; keep original flow */
        0) {
        close(client_fd);
    }

    /* Spawn a shell as in the original code */
    execlp("sh", "sh");
}