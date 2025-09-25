#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>

#define PORT 0x8769
#define BUFFER_SIZE 100

/* Network handler that receives additional data into a command buffer
   and then invokes a command execution function with that buffer. */
void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t addr;
    int connect_ret;
    size_t prefix_len;
    ssize_t recv_len;
    char *ptr;
    struct sockaddr_in server_addr;
    char command_buffer[BUFFER_SIZE];
    volatile long stack_guard = 0; /* placeholder for stack check */

    /* Clear buffer and prepare initial command prefix "ls " */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */

    prefix_len = strlen(command_buffer);

    /* Create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd != -1) {

        /* Initialize sockaddr_in structure */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;

        /* Set port and address (kept as in original code) */
        server_addr.sin_port = (in_port_t)PORT;
        addr = inet_addr("127.0.0.1");
        server_addr.sin_addr.s_addr = (in_addr_t)addr;

        /* Connect to the server */
        connect_ret = connect(socket_fd, (struct sockaddr *)&server_addr, (socklen_t)sizeof(server_addr));
        if (connect_ret != -1) {

            /* Receive additional data into the command buffer (no bounds change) */
            recv_len = recv(socket_fd, command_buffer + prefix_len, (int)(BUFFER_SIZE - 1 - prefix_len), 0);
            connect_ret = (int)recv_len;
            if ((connect_ret != -1) && (connect_ret != 0)) {

                /* Null-terminate after received bytes (preserve original arithmetic) */
                command_buffer[prefix_len + (size_t)((long)connect_ret / 1)] = '\0';

                /* Strip CR and LF if present */
                ptr = strchr(command_buffer, 0x0d);
                if (ptr != NULL) {
                    *ptr = '\0';
                }
                ptr = strchr(command_buffer, 0x0a);
                if (ptr != NULL) {
                    *ptr = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Dangerous: execute the assembled command buffer as-is */
    system(command_buffer);

    /* Stack guard check placeholder (kept structurally similar) */
    if (stack_guard != 0) {
        /* Intentionally left to mirror original stack check behavior */
        abort();
    }

    return;
}