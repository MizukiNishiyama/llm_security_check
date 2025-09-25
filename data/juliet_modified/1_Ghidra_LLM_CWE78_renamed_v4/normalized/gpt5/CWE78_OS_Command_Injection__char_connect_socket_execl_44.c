#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* External stack protector symbols (kept as in original) */
extern long __stack_chk_guard;
void __stack_chk_fail(void);

/* Preserve original external function (name kept) */
void func_1(char *data);

/* Constants and sizes */
#define PORT 0x8769
#define CMD_BUFFER_SIZE 100

/* Renamed for clarity: original func_0 */
void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t addr;
    int ret_connect;
    size_t prefix_len;
    ssize_t recv_len;
    char *found;
    struct sockaddr_in remote_addr;
    char command_buffer[CMD_BUFFER_SIZE];
    long stack_guard_saved;

    /* Save stack guard as in original */
    stack_guard_saved = __stack_chk_guard;

    /* Initialize buffer */
    memset(command_buffer, 0, CMD_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;
    command_buffer[2] = 0x20;

    /* Compute current length of the prefix in the buffer */
    prefix_len = strlen(command_buffer);

    /* Create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (socket_fd != -1) {
        /* Prepare sockaddr_in structure */
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;

        /* Set port and address using original-style calls */
        remote_addr.sin_port = (in_port_t)PORT; /* kept as numeric assignment */
        addr = inet_addr("127.0.0.1");
        remote_addr.sin_addr.s_addr = addr;

        /* Connect to the remote address (size kept explicit) */
        ret_connect = connect(socket_fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
        if (ret_connect != -1) {
            /* Receive data directly into the command buffer after the prefix */
            recv_len = recv(socket_fd, command_buffer + prefix_len, CMD_BUFFER_SIZE - 1 - prefix_len, 0);
            ret_connect = (int)recv_len;
            if ((ret_connect != -1) && (ret_connect != 0)) {
                /* Null-terminate after received bytes (integer division explicit) */
                command_buffer[prefix_len + (unsigned long)((long)ret_connect) / 1] = '\0';

                /* Strip CR if present */
                found = strchr(command_buffer, '\r');
                if (found != NULL) {
                    *found = '\0';
                }

                /* Strip LF if present */
                found = strchr(command_buffer, '\n');
                if (found != NULL) {
                    *found = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Call out to the original sink function */
    func_1(command_buffer);

    /* Stack guard check as in original */
    if (__stack_chk_guard != stack_guard_saved) {
        __stack_chk_fail();
    }

    return;
}