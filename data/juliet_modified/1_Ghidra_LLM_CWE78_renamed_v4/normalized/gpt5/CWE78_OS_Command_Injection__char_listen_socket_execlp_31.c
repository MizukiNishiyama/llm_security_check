#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>

/* External stack protector symbols kept to mirror original behavior */
extern long __stack_chk_guard;
void __stack_chk_fail(int);

/* Constants for readability */
#define BACKLOG 5
#define ADDR_LEN 16
#define COMMAND_BUFFER_SIZE 100

/* Renamed function for clarity; behavior and vulnerabilities preserved */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t base_len;
    ssize_t recv_len;
    char *p;
    int tmp_fd = -1;
    struct sockaddr_in addr;
    char command_buffer[COMMAND_BUFFER_SIZE];
    long guard = __stack_chk_guard;

    /* Initialize buffer */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;
    command_buffer[2] = 0x20;

    listen_fd = -1;
    base_len = strlen(command_buffer);

    /* Create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd != -1) {
        /* Prepare sockaddr_in by setting fields equivalent to original sockaddr bytes */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;

        /* Reproduce original byte-level assignments for port:
           original sa_data[0] = 'i' (0x69), sa_data[1] = -0x79 (0x87) */
        unsigned short raw_port = (unsigned short)((0x69 << 8) | (unsigned char)(-0x79));
        addr.sin_port = htons(raw_port);

        /* sin_addr and sin_zero remain zeroed as in original code */

        if (bind(listen_fd, (struct sockaddr *)&addr, ADDR_LEN) != -1 &&
            listen(listen_fd, BACKLOG) != -1 &&
            (tmp_fd = accept(listen_fd, (struct sockaddr *)0x0, (socklen_t *)0x0)) != -1) {

            /* Receive data directly into the remainder of the command buffer */
            recv_len = recv(tmp_fd, command_buffer + base_len, COMMAND_BUFFER_SIZE - 1 - base_len, 0);
            if (recv_len != -1 && recv_len != 0) {
                /* Null-terminate based on received length (preserves original integer casts) */
                command_buffer[base_len + (unsigned long)(long)((int)recv_len) / 1] = '\0';

                /* Strip CR and LF if present */
                p = strchr(command_buffer, '\r');
                if (p != (char *)0x0) {
                    *p = '\0';
                }
                p = strchr(command_buffer, '\n');
                if (p != (char *)0x0) {
                    *p = '\0';
                }
            }
        }
    }

    if (listen_fd != -1) {
        close(listen_fd);
    }
    if (tmp_fd != -1) {
        close(tmp_fd);
    }

    /* Execute a shell as in the original code (vulnerability preserved) */
    execlp("sh", "sh");

    /* Stack protector check reproduced */
    if (__stack_chk_guard != guard) {
        __stack_chk_fail((int)listen_fd);
    }

    return;
}