#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 100
#define REMOTE_ADDR "127.0.0.1"
#define PORT 0x8769

/* External symbols from original binary */
extern long PTR____stack_chk_guard_100004000;
extern void func_2(char *);      /* behavior preserved as original */
extern void ___stack_chk_fail(void);

void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t ip_addr;
    int connect_result;
    size_t prefix_len;
    ssize_t recv_len;
    char *p;
    struct sockaddr_in remote_sockaddr;
    char command_buffer[BUFFER_SIZE];
    long stack_chk;

    /* stack protector value load (preserve original check) */
    stack_chk = *(long *)PTR____stack_chk_guard_100004000;

    /* Initialize buffer and set a small static prefix ("ls ") */
    memset(command_buffer, 0, BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';
    prefix_len = strlen(command_buffer);

    /* Create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd != -1) {
        /* Prepare sockaddr_in structure (zero other fields explicitly) */
        memset(&remote_sockaddr, 0, sizeof(remote_sockaddr));
        remote_sockaddr.sin_family = AF_INET;
        /* Preserve original assignment style for port and address */
        remote_sockaddr.sin_port = (in_port_t)PORT;
        ip_addr = inet_addr(REMOTE_ADDR);
        remote_sockaddr.sin_addr.s_addr = ip_addr;

        /* Connect to remote host */
        connect_result = connect(socket_fd, (struct sockaddr *)&remote_sockaddr, sizeof(remote_sockaddr));
        if (connect_result != -1) {
            /* Receive data directly into the buffer after the prefix */
            recv_len = recv(socket_fd, command_buffer + prefix_len, 99 - prefix_len, 0);
            connect_result = (int)recv_len;
            if ((connect_result != -1) && (connect_result != 0)) {
                /* Null-terminate after received bytes */
                command_buffer[prefix_len + (size_t)connect_result] = '\0';

                /* Strip CR if present */
                p = strchr(command_buffer, '\r');
                if (p != NULL) {
                    *p = '\0';
                }

                /* Strip LF if present */
                p = strchr(command_buffer, '\n');
                if (p != NULL) {
                    *p = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Call original function with the constructed command buffer */
    func_2(command_buffer);

    /* stack protector check (preserve original behavior) */
    if (*(long *)PTR____stack_chk_guard_100004000 != stack_chk) {
        ___stack_chk_fail();
    }

    return;
}