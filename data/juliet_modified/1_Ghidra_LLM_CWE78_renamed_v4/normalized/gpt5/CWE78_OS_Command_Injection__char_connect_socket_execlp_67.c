#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

/* Preserve external symbols used for stack protector checks in original binary */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Preserve external function called at end of original function */
extern void func_2(char *buf);

/* Port as in original (0x8769) */
#define PORT 0x8769

void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t addr;
    int connect_ret;
    size_t prefix_len;
    ssize_t recv_len;
    char *p;
    struct sockaddr_in remote_addr;
    char command_buffer[100];
    long stack_guard_saved;

    /* Save stack guard value as in original */
    stack_guard_saved = __stack_chk_guard;

    /* Initialize buffer and set initial command prefix "ls " */
    memset(command_buffer, 0, sizeof(command_buffer));
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */
    prefix_len = strlen(command_buffer);

    /* Create TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_fd != -1) {
        /* Initialize sockaddr_in structure for 127.0.0.1:PORT */
        memset(&remote_addr, 0, sizeof(remote_addr));
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = (in_port_t)PORT; /* keep raw port value as in original */
        addr = inet_addr("127.0.0.1");
        remote_addr.sin_addr.s_addr = addr;

        /* Call connect using the sockaddr_in cast to sockaddr, keep length 0x10 */
        connect_ret = connect(socket_fd, (struct sockaddr *)&remote_addr, 0x10);
        if (connect_ret != -1) {
            /* Receive data into command_buffer after the prefix; preserve original size arithmetic */
            recv_len = recv(socket_fd, command_buffer + prefix_len, 99 - prefix_len, 0);
            connect_ret = (int)recv_len;
            if ((connect_ret != -1) && (connect_ret != 0)) {
                /* Null-terminate based on received length (preserve original division by 1) */
                command_buffer[prefix_len + (ulong)(long)connect_ret / 1] = '\0';

                /* Strip carriage return if present */
                p = strchr(command_buffer, 0x0d);
                if (p != (char *)0x0) {
                    *p = '\0';
                }

                /* Strip newline if present */
                p = strchr(command_buffer, 0x0a);
                if (p != (char *)0x0) {
                    *p = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Call out to preserved external function with the command buffer */
    func_2(command_buffer);

    /* Stack protector check as in original */
    if (__stack_chk_guard != stack_guard_saved) {
        __stack_chk_fail();
    }

    return;
}