#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* External symbols referenced by the original binary */
extern long __stack_chk_guard;
void func_2(void *ptr);
void __stack_chk_fail(void);

/* Constants extracted from magic numbers in the original code */
#define LISTEN_PORT_RAW 0x8769
#define LOCAL_BUFFER_SIZE 100

/* Renamed and documented version of the original function.
   Comments describe processing steps without altering logic or fixing vulnerabilities. */
void vulnerable_network_handler(void)
{
    int socket_fd;
    in_addr_t addr_bin;
    int connect_result;
    size_t prefix_len;
    ssize_t recv_len;
    char *found_chr;
    struct sockaddr_in server_addr;
    char command_buffer[LOCAL_BUFFER_SIZE];
    /* Stack check guard snapshot as in original binary */
    long stack_guard_snapshot;

    /* Preserve stack cookie behavior from original */
    stack_guard_snapshot = __stack_chk_guard;

    /* Initialize buffer and set fixed prefix "ls " (3 bytes) */
    memset(command_buffer, 0, LOCAL_BUFFER_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 's';
    command_buffer[2] = ' ';

    /* Determine current string length of the prefix */
    prefix_len = strlen(command_buffer);

    /* Create a socket: AF_INET (2), SOCK_STREAM (1), protocol 6 (TCP) */
    socket_fd = socket(2, 1, 6);
    if (socket_fd != -1) {

        /* Build sockaddr_in for 127.0.0.1:PORT (preserve raw port value) */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = (sa_family_t)2; /* AF_INET */
        /* Preserve the exact raw port constant used in the original */
        server_addr.sin_port = (in_port_t)LISTEN_PORT_RAW;
        addr_bin = inet_addr("127.0.0.1");
        server_addr.sin_addr.s_addr = (in_addr_t)addr_bin;

        /* Connect to the server using the sockaddr_in cast to sockaddr */
        connect_result = connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (connect_result != -1) {

            /* Receive data directly into command_buffer after the prefix,
               preserving original size uses and lack of additional checks */
            recv_len = recv(socket_fd, command_buffer + prefix_len, (int)(LOCAL_BUFFER_SIZE - 1 - prefix_len), 0);
            connect_result = (int)recv_len;
            if ((connect_result != -1) && (connect_result != 0)) {
                /* Null-terminate at the received length (preserve integer/size conversions) */
                command_buffer[prefix_len + (size_t)((long)connect_result / 1)] = '\0';

                /* Strip CR if present */
                found_chr = strchr(command_buffer, '\r');
                if (found_chr != NULL) {
                    *found_chr = '\0';
                }

                /* Strip LF if present */
                found_chr = strchr(command_buffer, '\n');
                if (found_chr != NULL) {
                    *found_chr = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Prepare argument and call the external function as in original */
    {
        void *arg = command_buffer;
        func_2(arg);
    }

    /* Final stack check as in original */
    if (__stack_chk_guard != stack_guard_snapshot) {
        __stack_chk_fail();
    }

    return;
}