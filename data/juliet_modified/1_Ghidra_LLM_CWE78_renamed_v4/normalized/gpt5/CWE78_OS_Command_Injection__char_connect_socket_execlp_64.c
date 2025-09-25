#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

/* External symbols used for stack protector checks (kept as in original) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(void);

/* Declaration for external function referenced in original */
void func_2(char **ptr);

/* Renamed function: preserves original control flow and vulnerabilities */
void vulnerable_network_handler(void) {
    int socket_fd;
    int connect_result;
    int temp_int;
    size_t initial_len;
    ssize_t recv_len;
    char *linebreak_ptr;
    char *command_buffer;
    struct sockaddr_in addr;
    char local_buffer[100];
    long saved_stack_guard;

    /* Save stack guard (as in original) */
    saved_stack_guard = *(long *)&__stack_chk_guard;

    /* Initialize buffer to zeros and set up initial content "ls " */
    memset(local_buffer, 0, 100);
    local_buffer[0] = 'l';
    local_buffer[1] = 0x73; /* 's' */
    local_buffer[2] = 0x20; /* ' ' */
    command_buffer = local_buffer;

    /* Compute current length of the buffer */
    initial_len = strlen(command_buffer);

    /* Create a socket (AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6) */
    socket_fd = socket(2, 1, 6);

    if (socket_fd != -1) {
        /* Prepare sockaddr_in structure (kept as explicit fields) */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = 0x02;            /* AF_INET */
        addr.sin_port = 0x8769;            /* raw port value preserved */
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");

        /* Connect using the sockaddr_in cast to sockaddr */
        connect_result = connect(socket_fd, (struct sockaddr *)&addr, 0x10);

        if (connect_result != -1) {
            /* Receive data into buffer, allowing overflow as in original */
            recv_len = recv(socket_fd,
                            command_buffer + initial_len,
                            99 - initial_len,
                            0);
            temp_int = (int)recv_len;

            if ((temp_int != -1) && (temp_int != 0)) {
                /* Preserve original index calculation and termination */
                command_buffer[initial_len + (size_t)(long)temp_int / 1] = '\0';

                /* Strip CR if present */
                linebreak_ptr = strchr(command_buffer, 0x0d);
                if (linebreak_ptr != (char *)0x0) {
                    *linebreak_ptr = '\0';
                }

                /* Strip LF if present */
                linebreak_ptr = strchr(command_buffer, 10);
                if (linebreak_ptr != (char *)0x0) {
                    *linebreak_ptr = '\0';
                }
            }
        }
    }

    if (socket_fd != -1) {
        close(socket_fd);
    }

    /* Call out to external function as in original */
    func_2(&command_buffer);

    /* Stack guard check (as in original) */
    if (*(long *)&__stack_chk_guard != saved_stack_guard) {
        __stack_chk_fail();
    }

    return;
}