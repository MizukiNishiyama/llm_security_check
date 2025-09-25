#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Constants for clarity */
#define BACKLOG 5
#define CMD_BUF_SIZE 100

/* External stack protector symbols (preserve original stack check logic) */
extern long __stack_chk_guard;
extern void __stack_chk_fail(int);

/* Prototype for an external condition function (kept as in original) */
int func_2(void);

/* Renamed function for readability; preserves original control flow and vulnerabilities */
void vulnerable_network_handler(void)
{
    int listen_fd;
    int client_fd;
    size_t base_len;
    ssize_t recv_len;
    char *ptr;
    int status_fd;
    struct sockaddr_in addr;
    char command_buffer[CMD_BUF_SIZE];
    long saved_guard;

    /* preserve stack guard value */
    saved_guard = __stack_chk_guard;

    /* initialize command buffer */
    memset(command_buffer, 0, CMD_BUF_SIZE);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73;
    command_buffer[2] = 0x20;

    /* conditional entry (original external check) */
    if (func_2() != 0) {
        status_fd = -1;

        /* compute current length of buffer prefix */
        base_len = strlen(command_buffer);

        /* create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
        listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (listen_fd != -1) {
            /* construct sockaddr_in by explicitly setting fields to mirror original byte-level setup */
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;

            /* set port bytes directly (network byte order expected by bind) */
            addr.sin_port = (in_port_t)(((unsigned char)'i' << 8) | (unsigned char)(-0x79));

            /* leave sin_addr as 0.0.0.0 and sin_zero zeroed (as original set sa_data[2..13]=0) */

            /* bind, listen, accept sequence (no additional checks or protections added) */
            if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) != -1 &&
                listen(listen_fd, BACKLOG) != -1 &&
                (client_fd = accept(listen_fd, (struct sockaddr *)0x0, (socklen_t *)0x0)) != -1) {

                /* receive data into command_buffer after the existing prefix */
                recv_len = recv(client_fd, command_buffer + base_len, CMD_BUF_SIZE - 1 - base_len, 0);
                status_fd = (int)recv_len;

                if (status_fd != -1 && status_fd != 0) {
                    /* terminate string where data ends (preserve original indexing behavior) */
                    command_buffer[base_len + (unsigned long)(long)status_fd / 1] = '\0';

                    /* strip CR and LF if present */
                    ptr = strchr(command_buffer, 0x0d);
                    if (ptr != (char *)0x0) {
                        *ptr = '\0';
                    }
                    ptr = strchr(command_buffer, 0x0a);
                    if (ptr != (char *)0x0) {
                        *ptr = '\0';
                    }
                }
            }
        }

        /* close descriptors if opened (preserve original cleanup behavior) */
        if (listen_fd != -1) {
            close(listen_fd);
        }
        if (status_fd != -1) {
            close(status_fd);
        }
    }

    /* execute shell (preserve dangerous call and original argument list) */
    int ret = execlp("sh", "sh");

    /* final stack guard check (preserve original behavior) */
    if (__stack_chk_guard != saved_guard) {
        __stack_chk_fail(ret);
    }

    return;
}