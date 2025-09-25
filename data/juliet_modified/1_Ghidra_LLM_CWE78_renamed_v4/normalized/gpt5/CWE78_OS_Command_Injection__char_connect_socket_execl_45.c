#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* Constants (magic numbers given symbolic names) */
#define AF_INET_FAMILY AF_INET
#define SOCK_TYPE SOCK_STREAM
#define PROTO_TCP IPPROTO_TCP
#define PORT 0x8769
#define REMOTE_ADDR "127.0.0.1"
#define BUFFER_TOTAL 100
#define CONNECT_ADDR_LEN sizeof(struct sockaddr_in)

/* External symbols kept as in the original binary layout */
char *DAT_100008000;
extern long PTR____stack_chk_guard_100004000;
extern void func_2(char *param);
extern void ___stack_chk_fail(void);

/* Vulnerable function (preserves original unsafe behavior) */
void vulnerable_network_handler(void)
{
    /* stack protector value preserved */
    long stack_guard = *(long *)PTR____stack_chk_guard_100004000;

    /* local command buffer with same fixed size as original */
    char command_buffer[BUFFER_TOTAL];
    size_t prefix_len;
    unsigned int sock_fd;
    unsigned int connect_ret;
    in_addr_t addr;
    char *temp_ptr;
    int recv_len;

    /* initialize buffer to zeros and set a short prefix ("ls ") as in original */
    memset(command_buffer, 0, BUFFER_TOTAL);
    command_buffer[0] = 'l';
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' (space) */

    /* compute current length of the prefix */
    prefix_len = strlen(command_buffer);

    /* create socket (returns unsigned int in original) */
    sock_fd = socket(AF_INET_FAMILY, SOCK_TYPE, PROTO_TCP);
    temp_ptr = (char *)(uintptr_t)sock_fd;

    if (sock_fd != (unsigned int)-1) {
        /* prepare sockaddr_in structure (explicit and clear layout) */
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET_FAMILY;
        serv_addr.sin_port = (uint16_t)PORT; /* preserved numeric port constant */
        addr = inet_addr(REMOTE_ADDR);
        serv_addr.sin_addr.s_addr = addr;

        /* perform connect using sockaddr pointer as in originals */
        connect_ret = connect((int)sock_fd, (struct sockaddr *)&serv_addr, CONNECT_ADDR_LEN);
        temp_ptr = (char *)(uintptr_t)connect_ret;

        if (connect_ret != (unsigned int)-1) {
            /* receive data directly into command_buffer starting at prefix_len
               NOTE: This preserves the original lack of bounds validation. */
            temp_ptr = (char *)recv((int)sock_fd, command_buffer + prefix_len, (int)(99 - prefix_len), 0);
            recv_len = (int)temp_ptr;
            if ((recv_len != -1) && (recv_len != 0)) {
                /* terminate received data (same arithmetic as original) */
                command_buffer[prefix_len + (unsigned long)(long)recv_len / 1] = '\0';

                /* strip CR and LF if present */
                temp_ptr = strchr(command_buffer, 0x0d);
                if (temp_ptr != NULL) {
                    *temp_ptr = '\0';
                }
                temp_ptr = strchr(command_buffer, 0x0a);
                if (temp_ptr != NULL) {
                    *temp_ptr = '\0';
                }
            }
        }
    }

    /* close socket if it was opened (preserve original behavior) */
    if (sock_fd != (unsigned int)-1) {
        sock_fd = close((int)sock_fd);
        temp_ptr = (char *)(uintptr_t)sock_fd;
    }

    /* expose buffer via global as in original binary */
    DAT_100008000 = command_buffer;

    /* call out to external function with the last temp_ptr value */
    func_2(temp_ptr);

    /* stack protector check preserved */
    if (*(long *)PTR____stack_chk_guard_100004000 != stack_guard) {
        ___stack_chk_fail();
    }

    return;
}