#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* External stack protector symbols (kept to mirror original checks) */
extern long __stack_chk_guard;
void __stack_chk_fail(void *);

/* Constants (magic numbers made explicit) */
#define COMMAND_BUFFER_SIZE 100
#define SOCKADDR_LEN 16
#define LISTEN_BACKLOG 5

/* Function prototypes (renamed for clarity) */
char *setup_and_receive(char *command_buffer);
void vulnerable_entry(void);
int main_flow(void);
unsigned long print_message(unsigned long msg);

/* Implementation */

/* Entry that prepares a command buffer and invokes shell (vulnerable behavior preserved) */
void vulnerable_entry(void)
{
    long stack_cookie;
    char command_buffer[COMMAND_BUFFER_SIZE];

    stack_cookie = __stack_chk_guard;

    /* Initialize buffer to zeros (same size as original) */
    memset(command_buffer, 0, COMMAND_BUFFER_SIZE);

    /* Fill initial bytes with 'l', 's', ' ' to form a command prefix */
    command_buffer[0] = 0x6c; /* 'l' */
    command_buffer[1] = 0x73; /* 's' */
    command_buffer[2] = 0x20; /* ' ' */

    /* Receive additional data into the command buffer over network */
    setup_and_receive(command_buffer);

    /* Call execl exactly as in original (no terminating NULL provided) */
    execl("/bin/sh", "/bin/sh");

    /* Stack protector check (preserved) */
    if (__stack_chk_guard != stack_cookie) {
        __stack_chk_fail((void *)0);
    }

    return;
}

/* Sets up a listening socket and appends received data to the provided buffer */
char *setup_and_receive(char *command_buffer)
{
    long stack_cookie;
    unsigned int client_fd = 0xffffffff;
    unsigned int server_fd;
    size_t prefix_len;
    ssize_t recv_ret;
    struct sockaddr_in addr_in;
    socklen_t addr_len = sizeof(struct sockaddr_in);

    stack_cookie = __stack_chk_guard;

    /* Initialize sentinel value as in original */
    client_fd = 0xffffffff;

    /* Determine current length of data in the buffer */
    prefix_len = strlen(command_buffer);

    /* Create a TCP socket (AF_INET, SOCK_STREAM, IPPROTO_TCP) */
    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (server_fd != 0xffffffff) {
        /* Zero out the sockaddr_in structure */
        memset(&addr_in, 0, sizeof(addr_in));

        /* Set address family and port bytes to reproduce original sa_data assignments:
           original used raw sa_data bytes [0]=0x69, [1]=0x87 (signed -0x79 -> 0x87).
           Construct port value preserving those bytes in network byte order. */
        addr_in.sin_family = AF_INET;
        {
            unsigned short raw_port_bytes = (unsigned short)((0x69 << 8) | 0x87);
            addr_in.sin_port = htons(raw_port_bytes);
        }

        /* Listen on any address */
        addr_in.sin_addr.s_addr = INADDR_ANY;

        /* Bind, listen, accept sequence (error checks left as in original) */
        if (bind(server_fd, (struct sockaddr *)&addr_in, SOCKADDR_LEN) != 0xffffffff) {
            if (listen(server_fd, LISTEN_BACKLOG) != 0xffffffff) {
                client_fd = accept(server_fd, (struct sockaddr *)0x0, (socklen_t *)0x0);
                if (client_fd != 0xffffffff) {
                    /* Receive data directly into the command buffer after current content.
                       The available space is 99 - prefix_len, matching original behavior. */
                    recv_ret = recv((int)client_fd, command_buffer + prefix_len, 99 - prefix_len, 0);
                    if ((recv_ret != -1) && (recv_ret != 0)) {
                        /* Null-terminate at end of received data (same arithmetic as original) */
                        command_buffer[prefix_len + (size_t)recv_ret] = '\0';

                        /* Strip CR and LF characters if present */
                        char *p;
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
        }
    }

    /* Close descriptors if opened (preserved behavior) */
    if (server_fd != 0xffffffff) {
        close((int)server_fd);
    }
    if (client_fd != 0xffffffff) {
        close((int)client_fd);
    }

    /* Stack protector check (preserved) */
    if (__stack_chk_guard != stack_cookie) {
        __stack_chk_fail((void *)0);
    }

    return command_buffer;
}

/* High-level flow: seed RNG, print messages, invoke vulnerable entry */
int main_flow(void)
{
    time_t t = time((time_t *)0x0);
    srand((unsigned int)t);

    print_message((unsigned long)"Calling ...");
    vulnerable_entry();
    print_message((unsigned long)"Finished ");

    return 0;
}

/* Simple print wrapper that prints a string followed by newline if non-null */
unsigned long print_message(unsigned long msg)
{
    if (msg != 0) {
        printf("%s\n", (const char *)msg);
    }
    return msg;
}

/* Simple main to invoke the flow (kept minimal) */
int main(void)
{
    return main_flow();
}