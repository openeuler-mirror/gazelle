/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* gazelle is licensed under the Mulan PSL v2.
* You can use this software according to the terms and conditions of the Mulan PSL v2.
* You may obtain a copy of Mulan PSL v2 at:
*     http://license.coscl.org.cn/MulanPSL2
* THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
* PURPOSE.
* See the Mulan PSL v2 for more details.
*/

#include "trace.h"

#include <stdio.h>
#include <string.h>


/* Lists the supported APIs by reading from a markdown file under a specific title */
void list_api()
{
    const char *file_path = API_LIST_MD_PATH; // Path to the markdown file
    FILE *file = fopen(file_path, "r"); // Open the file for reading
    if (file == NULL) {
        fprintf(stderr, "Error opening %s\n", file_path); // Output error message with the file path
        return;
    }

    char line[MAX_LINE_LENGTH];
    int in_section = 0;  // Flag to track if we are in the desired section
    const char *section_title = "# Gazelle Supported POSIX Interface List";  // The section we are looking for

    /* Read the file line by line */
    while (fgets(line, sizeof(line), file) != NULL) {
        // Optionally, check for reading errors
        if (ferror(file)) {
            fprintf(stderr, "Error reading from %s\n", file_path); // Output error message
            break;
        }

        // Check if the line is the section title
        if (strncmp(line, section_title, strlen(section_title)) == 0) {
            in_section = 1;  // Start printing the section content
            continue;        // Skip the section title line itself
        }

        // If we are in the section, print the content until we encounter a new section or an empty line
        if (in_section) {
            // Stop printing if we encounter a new title or an empty line
            if (line[0] == '\n' || line[0] == '#') {
                break;  // Exit the section
            }
            printf("%s", line);  // Print the current line
        }
    }

    // Close the file and handle any potential errors
    if (fclose(file) != 0) {
        fprintf(stderr, "Error closing %s\n", file_path);   // Output error message with the file path on closing error
    }
}

/* Generic function to handle system calls */
bool handle_syscall(pid_t pid, struct user_regs_struct *regs, bool *tracing, int *status)
{
    long syscall = regs->orig_rax;
    const char *name = net_syscall_name(syscall);

    if (name) {
        /* Handle specific POSIX API calls */
        bool should_return = handle_specific_syscall(pid, regs, syscall);
        if (should_return) {
            return true;  // Skip further processing and continue to the next iteration
        }

        /* Resume the traced process to execute the system call */
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace");
            *tracing = false;
            return false;
        }

        /* Wait for the traced process to pause again */
        waitpid(pid, status, 0);
        if (WIFEXITED(*status)) {
            *tracing = false;
            return false;
        }

        /* Retrieve the return value of the system call */
        if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
            perror("ptrace getregs");
            *tracing = false;
            return false;
        }
        long retval = regs->rax;

        if (retval < 0) {
            int err = -retval;
            printf("-1 %s (%s)\n", strerrorname_np(err), strerror(err));
        } else {
            printf("%ld\n", retval);
        }
    }

    /* Check if the traced process has exited */
    if (WIFEXITED(*status)) {
        *tracing = false;
    }

    return false;
}

/* Function to handle specific POSIX API calls */
bool handle_specific_syscall(pid_t pid, struct user_regs_struct *regs, long syscall)
{
    switch (syscall) {
        case SYS_socket:
            handle_socket(pid, regs);
            break;
        case SYS_connect:
            handle_connect(pid, regs);
            break;
        case SYS_setsockopt:
            handle_setsockopt(pid, regs);
            break;
        case SYS_bind:
            handle_bind(pid, regs);
            break;
        case SYS_getsockopt:
            handle_getsockopt(pid, regs);
            break;
        case SYS_getpeername:
            handle_getpeername(pid, regs);
            return true;  // Skip further processing and continue to the next iteration
        case SYS_accept:
            handle_accept(pid, regs);
            return true;  // Skip further processing and continue to the next iteration
        case SYS_socketpair:
            handle_socketpair(pid, regs);
            break;
        case SYS_getsockname:
            handle_getsockname(pid, regs);
            break;
        case SYS_sendto:
            handle_sendto(pid, regs);
            break;
        case SYS_recvfrom:
            handle_recvfrom(pid, regs);
            return true;  // Skip further processing and continue to the next iteration
        default:
            handle_generic_syscall(net_syscall_name(syscall), regs);
            break;
    }

    return false;
}

/* Traces POSIX API calls of the target executable */
void trace(const char *cmd)
{
    pid_t pid;
    int status;

    pid = fork();
    if (pid == 0) {
        /* Child process: request tracing and execute the command */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        /*
         * When the child process executes exec:
         * 1. It requests to execute a new program (e.g., /bin/sh).
         * 2. The kernel prepares to load the new program image.
         * 3. The kernel detects the PTRACE_TRACEME flag and pauses the child process,
         *    sending a SIGTRAP signal to the parent.
         * 4. The child process waits for the parent to handle the signal.
         */

        /* Prepare arguments for execvp */
        char *argv[] = {"sh", "-c", NULL, NULL};
        if (cmd != NULL && strlen(cmd) > 0) {
            argv[CMD_INDEX] = (char *)cmd;
            execvp("sh", argv);
        } else {
            fprintf(stderr, "Invalid command.\n");
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    } else if (pid > 0) {
        /* Parent process: trace the child */
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
        bool tracing = true;
        while (tracing) {
            /*
             * Continue the child process and request to pause at system call entry/exit.
             */
            if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                perror("ptrace error");
                break;
            }

            /* Wait for the child process to pause */
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                break;
            }

            struct user_regs_struct regs;
            /* Get the child's register state */
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);

            /* Handle the system call */
            if (handle_syscall(pid, &regs, &tracing, &status)) {
                continue;
            }
        }

        /* Detach from the child process */
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    } else {
        perror("fork");
    }
}

/* Traces POSIX API calls of the target PID */
void pid_trace(pid_t pid)
{
    int status;
    bool tracing = true;

    /* Attach to the target process */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach error");
        return;
    }

    /* Confirm attachment */
    printf("trace pid: Process %d attached\n", pid);

    /* Wait for the target process to stop */
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        printf("The process has already exited.\n");
        return;
    }

    /* Set ptrace options to trace system calls */
    if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD) == -1) {
        perror("ptrace set options");
        return;
    }

    while (tracing) {
        /* Continue the target process and request to pause at system call entry/exit */
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace syscall");
            break;
        }

        /* Wait for the target process to pause */
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        struct user_regs_struct regs;

        /* Get the target's register state */
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("ptrace getregs");
            break;
        }

        /* Handle the system call */
        if (handle_syscall(pid, &regs, &tracing, &status)) {
            continue;
        }
    }

    /* Detach from the target process */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

/* Function to handle IO multiplexing system calls */
void handle_multiplex_syscall(long syscall, int *select_detected, int *poll_detected, int *epoll_wait_detected)
{
    /* Detect IO multiplexing mechanisms */
    switch (syscall) {
        case SYS_select:
            if (!(*select_detected)) {
                printf("IO multiplexing mechanism used: select()\n");
                *select_detected = 1;
            }
            break;
        case SYS_poll:
            if (!(*poll_detected)) {
                printf("IO multiplexing mechanism used: poll()\n");
                *poll_detected = 1;
            }
            break;
        case SYS_epoll_wait:
            if (!(*epoll_wait_detected)) {
                printf("IO multiplexing mechanism used: epoll_wait()\n");
                *epoll_wait_detected = 1;
            }
            break;
        default:
            /* Skip non-IO multiplexing system calls */
            break;
    }
}

/* Traces IO multiplexing mechanisms used by the target executable */
void multiplex(const char *cmd)
{
    pid_t pid;
    int status;

    /* Flags to track detected IO multiplexing mechanisms */
    int select_detected = 0;
    int poll_detected = 0;
    int epoll_wait_detected = 0;

    pid = fork();
    if (pid == 0) {
        /* Child process: request tracing and execute the command */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);

        /* Execute the command using execvp */
        if (cmd != NULL && strlen(cmd) > 0) {
            char *argv[] = {"sh", "-c", (char *)cmd, NULL, NULL};
            execvp("sh", argv);
        } else {
            fprintf(stderr, "Invalid command.\n");
            exit(EXIT_FAILURE);
        }

        exit(EXIT_SUCCESS);
    } else if (pid > 0) {
        /* Parent process: trace the child */
        waitpid(pid, &status, 0);
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
        bool tracing = true;
        while (tracing) {
            /* Continue the child process and request to pause at system call entry/exit */
            if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                perror("ptrace error");
                break;
            }

            /* Wait for the child process to pause */
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                break;
            }

            struct user_regs_struct regs;
            /* Get the child's register state */
            ptrace(PTRACE_GETREGS, pid, NULL, &regs);
            long syscall = regs.orig_rax;

            /* Process IO multiplexing system calls */
            handle_multiplex_syscall(syscall, &select_detected, &poll_detected, &epoll_wait_detected);

            /* Continue the child process to execute the system call */
            if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
                perror("ptrace");
                tracing = false;
                break;
            }

            /* Wait for the child process to pause again */
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                tracing = false;
            }
        }
        /* Detach from the child process */
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        /* Report if no IO multiplexing mechanisms were detected */
        if (!select_detected && !poll_detected && !epoll_wait_detected) {
            printf("No IO multiplexing mechanisms were used by the target executable.\n");
        }
    } else {
        perror("fork");
    }
}
/* Track the IO multiplexing mechanisms used by the target PID */
void pid_multiplex(pid_t pid)
{
    int status;

    /* Flags to track detected IO multiplexing mechanisms */
    int select_detected = 0;
    int poll_detected = 0;
    int epoll_wait_detected = 0;

    /* Attach to the target process */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return;
    }

    /* Wait for the target process to stop */
    waitpid(pid, &status, 0);

    /* Set ptrace options to trace system calls */
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    bool tracing = true;
    while (tracing) {
        /* Resume the target process and request a stop at syscall entry/exit */
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace syscall");
            break;
        }

        /* Wait for the target process to stop */
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            break;
        }

        struct user_regs_struct regs;
        /* Retrieve the register state of the target */
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        long syscall = regs.orig_rax;

        /* Handle IO multiplexing system calls */
        handle_multiplex_syscall(syscall, &select_detected, &poll_detected, &epoll_wait_detected);

        /* Resume the target process to execute the system call */
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            perror("ptrace");
            tracing = false;
            break;
        }

        /* Wait for the target process to stop again */
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            tracing = false;
        }
    }

    /* Detach from the target process */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    /* Report if no IO multiplexing mechanisms were detected */
    if (!select_detected && !poll_detected && !epoll_wait_detected) {
        printf("No IO multiplexing mechanisms were used by the target process.\n");
    }
}

