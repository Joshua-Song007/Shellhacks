// Benign SPIKE-1 trigger: performs create/open, rename, unlink in its working
// dir `iterations` times (argv[1], default 1), then one fork + exec + exit.
// Built fresh by spike1_eslogger.sh so it is not an Apple platform binary
// (copies of /bin tools are killed by launch constraints on macOS 13+).
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int iterations = 1;
    if (argc > 1) {
        if (strcmp(argv[1], "child") == 0) {
            return 0;
        }
        iterations = atoi(argv[1]);
        if (iterations < 1) {
            iterations = 1;
        }
    }

    for (int i = 0; i < iterations; i++) {
        int fd = open("f1", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            return 1;
        }
        write(fd, "x", 1);
        close(fd);
        rename("f1", "f2");
        unlink("f2");
    }

    pid_t pid = fork();
    if (pid == 0) {
        execl(argv[0], argv[0], "child", (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
