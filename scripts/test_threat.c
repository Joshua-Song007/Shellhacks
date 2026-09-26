// Benign, on-stage-safe Stage-1 trigger (Phase 9 item 8). Crosses all 3
// Stage-1 detectors for real, live, without ever touching a real snapshot:
//
//   1. ExecFromTempOrCache: test_threat.sh execs this binary straight out
//      of a mktemp -d working dir (a TEMP_PREFIXES path).
//   2. RapidFileModBurst: the "burst" stage below does 80
//      create+write+unlink cycles well under BURST_WINDOW_NS.
//   3. RecoverySnapshotTamper: this binary then execs a sibling copy of
//      itself that test_threat.sh pre-staged under the literal name
//      "tmutil" with argv0="tmutil", argv1="deletelocalsnapshots" --
//      scout::scoring::is_snapshot_tamper matches on the exec target's
//      *basename* + verb arg, not on which real binary it is, so this is
//      the exact same shape a real tmutil invocation would produce without
//      running or being the real tmutil.
//
// No forking: a single process re-execs itself (twice), so this all stays
// one Scout lineage (matches lineage.rs's own exec-rekey rule) start to
// finish, same as spike1_trigger.c's "child" no-op convention for the
// final, harmless stage.
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 0 && strcmp(argv[0], "tmutil") == 0) {
        // Benign no-op impersonating tmutil's argv0 -- never touches a
        // real snapshot. Proves detection fires on shape, not on identity.
        return 0;
    }

    if (argc < 2 || strcmp(argv[1], "burst") != 0) {
        fprintf(stderr, "usage: payload burst\n");
        return 1;
    }

    for (int i = 0; i < 80; i++) {
        char name[32];
        snprintf(name, sizeof(name), "f%d", i);
        int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            return 1;
        }
        write(fd, "x", 1);
        close(fd);
        unlink(name);
    }

    // argv[0] is guaranteed absolute by test_threat.sh's `exec "$WORK/payload"`.
    char dir_buf[PATH_MAX];
    strncpy(dir_buf, argv[0], sizeof(dir_buf) - 1);
    dir_buf[sizeof(dir_buf) - 1] = '\0';
    char *dir = dirname(dir_buf);

    char tmutil_path[PATH_MAX];
    snprintf(tmutil_path, sizeof(tmutil_path), "%s/tmutil", dir);

    execl(tmutil_path, "tmutil", "deletelocalsnapshots", (char *)NULL);
    _exit(127);
}
