/* Audit 2026-11-06, finding 2: fails the first descriptor duplication
 * (F_DUPFD_CLOEXEC, as File::try_clone makes) after a rename onto the
 * path in TASO_AUDIT_RENAME_TARGET, with EMFILE.  LD_PRELOAD it into the
 * audit_compaction test only (see that test's header). */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
static int armed;
int rename(const char *from, const char *to) {
    int (*real)(const char*, const char*) = dlsym(RTLD_NEXT, "rename");
    int result = real(from, to);
    const char *target = getenv("TASO_AUDIT_RENAME_TARGET");
    if (result == 0 && target && strcmp(target, to) == 0) armed = 1;
    return result;
}
static int call_fcntl(const char *name, int fd, int cmd, long arg) {
    int (*real)(int,int,...) = dlsym(RTLD_NEXT, name);
    /* Only inside the compaction's finish: the test unsets the variable
     * after it, and a later duplication (the reopen) is not failed. */
    if (armed && !getenv("TASO_AUDIT_RENAME_TARGET")) armed = 0;
    if (armed && cmd == F_DUPFD_CLOEXEC) {
        armed = 0;
        errno = EMFILE;
        return -1;
    }
    return real(fd,cmd,arg);
}
int fcntl(int fd, int cmd, ...) {
    long arg = 0;
    if (cmd != F_GETFD && cmd != F_GETFL && cmd != F_GETOWN) {
        va_list ap; va_start(ap,cmd); arg = va_arg(ap,long); va_end(ap);
    }
    return call_fcntl("fcntl",fd,cmd,arg);
}
int fcntl64(int fd, int cmd, ...) {
    long arg = 0;
    if (cmd != F_GETFD && cmd != F_GETFL && cmd != F_GETOWN) {
        va_list ap; va_start(ap,cmd); arg = va_arg(ap,long); va_end(ap);
    }
    return call_fcntl("fcntl64",fd,cmd,arg);
}
