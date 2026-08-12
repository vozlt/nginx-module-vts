/*
 * Checks, while the tests run, that the tree is never walked without the
 * mutex of the zone being held.
 *
 * No source file of the module knows about this. It is linked in with
 * -Wl,--wrap, which sends the calls that cross a translation unit to the
 * __wrap_ names here and leaves __real_ as the function that would have been
 * called. That is why it can be a build of its own rather than instrumentation
 * the module has to carry.
 *
 * What it can and cannot see:
 *
 *   - the depth counts every ngx_shmtx_lock() the process takes, this module's
 *     or nginx's own, so a lock held elsewhere can hide a violation. It cannot
 *     invent one, which is the direction that matters for a check that fails a
 *     build.
 *   - a call within the translation unit that defines the function is resolved
 *     without going through the symbol, so it is not wrapped. Every caller of
 *     find_node() is in another file.
 *
 * usage:
 *
 *   cc -c -o lockcheck.o util/lockcheck.c
 *   ./configure --add-module=... \
 *       --with-ld-opt="-Wl,--wrap=ngx_shmtx_lock \
 *                      -Wl,--wrap=ngx_shmtx_unlock \
 *                      -Wl,--wrap=ngx_http_vhost_traffic_status_find_node \
 *                      /abs/path/lockcheck.o"
 *
 * Every violation appends a line to $VTS_LOCKCHECK_LOG, or to
 * /tmp/vts-lockcheck.log. An empty or absent file is a clean run.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>

/*
 * Weak, because configure links a trivial program with the ld options it is
 * given to see whether they work, and this object goes with them. The linker
 * defines __real_* only where --wrap has something to wrap, so in that test
 * link they resolve to nothing and the test passes. In the real one they are
 * the functions the calls were going to.
 */

extern void *__real_ngx_http_vhost_traffic_status_find_node(void *r, void *key,
    unsigned type, unsigned flag) __attribute__((weak));
extern void  __real_ngx_shmtx_lock(void *mtx) __attribute__((weak));
extern void  __real_ngx_shmtx_unlock(void *mtx) __attribute__((weak));

/* one per process: the workers do not share it, and neither do they need to */
static unsigned  vts_lc_depth;


static void
vts_lc_report(const char *what)
{
    int          fd;
    const char  *path;

    path = getenv("VTS_LOCKCHECK_LOG");

    if (path == NULL) {
        path = "/tmp/vts-lockcheck.log";
    }

    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);

    if (fd < 0) {
        return;
    }

    (void) write(fd, what, strlen(what));
    (void) write(fd, "\n", 1);

    close(fd);
}


void
__wrap_ngx_shmtx_lock(void *mtx)
{
    if (__real_ngx_shmtx_lock == NULL) {
        return;
    }

    __real_ngx_shmtx_lock(mtx);

    vts_lc_depth++;
}


void
__wrap_ngx_shmtx_unlock(void *mtx)
{
    if (__real_ngx_shmtx_unlock == NULL) {
        return;
    }

    if (vts_lc_depth) {
        vts_lc_depth--;
    }

    __real_ngx_shmtx_unlock(mtx);
}


void *
__wrap_ngx_http_vhost_traffic_status_find_node(void *r, void *key,
    unsigned type, unsigned flag)
{
    if (__real_ngx_http_vhost_traffic_status_find_node == NULL) {
        return NULL;
    }

    if (vts_lc_depth == 0) {
        vts_lc_report("find_node was entered with no mutex held");
    }

    return __real_ngx_http_vhost_traffic_status_find_node(r, key, type, flag);
}
