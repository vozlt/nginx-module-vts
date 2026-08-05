#!/usr/bin/env python3

# @file:    lockcheck.py
# @brief:   reads the sources for two mistakes around the mutex of the zone
# @author:  Y.Horie

"""Reports two things the compiler does not.

held
    a return between taking the mutex of the shared zone and giving it back.
    ngx_shmtx_lock() is not recursive, so a worker that returns holding it
    spins for ever on its next request and answers nothing more.

naked
    a function that searches the tree without taking the mutex. Every reader
    of the tree takes it -- shm_add_node(), the $vts_ variables, the limit
    handler, the display handlers -- and one that does not can read a node
    while another worker frees it.

Neither shows up in a test run unless the timing is right, and neither is
visible to a sanitizer: nginx workers are processes rather than threads, and
the nodes come from ngx_slab_alloc() rather than malloc.

    usage: python3 util/lockcheck.py [file ...]

With no argument it reads src/*.c relative to the working directory. It exits
non zero when it has something to say.
"""

import pathlib
import re
import sys

LOCK = "ngx_shmtx_lock"
UNLOCK = "ngx_shmtx_unlock"

SEARCHES_THE_TREE = (
    "ngx_http_vhost_traffic_status_find_node(",
    "ngx_http_vhost_traffic_status_node_lookup(",
)

# Functions whose caller has already taken the mutex. Each one was read to
# check that, and the reason is next to it; a new entry needs the same.
CALLED_LOCKED = {
    # the search itself, and the callers of these are what the check is about
    "ngx_http_vhost_traffic_status_find_node",
    "ngx_http_vhost_traffic_status_node_lookup",

    # display_handler_control() holds the mutex across the whole dispatch
    "ngx_http_vhost_traffic_status_node_status_zone",
    "ngx_http_vhost_traffic_status_node_delete_zone",
    "ngx_http_vhost_traffic_status_node_reset_zone",

    # display_handler_default() holds it while it writes the body
    "ngx_http_vhost_traffic_status_display_set_upstream_group",
}

# how far back to look for the unlock that belongs to a return
WINDOW = 3


def functions(text):
    """Yields (name, first line number, body lines) for each function."""

    lines = text.splitlines()
    i = 0

    while i < len(lines):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(", lines[i])

        if m and i and lines[i - 1].strip() and not lines[i - 1].startswith(" "):
            name = m.group(1)

            j = i
            while j < len(lines) and not lines[j].startswith("{"):
                j += 1
                if j - i > 12:
                    break

            if j < len(lines) and lines[j].startswith("{"):
                depth = 0
                k = j

                while k < len(lines):
                    depth += lines[k].count("{") - lines[k].count("}")
                    if depth == 0:
                        break
                    k += 1

                yield name, i + 1, lines[i:k + 1]
                i = k

        i += 1


def check(path):
    findings = []
    text = pathlib.Path(path).read_text()

    for name, start, body in functions(text):
        joined = "\n".join(body)

        if LOCK in joined:
            taken = next(n for n, line in enumerate(body) if LOCK in line)

            if UNLOCK not in joined:
                findings.append((start + taken, "held",
                                 "%s() takes the mutex and never gives it back"
                                 % name))
            else:
                given = max(n for n, line in enumerate(body) if UNLOCK in line)

                for n in range(taken, given):
                    if not re.search(r"\breturn\b", body[n]):
                        continue

                    if UNLOCK not in "\n".join(body[max(0, n - WINDOW):n]):
                        findings.append((start + n, "held",
                                         "%s() returns while holding the mutex"
                                         % name))

        if name in CALLED_LOCKED or LOCK in joined:
            continue

        for n, line in enumerate(body):
            if any(s in line for s in SEARCHES_THE_TREE):
                findings.append((start + n, "naked",
                                 "%s() searches the tree without taking the "
                                 "mutex" % name))
                break

    return findings


def main(argv):
    paths = argv[1:] or sorted(str(p) for p in pathlib.Path("src").glob("*.c"))

    if not paths:
        sys.stderr.write("lockcheck: no source to read\n")
        return 2

    total = 0

    for path in paths:
        for line, kind, message in check(path):
            print("%s:%d: %s: %s" % (path, line, kind, message))
            total += 1

    print("%d finding(s)" % total)

    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
