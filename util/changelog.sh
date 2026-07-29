#! /usr/bin/env bash
#
# @file:    changelog.sh
# @brief:   adds the section of a new release to CHANGELOG.md with git-cliff
# @author:  Y.Horie
#
# usage: util/changelog.sh v0.2.7            adds the section to CHANGELOG.md
#        util/changelog.sh v0.2.7 --notes    writes the release notes to stdout
#
# Only the section of the release being cut is generated, the sections that
# are already in CHANGELOG.md are never regenerated: the commits of the early
# releases use types that no longer parse the same way, regenerating them
# would drop entries.

set -eu

version="${1:-}"
mode="${2:-}"

if [ -z "${version}" ]; then
    echo "usage: $0 <version> [--notes]" >&2
    exit 1
fi

repository="https://github.com/vozlt/nginx-module-vts"
changelog="CHANGELOG.md"

if ! command -v git-cliff > /dev/null 2>&1; then
    echo "$0: git-cliff is not installed, see https://git-cliff.org/" >&2
    exit 1
fi

previous=$(git describe --tags --abbrev=0)

section=$(mktemp)

trap 'rm -f "${section}"' EXIT

# the command substitution drops the trailing empty lines, the blank lines
# that separate the sections come from CHANGELOG.md itself
generated=$(git-cliff --unreleased --tag "${version}" --strip all)

if [ -z "${generated}" ]; then
    echo "$0: nothing to release since ${previous}" >&2
    exit 1
fi

if [ "${mode}" = "--notes" ]; then
    printf 'Release %s\n\n' "${version}"
    printf '%s\n' "${generated}" \
        | sed -e 's/^## \[\(.*\)\] - \(.*\)$/Release [\1] - \2/' -e 's/^### /** /'
    printf '\n'
    exit 0
fi

printf '%s\n' "${generated}" > "${section}"

# the section is passed as a file, awk(1) of the BSD flavour does not take a
# newline in the value of -v
awk -v section="${section}" \
    -v version="${version}" \
    -v previous="${previous}" \
    -v repository="${repository}" '
    /^## \[Unreleased\]$/ && !inserted {
        print
        print ""
        print ""

        while ((getline line < section) > 0) {
            print line
        }

        close(section)

        inserted = 1
        next
    }

    /^\[Unreleased\]: / {
        print "[Unreleased]: " repository "/compare/" version "...HEAD"
        print "[" version "]: " repository "/compare/" previous "..." version
        next
    }

    { print }
' "${changelog}" > "${changelog}.new"

mv "${changelog}.new" "${changelog}"

echo "$0: added ${version} to ${changelog} (previous ${previous})"

# vi:set ft=sh ts=4 sw=4 et fdm=marker:
