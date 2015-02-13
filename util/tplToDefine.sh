#! /usr/bin/env bash
#
# @file:    tplToDefine.sh
# @brief:
# @author:  YoungJoo.Kim <vozlt@vozlt.com>
# @version:
# @date:

# Set up a default search path.
PATH="/sbin:/usr/sbin:/bin:/usr/bin"
export PATH

template=$1
if [ -z "$template" ]; then
    echo "Usage: $0 {template.html}"
    exit 2
fi

tmp=$template.$(date '+%s')

\cp -af $template $tmp

if [ -f "$tmp" ]; then
    perl -p -i -e 's/%/%%/g' $tmp
    perl -p -i -e 's/{{uri}}/%V/g' $tmp
fi

echo "#define NGX_HTTP_VHOST_TRAFFIC_STATUS_HTML_DATA \\"

\perl fileToHex.pl $tmp

\rm -f $tmp

# vi:set ft=sh ts=4 sw=4 et fdm=marker:
