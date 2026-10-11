# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

# Two checks per request, and the blocks do not send the same number of
# them, so the count is spelled out rather than derived from blocks().
plan tests => repeat_each() * 2 * 20;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: group=%2A selects every group, as * does
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=%2A',
]
--- response_body_like eval
[
    'OK',
    '"serverZones":\{"localhost"'
]



=== TEST 2: group=%2a, the encoding in lower case
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=%2a',
]
--- response_body_like eval
[
    'OK',
    '"serverZones":\{"localhost"'
]



=== TEST 3: a group is named in any case
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=SERVER&zone=localhost',
]
--- response_body_like eval
[
    'OK',
    '^\{"localhost"'
]



=== TEST 4: a command is not
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=STATUS&group=server&zone=localhost',
]
--- response_body_like eval
[
    'OK',
    '^\{"processingReturn":false,"processingCommandString":"STATUS","processingGroupString":"server","processingZoneString":"localhost","processingCounts":0\}'
]



=== TEST 5: a command it does not know is not carried out
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=purge&group=server&zone=localhost',
]
--- response_body_like eval
[
    'OK',
    '^\{"processingReturn":false,"processingCommandString":"purge","processingGroupString":"server","processingZoneString":"localhost","processingCounts":0\}'
]



=== TEST 6: nor is a known command on a group it does not know
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=delete&group=servers&zone=localhost',
]
--- response_body_like eval
[
    'OK',
    '^\{"processingReturn":false,"processingCommandString":"delete","processingGroupString":"servers","processingZoneString":"localhost","processingCounts":0\}'
]



=== TEST 7: the group the refused delete named is still there
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=delete&group=servers&zone=localhost',
    'GET /status/control?cmd=status&group=server&zone=localhost',
]
--- response_body_like eval
[
    'OK',
    '"processingReturn":false',
    '^\{"localhost"'
]



=== TEST 8: a group other than * needs a zone
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'server:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=server',
]
--- response_body_like eval
[
    'OK',
    '^\{"processingReturn":false,"processingCommandString":"status","processingGroupString":"server","processingZoneString":"","processingCounts":0\}'
]



=== TEST 9: [:alpha:] in a zone stands for an @ that is part of the name
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location /storage {
        vhost_traffic_status_filter_by_set_key user@example storage::$server_name;
    }
--- user_files eval
[
    ['storage/control/file.txt' => 'filter:OK']
]
--- request eval
[
    'GET /storage/control/file.txt',
    'GET /status/control?cmd=status&group=filter&zone=storage::localhost@user[:alpha:]example',
]
--- response_body_like eval
[
    'OK',
    '^\{"user@example"'
]



=== TEST 10: with no arguments nothing is carried out
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
--- request
GET /status/control
--- response_body_like eval
'^\{"processingReturn":false,"processingCommandString":"","processingGroupString":"","processingZoneString":"","processingCounts":0\}'
