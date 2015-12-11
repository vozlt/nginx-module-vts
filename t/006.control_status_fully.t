# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 4;
no_shuffle();
run_tests();

__DATA__

=== TEST 1: /status/control?cmd=status&group=*
--- http_config
    vhost_traffic_status_zone;
--- config
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format json;
        access_log off;
    }
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
    }
--- user_files eval
[
    ['storage/vol0/file.txt' => 'vol0:OK']
]
--- request eval
[
    'GET /storage/vol0/file.txt',
    'GET /status/control?cmd=status&group=*',
]
--- response_body_like eval
[
    'OK',
    'nginxVersion'
]

