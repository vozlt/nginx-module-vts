# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 6;
no_shuffle();
run_tests();

__DATA__

=== TEST1: access embeded variables starting with a $vts_* by lua
--- http_config
    vhost_traffic_status_zone;
--- config
    location /variables {
        access_by_lua_block {
            local i
            local variables = {
                                ngx.var.vts_request_counter,
                                ngx.var.vts_in_bytes,
                                ngx.var.vts_out_bytes,
                                ngx.var.vts_1xx_counter,
                                ngx.var.vts_2xx_counter,
                                ngx.var.vts_3xx_counter,
                                ngx.var.vts_4xx_counter,
                                ngx.var.vts_5xx_counter,
                                ngx.var.vts_request_time_counter,
                                ngx.var.vts_request_time,
                                ngx.var.vts_cache_miss_counter,
                                ngx.var.vts_cache_bypass_counter,
                                ngx.var.vts_cache_expired_counter,
                                ngx.var.vts_cache_stale_counter,
                                ngx.var.vts_cache_updating_counter,
                                ngx.var.vts_cache_revalidated_counter,
                                ngx.var.vts_cache_hit_counter,
                                ngx.var.vts_cache_scarce_counter
                              }
            ngx.print("embeded_variables: 18, find_variables: ", table.getn(variables), ", variables: ");
            for i=1, table.getn(variables) do
                if variables[i] then
                    ngx.print(i, ":[", variables[i], "] ")
                else
                    ngx.print(i, ":[nil] ")
                end
            end
        }
    }
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
    }
--- user_files eval
[
    ['storage/access/file.txt' => 'access:OK']
]
--- request eval
[
    'GET /storage/access/file.txt',
    'GET /variables',
    'GET /variables'
]
--- response_body_like eval
[
    'OK',
    'find_variables: 18',
    'find_variables: 18'
]
