# vi:set ft=perl ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket;

plan tests => repeat_each() * blocks() * 8;
no_shuffle();
run_tests();

__DATA__

=== TEST1: limit traffic using $vts_* by lua
--- http_config
    vhost_traffic_status_zone;
--- config
    set $limit_in 200;
    set $limit_out 256;
    access_by_lua_block {
        local limits = {
                         ["request"] = tonumber(ngx.var.limit_request),
                         ["in"] = tonumber(ngx.var.limit_in),
                         ["out"] = tonumber(ngx.var.limit_out),
                         ["1xx"] = tonumber(ngx.var.limit_1xx),
                         ["2xx"] = tonumber(ngx.var.limit_2xx),
                         ["3xx"] = tonumber(ngx.var.limit_3xx),
                         ["4xx"] = tonumber(ngx.var.limit_4xx),
                         ["5xx"] = tonumber(ngx.var.limit_5xx),
                         ["miss"] = tonumber(ngx.var.limit_miss),
                         ["bypass"] = tonumber(ngx.var.limit_bypass),
                         ["expired"] = tonumber(ngx.var.limit_expired),
                         ["stale"] = tonumber(ngx.var.limit_stale),
                         ["updating"] = tonumber(ngx.var.limit_updating),
                         ["revalidated"] = tonumber(ngx.var.limit_revalidated),
                         ["hit"] = tonumber(ngx.var.limit_hit),
                         ["scarce"] = tonumber(ngx.var.limit_scarce)
                       }

        local stats = {
                        ["request"] = limits["request"] and tonumber(ngx.var.vts_request_counter),
                        ["in"] = limits["in"] and tonumber(ngx.var.vts_in_bytes),
                        ["out"] = limits["out"] and tonumber(ngx.var.vts_out_bytes),
                        ["1xx"] = limits["1xx"] and tonumber(ngx.var.vts_1xx_counter),
                        ["2xx"] = limits["2xx"] and tonumber(ngx.var.vts_2xx_counter),
                        ["3xx"] = limits["3xx"] and tonumber(ngx.var.vts_3xx_counter),
                        ["4xx"] = limits["4xx"] and tonumber(ngx.var.vts_4xx_counter),
                        ["5xx"] = limits["5xx"] and tonumber(ngx.var.vts_5xx_counter),
                        ["miss"] = limits["miss"] and tonumber(ngx.var.vts_cache_miss_counter),
                        ["bypass"] = limits["bypass"] and tonumber(ngx.var.vts_cache_bypass_counter),
                        ["expired"] = limits["expired"] and tonumber(ngx.var.vts_cache_expired_counter),
                        ["stale"] = limits["stale"] and tonumber(ngx.var.vts_cache_stale_counter),
                        ["updating"] = limits["updating"] and tonumber(ngx.var.vts_cache_updating_counter),
                        ["revalidated"] = limits["revalidated"] and tonumber(ngx.var.vts_cache_revalidated_counter),
                        ["hit"] = limits["hit"] and tonumber(ngx.var.vts_cache_hit_counter),
                        ["scarce"] = limits["scarce"] and tonumber(ngx.var.vts_cache_scarce_counter)
                      }

        for k,v in pairs(limits) do
            if stats[k] and stats[k] > v then
                ngx.say("exceeded ", k, " traffic limit[", v, "] < current[", stats[k], "]");
            end
        end
    }
    location ~ ^/storage/(.+)/.*$ {
        set $volume $1;
        vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
    }
--- user_files eval
[
    ['storage/limit/file.txt' => 'limit:OK']
]
--- request eval
[
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt',
    'GET /storage/limit/file.txt'
]
--- response_body_like eval
[
    'OK',
    'OK',
    'exceeded',
    'exceeded'
]
