<a name="unreleased"></a>
## [Unreleased]


## [v0.2.0] - 2022-09-05
### Bugfix
- fixed for PR[#238](https://github.com/vozlt/nginx-module-vts/issues/238)
- fixed for PR[#238](https://github.com/vozlt/nginx-module-vts/issues/238)
- fixed issues/204 that syntax error has occured
- rollback to 549cc4d
- fixed issues/137, issues/98 that maxSize in cacheZones is displayed incorrectly
- fixed issues/174 that XSS vulnerability in the html page Feature: added moduleVersion field in format/json
- added escape strings for filter names in JSON
- fixed the sum value of histogram in upstream metrics
-  fixed to display all A records of server without zone directive in the upstream block.

### Chore
- Use git-chglog

### Comment
- added moduleVersion
- added additional information about cacheZones
- added tested versions
- added a diagram for the order of module directives

### Compatibility
- fixed ngx_http_vhost_traffic_status_display_get_upstream_nelts() to calculate all A records of server.

### Docs
- Fix README

### Docs
- fix simple typo, destory -> destroy

### Fix
- limit the r->uri search scope to avoid overflow

### Prometheus
- fix nginx_vts_filter_requests_total labels
- remove request "total" metrics

### Refactor
- changed version
- changed spacing
- changed spacing
- changed if statement from merged pull/145

### Test
- describe how to test and fix failed test case


## [v0.1.18] - 2018-06-22
### Bugfix
- fixed issues/130 that nginx_vts_main_connections metrics mixed
- fixed for issues/129 that worker process 4589 exited on signal 11

### Tag
- v0.1.18


## [v0.1.17] - 2018-06-20
### Comment
- added overCounts object explanation
- added additional explanation of vhost_traffic_status_zone

### Compatibility
- added "#if (NGX_HTTP_CACHE)" for the issues/122

### Delete
- a.diff

### Feature
- added TiB unit in format/html for the issues/111
- added vhost_traffic_status_filter_max_node directive to limit the size of filters
- added the histogram type of request processing time in format/json
- added vhost_traffic_status_histogram_buckets directive to set the histogram type of request processing time in format/prometheus
- added support for implementing format/prometheus
- added request_time_counter, response_time_counter section to support accumulated request processing time for pull/67, issues/73

### Tag
- v0.1.17


## [v0.1.16] - 2018-05-21
### Compatibility
- fixed ngx_current_msec that changed in nginx-1.13.10 for the issues/121

### Fix
- nginx will crash at vts module when configure file has no http block
- nginx will crash at vts module when configure file has no http block

### Tag
- v0.1.16


## [v0.1.15] - 2017-06-20
### Bugfix
- fixed issues/79 that does not exited at "worker process is shutting down"
- fixed issues/79 that does not exited at "worker process is shutting down"

### Comment
- fixed to be compatible with version 0.27-gfm

### Compatibility
- fixed goto label location for the issues/77
- fixed some issues for the nginx-module-sts/issues/1
- fixed "#define" macro to char array for the nginx-module-sts/issues/1

### Feature
- changed ngx_http_vhost_traffic_status_node_time_queue_merge()
- added vhost_traffic_status_dump to maintain statistics data permanently
- added period parameter in vhost_traffic_status_average_method directive to change the average value after the elapse of time

### Fix
- it is actually aam

### Tag
- v0.1.15


## [v0.1.14] - 2017-03-21
### Comment
- added the use cases & fixed vhost_traffic_status_bypass_(limit|stats) usage

### Compatibility
- added segfault prevent routine for the issues/75

### Feature
- added shared memory section to support shared memory information
- added vhost_traffic_status_average_method to support for selecting an average formula
- added sharedZones in JSON to support shared memory information


## [v0.1.13] - 2017-03-07
### Bugfix
- fixed issues/(71|72) worker process exited on signal 11

### Comment
- added nginx-vts-exporter & nginx-module-sysguard
- added stream status modules
- added modules nginx-module-sts and nginx-module-stream-sts

### Compatibility
- added "#if (NGX_HTTP_CACHE)"

### Feature
- added vhost_traffic_status_set_by_filter to support stats values access Feature: added "::main" in control to get only default status values
- added vhost_traffic_status_display_sum_key for issues/61
- added vhost_traffic_status_display_sum_key for issues/61

### Refactor
- javascript tidy


## [v0.1.12] - 2017-02-08
### Feature
- added hostname section for issues/37
- added request_time section for issues/(43|57)
- added request_time section for issues/(43|57)
- added request_time section for issues/(43|57)

### Refactor
- divided the source code


## [v0.1.11] - 2016-11-09
### Bugfix
- fixed issues/56 that worker process exited on signal 11 if running control query without group argument or nonexistent group
- fixed issues/52 that worker process exited on signal 11
- fixed issues/6 that occured error(handler::shm_add_upstream() failed) when using fastcgi_pass $variables
- fixed issues/45 that occurred segfault when balancer_by_lua breaks

### Compatibility
- changed for issues/49 that occured errors when using compile with clang -Werror,-Wtautological-pointer-compare in osx os.
- changed for issues/47 that occured errors when using compile with -Werror(Make all warnings into errors). The number returned by ngx_http_vhost_traffic_status_max_integer() consist of string without the suffix ULL(unsigned long long int).

### Tag
- v0.1.11
- v0.1.10


## [v0.1.10] - 2016-03-24
### Bugfix
- initialize a variable(filter->filter_name.flushes) for issues/35 that worker process exited on signal 11

### Compatibility
- added dynamic module build option for --add-dynamic-module in nginx 1.9.11


## [v0.1.9] - 2016-03-01
### Bugfix
- initialize a variable(filter->filter_name.value.len) for issues/33 that occurred segfault when running "nginx -s reload"

### Exception
- return NGX_CONF_ERROR if failed ngx_http_vhost_traffic_status_filter_unique()

### Feature
- added vhost_traffic_status_display_jsonp to support JSONP
- added vhost_traffic_status_display_jsonp to support JSONP

### Refactor
- changed function names from ngx_vhost_* to ngx_http_vhost_*


## [v0.1.8] - 2015-12-15
### Feature
- added support for implementing the feature that upstream peers use shared memory.(upstream zone directive)


## [v0.1.7] - 2015-12-11
### Bugfix
- fixed issues/28 that can't use control functionality if location has more than a segment

### Comment
- fixed spelling

### Compatibility
- changed for issues/27 that error occurred(comparison of integers of different signs)

### Feature
- added support for implementing traffic limit.


## [v0.1.6] - 2015-11-25
### Feature
- added support for implementing variables for current traffic status values. It is starting with a $vts_*.


## [v0.1.5] - 2015-11-23
### Bugfix
- fixed to work escape_json in ngx_http_vhost_traffic_status_display_set_filter_node()

### Compatibility
- changed for issues/27 that ngx_vhost_traffic_status_group_to_string() macro is an error when using -Wstring-plus-int at clang compiler.


## [v0.1.4] - 2015-11-04
### Comment
- fixed spelling
- fixed spelling
- fixed spelling

### Compatibility
- fixed unused variables

### Feature
- added vhost_traffic_status_filter to globally enable or disable the filter features. Feature: fixed vhost_traffic_status_filter_by_host to globally enable or disable. Feature: fixed vhost_traffic_status_filter_by_set_key to calculate user defined individual stats. Basically, country flags image is built-in in HTML. Feature: added vhost_traffic_status_filter_check_duplicate for deduplication of vhost_traffic_status_filter_by_set_key. Feature: added update interval in HTML.


## [v0.1.3] - 2015-10-21
### Bugfix
- stats for cached responses with error_page directive do not create a cache file

### Feature
- added vhost_traffic_status_filter_by_host, vhost_traffic_status_filter_by_set_key directive to set the dynamically keys

### Tag
- v0.1.2


## [v0.1.2] - 2015-09-03
### Bugfix
- added cache variable's lock routine in ngx_http_vhost_traffic_status_shm_add_cache() for issues/19

### Comment
- added donation button
- added uptime calculation
- added the customizing
- added the customizing
- added the caveats

### Compatibility
- added overflow handling routines of variables. It deals with the overflow of both 32bit and 64bit variables but I think that not be useful in 64bit variable(Max:16EB) at this moment.


## [v0.1.1] - 2015-05-28
### Feature
- cache status support when using the proxy_cache directive


## v0.1.0 - 2015-05-28
### Bugfix
- added the uscf found routine in ngx_http_vhost_traffic_status_shm_add_upstream() for issues/6
- added default server_name "_" in ngx_http_vhost_traffic_status_shm_add_server(), if the server_name directive is not defined
- added ngx_escape_json() in ngx_http_vhost_traffic_status_display_set_server() for the regular expressions names of server_name directive
- added compare upstream hash. It does not updated upstream peers status so I have fixed it.
- removed a reference(*shm_zone) in ngx_http_vhost_traffic_status_ctx_t.
- changed the obtaining ms of phase for the keeping reference.
- changed a reference from vtsn->stat_upstream.rtms to vtscf->vtsn_upstream->stat_upstream.rtms. It is referred to as non-existent reference after kept a reference.

### Comment
- added the table of contents

### Compatibility
- added response_time for the nginx v1.9.1(http://hg.nginx.org/nginx/rev/59fc60585f1e)
- changed the position of nginx.h to avoid compile error on windows at v1.7.12
- added ngx_http_vhost_traffic_status_escape_json() for less than 1.7.9

### Refactor
- changed NGX_CONF_UNSET to 0 for uint32_t
- changed uptime output from issue(pull/4#issuecomment-77839027)
- added ngx_log_error() in ngx_http_vhost_traffic_status_handler()
- changed length of key
- changed from (ngx_atomic_t) to (ngx_atomic_uint_t) in the ngx_vhost_traffic_status_node_init() and ngx_vhost_traffic_status_node_set() for compile compatibility
- added type casting(ngx_atomic_t) in the ngx_vhost_traffic_status_node_init() and ngx_vhost_traffic_status_node_set()


[Unreleased]: https://github.com/vozlt/nginx-module-vts/compare/v0.2.0...HEAD
[v0.2.0]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.18...v0.2.0
[v0.1.18]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.17...v0.1.18
[v0.1.17]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.16...v0.1.17
[v0.1.16]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.15...v0.1.16
[v0.1.15]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.14...v0.1.15
[v0.1.14]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.13...v0.1.14
[v0.1.13]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.12...v0.1.13
[v0.1.12]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.11...v0.1.12
[v0.1.11]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.10...v0.1.11
[v0.1.10]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.9...v0.1.10
[v0.1.9]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.8...v0.1.9
[v0.1.8]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.7...v0.1.8
[v0.1.7]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.6...v0.1.7
[v0.1.6]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.5...v0.1.6
[v0.1.5]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.4...v0.1.5
[v0.1.4]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.3...v0.1.4
[v0.1.3]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.2...v0.1.3
[v0.1.2]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.1...v0.1.2
[v0.1.1]: https://github.com/vozlt/nginx-module-vts/compare/v0.1.0...v0.1.1
