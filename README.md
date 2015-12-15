Nginx virtual host traffic status module
==========

[![License](http://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/vozlt/nginx-module-vts/blob/master/LICENSE)

Nginx virtual host traffic status module

Table of Contents
=================

* [Version](#version)
* [Dependencies](#dependencies)
* [Screenshots](#screenshots)
* [Installation](#installation)
* [Synopsis](#synopsis)
* [Description](#description)
* [Control](#control)
 * [To get status of traffic zones on the fly](#to-get-status-of-traffic-zones-on-the-fly)
    * [To get fully zones](#to-get-fully-zones)
    * [To get group zones](#to-get-group-zones)
    * [To get each zones](#to-get-each-zones)
 * [To reset traffic zones on the fly](#to-reset-traffic-zones-on-the-fly)
    * [To reset fully zones](#to-reset-fully-zones)
    * [To reset group zones](#to-reset-group-zones)
    * [To reset each zones](#to-reset-each-zones)
 * [To delete traffic zones on the fly](#to-delete-traffic-zones-on-the-fly)
    * [To delete fully zones](#to-delete-fully-zones)
    * [To delete group zones](#to-delete-group-zones)
    * [To delete each zones](#to-delete-each-zones)
* [JSON](#json)
 * [Json used by status](#json-used-by-status)
 * [Json used by control](#json-used-by-control)
* [Variables](#variables)
* [Limit](#limit)
 * [To limit traffic for server](#to-limit-traffic-for-server)
 * [To limit traffic for filter](#to-limit-traffic-for-filter)
 * [To limit traffic for upstream](#to-limit-traffic-for-upstream)
* [Use cases](#use-cases)
 * [To calculate traffic for individual country using GeoIP](#to-calculate-traffic-for-individual-country-using-geoip)
 * [To calculate traffic for individual storage volume](#to-calculate-traffic-for-individual-storage-volume)
 * [To calculate traffic for individual user agent](#to-calculate-traffic-for-individual-user-agent)
* [Customizing](#customizing)
 * [To customize after the module installed](#to-customize-after-the-module-installed)
 * [To customize before the module installed](#to-customize-before-the-module-installed)
* [Directives](#directives)
 * [vhost_traffic_status](#vhost_traffic_status)
 * [vhost_traffic_status_zone](#vhost_traffic_status_zone)
 * [vhost_traffic_status_display](#vhost_traffic_status_display)
 * [vhost_traffic_status_display_format](#vhost_traffic_status_display_format)
 * [vhost_traffic_status_filter](#vhost_traffic_status_filter)
 * [vhost_traffic_status_filter_by_host](#vhost_traffic_status_filter_by_host)
 * [vhost_traffic_status_filter_by_set_key](#vhost_traffic_status_filter_by_set_key)
 * [vhost_traffic_status_filter_check_duplicate](#vhost_traffic_status_filter_check_duplicate)
 * [vhost_traffic_status_limit](#vhost_traffic_status_limit)
 * [vhost_traffic_status_limit_traffic](#vhost_traffic_status_limit_traffic)
 * [vhost_traffic_status_limit_traffic_by_set_key](#vhost_traffic_status_limit_traffic_by_set_key)
 * [vhost_traffic_status_limit_check_duplicate](#vhost_traffic_status_limit_check_duplicate)
* [TODO](#todo)
* [Donation](#donation)
* [Author](#author)

## Version
This document describes nginx-module-vts `v0.1.8` released on 15 Dec 2015.

## Dependencies
* [nginx](http://nginx.org)

## Compatibility
* 1.9.x (last tested: 1.9.9)
* 1.8.x (last tested: 1.8.0)
* 1.6.x (last tested: 1.6.3)
* 1.4.x (last tested: 1.4.7)

Earlier versions is not tested.

## Screenshots
![nginx-module-vts screenshot](https://cloud.githubusercontent.com/assets/3648408/7854611/1386f3b2-0556-11e5-8323-7c624da0fcb3.png "screenshot with deault")

---

![nginx-module-vts screenshot](https://cloud.githubusercontent.com/assets/3648408/10876811/77a67b70-8183-11e5-9924-6a6d0c5dc73a.png "screenshot with filter")

## Installation

1. Clone the git repository.

  ```
  shell> git clone git://github.com/vozlt/nginx-module-vts.git
  ```

2. Add the module to the build configuration by adding
  `--add-module=/path/to/nginx-module-vts`

3. Build the nginx binary.

4. Install the nginx binary.

## Synopsis

```Nginx
http {
    vhost_traffic_status_zone;

    ...

    server {

        ...

        location /status {
            vhost_traffic_status_display;
            vhost_traffic_status_display_format html;
        }
    }
}
```

## Description
This is an Nginx module that provides access to virtual host status information.
It contains the current status such as servers, upstreams, caches.
This is similar to the live activity monitoring of nginx plus.
The built-in html is also taken from the demo page of old version.

First of all, the directive `vhost_traffic_status_zone` is required,
and then if the directive `vhost_traffic_status_display` is set, can be access to as follows:

* /status/format/json

* /status/format/html

* /status/control

 * If you request `/status/format/json`, will respond with a JSON document containing the current activity data for using in live dashboards and third-party monitoring tools.

 * If you request `/status/format/html`, will respond with the built-in live dashboard in HTML that requests internally to `/status/format/json`.

 * If you request `/status/control`, will respond with a JSON document after it reset or delete zones through a query string. See the [Control](#control).

JSON document contains as follows:

```Json
{
    "nginxVersion": ...,
    "loadMsec": ...,
    "nowMsec": ...,
    "connections": {
        "active":...,
        "reading":...,
        "writing":...,
        "waiting":...,
        "accepted":...,
        "handled":...,
        "requests":...
    },
    "serverZones": {
        "...":{
            "requestCounter":...,
            "inBytes":...,
            "outBytes":...,
            "responses":{
                "1xx":...,
                "2xx":...,
                "3xx":...,
                "4xx":...,
                "5xx":...,
                "miss":...,
                "bypass":...,
                "expired":...,
                "stale":...,
                "updating":...,
                "revalidated":...,
                "hit":...,
                "scarce":...
            }
        }
        ...
    },
    "filterZones": {
        "...":{
            "...":{
                "requestCounter":...,
                "inBytes":...,
                "outBytes":...,
                "responses":{
                    "1xx":...,
                    "2xx":...,
                    "3xx":...,
                    "4xx":...,
                    "5xx":...,
                    "miss":...,
                    "bypass":...,
                    "expired":...,
                    "stale":...,
                    "updating":...,
                    "revalidated":...,
                    "hit":...,
                    "scarce":...
                }
            },
            ...
        },
        ...
    },
    "upstreamZones": {
        "...":[
            {
                "server":...,
                "requestCounter":...,
                "inBytes":...,
                "outBytes":...,
                "responses":{
                    "1xx":...,
                    "2xx":...,
                    "3xx":...,
                    "4xx":...,
                    "5xx":...
                },
                "responseMsec":...,
                "weight":...,
                "maxFails":...,
                "failTimeout":...,
                "backup":...,
                "down":...
            }
            ...
        ],
        ...
    }
    "cacheZones": {
        "...":{
            "maxSize":...,
            "usedSize":...,
            "inBytes":...,
            "outBytes":...,
            "responses":{
                "miss":...,
                "bypass":...,
                "expired":...,
                "stale":...,
                "updating":...,
                "revalidated":...,
                "hit":...,
                "scarce":...
            }
        },
        ...
    }
}
```

* main
 * Basic version, uptime((nowMsec - loadMsec)/1000)
 * nowMsec, loadMsec is a millisecond.
* connections
 * Total connections and requests(same as stub_status_module in NGINX)
* serverZones
 * Traffic(in/out) and request and response counts and cache hit ratio per each server zone
 * Total traffic(In/Out) and request and response counts(It zone name is `*`) and hit ratio
* filterZones
 * Traffic(in/out) and request and response counts and cache hit ratio per each server zone filtered through the `vhost_traffic_status_filter_by_set_key` directive
 * Total traffic(In/Out) and request and response counts(It zone name is `*`) and hit ratio filtered through the `vhost_traffic_status_filter_by_set_key` directive
* upstreamZones
 * Traffic(in/out) and request and response counts per server in each upstream group
 * Current settings(weight, maxfails, failtimeout...) in nginx.conf
* cacheZones
 * Traffic(in/out) and size(capacity/used) and hit ratio per each cache zone when using the proxy_cache directive.

The directive `vhost_traffic_status_display_format` sets the default ouput format that is one of json or html. (Default: json)

Traffic calculation as follows:

* ServerZones
 * in += requested_bytes
 * out += sent_bytes
* FilterZones
 * in += requested_bytes via the filter
 * out += sent_bytes via the filter
* UpstreamZones
 * in += requested_bytes via the ServerZones
 * out += sent_bytes via the ServerZones
* cacheZones
 * in += requested_bytes via the ServerZones
 * out += sent_bytes via the ServerZones

All calculations are working in log processing phase of Nginx.
Internal redirects(X-Accel-Redirect or error_page) does not calculate in the UpstreamZones.

`Caveats:` this module relies on nginx logging system(NGX_HTTP_LOG_PHASE:last phase of the nginx http), so the traffic may be
in certain cirumstances different that real bandwidth traffic.
Websocket, canceled downloads may be cause of inaccuracies.
The working of the module doesn't matter at all whether the access_log directive "on" or "off".
Again, this module works well on "access_log off".
When using several domains it sets to be first domain(left) of server_name directive.
If you don't want it, see the [vhost_traffic_status_filter_by_host](#vhost_traffic_status_filter_by_host), [vhost_traffic_status_filter_by_set_key](#vhost_traffic_status_filter_by_set_key) directive.

## Control
It is able to reset or delete traffic zones through a query string.
The request responds with a JSON document.

* URI Syntax
 * /*`{status_uri}`*/control?cmd=*`{command}`*&group=*`{group}`*&zone=*`{name}`*

```Nginx
http {

    geoip_country                   /usr/share/GeoIP/GeoIP.dat;

    vhost_traffic_status_zone;
    vhost_traffic_status_filter_by_set_key $geoip_country_code country::*;

    ...

    server {

        server_name example.org;

        ...

        vhost_traffic_status_filter_by_set_key $geoip_country_code country::$server_name;

        location /status {
            vhost_traffic_status_display;
            vhost_traffic_status_display_format html;
        }
    }                                                                                                                                                                                           }
```

If it set as above, then the control uri is like `example.org/status/control`.

The available request arguments are as follows:
* **cmd**=\<`status`\|`reset`\|`delete`\>
 * status
   * It returns status of traffic zones to json format like `status/format/json`.
 * reset
   * It reset traffic zones without deleting nodes in shared memory.(= init to 0)
 * delete
   * It delete traffic zones in shared memory. when re-request recreated. 
* **group**=\<`server`\|`filter`\|`upstream@alone`\|`upstream@group`\|`cache`\|`*`\>
 * server
 * filter
 * upstream@alone
 * upstream@group
 * cache
 * *
* **zone**=*name*
 * server
   * *name*
 * filter
   * *filter_group*@*name*
 * upstream@group
   * *upstream_group*@*name*
 * upstream@alone
   * @*name*
 * cache
   * *name*


### To get status of traffic zones on the fly
This is similar to the `status/format/json` except that it can get each zones.

#### To get fully zones
* It is exactly the same with the `status/format/json`.
 * /status/control?cmd=status&group=*

#### To get group zones
* serverZones
 * /status/control?cmd=status&group=server&zone=*
* filterZones
 * /status/control?cmd=status&group=filter&zone=*
* upstreamZones
 * /status/control?cmd=status&group=upstream@group&zone=*
* upstreamZones::nogroups
 * /status/control?cmd=status&group=upstream@alone&zone=*
* cacheZones
 * /status/control?cmd=status&group=cache&zone=*

#### To get each zones
* single zone in serverZones
 * /status/control?cmd=status&group=server&zone=*`name`*
* single zone in filterZones
 * /status/control?cmd=status&group=filter&zone=*`filter_group`*@*`name`*
* single zone in upstreamZones
 * /status/control?cmd=status&group=upstream@group&zone=*`upstream_group`*@*`name`*
* single zone in upstreamZones::nogroups
 * /status/control?cmd=status&group=upstream@alone&zone=*`name`*
* single zone in cacheZones
 * /status/control?cmd=status&group=cache&zone=*`name`*

### To reset traffic zones on the fly
It reset the values of specified zones to 0.

#### To reset fully zones
* /status/control?cmd=reset&group=*

#### To reset group zones
* serverZones
 * /status/control?cmd=reset&group=server&zone=*
* filterZones
 * /status/control?cmd=reset&group=filter&zone=*
* upstreamZones
 * /status/control?cmd=reset&group=upstream@group&zone=*
* upstreamZones::nogroups
 * /status/control?cmd=reset&group=upstream@alone&zone=*
* cacheZones
 * /status/control?cmd=reset&group=cache&zone=*

#### To reset each zones
* single zone in serverZones
 * /status/control?cmd=reset&group=server&zone=*`name`*
* single zone in filterZones
 * /status/control?cmd=reset&group=filter&zone=*`filter_group`*@*`name`*
* single zone in upstreamZones
 * /status/control?cmd=reset&group=upstream@group&zone=*`upstream_group`*@*`name`*
* single zone in upstreamZones::nogroups
 * /status/control?cmd=reset&group=upstream@alone&zone=*`name`*
* single zone in cacheZones
 * /status/control?cmd=reset&group=cache&zone=*`name`*

### To delete traffic zones on the fly
It delete the specified zones in shared memory.

#### To delete fully zones
* /status/control?cmd=delete&group=*

#### To delete group zones
* serverZones
 * /status/control?cmd=delete&group=server&zone=*
* filterZones
 * /status/control?cmd=delete&group=filter&zone=*
* upstreamZones
 * /status/control?cmd=delete&group=upstream@group&zone=*
* upstreamZones::nogroups
 * /status/control?cmd=delete&group=upstream@alone&zone=*
* cacheZones
 * /status/control?cmd=delete&group=cache&zone=*

#### To delete each zones
* single zone in serverZones
 * /status/control?cmd=delete&group=server&zone=*`name`*
* single zone in filterZones
 * /status/control?cmd=delete&group=filter&zone=*`filter_group`*@*`name`*
* single zone in upstreamZones
 * /status/control?cmd=delete&group=upstream@group&zone=*`upstream_group`*@*`name`*
* single zone in upstreamZones::nogroups
 * /status/control?cmd=delete&group=upstream@alone&zone=*`name`*
* single zone in cacheZones
 * /status/control?cmd=delete&group=cache&zone=*`name`*

## JSON
The following status information is provided in the JSON format:

### Json used by status
/*`{status_uri}`*/format/json

/*`{status_uri}`*/control?cmd=status&...

* nginxVersion
 * Version of the provided.
* loadMsec
 * Loaded process time in milliseconds.
* nowMsec
 * Current time in milliseconds
* connections
 * active
   * The current number of active client connections.
 * reading
   * The total number of reading client connections.
 * writing
   * The total number of writing client connections.
 * waiting
   * The total number of wating client connections.
 * accepted
   * The total number of accepted client connections.
 * handled
   * The total number of handled client connections.
 * requests
   * The total number of requested client connections.
* serverZones
 * requestCounter
   * The total number of client requests received from clients.
 * inBytes
   * The total number of bytes received from clients.
 * outBytes
   * The total number of bytes sent to clients.
 * responses
    * 1xx, 2xx, 3xx, 4xx, 5xx
      * The number of responses with status codes 1xx, 2xx, 3xx, 4xx, and 5xx.
    * miss
      * The number of cache miss.
    * bypass
      * The number of cache bypass.
    * expired
      * The number of cache expired.
    * stale
      * The number of cache stale.
    * updating
      * The number of cache updating.
    * revalidated
      * The number of cache revalidated.
    * hit
      * The number of cache hit.
    * scarce
      * The number of cache scare.
* filterZones
 * It provides the same fields with `serverZones` except that it included group names.
* upstreamZones
 * server
   * An address of the server.
 * requestCounter
   * The total number of client connections forwarded to this server.
 * inBytes
   * The total number of bytes received from this server.
 * outBytes
   * The total number of bytes sent to this server.
 * responses
   * 1xx, 2xx, 3xx, 4xx, 5xx
     * The number of responses with status codes 1xx, 2xx, 3xx, 4xx, and 5xx.
 * responseMsec
   * The average time to receive the last byte of data.
 * weight
   * Current `weight` setting of the server.
 * maxFails
   * Current `max_fails` setting of the server.
 * failTimeout
   * Current `fail_timeout` setting of the server.
 * backup
   * Current `backup` setting of the server.
 * down
   * Current `down` setting of the server.
* cacheZones
 * maxSize
   * The limit on the maximum size of the cache specified in the configuration.
 * usedSize
   * The current size of the cache.
 * inBytes
   * The total number of bytes received from the cache.
 * outBytes
   * The total number of bytes sent from the cache.
 * responses
    * miss
      * The number of cache miss.
    * bypass
      * The number of cache bypass.
    * expired
      * The number of cache expired.
    * stale
      * The number of cache stale.
    * updating
      * The number of cache updating.
    * revalidated
      * The number of cache revalidated.
    * hit
      * The number of cache hit.
    * scarce
      * The number of cache scare.

### Json used by control
/*`{status_uri}`*/control?cmd=reset&...

/*`{status_uri}`*/control?cmd=delete&...

* processingReturn
 * The result of true or false.
* processingCommandString
 * The requested command string.
* processingGroupString
 * The requested group string.
* processingZoneString
 * The requested zone string.
* processingCounts
 * The actual processing number.

## Variables
The following embedded variables are provided:

* **$vts_request_counter**
 * The total number of client requests received from clients.
* **$vts_in_bytes**
 * The total number of bytes received from clients.
* **$vts_out_bytes**
 * The total number of bytes sent to clients.
* **$vts_1xx_counter**
 * The number of responses with status codes 1xx.
* **$vts_2xx_counter**
 * The number of responses with status codes 2xx.
* **$vts_3xx_counter**
 * The number of responses with status codes 3xx.
* **$vts_4xx_counter**
 * The number of responses with status codes 4xx.
* **$vts_5xx_counter**
 * The number of responses with status codes 5xx.
* **$vts_cache_miss_counter**
 * The number of cache miss.
* **$vts_cache_bypass_counter**
 * The number of cache bypass.
* **$vts_cache_expired_counter**
 * The number of cache expired.
* **$vts_cache_stale_counter**
 * The number of cache stale.
* **$vts_cache_updating_counter**
 * The number of cache updating.
* **$vts_cache_revalidated_counter**
 * The number of cache revalidated.
* **$vts_cache_hit_counter**
 * The number of cache hit.
* **$vts_cache_scarce_counter**
 * The number of cache scare.

## Limit

It is able to limit total traffic per each host by using the directive
[`vhost_traffic_status_limit_traffic`](#vhost_traffic_status_limit_traffic).
It also is able to limit all traffic by using the directive
[`vhost_traffic_status_limit_traffic_by_set_key`](#vhost_traffic_status_limit_traffic_by_set_key).
When the limit is exceeded, the server will return the 503
(Service Temporarily Unavailable) error in reply to a request. 
The return code can be changeable.

### To limit traffic for server
```Nginx
http {

    vhost_traffic_status_zone;

    ...

    server {

        server_name *.example.org;

        vhost_traffic_status_limit_traffic in:64G;
        vhost_traffic_status_limit_traffic out:1024G;

        ...
    }
}
```

* Limit in/out total traffic on the `*.example.org` to 64G and 1024G respectively.
It works individually per each domain if `vhost_traffic_status_filter_by_host` directive is enabled.

### To limit traffic for filter
```Nginx
http {
    geoip_country /usr/share/GeoIP/GeoIP.dat;

    vhost_traffic_status_zone;

    ...

    server {

        server_name example.org;

        vhost_traffic_status_filter_by_set_key $geoip_country_code country::$server_name;
        vhost_traffic_status_limit_traffic_by_set_key FG@country::$server_name@US out:1024G;
        vhost_traffic_status_limit_traffic_by_set_key FG@country::$server_name@CN out:2048G;

        ...

    }
}

```

* Limit total traffic of going into US and CN on the `example.org` to 1024G and 2048G respectively.

### To limit traffic for upstream
```Nginx
http {

    vhost_traffic_status_zone;

    ...

    upstream backend {
        server 10.10.10.17:80;
        server 10.10.10.18:80;
    }

    server {

        server_name example.org;

        location /backend {
            vhost_traffic_status_limit_traffic_by_set_key UG@backend@10.10.10.17:80 in:512G;
            vhost_traffic_status_limit_traffic_by_set_key UG@backend@10.10.10.18:80 in:1024G;
            proxy_pass http://backend;
        }

        ...

    }
}

```

* Limit total traffic of going into upstream backend on the `example.org` to 512G and 1024G per each peer.

`Caveats:` Traffic is the cumulative transfer or counter, not a bandwidth.

## Use cases

It is able to calculate the user defined individual stats by using the directive `vhost_traffic_status_filter_by_set_key`.

### To calculate traffic for individual country using GeoIP
```Nginx
http {
    geoip_country /usr/share/GeoIP/GeoIP.dat;

    vhost_traffic_status_zone;
    vhost_traffic_status_filter_by_set_key $geoip_country_code country::*;

    ...

    server {

        ...

        vhost_traffic_status_filter_by_set_key $geoip_country_code country::$server_name;

        location /status {
            vhost_traffic_status_display;
            vhost_traffic_status_display_format html;
        }
    }
}
```

* Calculate traffic for individual country of total server groups.
* Calculate traffic for individual country of each server groups.

Basically, country flags image is built-in in HTML.
The country flags image is enabled if the `country` string is included
in group name which is second argument of `vhost_traffic_status_filter_by_set_key` directive.

### To calculate traffic for individual storage volume
```Nginx
http {
    vhost_traffic_status_zone;

    ...

    server {

        ...

        location ~ ^/storage/(.+)/.*$ {
            set $volume $1;
            vhost_traffic_status_filter_by_set_key $volume storage::$server_name;
        }

        location /status {
            vhost_traffic_status_display;
            vhost_traffic_status_display_format html;
        }
    }
}
```

* Calculate traffic for individual storage volume matched by regular expression of location directive.

### To calculate traffic for individual user agent
```Nginx
http {
    vhost_traffic_status_zone;

    map $http_user_agent $filter_user_agent {
        default 'unknown';
        ~iPhone ios;
        ~Android android;
        ~(MSIE|Mozilla) windows;
    }

    vhost_traffic_status_filter_by_set_key $filter_user_agent agent::*;

    ...

    server {

        ...

        vhost_traffic_status_filter_by_set_key $filter_user_agent agent::$server_name;

        location /status {
            vhost_traffic_status_display;
            vhost_traffic_status_display_format html;
        }
    }
}
```

* Calculate traffic for individual `http_user_agent`

## Customizing
### To customize after the module installed
1. You need to change the `{{uri}}` string to your status uri in status.template.html as follows:
 ```
 shell> vi share/status.template.html
 ```
 ```
 var vtsStatusURI = "yourStatusUri/format/json", vtsUpdateInterval = 1000;
 ```

2. And then, customizing and copy status.template.html to server root directory as follows:
 ```
 shell> cp share/status.template.html /usr/share/nginx/html/status.html
 ```

4. Configure `nginx.conf`
 ```Nginx
    server {
        server_name example.org;
        root /usr/share/nginx/html;

        # Redirect requests for / to /status.html
        location = / {
            return 301 /status.html;
        }

        location = /status.html {}

        # Everything beginning /status (except for /status.html) is
        # processed by the status handler
        location /status {
            vhost_traffic_status_display;
            vhost_traffic_status_display_format json;
        }
    }

 ```

4. Access to your html.
 ```
 http://example.org/status.html
 ```

### To customize before the module installed
1. Modify `share/status.template.html` (Do not change `{{uri}}` string)

2. Recreate the `ngx_http_vhost_traffic_status_module_html.h` as follows:
 ```
 shell> cd util
 shell> ./tplToDefine.sh ../share/status.template.html > ../src/ngx_http_vhost_traffic_status_module_html.h
 ```

3. Add the module to the build configuration by adding
  `--add-module=/path/to/nginx-module-vts`

4. Build the nginx binary.

5. Install the nginx binary.


## Directives

### vhost_traffic_status

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status** \<on\|off\>
**Default** | off
**Context** | http, server, location

`Description:` Enables or disables the module working.
If you set `vhost_traffic_status_zone` directive, is automatically enabled.

### vhost_traffic_status_zone

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_zone** [shared:*name:size*]
**Default** | shared:vhost_traffic_status:1m
**Context** | http

`Description:` Sets parameters for a shared memory zone that will keep states for various keys.
The cache is shared between all worker processes.

### vhost_traffic_status_display

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_display**
**Default** | -
**Context** | http, server, location

`Description:` Enables or disables the module display handler.

### vhost_traffic_status_display_format

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_display_format** \<json\|html\>
**Default** | json
**Context** | http, server, location

`Description:` Sets the display handler's output format.
If you set `json`, will respond with a JSON document.
If you set `html`, will respond with the built-in live dashboard in HTML.

### vhost_traffic_status_filter

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_filter** \<on\|off\>
**Default** | on
**Context** | http, server, location

`Description:` Enables or disables the filter features.

### vhost_traffic_status_filter_by_host

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_filter_by_host** \<on\|off\>
**Default** | off
**Context** | http, server, location

`Description:` Enables or disables the keys by Host header field.
If you set `on` and nginx's server_name directive set several or wildcard name starting with an asterisk, e.g. “*.example.org”
and requested to server with hostname such as (a|b|c).example.org or *.example.org
then json serverZones is printed as follows:

```Nginx
server {
  server_name *.example.org;
  vhost_traffic_status_filter_by_host on;

  ...

}
```

```Json
  ...
  "serverZones": {
      "a.example.org": {
      ...
      },
      "b.example.org": {
      ...
      },
      "c.example.org": {
      ...
      }
      ...
   },
   ...
```

It provides the same function that set `vhost_traffic_status_filter_by_set_key $host`.

### vhost_traffic_status_filter_by_set_key

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_filter_by_set_key** *key* [*name*]
**Default** | -
**Context** | http, server, location

`Description:` Enables the keys by user defined variable.
The *key* is a key string to calculate traffic.
The *name* is a group string to calculate traffic.
The *key* and *name* can contain variables such as $host, $server_name.
The *name*'s group belongs to `filterZones` if specified.
The *key*'s group belongs to `serverZones` if not specified second argument *name*.
The example with geoip module is as follows:

```Nginx
server {
  server_name example.org;
  vhost_traffic_status_filter_by_set_key $geoip_country_code country::$server_name;

  ...

}
```

```Json
  ...
  "serverZones": {
  ...
  },
  "filterZones": {
      "country::example.org": {
          "KR": {
              "requestCounter":...,
              "inBytes":...,
              "outBytes":...,
              "responses":{
                  "1xx":...,
                  "2xx":...,
                  "3xx":...,
                  "4xx":...,
                  "5xx":...,
                  "miss":...,
                  "bypass":...,
                  "expired":...,
                  "stale":...,
                  "updating":...,
                  "revalidated":...,
                  "hit":...,
                  "scarce":...
              }
          },
          "US": {
          ...
          },
          ...
      },
      ...
  },
  ...

```

### vhost_traffic_status_filter_check_duplicate

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_filter_check_duplicate** \<on\|off\>
**Default** | on
**Context** | http, server, location

`Description:` Enables or disables the deduplication of vhost_traffic_status_filter_by_set_key.
It is processed only one of duplicate values(`key` + `name`) in each directives(http, server, location) if this option is enabled.

### vhost_traffic_status_limit

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_limit** \<on\|off\>
**Default** | on
**Context** | http, server, location

`Description:` Enables or disables the limit features.

### vhost_traffic_status_limit_traffic

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_limit_traffic** *member*:*size* [*code*]
**Default** | -
**Context** | http, server, location

`Description:` Enables the traffic limit for specified *member*.
The *member* is a member string to limit traffic.
The *size* is a size(k/m/g) to limit traffic.
The *code* is a code to return in response to rejected requests.(Default: 503)

The available *`member`* strings are as follows:
* **request**
 * The total number of client requests received from clients.
* **in**
 * The total number of bytes received from clients.
* **out**
 * The total number of bytes sent to clients.
* **1xx**
 * The number of responses with status codes 1xx.
* **2xx**
 * The number of responses with status codes 2xx.
* **3xx**
 * The number of responses with status codes 3xx.
* **4xx**
 * The number of responses with status codes 4xx.
* **5xx**
 * The number of responses with status codes 5xx.
* **cache_miss**
 * The number of cache miss.
* **cache_bypass**
 * The number of cache bypass.
* **cache_expired**
 * The number of cache expired.
* **cache_stale**
 * The number of cache stale.
* **cache_updating**
 * The number of cache updating.
* **cache_revalidated**
 * The number of cache revalidated.
* **cache_hit**
 * The number of cache hit.
* **cache_scarce**
 * The number of cache scare.

### vhost_traffic_status_limit_traffic_by_set_key

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_limit_traffic_by_set_key** *key* *member*:*size* [*code*]
**Default** | -
**Context** | http, server, location

`Description:` Enables the traffic limit for specified *key* and *member*.
The *key* is a key string to limit traffic.
The *member* is a member string to limit traffic.
The *size* is a size(k/m/g) to limit traffic.
The *code* is a code to return in response to rejected requests.(Default: 503)


The *`key`* syntax is as follows:
* *`group`*@[*`subgroup`*@]*`name`*

The available *`group`* strings are as follows:
* **NO**
 * The group of server.
* **UA**
 * The group of upstream alone.
* **UG**
 * The group of upstream group.(use *`subgroup`*)
* **CC**
 * The group of cache.
* **FG**
 * The group of filter.(use *`subgroup`*)

The available *`member`* strings are as follows:
* **request**
 * The total number of client requests received from clients.
* **in**
 * The total number of bytes received from clients.
* **out**
 * The total number of bytes sent to clients.
* **1xx**
 * The number of responses with status codes 1xx.
* **2xx**
 * The number of responses with status codes 2xx.
* **3xx**
 * The number of responses with status codes 3xx.
* **4xx**
 * The number of responses with status codes 4xx.
* **5xx**
 * The number of responses with status codes 5xx.
* **cache_miss**
 * The number of cache miss.
* **cache_bypass**
 * The number of cache bypass.
* **cache_expired**
 * The number of cache expired.
* **cache_stale**
 * The number of cache stale.
* **cache_updating**
 * The number of cache updating.
* **cache_revalidated**
 * The number of cache revalidated.
* **cache_hit**
 * The number of cache hit.
* **cache_scarce**
 * The number of cache scare.

The *member* is the same as `vhost_traffic_status_limit_traffic` directive.

### vhost_traffic_status_limit_check_duplicate

-   | -
--- | ---
**Syntax**  | **vhost_traffic_status_limit_check_duplicate** \<on\|off\>
**Default** | on
**Context** | http, server, location

`Description:` Enables or disables the deduplication of vhost_traffic_status_limit_by_set_key.
It is processed only one of duplicate values(`member` | `key` + `member`)
in each directives(http, server, location) if this option is enabled.

## TODO
* Add support for implementing `stream` stats.

## Donation
[![License](http://img.shields.io/badge/PAYPAL-DONATE-yellow.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=PWWSYKQ9VKH38&lc=KR&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)

## Author
YoungJoo.Kim(김영주) [<vozlt@vozlt.com>]
