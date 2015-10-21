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
* [Customizing](#customizing)
 * [To customize after the module installed](#to-customize-after-the-module-installed)
 * [To customize before the module installed](#to-customize-before-the-module-installed)
* [Directives](#directives)
 * [vhost_traffic_status](#vhost_traffic_status)
 * [vhost_traffic_status_zone](#vhost_traffic_status_zone)
 * [vhost_traffic_status_display](#vhost_traffic_status_display)
 * [vhost_traffic_status_display_format](#vhost_traffic_status_display_format)
 * [vhost_traffic_status_filter_by_host](#vhost_traffic_status_filter_by_host)
 * [vhost_traffic_status_filter_by_set_key](#vhost_traffic_status_filter_by_set_key)
* [Donation](#donation)
* [Author](#author)

## Version
This document describes nginx-module-vts `v0.1.3` released on 21 Oct 2015.

## Dependencies
* [nginx](http://nginx.org)

## Compatibility
* 1.9.x (last tested: 1.9.4)
* 1.8.x (last tested: 1.8.0)
* 1.7.x (last tested: 1.7.10)
* 1.6.x (last tested: 1.6.2)
* 1.4.x (last tested: 1.4.7)

Earlier versions is not tested.

## Screenshots

![nginx-module-vts screenshot](https://cloud.githubusercontent.com/assets/3648408/7854611/1386f3b2-0556-11e5-8323-7c624da0fcb3.png)

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

 * If you request `/status/format/json`, will respond with a JSON document containing the current activity data for using in live dashboards and third-party monitoring tools.

 * If you request `/status/format/html`, will respond with the built-in live dashboard in HTML that requests internally to `/status/format/json`.

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
                "responeMsec":...,
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
If you don't want it, see the `vhost_traffic_status_filter_by_host`, `vhost_traffic_status_filter_by_set_key` directive.

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
**Syntax**  | vhost_traffic_status [on\|off]
**Default** | off
**Context** | http, server, location

`Description:` Enables or disables the module working.
If you set `vhost_traffic_status_zone` directive, is automatically enabled.

### vhost_traffic_status_zone

-   | - 
--- | ---
**Syntax**  | vhost_traffic_status_zone [shared:*name:size*]
**Default** | shared:vhost_traffic_status:1m
**Context** | http

`Description:` Sets parameters for a shared memory zone that will keep states for various keys.
The cache is shared between all worker processes.

### vhost_traffic_status_display

-   | - 
--- | ---
**Syntax**  | vhost_traffic_status_display
**Default** | -
**Context** | http, server, location

`Description:` Enables or disables the module display handler.

### vhost_traffic_status_display_format

-   | - 
--- | ---
**Syntax**  | vhost_traffic_status_display_format [json\|html]
**Default** | json
**Context** | http, server, location

`Description:` Sets the display handler's output format.
If you set `json`, will respond with a JSON document.
If you set `html`, will respond with the built-in live dashboard in HTML.

### vhost_traffic_status_filter_by_host

-   | - 
--- | ---
**Syntax**  | vhost_traffic_status_filter_by_host [on\|off]
**Default** | off
**Context** | server, location

`Description:` Enables or disables the keys by Host header field.
If you set `on` and nginx's server_name directive set several or wildcard name starting with an asterisk, e.g. “*.example.org”
and requested to server with hostname such as (a|b|c).example.org or *.example.org
then json serverZones is printed as follows:

```Nginx
server {
  server_name *.example.org;
  vhost_traffic_status_filter_by_host on;
  .
  .
}
```

```Json
.
.
  "serverZones": {
  .
  .
    "a.example.org": {
	.
	.
	},
	"b.example.org": {
	.
	.
	}
	"c.example.org": {
	.
	.
	}
	.
	.
```

It provides the same function that set `vhost_traffic_status_filter_by_set_key $host`.

### vhost_traffic_status_filter_by_set_key

-   | - 
--- | ---
**Syntax**  | vhost_traffic_status_filter_by_set_key [*key*]
**Default** | -
**Context** | server, location

`Description:` Enables the keys by user defined variable.
The *key* name can contain variables such as $host, $uri.
The example with geoip module is as follows:

```Nginx
server {
  server_name *.example.org;
  vhost_traffic_status_filter_by_set_key $geoip_country_code@$host;
  .
  .
}
```

```Json
.
.
  "serverZones": {
  .
  .
    "KR@a.example.org": {
    .
    .
    },
    "FI@b.example.org": {
    .
    .
    }
    "US@c.example.org": {
    .
    .
    }
    .
    .
```

This directive is high priority than `vhost_traffic_status_filter_by_host`.
If it set both, then `vhost_traffic_status_filter_by_host` directive will be ignore.

## Donation
[![License](http://img.shields.io/badge/PAYPAL-DONATE-yellow.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=PWWSYKQ9VKH38&lc=KR&currency_code=USD&bn=PP%2dDonationsBF%3abtn_donateCC_LG%2egif%3aNonHosted)

## Author
YoungJoo.Kim(김영주) [<vozlt@vozlt.com>]
