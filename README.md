Nginx virtual host traffic status module
==========

[![License](http://img.shields.io/badge/license-BSD-brightgreen.svg)](https://github.com/vozlt/nginx-module-vts/blob/master/LICENSE)

Nginx virtual host traffic status module

## Dependencies
* [nginx](http://nginx.org)

## Compatibility
* 1.7.x (last tested: 1.7.10)
* 1.6.x (last tested: 1.6.2)

Earlier versions is not tested.

## Screenshots

![nginx-module-vts screenshot](https://cloud.githubusercontent.com/assets/3648408/6163286/55ea810e-b2d3-11e4-93e4-72e9b402c12d.png)

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
This is similar to the live activity monitoring of nginx plus.
The built-in html is also taken from the demo page.

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
  ...
  },
  "serverZones": {
  ...
  },
  "upstreamZones": {
  ...
  }
}
```

* main
 * Basic version, uptime(nowMsec - loadMsec)
* connections
 * Total connections and requests(same as stub_status_module in NGINX)
* serverZones
 * Traffic(in/out) and request and response counts per each server zone
 * Total traffic(In/Out) and request and response counts(It zone name is `*`)
* upstreamZones
 * Traffic(in/out) and request and response counts per server in each upstream group
 * Current settings(weight, maxfails, failtimeout...) in nginx.conf

The directive `vhost_traffic_status_display_format` sets the default ouput format that is one of json or html. (Default: json)

Traffic calculation as follows:

* ServerZones
 * in += requested_bytes
 * out += sent_bytes
* UpstreamZones
 * in += requested_bytes via the ServerZones
 * out += sent_bytes via the ServerZones
  
All calculations are working in log processing phase of Nginx.
Internal redirects(X-Accel-Redirect or error_page) does not calculate in the UpstreamZones. 

`Caveats:` this module relies on nginx logging system, so the traffic may be
in certain cirumstances different that real bandwidth traffic.
Websocket, canceled downloads may be cause of inaccuracies.

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
If you set json, will respond with a JSON document.
If you set html, will respond with the built-in live dashboard in HTML.


## Author
YoungJoo.Kim(김영주) [<vozlt@vozlt.com>]
