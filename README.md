# nginx-auth-cas-lua

### WARNING, CAS integration is functional, but mileage may vary.

This is a CAS client written entirely using nginx's lua module.
It is similar to [apache mod_auth_cas](https://github.com/apereo/mod_auth_cas).

# Installation

## Install dependencies

* [ngx_http_lua_module by OpenResty](https://github.com/openresty/ngx_openresty) : 

`apt install libnginx-mod-http-lua` 

or 

`yum install nginx-mod-http-lua`

* [lua-resty-http](https://github.com/ledgetech/lua-resty-http) : 

```
mkdir -p /etc/nginx/lua/resty
cd /etc/nginx/lua/resty/
wget https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http_headers.lua
wget https://raw.githubusercontent.com/ledgetech/lua-resty-http/master/lib/resty/http.lua
```

## Install nginx-auth-cas-lua

```
cd /etc/nginx/lua/
wget https://raw.githubusercontent.com/prigaux/nginx-auth-cas-lua/master/src/cas.lua
wget https://raw.githubusercontent.com/prigaux/nginx-auth-cas-lua/master/src/global_cas_conf.lua
```

# Configuration

* configure `cas_uri` in /etc/nginx/lua/global_cas_conf.lua
* configure various global stuff

```
# needed for resty.http
resolver 8.8.8.8;
lua_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;

lua_package_path '/etc/nginx/lua/?.lua;;';
lua_shared_dict cas_store 10M;
```

* protect a location (REMOTE_USER is passed to proxy implicitly):

```
location /secured {
    access_by_lua_block { require('cas').forceAuthentication() }
    proxy_pass ...;
    ...
}
```

NB: `access_by_lua_block` must be *before* proxy_pass

* or for FASTCGI protect a location and provide REMOTE_USER explicitly:
  ```
  location /secured {
    access_by_lua_block { require('cas').forceAuthentication() }
    fastcgi_pass ...;
    fastcgi_param REMOTE_USER $http_remote_user;
    ...
  }
  ```


# Known limitations

* only CAS protocol v2
* no CAS proxy
* no CAS single sign out

# Various information

* this work is based on [Toshi Piazza's ngx-http-cas-client-lua](https://github.com/toshipiazza/ngx-http-cas-client-lua)
* we could be using [ngx.location.capture](https://github.com/openresty/lua-nginx-module#ngxlocationcapture), but it [does not work with HTTP/2](https://github.com/openresty/lua-nginx-module/issues/1195#issuecomment-346410275).