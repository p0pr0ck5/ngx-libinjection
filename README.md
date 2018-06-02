# Name

ngx-libinjection

# Description

Simple module integrating [libinjection](https://github.com/client9/libinjection/) as a basic access phase handler. Defined query parameters are evaluated against `libinjection`; requests containing param values flagged as potential SQL injection are rejected as forbidden.

# Installation

`libinjection` must first be built and referenced by the environmental variable `LIBINJECTION_PATH`. Because both the source and object files in `libinjection` live in the projects `src` directory, it's easiest to just reference this sub directory:

```bash
$ git clone https://github.com/client9/libinjection.git && cd libinjection && make all
$ export LIBINJECTION_PATH=/path/to/libinjection/src
```

And configure Nginx with this module as any other module:


```bash
$ ./configure --add-module=/path/to/ngx-libinjection
```

By default, Nginx will link to `libinjection` as a shared object; if you wish to link `libinjection` statically into the Nginx binary, define the variable `LIBINJECTION_STATIC`:

```bash
$ export LIBINJECTION_STATIC=yes
```

# Synopsis

```
server {
    libinjection on;
    libinjection_keys foo;
    libinjection_keys bat;
}
```

```bash
$ curl "localhost/index.html?foo=bar&bat=-1' and 1=1 union/* foo */select load_file('/etc/passwd')--"
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.13.9</center>
</body>
</html>
```

# Directives

## libinjection

**Syntax**: *libinjection on | off*

**Default**: *libinjection off*

**Context**: *http, server, location*

Enables processing of query string params with `libinjection`.

## libinjection_keys

**Syntax**: *libinjection_keys foo*

**Default**: *-*

**Context**: *http, server, location*

Defines one or more query string keys whose value will be passed to `libinjection`. Multiple keys can be defined with multiple directives.

# TODO

* Support wildcard/regular expression key definitions
* Support request body processing

# LICENSE

Copyright (c) 2018, Robert Paprocki

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
