/*
 * Copyright (C) Robert Paprocki
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <libinjection.h>
#include <libinjection_sqli.h>


typedef struct libinjection_sqli_state libinjection_sqli_state_t;


typedef struct {
    ngx_flag_t   enabled;
    ngx_array_t  *patterns;
} ngx_http_libinjection_loc_conf_t;


typedef enum {
    SKIPPING,
    SEARCHING,
    KEY_FOUND,
    GATHERING,
    PRINTING
} arg_parse_state_t;


static char *
ngx_http_libinjection_patterns(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_libinjection_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_libinjection_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_libinjection_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_libinjection_handler(ngx_http_request_t *r);


static ngx_command_t ngx_http_libinjection_commands[] = {

    {
        ngx_string("libinjection"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_libinjection_loc_conf_t, enabled),
        NULL
    },
    {
        ngx_string("libinjection_patterns"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_http_libinjection_patterns,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};


static ngx_http_module_t ngx_http_libinjection_module_ctx = {
    NULL,                                     /* preconfiguration */
    ngx_http_libinjection_postconfiguration,  /* postconfiguration */

    NULL,                                     /* create main configuration */
    NULL,                                     /* init main configuration */

    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */

    ngx_http_libinjection_create_loc_conf,    /* create loc configuration */
    ngx_http_libinjection_merge_loc_conf      /* merge loc configuration */
};


ngx_module_t  ngx_http_libinjection_module = {
    NGX_MODULE_V1,
    &ngx_http_libinjection_module_ctx,  /* module context */
    ngx_http_libinjection_commands,     /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_str_t
ngx_http_libinjection_arg_search(ngx_http_request_t *r, ngx_regex_t *re,
                                 ngx_str_t *key, u_char **buf,
                                 ngx_uint_t *offset)
{
    u_char             *p, *q, *last, *src;
    ngx_int_t           n, found;
    ngx_str_t           value, decoded;
    arg_parse_state_t   state;

    found = 0;

    value.data = NULL;
    value.len = 0;
    
    if (*offset >= r->args.len) {
        return value;
    }

    p = q = r->args.data + *offset;
    last = r->args.data + r->args.len;

    state = SEARCHING;


    while (p != last) {
        switch(state) {
        case SKIPPING:
            if (*p == '&') {
                state = SEARCHING;
                q = p + 1;
            }

            break;

        case SEARCHING:
            /* key with no value */

            if (*p == '&') {
                state = SKIPPING;

                continue;
            }

            /* end key */

            if (*p == '=' && *(p + 1) != '&' ) {
                key->len  = p - q;
                key->data = q;

                n = ngx_regex_exec(re, key, NULL, 0);

                if (n >= 0) {
                     /* key match, find the value */

                    state = KEY_FOUND;

                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                   "http libinjection examine \"%V\"", key);
                } else if (n == NGX_REGEX_NO_MATCHED) {
                    /* no match, on to the next param */

                    state = SKIPPING;
                } else {
                    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                                  ngx_regex_exec_n " failed: %i", n);
                }
            }

            break;

        case KEY_FOUND:
            /* move past '=' */

            q = p + 1;

            p = q - 1;

            state = GATHERING;

            break;

        case GATHERING:

            if (*p == '&' || p + 1 == last) {
                state = PRINTING;
                continue;
            }

            break;

        case PRINTING:
            value.len = p + 1 == last ? p - q + 1 : p - q;
            if (value.len > 0) {
                value.data = q;

                found = 1;
                *offset = (q + value.len + 1) - r->args.data;
            }
            state = SKIPPING;

            continue;
        }

        if (found) {
            break;
        }

        ++p;
    }

    if (!found) {
        return value;
    }

    src = value.data;

    decoded.data = *buf;

    ngx_unescape_uri(buf, &src, value.len, 0);

    decoded.len = *buf - decoded.data;

    return decoded;
}


static ngx_int_t
ngx_http_libinjection_handler(ngx_http_request_t *r)
{
    u_char                            *dst, *src;
    ngx_str_t                          decoded, key;
    ngx_uint_t                         i, offset;
    ngx_regex_t                       *re;
    libinjection_sqli_state_t          state;
    ngx_http_libinjection_loc_conf_t  *ulcf;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_libinjection_module);

    if (!ulcf->enabled || ulcf->patterns == NGX_CONF_UNSET_PTR) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http libinjection access handler");

    dst = ngx_pnalloc(r->pool, r->args.len);
    src = dst;

    re = ulcf->patterns->elts;
    i = offset = 0;
    
    for ( ;; ) {
        decoded = ngx_http_libinjection_arg_search(r, &re[i], &key, &dst,
                                                   &offset);

        if (decoded.len) {
            libinjection_sqli_init(&state, (const char *)decoded.data,
                                   decoded.len, FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "injection found in param \"%V\": \"%s\"",
                              &key, state.fingerprint);

                return NGX_HTTP_FORBIDDEN;
            }

        } else {
            /* next param */
            offset = 0;

            if (++i >= ulcf->patterns->nelts) {
                break;
            }
        }

        dst = src;
    }

    return NGX_DECLINED;
}


static char *
ngx_http_libinjection_patterns(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t            *value;
    ngx_regex_t          *re, *entry;
    ngx_regex_compile_t   rc;
    u_char                errstr[NGX_MAX_CONF_ERRSTR];

    ngx_http_libinjection_loc_conf_t *lcf = conf;

    /* compile the expression */

    value = cf->args->elts;
    value++;

    ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

    rc.pattern  = *value;
    rc.pool     = cf->pool;
    rc.err.len  = NGX_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (ngx_regex_compile(&rc) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V", &rc.err);
        return NGX_CONF_ERROR;
    }

    re = rc.regex;

    /* create the array if missing */

    if (lcf->patterns == NGX_CONF_UNSET_PTR) {
        lcf->patterns = ngx_array_create(cf->pool, 4, sizeof(ngx_regex_t));

        if (lcf->patterns == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    entry = ngx_array_push(lcf->patterns);

    ngx_memcpy(entry, re, sizeof(ngx_regex_t));

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_libinjection_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }   

    *h = ngx_http_libinjection_handler;

    return NGX_OK;
}


static void *
ngx_http_libinjection_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_libinjection_loc_conf_t  *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_libinjection_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }

    lcf->enabled  = NGX_CONF_UNSET;
    lcf->patterns = NGX_CONF_UNSET_PTR;

    return lcf;
}


static char *
ngx_http_libinjection_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_libinjection_loc_conf_t *prev = parent;
    ngx_http_libinjection_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->enabled, prev->enabled, 0);

    if (conf->patterns == NGX_CONF_UNSET_PTR) {
        conf->patterns = prev->patterns;
    }

    return NGX_CONF_OK;
}
