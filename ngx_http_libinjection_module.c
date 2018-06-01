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
    ngx_array_t  *keys;
} ngx_http_libinjection_loc_conf_t;


typedef enum {
    SKIPPING,
    SEARCHING,
    KEY_FOUND,
    GATHERING,
    PRINTING
} arg_parse_state_t;


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
        ngx_string("libinjection_keys"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_libinjection_loc_conf_t, keys),
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
ngx_http_libinjection_arg_search(ngx_http_request_t *r, ngx_str_t *key,
                                 u_char **buf, ngx_uint_t *offset)
{
    int                 i, found;
    u_char             *p, *q, *last, *src;
    ngx_str_t           value, decoded, dummy;
    arg_parse_state_t   state;

    i = found = 0;

    value.data = dummy.data = NULL;
    value.len = dummy.len = 0;
    
    if (*offset >= r->args.len) {
        return dummy;
    }

    p = q = r->args.data + *offset;
    last = r->args.data + r->args.len;

    state = SEARCHING;
    
    while (p != last) {
        switch (state) {
        case SKIPPING:
            if (*p == '&') {
                state = SEARCHING;
                q = p + 1;
                i = 0;
            }

            break;

        case SEARCHING:
            if (*p != key->data[i]) {
                state = SKIPPING;
                break;
            }

            /* match so far */
            i++;

            if ((size_t)(p - q) == key->len - 1) {
                if (*(p + 1) == '=') {
                    state = KEY_FOUND;

                } else {
                    state = SKIPPING;
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
        return dummy;
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
    ngx_str_t                          decoded, *key;
    ngx_uint_t                         i, offset;
    libinjection_sqli_state_t          state;
    ngx_http_libinjection_loc_conf_t  *ulcf;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_libinjection_module);

    if (!ulcf->enabled) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http libinjection access handler");

    dst = ngx_pnalloc(r->pool, r->args.len);
    src = dst;

    key = ulcf->keys->elts;
    i = offset = 0;
    
    for ( ;; ) {
        decoded = ngx_http_libinjection_arg_search(r, &key[i], &dst, &offset);

        if (decoded.len) {
            libinjection_sqli_init(&state, (const char *)decoded.data,
                                   decoded.len, FLAG_NONE);

            if (libinjection_is_sqli(&state)) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "injection found in param \"%V\": \"%s\"",
                              &key[i], state.fingerprint);

                return NGX_HTTP_FORBIDDEN;
            }

        } else {
            /* next param */
            offset = 0;

            if (++i >= ulcf->keys->nelts) {
                break;
            }
        }

        dst = src;
    }

    return NGX_DECLINED;
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

    lcf->enabled = NGX_CONF_UNSET;
    lcf->keys = NGX_CONF_UNSET_PTR;

    return lcf;
}


static char *
ngx_http_libinjection_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_libinjection_loc_conf_t *prev = parent;
    ngx_http_libinjection_loc_conf_t *conf = child;

    ngx_conf_merge_off_value(conf->enabled, prev->enabled, 0);

    return NGX_CONF_OK;
}
