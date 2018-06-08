/*
 * Copyright (C) Robert Paprocki
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_string.h>
#include <libinjection.h>
#include <libinjection_sqli.h>


typedef struct libinjection_sqli_state libinjection_sqli_state_t;


typedef struct {
    ngx_flag_t    done;
    ngx_flag_t    reject;
    ngx_array_t  *patterns;
} ngx_http_libinjection_ctx_t;


typedef struct {
    ngx_flag_t    enabled;
    ngx_flag_t    body_enabled;
    ngx_array_t  *patterns;
} ngx_http_libinjection_loc_conf_t;


typedef enum {
    SKIPPING,
    SEARCHING,
    KEY_FOUND,
    GATHERING,
    PRINTING
} arg_parse_state_t;


static ngx_str_t ngx_http_libinjection_arg_search(ngx_http_request_t *r,
    ngx_str_t data, ngx_regex_t *re, ngx_str_t *key, u_char **buf,
    ngx_uint_t *offset);
static char * ngx_http_libinjection_patterns(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_libinjection_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_libinjection_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_libinjection_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_libinjection_process(ngx_http_request_t *r,
    ngx_str_t data, ngx_array_t *patterns);
static ngx_int_t ngx_http_libinjection_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_libinjection_body_handler(ngx_http_request_t *r);
static void ngx_http_libinjection_body_post_handler(ngx_http_request_t *r);


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
    {
        ngx_string("libinjection_body"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_libinjection_loc_conf_t, body_enabled),
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
ngx_http_libinjection_arg_search(ngx_http_request_t *r, ngx_str_t data,
                                 ngx_regex_t *re, ngx_str_t *key, u_char **buf,
                                 ngx_uint_t *offset)
{
    u_char             *p, *q, *last, *src;
    ngx_int_t           n, found;
    ngx_str_t           value, decoded;
    arg_parse_state_t   state;

    found = 0;

    value.data = NULL;
    value.len = 0;
    
    if (*offset >= data.len) {
        return value;
    }

    p = q = data.data + *offset;
    last = data.data + data.len;

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
            if (*p == '&') {
                /* key with no value */

                state = SKIPPING;

                continue;
            }

            if (*p == '=' && *(p + 1) != '&' ) {
                /* end key */

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
ngx_http_libinjection_process(ngx_http_request_t *r, ngx_str_t data,
                              ngx_array_t *patterns)
{
    u_char                     *src, *buf;
    ngx_str_t                   decoded, key;
    ngx_uint_t                  i, offset;
    ngx_regex_t                *re;
    libinjection_sqli_state_t   state;

    /* url decode buffer */
    buf = ngx_pnalloc(r->pool, data.len);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no memory to allocate libinjection decode buffer");

        return NGX_ERROR;
    }

    re  = patterns->elts;
    src = buf;
    i   = offset = 0;
    
    for ( ;; ) {
        decoded = ngx_http_libinjection_arg_search(r, data, &re[i], &key,
                                                   &buf, &offset);

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

            if (++i >= patterns->nelts) {
                break;
            }
        }

        buf = src;
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_libinjection_handler(ngx_http_request_t *r)
{
    ngx_http_libinjection_loc_conf_t  *ulcf;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_libinjection_module);

    if (!ulcf->enabled || ulcf->patterns == NGX_CONF_UNSET_PTR) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http libinjection query handler");

    return ngx_http_libinjection_process(r, r->args, ulcf->patterns);
}


static void
ngx_http_libinjection_body_post_handler(ngx_http_request_t *r)
{
    /* TODO handle unbuffered body read */

    u_char                       *buf, *p;
    ngx_str_t                     body;
    ngx_int_t                     rc;
    ngx_chain_t                  *cl;
    ngx_http_libinjection_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http libinjection body post handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_libinjection_module);
    if (ctx == NULL) {
        /* wat */
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }

    rc = NGX_DECLINED;

    if (r->request_body == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "no request body found");

        goto done;
    }

    if (r->request_body->temp_file) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "request body buffered to disk, not processing");

        goto done;
    }

    if (r->request_body->bufs == NULL) {
        goto done;
    }

    /* copy the body bufs into a separate buf so we can decode it */

    body.len = 0;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        body.len += cl->buf->last - cl->buf->pos;
    }

    if (body.len == 0) {
        goto done;
    }

    buf = ngx_palloc(r->pool, body.len);
    if (buf == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "no memory to allocate libinjection request body buffer");

        goto done;
    }

    p = buf;
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        p = ngx_copy(p, cl->buf->pos, cl->buf->last - cl->buf->pos);
    }

    body.data = buf;

    rc = ngx_http_libinjection_process(r, body, ctx->patterns);

    if (rc != NGX_DECLINED) {
        ctx->reject = 1;
    }

done:

/* need to decrease count because we are not run wrapped inside of
 * ngx_http_finalize_request() */

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (!ctx->done) {
        ctx->done = 1;

        ngx_http_core_run_phases(r);
    }
}


static ngx_int_t
ngx_http_libinjection_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                          rc;
    ngx_http_libinjection_ctx_t       *ctx;
    ngx_http_libinjection_loc_conf_t  *ulcf;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_libinjection_module);

    if (!ulcf->body_enabled || ulcf->patterns == NGX_CONF_UNSET_PTR) {
        return NGX_DECLINED;
    }

    if (r->method == NGX_HTTP_GET || r->method == NGX_HTTP_HEAD) {
        return NGX_DECLINED;
    }

    if (r->headers_in.content_type == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_strcmp("application/x-www-form-urlencoded",
                   r->headers_in.content_type->value.data) != 0) {
        return NGX_DECLINED;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http libinjection body handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_libinjection_module);

    if (ctx == NULL) {
        /* no ctx, first run, create the ctx and initialize */

        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_libinjection_ctx_t));
        if (ctx == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /*
         * set by ngx_pcalloc():
         *
         * ctx->done = 0;
         * ctx->reject = 0;
         */

        ctx->patterns = ulcf->patterns;

        ngx_http_set_ctx(r, ctx, ngx_http_libinjection_module);
    }

    if (!ctx->done) {
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        r->request_body_in_clean_file = 1;

        rc = ngx_http_read_client_request_body(r,
            ngx_http_libinjection_body_post_handler);

        if (rc == NGX_ERROR) {
            return rc;
        }

        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                              \
        (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif

            return rc;
        }

        return NGX_DONE;
    }

    if (ctx->reject == 1) {
        return NGX_HTTP_FORBIDDEN;

    } else {
        return NGX_DECLINED;
    }
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
    ngx_http_handler_pt        *h, *hb;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* modules are executed LIFO */

    hb = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (hb == NULL) {
        return NGX_ERROR;
    }

    *hb = ngx_http_libinjection_body_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
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

    lcf->enabled      = NGX_CONF_UNSET;
    lcf->body_enabled = NGX_CONF_UNSET;
    lcf->patterns     = NGX_CONF_UNSET_PTR;

    return lcf;
}


static char *
ngx_http_libinjection_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child)
{
    ngx_http_libinjection_loc_conf_t *prev = parent;
    ngx_http_libinjection_loc_conf_t *conf = child;

    ngx_uint_t    i;
    ngx_regex_t  *re, *entry;

    ngx_conf_merge_off_value(conf->enabled, prev->enabled, 0);
    ngx_conf_merge_off_value(conf->body_enabled, prev->body_enabled, 0);

    if (conf->patterns == NGX_CONF_UNSET_PTR) {
        conf->patterns = prev->patterns;
    } else if (conf->patterns != NGX_CONF_UNSET_PTR &&
               prev->patterns != NGX_CONF_UNSET_PTR) {
        /* merge parent values into us  */

        re = prev->patterns->elts;

        /* TODO fix merge order */
        for (i = 0; i < prev->patterns->nelts; i++) {
            entry = ngx_array_push(conf->patterns);

            ngx_memcpy(entry, &re[i], sizeof(ngx_regex_t));
        }
    }

    return NGX_CONF_OK;
}
