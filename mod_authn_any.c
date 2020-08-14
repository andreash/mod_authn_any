/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * http_auth: authentication
 *
 * Rob McCool & Brian Behlendorf.
 *
 * Adapted to Apache by rst.
 *
 */

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_dbm.h"

#include "ap_provider.h"
#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/

#include "mod_auth.h"


typedef struct {
} authn_dbm_config_rec;

static void *create_authn_dbm_dir_config(apr_pool_t *p, char *d)
{
    authn_dbm_config_rec *conf = apr_palloc(p, sizeof(*conf));
    return conf;
}

static const command_rec authn_dbm_cmds[] =
{
    {NULL}
};

module AP_MODULE_DECLARE_DATA authn_dbm_module;

static authn_status check_dbm_pw(request_rec *r, const char *user,
                                 const char *password)
{
    return AUTH_GRANTED;
}

static authn_status get_dbm_realm_hash(request_rec *r, const char *user,
                                       const char *realm, char **rethash)
{
    return AUTH_USER_FOUND;
}

static const authn_provider authn_any_provider =
{
    &check_dbm_pw,
    &get_dbm_realm_hash,
};

static void register_hooks(apr_pool_t *p)
{
    ap_register_auth_provider(p, AUTHN_PROVIDER_GROUP, "any",
                              AUTHN_PROVIDER_VERSION,
                              &authn_any_provider, AP_AUTH_INTERNAL_PER_CONF);
}

AP_DECLARE_MODULE(authn_any) =
{
    STANDARD20_MODULE_STUFF,
    create_authn_dbm_dir_config, /* dir config creater */
    NULL,                        /* dir merger --- default is to override */
    NULL,                        /* server config */
    NULL,                        /* merge server config */
    authn_dbm_cmds,              /* command apr_table_t */
    register_hooks               /* register hooks */
};
