#include <pthread.h>
#include <stdlib.h>
#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif
#include <crystal.h>
#if defined(HAVE_IO_H)
#include <io.h>
#endif
#include <sys/stat.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <cjson/cJSON.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#include <stdio.h>

#include "http_client.h"
#include "oauth_client.h"
#include "sandbird.h"

typedef struct server_response {
    char *auth_code;
    char *token_type;
    struct timeval expires_at;
    char *scope;
    char *access_token;
    char *refresh_token;
} svr_resp_t;

typedef struct oauth_client {
    oauth_opt_t     opt;
    svr_resp_t      svr_resp;
    pthread_mutex_t lock;
    bool            logging_in;
    bool            logged_in;
} oauth_client_t;


#define set_ptr_field(field, val) \
    do {                          \
       if (field)                 \
           free(field);           \
       (field) = (val);           \
    } while (0)

#define reset_svr_resp(resp)                        \
    do {                                            \
        set_ptr_field((resp)->auth_code, NULL);     \
        set_ptr_field((resp)->token_type, NULL);    \
        set_ptr_field((resp)->scope, NULL);         \
        set_ptr_field((resp)->access_token, NULL);  \
        set_ptr_field((resp)->refresh_token, NULL); \
    } while (0)

static char *encode_profile(oauth_client_t *cli)
{
    cJSON *json = NULL;
    cJSON *auth_code;
    cJSON *token_type;
    cJSON *expires_at;
    cJSON *scope;
    cJSON *access_token;
    cJSON *refresh_token;
    char *json_str = NULL;

    json = cJSON_CreateObject();
    if (!json)
        goto end;

    pthread_mutex_lock(&cli->lock);
    auth_code = cJSON_CreateStringReference(cli->svr_resp.auth_code);
    if (!cli->svr_resp.auth_code || !auth_code)
        goto end;
    cJSON_AddItemToObject(json, "auth_code", auth_code);

    token_type = cJSON_CreateStringReference(cli->svr_resp.token_type);
    if (!cli->svr_resp.token_type || !token_type)
        goto end;
    cJSON_AddItemToObject(json, "token_type", token_type);

    expires_at = cJSON_CreateNumber(cli->svr_resp.expires_at.tv_sec);
    if (!expires_at)
        goto end;
    cJSON_AddItemToObject(json, "expires_at", expires_at);

    scope = cJSON_CreateStringReference(cli->svr_resp.scope);
    if (!cli->svr_resp.scope || !scope)
        goto end;
    cJSON_AddItemToObject(json, "scope", scope);

    access_token = cJSON_CreateStringReference(cli->svr_resp.access_token);
    if (!cli->svr_resp.access_token || !access_token)
        goto end;
    cJSON_AddItemToObject(json, "access_token", access_token);

    refresh_token = cJSON_CreateStringReference(cli->svr_resp.refresh_token);
    if (!cli->svr_resp.refresh_token || !refresh_token)
        goto end;
    cJSON_AddItemToObject(json, "refresh_token", refresh_token);

    json_str = cJSON_PrintUnformatted(json);

end:
    pthread_mutex_unlock(&cli->lock);
    if (json)
        cJSON_Delete(json);
    return json_str;
}

static void save_profile(oauth_client_t *cli)
{
    char *json_str = NULL;
    int fd;
    char tmp_profile_path_new[PATH_MAX];
    char tmp_profile_path_old[PATH_MAX];
    char *new_prof;
    int rc;
    size_t nleft;
    bool old_prof_exists = true;

    if (access(cli->opt.profile_path, F_OK)) {
        old_prof_exists = false;
        new_prof = cli->opt.profile_path;
    } else {
        strcpy(tmp_profile_path_new, cli->opt.profile_path);
        strcat(tmp_profile_path_new, ".new");
        new_prof = tmp_profile_path_new;
    }

    json_str = encode_profile(cli);
    if (!json_str)
        return;

    fd = open(new_prof, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        free(json_str);
        return;
    }

    nleft = strlen(json_str);
    while (nleft) {
        ssize_t nwr = write(fd, json_str, nleft);
        if (nwr < 0) {
            free(json_str);
            close(fd);
            remove(new_prof);
            return;
        }
        nleft -= nwr;
    }
    free(json_str);
    close(fd);

    if (old_prof_exists) {
        strcpy(tmp_profile_path_old, cli->opt.profile_path);
        strcat(tmp_profile_path_old, ".old");
        rc = rename(cli->opt.profile_path, tmp_profile_path_old);
        if (rc) {
            remove(new_prof);
            return;
        }

        rc = rename(new_prof, cli->opt.profile_path);
        if (rc) {
            rename(tmp_profile_path_old, cli->opt.profile_path);
            remove(new_prof);
            return;
        }

        remove(tmp_profile_path_old);
    }
}

static int perform_token_tsx(oauth_client_t *cli, char *req_body, char **resp_body)
{
    http_client_t *http_cli;
    long resp_code;
    int rc;

    http_cli = http_client_new();
    if (!http_cli)
        return -1;

    http_client_set_url(http_cli, cli->opt.token_url);
    http_client_set_method(http_cli, HTTP_METHOD_POST);
    http_client_set_request_body_instant(http_cli, req_body, strlen(req_body));
    http_client_enable_response_body(http_cli);

    rc = http_client_request(http_cli);
    if (rc) {
        http_client_close(http_cli);
        return -1;
    }

    rc = http_client_get_response_code(http_cli, &resp_code);
    if (rc < 0 && resp_code != 200) {
        http_client_close(http_cli);
        return -1;
    }

    *resp_body = http_client_move_response_body(http_cli, NULL);
    http_client_close(http_cli);
    if (!*resp_body)
        return -1;

    return 0;
}

static int decode_access_token_resp(oauth_client_t *cli, const char *json_str, bool load_profile)
{
    cJSON *json;
    cJSON *auth_code;
    cJSON *token_type;
    cJSON *expires_in;
    cJSON *scope;
    cJSON *access_token;
    cJSON *refresh_token;
    cJSON *expires_at;
    int rc = 0;
    svr_resp_t resp;

    memset(&resp, 0, sizeof(resp));

    json = cJSON_Parse(json_str);
    if (!json)
        return -1;

    if (load_profile) {
        expires_at = cJSON_GetObjectItemCaseSensitive(json, "expires_at");
        if (!cJSON_IsNumber(expires_at))
            goto fail;
        resp.expires_at.tv_sec = expires_at->valuedouble;

        auth_code = cJSON_GetObjectItemCaseSensitive(json, "auth_code");
        if (!cJSON_IsString(auth_code) || !auth_code->valuestring || !*auth_code->valuestring)
            goto fail;
        resp.auth_code = auth_code->valuestring;
        auth_code->valuestring = NULL;
    } else {
        expires_in = cJSON_GetObjectItemCaseSensitive(json, "expires_in");
        if (!cJSON_IsNumber(expires_in) || (int)expires_in->valuedouble < 0)
            goto fail;

        struct timeval now;
        rc = gettimeofday(&now, NULL);
        if (rc)
            goto fail;
        resp.expires_at.tv_sec = now.tv_sec + expires_in->valuedouble;
    }

    token_type = cJSON_GetObjectItemCaseSensitive(json, "token_type");
    if (!cJSON_IsString(token_type) || !token_type->valuestring || !*token_type->valuestring)
        goto fail;
    resp.token_type = token_type->valuestring;
    token_type->valuestring = NULL;

    scope = cJSON_GetObjectItemCaseSensitive(json, "scope");
    if (!cJSON_IsString(scope) || !scope->valuestring || !*scope->valuestring)
        goto fail;
    resp.scope = scope->valuestring;
    scope->valuestring = NULL;

    access_token = cJSON_GetObjectItemCaseSensitive(json, "access_token");
    if (!cJSON_IsString(access_token) || !access_token->valuestring || !*access_token->valuestring)
        goto fail;
    resp.access_token = access_token->valuestring;
    access_token->valuestring = NULL;

    refresh_token = cJSON_GetObjectItemCaseSensitive(json, "refresh_token");
    if (!cJSON_IsString(refresh_token) || !refresh_token->valuestring || !*refresh_token->valuestring)
        goto fail;
    resp.refresh_token = refresh_token->valuestring;
    refresh_token->valuestring = NULL;

    pthread_mutex_lock(&cli->lock);
    if (load_profile)
        set_ptr_field(cli->svr_resp.auth_code, resp.auth_code);
    set_ptr_field(cli->svr_resp.access_token, resp.access_token);
    set_ptr_field(cli->svr_resp.refresh_token, resp.refresh_token);
    set_ptr_field(cli->svr_resp.scope, resp.scope);
    cli->svr_resp.expires_at = resp.expires_at;
    set_ptr_field(cli->svr_resp.token_type, resp.token_type);
    pthread_mutex_unlock(&cli->lock);
    goto succeed;

fail:
    reset_svr_resp(&resp);
    rc = -1;
succeed:
    cJSON_Delete(json);
    return rc;
}

static int refresh_token(oauth_client_t *cli)
{
#define REQ_BODY_MAX_SZ 2048
    char req_body[REQ_BODY_MAX_SZ];
    char *resp_body;
    int rc;
    char redirect_url_raw[128];
    http_client_t *http_cli;
    char *cli_id;
    char *refresh_token;
    char *redirect_url;

    rc = snprintf(redirect_url_raw, sizeof(redirect_url_raw), "%s:%s%s",
         cli->opt.redirect_url, cli->opt.redirect_port, cli->opt.redirect_path);
    if (rc < 0 || rc >= sizeof(redirect_url_raw))
        return -1;

    http_cli = http_client_new();
    if (!http_cli)
        return -1;

    cli_id = http_client_escape(http_cli, cli->opt.client_id, strlen(cli->opt.client_id));
    if (!cli_id) {
        http_client_close(http_cli);
        return -1;
    }

    redirect_url = http_client_escape(http_cli, redirect_url_raw, strlen(redirect_url_raw));
    if (!redirect_url) {
        http_client_memory_free(cli_id);
        http_client_close(http_cli);
        return -1;
    }

    pthread_mutex_lock(&cli->lock);
    if (!cli->svr_resp.refresh_token) {
        pthread_mutex_unlock(&cli->lock);
        return -1;
    }
    refresh_token = http_client_escape(http_cli, cli->svr_resp.refresh_token, strlen(cli->svr_resp.refresh_token));
    pthread_mutex_unlock(&cli->lock);
    http_client_close(http_cli);
    if (!refresh_token) {
        http_client_memory_free(cli_id);
        http_client_memory_free(redirect_url);
        return -1;
    }

    rc = snprintf(req_body, sizeof(req_body),
        "client_id=%s&"
        "redirect_uri=%s&"
        "refresh_token=%s&"
        "grant_type=refresh_token",
        cli_id,
        redirect_url,
        refresh_token);
    http_client_memory_free(cli_id);
    http_client_memory_free(redirect_url);
    http_client_memory_free(refresh_token);
    if (rc < 0 || rc >= sizeof(req_body))
        return -1;

    rc = perform_token_tsx(cli, req_body, &resp_body);
    if (rc)
        return -1;

    rc = decode_access_token_resp(cli, resp_body, false);
    free(resp_body);
    if (rc)
        return -1;

    return 0;
#undef REQ_BODY_MAX_SZ
}

static int load_profile(oauth_client_t *cli)
{
    struct stat sbuf;
    int fd;
    char *json_str;
    off_t nleft;
    int rc;

    fd = open(cli->opt.profile_path, O_RDONLY);
    if (fd < 0)
        return -1;

    if (fstat(fd, &sbuf)) {
        close(fd);
        return -1;
    }

    if (!sbuf.st_size) {
        close(fd);
        return -1;
    }
    nleft = sbuf.st_size;

    json_str = (char *)malloc(sbuf.st_size);
    if (!json_str) {
        close(fd);
        return -1;
    }

    while (nleft) {
        ssize_t nrd;
        nrd = read(fd, json_str, sbuf.st_size);
        if (nrd < 0) {
            close(fd);
            free(json_str);
            return -1;
        }
        nleft -= nrd;
    }

    rc = decode_access_token_resp(cli, json_str, true);

    close(fd);
    free(json_str);
    return rc;
}

static int handle_auth_redirect(sb_Event *e)
{
    bool *finish = (bool *)(((void **)e->udata)[1]);
    oauth_client_t *cli = (oauth_client_t *)(((void **)e->udata)[0]);
    char code[128];
    int rc;

    if (e->type != SB_EV_REQUEST) {
        if (e->type == SB_EV_CLOSE)
            *finish = true;
        return SB_RES_OK;
    }

    if (strcmp(e->path, cli->opt.redirect_path))
        return SB_RES_OK;

    rc = sb_get_var(e->stream, "code", code, sizeof(code));
    if (rc != SB_ESUCCESS)
        return SB_RES_OK;

    pthread_mutex_lock(&cli->lock);
    if (cli->svr_resp.auth_code)
        free(cli->svr_resp.auth_code);

    cli->svr_resp.auth_code = (char *)malloc(strlen(code) + 1);
    if (!cli->svr_resp.auth_code) {
        pthread_mutex_unlock(&cli->lock);
        return SB_RES_OK;
    }

    strcpy(cli->svr_resp.auth_code, code);
    pthread_mutex_unlock(&cli->lock);
    sb_send_status(e->stream, 200, "OK");
    return SB_RES_OK;
}

static void *open_auth_url(void *args)
{
    oauth_client_t *cli = (oauth_client_t *)(((void **)args)[0]);
    char *url = (char *)(((void **)args)[1]);

    cli->opt.grant_authorize(url);

    return NULL;
}

static int get_auth_code(oauth_client_t *cli)
{
    sb_Options opt;
    sb_Server *server;
    pthread_t tid;
    int rc;
    http_client_t *http_cli;
    char buf[512];
    bool svr_finish = false;
    char *url;

    http_cli = http_client_new();
    if (!http_cli)
        return -1;

    http_client_set_url(http_cli, cli->opt.auth_url);

    rc = snprintf(buf, sizeof(buf), "%s:%s%s",
        cli->opt.redirect_url, cli->opt.redirect_port, cli->opt.redirect_path);
    assert(rc > 0 && rc < sizeof(buf));

    http_client_set_query(http_cli, "client_id", cli->opt.client_id);
    http_client_set_query(http_cli, "scope", cli->opt.scope);
    http_client_set_query(http_cli, "redirect_uri", buf);
    http_client_set_query(http_cli, "response_type", "code");

    void *args1[] = {cli, &svr_finish};
    memset(&opt, 0, sizeof(opt));
    opt.port = cli->opt.redirect_port;
    opt.handler = handle_auth_redirect;
    opt.udata = args1;

    server = sb_new_server(&opt);
    if (!server) {
        http_client_close(http_cli);
        return -1;
    }

    rc = http_client_get_url_escape(http_cli, &url);
    http_client_close(http_cli);
    if (rc) {
        sb_close_server(server);
        return -1;
    }

    void *args2[] = {cli, url};
    rc = pthread_create(&tid, NULL, open_auth_url, args2);
    if (rc) {
        http_client_memory_free(url);
        sb_close_server(server);
        return -1;
    }

    while (!svr_finish)
        sb_poll_server(server, 300000);
    sb_close_server(server);
    pthread_join(tid, NULL);
    http_client_memory_free(url);
    return cli->svr_resp.auth_code ? 0 : -1;
}

static int redeem_access_token(oauth_client_t *cli)
{
#define REQ_BODY_MAX_SZ 512
    char req_body[REQ_BODY_MAX_SZ];
    char *resp_body;
    int rc;
    char redirect_url_raw[128];
    http_client_t *http_cli;
    char *cli_id;
    char *code;
    char *redirect_url;

    rc = snprintf(redirect_url_raw, sizeof(redirect_url_raw), "%s:%s%s",
        cli->opt.redirect_url, cli->opt.redirect_port, cli->opt.redirect_path);
    if (rc < 0 || rc >= sizeof(redirect_url_raw))
        return -1;

    http_cli = http_client_new();
    if (!http_cli)
        return -1;

    cli_id = http_client_escape(http_cli, cli->opt.client_id, strlen(cli->opt.client_id));
    if (!cli_id) {
        http_client_close(http_cli);
        return -1;
    }

    redirect_url = http_client_escape(http_cli, redirect_url_raw, strlen(redirect_url_raw));
    if (!redirect_url) {
        http_client_memory_free(cli_id);
        http_client_close(http_cli);
        return -1;
    }

    pthread_mutex_lock(&cli->lock);
    code = http_client_escape(http_cli, cli->svr_resp.auth_code, strlen(cli->svr_resp.auth_code));
    pthread_mutex_unlock(&cli->lock);
    http_client_close(http_cli);
    if (!code) {
        http_client_memory_free(cli_id);
        http_client_memory_free(redirect_url);
        return -1;
    }

    rc = snprintf(req_body, sizeof(req_body),
        "client_id=%s&"
        "redirect_uri=%s&"
        "code=%s&"
        "grant_type=authorization_code",
        cli_id,
        redirect_url,
        code);
    http_client_memory_free(cli_id);
    http_client_memory_free(redirect_url);
    http_client_memory_free(code);
    if (rc < 0 || rc >= sizeof(req_body))
        return -1;

    rc = perform_token_tsx(cli, req_body, &resp_body);
    if (rc)
        return -1;

    rc = decode_access_token_resp(cli, resp_body, false);
    free(resp_body);
    if (rc)
        return -1;

    return 0;
#undef REQ_BODY_MAX_SZ
}

static void optrst(oauth_opt_t *opt)
{
#define FREE(ptr) \
do { \
   if (ptr) { \
       free((void *)(ptr)); \
       (ptr) = NULL; \
   }  \
} while (0)

    FREE(opt->auth_url);
    FREE(opt->token_url);
    FREE(opt->scope);
    FREE(opt->client_id);
    FREE(opt->redirect_port);
    FREE(opt->redirect_path);
    FREE(opt->redirect_url);
    opt->profile_path[0] = '\0';
    opt->grant_authorize = NULL;

#undef FREE
}

static void oauth_client_destructor(void *arg)
{
    oauth_client_t *cli = (oauth_client_t *)arg;

    optrst(&cli->opt);
    reset_svr_resp(&cli->svr_resp);
    pthread_mutex_destroy(&cli->lock);
}

static int optcpy(oauth_opt_t *dst, oauth_opt_t *src)
{
    int rc;

    dst->auth_url = strdup(src->auth_url);
    if (!dst->auth_url) {
        optrst(dst);
        return -1;
    }

    dst->token_url = strdup(src->token_url);
    if (!dst->token_url) {
        optrst(dst);
        return -1;
    }

    dst->scope = strdup(src->scope);
    if (!dst->scope) {
        optrst(dst);
        return -1;
    }

    dst->client_id = strdup(src->client_id);
    if (!dst->client_id) {
        optrst(dst);
        return -1;
    }

    dst->redirect_port = strdup(src->redirect_port);
    if (!dst->redirect_port) {
        optrst(dst);
        return -1;
    }

    dst->redirect_path = strdup(src->redirect_path);
    if (!dst->redirect_path) {
        optrst(dst);
        return -1;
    }

    dst->redirect_url = strdup(src->redirect_url);
    if (!dst->redirect_url) {
        optrst(dst);
        return -1;
    }

    rc = snprintf(dst->profile_path, sizeof(dst->profile_path), "%s", src->profile_path);
    if (rc < 0 || rc >= sizeof(dst->profile_path)) {
        optrst(dst);
        return -1;
    }

    dst->grant_authorize = src->grant_authorize;

    return 0;
}

oauth_client_t *oauth_client_new(oauth_opt_t *opt)
{
    oauth_client_t *cli;
    int rc;

    cli = (oauth_client_t *)rc_zalloc(sizeof(oauth_client_t), oauth_client_destructor);
    if (!cli)
        return NULL;

    pthread_mutex_init(&cli->lock, NULL);

    rc = optcpy(&cli->opt, opt);
    if (rc) {
        deref(cli);
        return NULL;
    }

    if (!access(opt->profile_path, F_OK)) {
        rc = load_profile(cli);
        if (rc) {
            deref(cli);
            return NULL;
        }
        cli->logged_in = true;
    }

    return cli;
}

void oauth_client_delete(oauth_client_t *cli)
{
    deref(cli);
}

int oauth_client_login(oauth_client_t *client)
{
    int rc;

    if (client->logged_in || client->logging_in)
        return client->logged_in ? 0 : -1;

    client->logging_in = true;

    rc = get_auth_code(client);
    if (rc) {
        client->logging_in = false;
        return -1;
    }

    rc = redeem_access_token(client);
    if (rc) {
        client->logging_in = false;
        return -1;
    }

    client->logging_in = false;
    client->logged_in = true;
    save_profile(client);

    return 0;
}

int oauth_client_logout(oauth_client_t *client)
{
    if (client->logging_in)
        return -1;

    if (!client->logged_in)
        return 0;

    remove(client->opt.profile_path);

    pthread_mutex_lock(&client->lock);
    reset_svr_resp(&client->svr_resp);
    pthread_mutex_unlock(&client->lock);
    client->logged_in = false;

    return 0;
}

static bool token_expired(struct timeval *expires_at)
{
    struct timeval now;

    gettimeofday(&now, NULL);

    return now.tv_sec < expires_at->tv_sec ? false : true;
}

static int get_access_token(oauth_client_t *cli, bool force_refresh, char **token)
{
    int rc;

    if (force_refresh || token_expired(&cli->svr_resp.expires_at)) {
        rc = refresh_token(cli);
        if (rc)
            return -1;

        save_profile(cli);
    }

    pthread_mutex_lock(&cli->lock) ;
    if (!cli->svr_resp.token_type || !cli->svr_resp.access_token) {
        pthread_mutex_unlock(&cli->lock);
        return -1;
    }

    *token = malloc(strlen(cli->svr_resp.token_type) +
        strlen(cli->svr_resp.access_token) + 2);
    if (!*token) {
        pthread_mutex_unlock(&cli->lock);
        return -1;
    }
    sprintf(*token, "%s %s", cli->svr_resp.token_type, cli->svr_resp.access_token);
    pthread_mutex_unlock(&cli->lock);

    return 0;
}

int oauth_client_get_access_token(oauth_client_t *cli, char **token)
{
    return get_access_token(cli, false, token);
}

int oauth_client_refresh_access_token(oauth_client_t *cli, char **token)
{
    return get_access_token(cli, true, token);
}

int oauth_client_set_expired(oauth_client_t *client)
{
    client->svr_resp.expires_at.tv_sec = 0;

    return 0;
}
