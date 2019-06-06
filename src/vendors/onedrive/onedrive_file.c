#include <stddef.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <crystal.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>

#include "onedrive_file.h"
#include "http_client.h"
#include "oauth_client.h"

#define FILE_LARGE_SIZE 4096

typedef struct OneDriveFile {
    HiveFile base;
    int fd;
    int upload_flag;
    char file_path[ MAXPATHLEN + 1];
    char local_path[MAXPATHLEN + MAXPATHLEN + 1];
    HiveFileOpenFlags flags;
} OneDriveFile;

static int get_item_id(HiveDrive *obj, const char *path)
{
    OneDriveDrive *drive = (OneDriveDrive*)obj;

    char* access_token = NULL;
    char url[MAXPATHLEN + 1];
    int item_id;
    int rc;
    long resp_code;
    http_client_t *httpc = NULL;
    char *resp_body_str = NULL;
    cJSON *resp_part = NULL;
    cJSON *item_part = NULL;

    rc = oauth_client_get_access_token(drive->credential, &access_token);
    if(rc)
        goto error_exit;

    httpc = http_client_new();
    if(!httpc)
        goto error_exit;

    path_esc = http_client_escape(httpc, path, strlen(path));
    http_client_reset(httpc);
    if(!path_esc)
        goto error_exit;

    rc = snprintf(url, sizeof(url), "%s/root:%s", drive->drv_url, path_esc);
    http_client_memory_free(path_esc);
    if (rc < 0 || rc >= sizeof(url))
        goto error_exit;

    http_client_set_url_escape(httpc, url);
    http_client_set_method(httpc, HTTP_METHOD_GET);
    http_client_enable_response_body(httpc);
    http_client_set_header(httpc, "Authorization", access_token);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    if (rc < 0)
        goto error_exit;

    if(resp_code == 401) {
        oauth_client_set_expired(drv->credential);
        goto error_exit;
    }

    if (resp_code != 200)
        goto error_exit;

    resp_body_str = http_client_move_response_body(httpc, NULL);
    if (!resp_body_str) {
        goto error_exit;

    resp_part = cJSON_Parse(resp_body_str);
    if (!resp_part)
        goto error_exit;

    item_part = cJSON_GetObjectItemCaseSensitive(resp_part, "id");
    free(resp_part);
    resp_part = NULL;
    if (!item_part)
        goto error_exit;

    http_client_close(httpc);

    return item_part->valueint;

error_exit:
    if(access_token)
        free(access_token);
    if(httpc)
        http_client_close(httpc);

    return -1;
}

static int upload_small_file(HiveDrive *obj, int fsize)
{
    OneDriveDrive *drive = (OneDriveDrive*)obj;

    char* access_token = NULL;
    char url[MAXPATHLEN + 1];
    int item_id;
    int rc;
    long resp_code;
    http_client_t *httpc = NULL;
    char *resp_body_str = NULL;
    cJSON *resp_part = NULL;
    cJSON *item_part = NULL;

    item_id = get_item_id(obj);

    rc = oauth_client_get_access_token(drive->credential, &access_token);
    if(rc)
        goto error_exit;

    httpc = http_client_new();
    if(!httpc)
        goto error_exit;

    rc = snprintf(url, sizeof(url), "%s/items/%s/content", drive->drv_url, item_id);
    if (rc < 0 || rc >= sizeof(url))
        goto error_exit;

    http_client_set_url_escape(httpc, url);
    http_client_set_method(httpc, HTTP_METHOD_PUT);
    http_client_enable_response_body(httpc);
    http_client_set_header(httpc, "Authorization", access_token);
    http_client_set_upload_file(httpc, drive->fd, url, fsize);

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    if (rc < 0)
        goto error_exit;

    if(resp_code == 401) {
        oauth_client_set_expired(drv->credential);
        goto error_exit;
    }

    if (resp_code != 201)
        goto error_exit;

    http_client_close(httpc);

    return 0;

error_exit:
    if(access_token)
        free(access_token);
    if(httpc)
        http_client_close(httpc);

    return -1;
}

static upload_large_file(HiveFile *file, int fsize)
{

}

static int file_size(const char* path)
{
    struct stat statbuf;
    stat(path,&statbuf);

    return statbuf.st_size;
}

static ssize_t onedrive_file_read(HiveFile * file, char *buf, size_t bufsz)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    ssize_t len;

    if(drv_file->fd <= 0)
        return -1;

    len = read(drv_file->fd, buf, bufsz);

    return len;
}

static ssize_t onedrive_file_write(HiveFile *file, const char *buf, size_t bufsz)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    int fd;
    ssize_t len;

    if(drv_file->fd <= 0)
        return -1;

    len = write(drv_file->fd, buf, bufsz);
    if(len < 0)
        drv_file->upload_flag = 0;

    drv_file->upload_flag = 1;

    return len;
}

static ssize_t onedrive_file_lseek(HiveFile *file, size_t offset, HiveFileSeekWhence whence)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    ssize_t len;

    if(drv_file->fd <= 0)
        return -1;

    len = lseek(drv_file->fd, offset, whence);

    return len;
}

static int ondrive_file_close(HiveFile *file)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    int rc;

    if(drv_file->fd <= 0)
        return -1;

    if(drv_file->upload_flag) {
        int len = file_size(drv_file->local_path);
        if(len <= FILE_LARGE_SIZE){
            if(upload_small_file(file, len) == -1)
                return -1;
        }
        else {      //large file

        }

    }

    rc = close(drv_file->fd);
    if(rc)
        return -1;

    return remove(drv_file->local_path);;
}

static int ondrive_file_get_path(HiveFile *file, char *buf, size_t bufsz)
{
    OneDriveFile* drv_file = (OneDriveFile*)file;
    OneDriveDrive *drv = (OneDriveDrive*)(file->drive);

    char url[MAXPATHLEN + 1];
    int len;
    int rc;
    long resp_code;
    char* access_token = NULL;
    http_client_t *httpc = NULL;
    char *resp_body_str = NULL;
    cJSON *resp_part = NULL;
    cJSON *root_part = NULL;

    rc = oauth_client_get_access_token(drv->credential, &access_token);
    if(rc)
        goto error_exit;

    httpc = http_client_new();
    if(!httpc)
        goto error_exit;

    rc = snprintf(url, sizeof(url), "%s/root", drv->drv_url);
    if (rc < 0 || rc >= sizeof(url))
        goto error_exit;

    while (true) {
        http_client_set_url_escape(httpc, url);
        http_client_set_method(httpc, HTTP_METHOD_GET);
        http_client_enable_response_body(httpc);
        http_client_set_header(httpc, "Authorization", access_token);

        rc = http_client_request(httpc);
        if (rc)
            goto error_exit;

        rc = http_client_get_response_code(httpc, &resp_code);
        if (rc < 0)
            goto error_exit;

        if(resp_code == 401) {
            oauth_client_set_expired(drv->credential);
            goto error_exit;
        }

        if (resp_code != 200)
            goto error_exit;

        resp_body_str = http_client_move_response_body(httpc, NULL);
        if (!resp_body_str) {
            goto error_exit;

        resp_part = cJSON_Parse(resp_body_str);
        if (!resp_part)
            goto error_exit;

        root_part = cJSON_GetObjectItemCaseSensitive(resp_part, "root");
        free(resp_part);
        resp_part = NULL;
        if (!root_part || (root_part && (!*root_part->valuestring)))
            goto error_exit;

        len = strlen(root_part->valuestring) + strlen(drv_file->file_path) + 1;
        if(len > bufsz)
            goto error_exit;

        strcpy(buf, root_part->valuestring);
        strcat(buf, drv_file->file_path);

        http_client_close(httpc);
    }
    return 0;

error_exit:
    if(access_token)
        free(access_token);
    if(httpc)
        http_client_close(httpc);

    return -1;
}



HiveFile *onedrive_file_open(HiveDrive *obj, const char *path, HiveFileOpenFlags flags)
{
    OneDriveDrive *drive = (OneDriveDrive*)obj;

    OneDriveFile *file;
    char path[MAXPATH + 1];
    char url[MAXPATHLEN + 1];
    char download_url[MAXPATHLEN + 1];
    size_t len;
    int rc, fd;
    long resp_code;
    char* access_token = NULL;
    http_client_t *httpc = NULL;
    char* path_esc = NULL;
    char *resp_body_str = NULL;
    cJSON *resp_part = NULL;
    cJSON *location_part = NULL;

    rc = oauth_client_get_access_token(drive->credential, &access_token);
    if(rc)
        goto error_exit;

    httpc = http_client_new();
    if(!httpc)
        goto error_exit;

    path_esc = http_client_escape(httpc, path, strlen(path));
    http_client_reset(httpc);
    if(!path_esc)
        goto error_exit;

    rc = snprintf(url, sizeof(url), "%s/root:%s:/content", drive->drv_url, path_esc);
    http_client_memory_free(path_esc);
    if (rc < 0 || rc >= sizeof(url))
        goto error_exit;

    while (true) {
        http_client_set_url_escape(httpc, url);
        http_client_set_method(httpc, HTTP_METHOD_GET);
        http_client_enable_response_body(httpc);
        http_client_set_header(httpc, "Authorization", access_token);

        rc = http_client_request(httpc);
        if (rc)
            goto error_exit;

        rc = http_client_get_response_code(httpc, &resp_code);
        if (rc < 0)
            goto error_exit;

        if(resp_code == 401) {
            oauth_client_set_expired(drv->credential);
            goto error_exit;
        }

        if (resp_code != 302)
            goto error_exit;

        resp_body_str = http_client_move_response_body(httpc, NULL);
        if (!resp_body_str) {
            goto error_exit;

        resp_part = cJSON_Parse(resp_body_str);
        if (!resp_part)
            goto error_exit;

        location_part = cJSON_GetObjectItemCaseSensitive(resp_part, "Location");
        free(resp_part);
        resp_part = NULL;
        if (!location_part || (location_part && (!*location_part->valuestring)))
            goto error_exit;

        strcpy(download_url, location_part->valuestring);

        http_client_close(httpc);
    }

    strcpy(file->local_path, persistent_location);
    strcat(file->local_path, path);
    //Todo: how to download file

    file->flags = flags;
    file->upload_flag = 0;

    fd = open(file->local_path, flags);
    if(fd != -1)
        file->fd = fd;
    //Todo:

    file->base.read = &onedrive_file_read;
    file->base.write = &onedrive_file_write;
    file->base.hive_file_lseek = &onedrive_file_lseek;
    file->base.get_path = &onedrive_file_get_path;
    file->base.close = &ondrive_file_close;

    return &file->base;

error_exit:
    if(access_token)
        free(access_token);
    if(httpc)
        http_client_close(httpc);

    return NULL;

}