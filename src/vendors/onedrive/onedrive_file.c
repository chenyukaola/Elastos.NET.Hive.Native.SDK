#include <stddef.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <crystal.h>
#include <unistd.h>

#include "onedrive_file.h"
#include "http_client.h"
#include "oauth_client.h"

typedef struct OneDriveFile {
    HiveFile base;
    char file_path[MAXPATHLEN+1];
    //char local_path[MAXPATHLEN+1];
    HiveFileOpenFlags flags;
} OneDriveFile;

static ssize_t onedrive_file_read(HiveFile * file, char *buf, size_t bufsz)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    int fd;
    ssize_t len;

    fd = open(drv_file->file_path, flags);
    if(fd == -1)
        return -1;

    len = read(fd, buf, bufsz);
    close(fd);

    return len;
}

static ssize_t onedrive_file_write(HiveFile *file, const char *buf, size_t bufsz)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    int fd;
    ssize_t len;

    fd = open(drv_file->file_path, flags);
    if(fd == -1)
        return -1;

    len = write(fd, buf, bufsz);
    close(fd);

    //TOdo: to upload to onedrive


    return len;
}

static ssize_t onedrive_file_lseek(HiveFile *file, size_t offset, HiveFileSeekWhence whence)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    int fd;
    ssize_t len;

    fd = open(drv_file->file_path, flags);
    if(fd == -1)
        return -1;

    len = lseek(fd, offset, whence);
    close(fd);

    return len;
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

    return NULL;
}

static int onedrive_file_close(HiveFile *file)
{
    OneDriveFile *drv_file = (OneDriveFile*)file;
    int fd;
    int rc;

    fd = open(drv_file->file_path, flags);
    if(fd == -1)
        return -1;

    rc = close(fd);
    close(fd);

    return rc;
}

HiveFile *onedrive_file_open(HiveDrive *obj, const char *path, HiveFileOpenFlags flags)
{
    OneDriveDrive *drive = (OneDriveDrive*)obj;

    OneDriveFile *file;
    char path[MAXPATH + 1];
    char url[MAXPATHLEN + 1];
    char download_url[MAXPATHLEN + 1];
    size_t len;
    int rc;
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

        //Todo: how to download file

        http_client_close(httpc);
    }

    file->base = base;
    file->flags = flags;
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