#include <stddef.h>
#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <crystal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdio.h>
#include <sys/stat.h>

#include "onedrive_file.h"
#include "http_client.h"
#include "oauth_client.h"

#define CONTENT_LEN         128
#define FILE_LARGE_SIZE     1024*1024
#define FILE_FRAGEMENT_SIZE 327680
#define FILE_MAX_LARGE_SIZE 1048576*60

typedef struct OneDriveFile {
    HiveFile base;
    int fd;
    int upload_flag;
    char file_path[ MAXPATHLEN + 1];
    char local_path[MAXPATHLEN + MAXPATHLEN + 1];
    HiveFileOpenFlags flags;
} OneDriveFile;

static ssize_t download_file(void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
    return written;
}

static int get_item_id(HiveFile *obj, const char *path)
{
    OneDriveFile *file = (OneDriveFile*)obj;
    OneDriveDrive *drive = (OneDriveDrive*)(file->base->drive);

    char* access_token = NULL;
    char url[MAXPATHLEN + 1];
    int item_id, rc, is_finish = 0;
    long resp_code;
    http_client_t *httpc = NULL;
    char *resp_body_str = NULL;
    char *path_esc = NULL;
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
    if (rc)
        goto error_exit;

    if(resp_code == 401) {
        oauth_client_set_expired(drive->credential);
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
    if (!item_part)
        goto error_exit;

    item_id = item_part->valueint;
    is_finish = 1;

error_exit:
    if(path_esc) {
        http_client_memory_free(path_esc);
        path_esc = NULL;
    }
    if(access_token) {
        free(access_token);
        access_token = NULL;
    }
    if(resp_part) {
        free(resp_part);
        resp_part = NULL;
    }
    if(httpc) {
        http_client_close(httpc);
        httpc = NULL;
    }

    if(is_finish)
        return item_id;

    return -1;
}

static int upload_small_file(HiveFile *obj, int fsize)
{
    OneDriveFile *file = (OneDriveFile*)obj;
    OneDriveDrive *drive = (OneDriveDrive*)(file->base->drive);

    char* access_token = NULL;
    char url[MAXPATHLEN + 1];
    int item_id, rc, is_finish = 0;
    long resp_code;
    http_client_t *httpc = NULL;
    char *resp_body_str = NULL;
    cJSON *resp_part = NULL;
    char* req_body = NULL;

    //To read file and put it into req_body
    req_body = malloc(fsize + 1);
    if(!req_body)
        goto error_exit;

    ssize_t len = read(file->fd, req_body, fsize+1);
    if(len == -1)
        goto error_exit;

    item_id = get_item_id(file);
    if(item_id < 0)
        goto error_exit;

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
    http_client_set_header(httpc, "Content-Type", "text/plain");
    http_client_enable_response_body(httpc);
    http_client_set_header(httpc, "Authorization", access_token);
    http_client_set_request_body_instant(httpc, req_body, strlen(req_body));

    rc = http_client_request(httpc);
    if (rc)
        goto error_exit;

    rc = http_client_get_response_code(httpc, &resp_code);
    if (rc)
        goto error_exit;

    if(resp_code == 401) {
        oauth_client_set_expired(drive->credential);
        goto error_exit;
    }

    if (resp_code != 201)
        goto error_exit;

    is_finish = 1;

error_exit:
    if(req_body) {
       free(req_body);
       req_body = NULL;
    }
    if(access_token) {
        free(access_token);
        access_token = NULL;
    }
    if(httpc) {
        http_client_close(httpc);
        httpc = NULL;
    }

    if(is_finish)
        return 0;

    return -1;
}

static int upload_large_file(HiveFile *obj, int fsize)
{
    OneDriveFile *file = (OneDriveFile*)obj;
    OneDriveDrive *drive = (OneDriveDrive*)(file->base->drive);

    char url[MAXPATHLEN + 1];
    char upload_url[MAXPATHLEN + 1];
    char fragment_size[2];
    char *access_token = NULL;
    char *resp_body_str = NULL;
    cJSON *req_body = NULL;
    cJSON *parent_ref = NULL;
    cJSON *resp_part = NULL;
    cJSON *uploadurl_part = NULL;
    int rc, item_id;
    int i = 0;

    int file_len = file_size(file->local_path);
    snprintf(fragment_size, 2, "%d", file_len);

    req_body = cJSON_CreateObject();
    if (!req_body)
        goto error_exit;

    parent_ref = cJSON_AddObjectToObject(req_body, "item");
    if (!parent_ref)
       goto error_exit;

    if(!cJSON_AddObjectToObject(parent_ref, "@odata.type", "microsoft.graph.driveItemUploadableProperties"))
        goto error_exit;

    if(!cJSON_AddObjectToObject(parent_ref, "@microsoft.graph.conflictBehavior", "replace"))
        goto error_exit;

    if(!cJSON_AddObjectToObject(parent_ref, "name", basename(file->local_path)));
        goto error_exit;

    req_body_str = cJSON_PrintUnformatted(req_body);
    cJSON_Delete(req_body);
    req_body = NULL;
    if (!req_body_str)
        goto error_exit;

    rc = oauth_client_get_access_token(drv->credential, &access_token);
    if (rc)
        goto error_exit;

    httpc = http_client_new();
    if (!httpc)
        goto error_exit;

    item_id = get_item_id(obj);
    if(item_id < 0)
        goto error_exit;

    //1.Create an upload session
    rc = snprintf(url, sizeof(url), "%s/items/%s/createUploadSession", drive->drv_url, item_id);
    if (rc < 0 || rc >= sizeof(url))
        goto error_exit;

    http_client_set_url_escape(httpc, url);
    http_client_set_method(httpc, HTTP_METHOD_POST);
    http_client_set_header(httpc, "Content-Type", "application/json");
    http_client_set_header(httpc, "Authorization", access_token);
    http_client_set_request_body_instant(httpc, req_body_str, strlen(req_body_str));
    http_client_enable_response_body(httpc);

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

    uploadurl_part = cJSON_GetObjectItemCaseSensitive(resp_part, "uploadUrl");
    free(resp_part);
    resp_part = NULL;
    if (!uploadurl_part || (uploadurl_part && (!*uploadurl_part->valuestring)))
        goto error_exit;

    //2.Upload bytes to the upload session
    http_client_reset(httpc);
    strcpy(url, uploadurl_part->valuestring);

    http_client_set_url_escape(httpc, url);
    http_client_set_method(httpc, HTTP_METHOD_PUT);
    http_client_set_header(httpc, "Authorization", access_token);
    http_client_enable_response_body(httpc);

    //if If app splits a file into multiple byte ranges,
    //the size of each byte range MUST be a multiple of 320 KiB (327,680 bytes)
    int flag = 0;
    while(!flag)
    {
        char fragment_range[CONTENT_LEN];
        char req_body[CONTENT_LEN];
        int index = 0;

        if(file_len > FILE_FRAGEMENT_SIZE){
            snprintf(fragment_range, sizeof(fragment_range), "bytes %d-%d/%d", i-1, i+FILE_FRAGEMENT_SIZE-1, file_size(file->local_path));
            snprintf(req_body, sizeof(req_body), "<bytes %d-%d of the file>",i-1, i+FILE_FRAGEMENT_SIZE-1);
        }
        else{
            flag = 1;
            snprintf(fragment_size, sizeof(fragment_size), "%d", file_size(file->local_path)-index);
            snprintf(fragment_range, sizeof(fragment_range), "bytes %d-%d/%d", i-1, file_size(file->local_path)-1, file_size(file->local_path));
            strcpy(req_body, "<final bytes of the file>");
        }

        http_client_set_header(httpc, "Content-Length", fragment_size);
        http_client_set_header(httpc, "Content-Range", fragment_range);
        http_client_set_request_body_instant(httpc, req_body, strlen(req_body));

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

        if(resp_code == 416)
            //todo: handle the error status
            goto error_exit;

        if (resp_code != 202 && !flag)
            goto error_exit;

        if(resp_code ！= 201 && flag)
            goto error_exit;

        resp_body_str = http_client_move_response_body(httpc, NULL);
        if (!resp_body_str)
            goto error_exit;

        resp_part = cJSON_Parse(resp_body_str);
        if (!resp_part)
            goto error_exit;

        cJSON *ner_part = cJSON_GetObjectItemCaseSensitive(resp_part, "nextExpectedRanges");
        free(ner_part);
        ner_part = NULL;
        if (!ner_part || (ner_part && (!*ner_part->valuestring)))
            goto error_exit;

        if(!flag){
            sscanf(ner_part->valuestring, "["%d-"]", index);
            i = index;
            file_len = file_len - index;
        }
    }

    if(access_token)
        free(access_token);
    if(httpc)
        http_client_close(httpc);
    if (req_body)
        cJSON_Delete(req_body);

    return 0;

error_exit:
    if(access_token)
        free(access_token);
    if(httpc)
        http_client_close(httpc);
    if (req_body)
        cJSON_Delete(req_body);

    return -1;
}

static int file_size(const char* path)
{
    struct stat statbuf;
    stat(path,&statbuf);

    return statbuf.st_size;
}

static ssize_t onedrive_file_read(HiveFile * obj, char *buf, size_t bufsz)
{
    OneDriveFile *file = (OneDriveFile*)obj;

    if(file->fd <= 0)
        return -1;

    return read(file->fd, buf, bufsz);
}

static ssize_t onedrive_file_write(HiveFile *obj, const char *buf, size_t bufsz)
{
    OneDriveFile *file = (OneDriveFile*)obj;
    ssize_t len;

    if(file->fd <= 0)
        return -1;

    len = write(file->fd, buf, bufsz);
    if(len < 0)
        file->upload_flag = 0;

    file->upload_flag = 1;

    return len;
}

static ssize_t onedrive_file_lseek(HiveFile *obj, size_t offset, HiveFileSeekWhence whence)
{
    OneDriveFile *file = (OneDriveFile*)obj;

    if(file->fd <= 0)
        return -1;

    return lseek(file->fd, offset, whence);
}

static int ondrive_file_close(HiveFile *obj)
{
    OneDriveFile *file = (OneDriveFile*)obj;
    int rc, len;

    if(drv_file->fd <= 0)
        return -1;

    if(file->upload_flag) {
        len = file_size(file->local_path);
        if(len <= FILE_LARGE_SIZE) {
            if(upload_small_file(file, len) == -1)
                return -1;
        }
        else {
            if(upload_large_file(file, len) == -1)
                return -1;
        }
    }

    rc = close(file->fd);
    if(rc)
        return -1;

    return remove(file->local_path);
}

static int ondrive_file_get_path(HiveFile *obj, char *buf, size_t bufsz)
{
    OneDriveFile* file = (OneDriveFile*)obj;
    OneDriveDrive *drive = (OneDriveDrive*)(file->base->drive);

    char url[MAXPATHLEN + 1];
    int len, rc, is_finish = 0;
    long resp_code;
    char* access_token = NULL;
    http_client_t *httpc = NULL;
    char *resp_body_str = NULL;
    cJSON *resp_part = NULL;
    cJSON *root_part = NULL;

    rc = oauth_client_get_access_token(drive->credential, &access_token);
    if(rc)
        goto error_exit;

    httpc = http_client_new();
    if(!httpc)
        goto error_exit;

    rc = snprintf(url, sizeof(url), "%s/root", drive->drv_url);
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
        oauth_client_set_expired(drive->credential);
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
    if (!root_part || (root_part && (!*root_part->valuestring)))
        goto error_exit;

    len = strlen(root_part->valuestring) + strlen(file->file_path) + 1;
    if(len > bufsz)
        goto error_exit;

    strcpy(buf, root_part->valuestring);
    strcat(buf, file->file_path);

    is_finish = 1;

error_exit:
    if(access_token) {
        free(access_token);
        access_token = NULL;
    }
    if(resp_part) {
        free(resp_part);
        resp_part = NULL;
    }
    if(httpc) {
        http_client_close(httpc);
        httpc = NULL;
    }

    if(is_finish)
        return 0;

    return -1;
}

static void onedrive_file_destroy(void *obj)
{
    OneDriveFile *file = (OneDriveFile *)obj;

    deref(file->credential);
}

HiveFile *onedrive_file_open(HiveDrive *base, const char *path, HiveFileOpenFlags flags)
{
    OneDriveDrive *drive = (OneDriveDrive*)base;

    OneDriveFile *file;
    char path[MAXPATH + 1];
    char url[MAXPATHLEN + 1];
    char download_url[MAXPATHLEN + 1];
    size_t len;
    int rc, fd, is_finish = 0;
    long resp_code;
    char* access_token = NULL;
    http_client_t *httpc = NULL;
    char* path_esc = NULL;
    char *resp_body_str = NULL;
    cJSON *resp_part = NULL;
    cJSON *location_part = NULL;

    file = (OneDriveFile *)rc_zalloc(sizeof(OneDriveFile), &onedrive_file_destroy);
    if(!file)
        goto error_exit;

    strcpy(file->local_path, persistent_location);
    strcat(file->local_path, path);

    int fd = open(file->local_path, flags);
    if(!fd)
        goto error_exit;

    file->fd = fd;
    file->flags = flags;

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
    if (rc < 0 || rc >= sizeof(url))
        goto error_exit;

    // To get download url
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
        oauth_client_set_expired(drive->credential);
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
    if (!location_part || (location_part && (!*location_part->valuestring)))
        goto error_exit;

    // To download file
    strcpy(download_url, location_part->valuestring);
    http_client_reset(httpc);
    http_client_set_url_escape(httpc, download_url);
    http_client_set_response_body(httpc, download_file, fd);
    http_client_enable_response_body(httpc);

    rc = http_client_request(httpc);
    if(rc)
        return goto_exit;

    file->upload_flag = 0;
    file->base.read = &onedrive_file_read;
    file->base.write = &onedrive_file_write;
    file->base.hive_file_lseek = &onedrive_file_lseek;
    file->base.get_path = &onedrive_file_get_path;
    file->base.close = &ondrive_file_close;

    is_finish = 1;

error_exit:
    if(fd) {
        fclose(fd);
        fd = NULL;
    }
    if(path_esc) {
        http_client_memory_free(path_esc);
        path_esc = NULL;
    }
    if(access_token) {
        free(access_token);
        access_token = NULL;
    }
    if(resp_part) {
        free(resp_part);
        resp_part = NULL;
    }
    if(httpc) {
        http_client_close(httpc);
        httpc = NULL;
    }

    if(is_finish)
        return &file->base;

    return NULL;

}