#include <stdlib.h>
#include <stdbool.h>
#include <crystal.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#include "drive.h"
#include "client.h"

int hive_drive_get_info(HiveDrive *drive, char **result)
{
    int rc;

    if (!drive || !result) {
        hive_set_error(-1);
        return -1;
    }

    if (!drive->get_info) {
        hive_set_error(-1);
        return -1;
    }

    ref(drive);
    rc = drive->get_info(drive, result);
    deref(drive);

    return rc;
}

int hive_drive_file_stat(HiveDrive *drive, const char *path, char **result)
{
    int rc;

    if (!drive || !path || !*path || !result || path[0] != '/') {
        hive_set_error(-1);
        return  -1;
    }

    ref(drive);
    rc = drive->file_stat(drive, path, result);
    deref(drive);

    return rc;
}

int hive_drive_list_files(HiveDrive *drive, const char *path, char **result)
{
    int rc;

    if (!drive || !path || !*path || !result || path[0] != '/') {
        hive_set_error(-1);
        return  -1;
    }

    ref(drive);
    rc = drive->list_files(drive, path, result);
    deref(drive);

    return rc;
}

int hive_drive_mkdir(HiveDrive *drive, const char *path)
{
    int rc;

    if (!drive || !path || !*path || path[0] != '/') {
        hive_set_error(-1);
        return  -1;
    }

    ref(drive);
    rc = drive->makedir(drive, path);
    deref(drive);

    return rc;
}

int hive_drive_move_file(HiveDrive *drive, const char *old, const char *new)
{
    int rc;

    if (!drive || !old || !*old || !new || !*new ||
        strlen(old) > MAXPATHLEN ||
        strlen(new) > MAXPATHLEN ||
        strcmp(old, new) == 0) {
        hive_set_error(-1);
        return -1;
    }

    ref(drive);
    rc = drive->move_file(drive, old, new);
    deref(drive);

    return rc;
}

int hive_drive_copy_file(HiveDrive *drive, const char *src, const char *dest)
{
    int rc;

    if (!drive || !src || !*src || !dest || !*dest ||
        strlen(src) > MAXPATHLEN ||
        strlen(dest) > MAXPATHLEN ||
        strcmp(src, dest) == 0) {
        hive_set_error(-1);
        return -1;
    }

    ref(drive);
    rc = drive->copy_file(drive, src, dest);
    deref(drive);

    return rc;
}

int hive_drive_delete_file(HiveDrive *drive, const char *path)
{
    int rc;

    if (!drive || !path || !*path) {
        hive_set_error(-1);
        return -1;
    }

    ref(drive);
    rc = drive->delete_file(drive, path);
    deref(drive);

    return rc;
}

int hive_drive_close(HiveDrive *drive)
{
    if (!drive) {
        hive_set_error(-1);
        return -1;
    }

    drive->close(drive);
    return 0;
}

#define HIVE_FILE_OPS_FLAGS (HIVE_FILE_RDONLY | HIVE_FILE_WRONLY | HIVE_FILE_RDWR)
#define HIVE_FILE_WR_OPT_FLAGS (HIVE_FILE_APPEND | HIVE_FILE_CREAT | HIVE_FILE_TRUNC)
HiveFile *hive_file_open(HiveDrive *drv, const char *path, HiveFileOpenFlags mode)
{
    HiveFile *file;
    int len;
    int rc;

    HiveFileOpenFlags op = mode & HIVE_FILE_OPS_FLAGS;
    HiveFileOpenFlags wr_opt = mode & HIVE_FILE_WR_OPT_FLAGS;

    len = strlen(path);
    if(len <= 0)
        return NULL;

    if (!drv || !path || path[0] != '/' || path[len-1] != '/' || !mode )
        return NULL;

    if (op == HIVE_FILE_RDONLY) {
        if (wr_opt)
            return NULL;
    } else if (op == HIVE_FILE_WRONLY || op == HIVE_FILE_RDWR) {
        if ((wr_opt & HIVE_FILE_CREAT) && (wr_opt & ~HIVE_FILE_CREAT))
            return NULL;
    }

    ref(drv);
    rc = drv->open_file(drv, path, mode, &file);
    deref(drv);
    if(rc)
        return NULL;

    return file;
}