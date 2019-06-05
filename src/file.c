#include <stdlib.h>
#include <stdbool.h>
#include <crystal.h>
#include <sys/param.h>

#include "drive.h"
#include "file.h"


int hive_file_get_path(HiveFile *file, char *buf, size_t bufsz)
{
    int rc;

    if(!file || !buf || bufsz <= 0 )
        return NULL;

    ref(file);
    rc = file->hive_file_get_path(file, buf, bufsz);
    deref(file);

    return rc;
}

//#define HIVE_FILE_SEEK_FLAGS (HIVE_SEEK_SET | HIVE_SEEK_CUR | HIVE_SEEK_END)
ssize_t hive_file_lseek(HiveFile *file, size_t offset, HiveFileSeekWhence whence)
{
    int rc;
    ssize_t len;

    if(!file || offset < 0)
        return -1;

    if( whence != HIVE_SEEK_SET && whence != HIVE_SEEK_CUR && whence != HIVE_SEEK_END)
        return -1;

    ref(file);
    len = file->hive_file_lseek(file, offset, whence);
    deref(file);

    return len;
}

ssize_t hive_file_read(HiveFile *file, char *buf, size_t bufsz)
{
    int rc;
    ssize_t len;

    if(!file || !buf || bufsz <= 0)
        return -1;

    ref(file);
    len = file->read(file, buf, bufsz);
    deref(file);

    return len;
}

ssize_t hive_file_write(HiveFile *file, const char *buf, size_t bufsz)
{
    int rc;
    ssize_t len;

    if(!file || !buf || bufsz <= 0)
        return -1;

    ref(file);
    len = file->write(file, buf, bufsz);
    deref(file);

    return len;
}

int hive_file_close(HiveFile *file)
{
    int rc;

    if (!file)
        return -1;

    rc = file->close(file);
    return rc;
}
