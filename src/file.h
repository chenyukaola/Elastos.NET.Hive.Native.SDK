#ifndef __FILE_H__
#define __FILE_H__

#include "elastos_hive.h"

struct HiveFile {
    HiveDrive *drive;

    ssize_t (*read)              (HiveFile *, char *buf, size_t bufsz);
    ssize_t (*write)             (HiveFile *, const char *buf, size_t bufsz);
    ssize_t (*hive_file_lseek)   (HiveFile *, size_t offset, HiveFileSeekWhence whence);
    int     (*hive_file_get_path)(HiveFile *, char *buf, size_t bufsz);
    int     (*close)             (HiveFile *);
};

#endif // __FILE_H__
