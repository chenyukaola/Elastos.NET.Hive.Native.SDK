#ifndef __FILE_H__
#define __FILE_H__

#include "elastos_hive.h"

struct HiveFile {
    ssize_t (*read)(HiveFile *, char *buf, size_t bufsz);
};

#endif // __FILE_H__
