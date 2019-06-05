#ifndef __ONEDRIVE_FILE_H__
#define __ONEDRIVE_FILE_H__

#include "file.h"

HiveFile *onedrive_file_open(HiveDrive *obj, char *path, HiveFileOpenFlags flags);

#endif // __ONEDRIVE_FILE_H__
