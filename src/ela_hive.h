#ifndef __ELA_HIVE_H__
#define __ELA_HIVE_H__

#if defined(__APPLE__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#if defined(HIVE_STATIC)
#define HIVE_API
#elif defined(HIVE_DYNAMIC)
#ifdef HIVE_BUILD
#if defined(_WIN32) || defined(_WIN64)
#define HIVE_API __declspec(dllexport)
#else
#define HIVE_API __attribute__((visibility("default")))
#endif
#else
#if defined(_WIN32) || defined(_WIN64)
      #define HIVE_API __declspec(dllimport)
    #else
      #define HIVE_API
    #endif
#endif
#else
#define HIVE_API
#endif

typedef struct HiveClient       HiveClient;
typedef struct HiveClientInfo   HiveClientInfo;
typedef struct HiveDrive        HiveDrive;
typedef struct HiveDriveInfo    HiveDriveInfo;
typedef struct HiveFile         HiveFile;

#define HIVE_FILE_RDONLY (1U << 0)
#define HIVE_FILE_WRONLY (1U << 1)
#define HIVE_FILE_RDWR   (1U << 2)
#define HIVE_FILE_APPEND (1U << 3)
#define HIVE_FILE_CREAT  (1U << 4)
#define HIVE_FILE_TRUNC  (1U << 5)
typedef unsigned HiveFileOpenFlags;

#define HIVE_SEEK_SET    (1U << 0)
#define HIVE_SEEK_CUR    (1U << 1)
#define HIVE_SEEK_END    (1U << 2)
typedef unsigned HiveFileSeekWhence;

struct HiveOAuthInfo {
    const char *client_id;
    const char *scope;
    const char *redirect_url;
};

enum HiveDriveType {
    HiveDriveType_Native    = 0x0,
    HiveDriveType_IPFS      = 0x01,

    HiveDriveType_OneDrive  = 0x10,
    HiveDriveType_ownCloud  = 0x51,
    HiveDriveType_Butt      = 0x99
};

typedef struct HiveOptions {
    char *persistent_location;
    int  drive_type;
} HiveOptions;

typedef struct OneDriveOptions {
    HiveOptions base;

    const char *client_id;
    const char *scope;
    const char *redirect_url;

    int (*grant_authorize)(const char *request_url);
} OneDriveOptions;

typedef struct IPFSOptions {
    HiveOptions base;

    char *uid;
    size_t bootstraps_size;
    const char *bootstraps_ip[0];
} IPFSOptions;

/**
* \~English
 * Create a new hive client instance to the specific drive.
 * All other hive APIs should be called after having client instance.
 *
 * @param
 *      options     [in] A pointer to a valid HiveOptions structure.
 *
 * @return
 *      If no error occurs, return the pointer of Hive client instance.
 *      Otherwise, return NULL, and a specific error code can be
 *      retrieved by calling hive_get_error().
 */
HIVE_API
HiveClient *hive_client_new(const HiveOptions *options);

/**
 * \~English
 * Destroy all associated resources with the Hive client instance.
 *
 * After calling the function, the client pointer becomes invalid.
 * No other functions should be called.
 *
 * @param
 *      client      [in] A handle identifying the Hive client instance.
 */
HIVE_API
int hive_client_close(HiveClient *client);

HIVE_API
int hive_client_login(HiveClient *client);

HIVE_API
int hive_client_logout(HiveClient *client);

HIVE_API
int hive_client_get_info(HiveClient *client, char **result);

HIVE_API
HiveDrive *hive_drive_open(HiveClient *client);

HIVE_API
int hive_drive_close(HiveDrive *client);

HIVE_API
int hive_drive_get_info(HiveDrive *, char **result);

HIVE_API
int hive_drive_file_stat(HiveDrive *, const char *file_path, char **result);

HIVE_API
int hive_drive_list_files(HiveDrive *, const char *dir_path, char **result);

HIVE_API
int hive_drive_mkdir(HiveDrive *, const char *path);

HIVE_API
int hive_drive_move_file(HiveDrive *, const char *old, const char *new);

HIVE_API
int hive_drive_copy_file(HiveDrive *, const char *src_path, const char *dest_path);

HIVE_API
int hive_drive_delete_file(HiveDrive *, const char *path);

HIVE_API
HiveFile *hive_file_open(HiveDrive *drive, const char *path, HiveFileOpenFlags flags);

HIVE_API
int hive_file_close(HiveFile *file);

HIVE_API
char *hive_file_get_path(HiveFile *file, char *buf, size_t bufsz);

HIVE_API
ssize_t hive_file_lseek(HiveFile *, size_t offset, HiveFileSeekWhence whence);

HIVE_API
ssize_t hive_file_read(HiveFile *, char *buf, size_t bufsz);

HIVE_API
ssize_t hive_file_write(HiveFile *file, const char *buf, size_t bufsz);

#ifdef __cplusplus
} // extern "C"
#endif

#if defined(__APPLE__)
#pragma GCC diagnostic pop
#endif

#endif // __ELASTOS_HIVE_H__