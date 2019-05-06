#ifndef __HIVE_CLIENT_H__
#define __HIVE_CLIENT_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct HiveClient HiveClient;

typedef struct HiveDrive HiveDrive;

enum HiveDriveType {
    HiveDriveType_Local     = 0x0,
    HiveDriveType_OneDrive  = 0x01,

    HiveDriveType_ownCloud  = 0x51,

    HiveDriveType_HiveIPFS  = 0x98,
    HiveDriveType_Butt      = 0x99
};


typedef struct HiveOptions {
    char *perisisten_location;
    int  drive_type;
} HiveOptions;

typedef struct OneDriveOptions {
    HiveOptions base;

    const char *client_id;
    const char *scope;
    const char *redirect_url;

    int (*grant_authorize)(const char *request_url);
} OneDriveOptions;

/*
 * Create a hive client instance.
 */
HiveClient *hive_client_new(const HiveOptions *options);

/*
 * Close a hive client instance.
 */
int hive_client_close(HiveClient *client);

/*
 * Login via OAuth2.
 */
int hive_client_login(HiveClient *client);

/*
 *
 */
HiveDrive *hive_drive_new(HiveClient *client);

int hive_drive_close(HiveDrive *drive);


HIVE_API
int hivefs_stat(hive_t *hive, const char *path, char **result);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __HIVE_CLIENT_H__

