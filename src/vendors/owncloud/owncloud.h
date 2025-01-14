#ifndef __OWNCLOUD_CLIENT_H__
#define __OWNCLOUD_CLIENT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "client.h"

HiveClient *owncloud_client_new(const HiveOptions *);

#ifdef __cplusplus
}
#endif

#endif // __OWNCLOUD_CLIENT_H__
