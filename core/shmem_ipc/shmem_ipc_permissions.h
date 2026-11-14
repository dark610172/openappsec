#ifndef SHMEM_IPC_PERMISSIONS_H
#define SHMEM_IPC_PERMISSIONS_H

#ifdef __cplusplus
extern "C" {
#endif

// Internal permission helpers, shared with the unit tests.
int shmemIpcIsIdentityMap(const char *text);
int shmemIpcCompatPermissionsEnabled(void);

#ifdef __cplusplus
}
#endif

#endif // SHMEM_IPC_PERMISSIONS_H
