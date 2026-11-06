#ifndef AMNEZIA_WARP_TRANSPORT_H
#define AMNEZIA_WARP_TRANSPORT_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef bool (*amnezia_warp_protect)(int32_t socket, void *context);

int32_t amneziaWarpStart(char *underlay, char *protocol, char *configuration, amnezia_warp_protect protect,
                         void *context);
char *amneziaWarpConfiguration(int32_t handle);
int32_t amneziaWarpState(int32_t handle);
int32_t amneziaWarpRebind(int32_t handle);
void amneziaWarpStop(int32_t handle);
void amneziaWarpFree(char *value);

#ifdef __cplusplus
}
#endif

#endif
