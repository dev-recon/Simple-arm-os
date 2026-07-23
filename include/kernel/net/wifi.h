/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/net/wifi.h
 * Layer: Kernel / common wireless networking
 *
 * Responsibilities:
 * - Define architecture-neutral Wi-Fi profiles and scan results.
 * - Load persistent profiles without exposing VFS policy to radio drivers.
 * - Coordinate hot association, disconnection and DHCP reconfiguration.
 *
 * Notes:
 * - Hardware drivers implement optional net_device Wi-Fi operations.
 * - /etc/wifi.conf may contain credentials directly for compatibility or a
 *   default=<profile> entry referring to /etc/wifi.d/<profile>.conf.
 */

#ifndef KERNEL_NET_WIFI_H
#define KERNEL_NET_WIFI_H

#include <kernel/net/device.h>

#define NET_WIFI_COUNTRY_SIZE       2u
#define NET_WIFI_SSID_MAX           32u
#define NET_WIFI_PASSWORD_MAX       64u
#define NET_WIFI_PROFILE_NAME_MAX   48u
#define NET_WIFI_PROFILE_PATH_MAX   96u
#define NET_WIFI_SCAN_MAX           24u

#define NET_WIFI_DEFAULT_CONFIG     "/etc/wifi.conf"
#define NET_WIFI_PROFILE_DIRECTORY  "/etc/wifi.d"

typedef enum net_wifi_security {
    NET_WIFI_SECURITY_OPEN = 0,
    NET_WIFI_SECURITY_WPA2,
} net_wifi_security_t;

typedef struct net_wifi_profile {
    char country[NET_WIFI_COUNTRY_SIZE + 1u];
    char ssid[NET_WIFI_SSID_MAX + 1u];
    char password[NET_WIFI_PASSWORD_MAX + 1u];
    net_wifi_security_t security;
} net_wifi_profile_t;

typedef struct net_wifi_scan_result {
    char ssid[NET_WIFI_SSID_MAX + 1u];
    uint8_t bssid[NET_DEVICE_MAC_SIZE];
    int16_t signal_dbm;
    uint16_t channel;
    net_wifi_security_t security;
} net_wifi_scan_result_t;

int net_wifi_profile_load(const char *path, net_wifi_profile_t *profile,
                          char *resolved_path, uint32_t resolved_capacity);
int net_wifi_country_load(const char *path,
                          char country[NET_WIFI_COUNTRY_SIZE + 1u]);
int net_wifi_set_country(net_device_t *device,
                         const char country[NET_WIFI_COUNTRY_SIZE + 1u]);
int net_wifi_scan(net_device_t *device, net_wifi_scan_result_t *results,
                  uint32_t capacity, uint32_t *count);
int net_wifi_connect_profile(net_device_t *device, const char *path,
                             char *resolved_path, uint32_t resolved_capacity);
int net_wifi_autoconnect(net_device_t *device, const char *default_path,
                         char *ssid, uint32_t ssid_capacity);
int net_wifi_disconnect(net_device_t *device);
bool net_wifi_supported(const net_device_t *device);

#endif /* KERNEL_NET_WIFI_H */
