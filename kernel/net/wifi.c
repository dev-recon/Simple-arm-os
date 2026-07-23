/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/net/wifi.c
 * Layer: Kernel / common wireless networking
 *
 * Responsibilities:
 * - Parse the persistent ArmOS Wi-Fi profile format.
 * - Resolve the default profile selected by /etc/wifi.conf.
 * - Invoke optional wireless operations through the common net_device ABI.
 * - Reset common IPv4 state when a radio disconnects or reassociates.
 *
 * Notes:
 * - Profile parsing belongs here rather than in CYW43 or another radio driver.
 * - Passwords are never returned through /dev/netctl diagnostics.
 */

#include <kernel/net/stack.h>
#include <kernel/net/wifi.h>
#include <kernel/string.h>
#include <kernel/vfs.h>

#define NET_WIFI_CONFIG_MAX 768u
#define NET_WIFI_PROFILE_SUFFIX ".conf"

typedef struct net_wifi_parsed_config {
    net_wifi_profile_t profile;
    char default_profile[NET_WIFI_PROFILE_NAME_MAX + 1u];
    bool have_country;
    bool have_ssid;
} net_wifi_parsed_config_t;

static char *net_wifi_trim(char *text)
{
    char *end;

    while (*text && isspace((unsigned char)*text))
        text++;
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return text;
}

static int net_wifi_copy(char *destination, uint32_t capacity,
                         const char *value)
{
    uint32_t length;

    if (!destination || !value || capacity == 0u)
        return -EINVAL;
    length = (uint32_t)strlen(value);
    if (length >= capacity)
        return -EFBIG;
    memcpy(destination, value, length + 1u);
    return 0;
}

static bool net_wifi_valid_profile_name(const char *name)
{
    const char *start = name;
    uint32_t length = 0u;

    if (!name || *name == '\0')
        return false;
    while (*name) {
        unsigned char ch = (unsigned char)*name++;

        if (!(isalnum(ch) || ch == '-' || ch == '_' || ch == '.'))
            return false;
        if (++length > NET_WIFI_PROFILE_NAME_MAX)
            return false;
    }
    return strcmp(start, ".") != 0 && strcmp(start, "..") != 0;
}

static bool net_wifi_valid_country(const char country[3])
{
    if (!country || country[0] == '\0' || country[1] == '\0' ||
        country[2] != '\0')
        return false;
    if (country[0] == '0' && country[1] == '0')
        return true;
    return isalpha((unsigned char)country[0]) &&
           isalpha((unsigned char)country[1]);
}

static int net_wifi_read_config(const char *path, char *buffer,
                                uint32_t capacity)
{
    kernel_file_t file;
    uint32_t size;
    ssize_t got;
    int ret;

    if (!path || !buffer || capacity < 2u)
        return -EINVAL;
    ret = vfs_kernel_file_open(path, &file);
    if (ret < 0)
        return ret;
    size = vfs_kernel_file_size(&file);
    if (size == 0u || size >= capacity) {
        vfs_kernel_file_close(&file);
        return -EFBIG;
    }
    got = vfs_kernel_file_read(&file, buffer, size);
    vfs_kernel_file_close(&file);
    if (got < 0)
        return (int)got;
    if ((uint32_t)got != size)
        return -EIO;
    buffer[size] = '\0';
    return 0;
}

static int net_wifi_parse_config(char *buffer,
                                 net_wifi_parsed_config_t *parsed)
{
    char *line;

    if (!buffer || !parsed)
        return -EINVAL;
    memset(parsed, 0, sizeof(*parsed));
    parsed->profile.country[0] = '0';
    parsed->profile.country[1] = '0';
    parsed->profile.security = NET_WIFI_SECURITY_WPA2;

    line = buffer;
    while (*line) {
        char *next = strchr(line, '\n');
        char *separator;
        char *key;
        char *value;
        int ret;

        if (next)
            *next++ = '\0';
        key = net_wifi_trim(line);
        if (*key != '\0' && *key != '#') {
            separator = strchr(key, '=');
            if (!separator)
                return -EINVAL;
            *separator++ = '\0';
            key = net_wifi_trim(key);
            value = net_wifi_trim(separator);
            if (strcmp(key, "default") == 0) {
                if (!net_wifi_valid_profile_name(value))
                    return -EINVAL;
                ret = net_wifi_copy(parsed->default_profile,
                                    sizeof(parsed->default_profile), value);
            } else if (strcmp(key, "country") == 0) {
                if (strlen(value) != NET_WIFI_COUNTRY_SIZE)
                    return -EINVAL;
                parsed->profile.country[0] =
                    (char)toupper((unsigned char)value[0]);
                parsed->profile.country[1] =
                    (char)toupper((unsigned char)value[1]);
                if (!net_wifi_valid_country(parsed->profile.country))
                    return -EINVAL;
                parsed->have_country = true;
                ret = 0;
            } else if (strcmp(key, "ssid") == 0) {
                ret = net_wifi_copy(parsed->profile.ssid,
                                    sizeof(parsed->profile.ssid), value);
                parsed->have_ssid = ret == 0;
            } else if (strcmp(key, "password") == 0) {
                ret = net_wifi_copy(parsed->profile.password,
                                    sizeof(parsed->profile.password), value);
            } else if (strcmp(key, "security") == 0) {
                if (strcmp(value, "open") == 0)
                    parsed->profile.security = NET_WIFI_SECURITY_OPEN;
                else if (strcmp(value, "wpa2") == 0)
                    parsed->profile.security = NET_WIFI_SECURITY_WPA2;
                else
                    return -EINVAL;
                ret = 0;
            } else {
                return -EINVAL;
            }
            if (ret < 0)
                return ret;
        }
        if (!next)
            break;
        line = next;
    }
    return 0;
}

static int net_wifi_validate_profile(const net_wifi_profile_t *profile)
{
    uint32_t password_length;

    if (!profile || profile->ssid[0] == '\0')
        return -EINVAL;
    if (strlen(profile->ssid) > NET_WIFI_SSID_MAX)
        return -EFBIG;
    if (profile->security == NET_WIFI_SECURITY_OPEN)
        return 0;
    password_length = (uint32_t)strlen(profile->password);
    if (password_length < 8u || password_length > NET_WIFI_PASSWORD_MAX)
        return -EINVAL;
    return 0;
}

int net_wifi_country_load(const char *path, char country[3])
{
    net_wifi_parsed_config_t parsed;
    char buffer[NET_WIFI_CONFIG_MAX + 1u];
    int ret;

    if (!path || !country)
        return -EINVAL;
    ret = net_wifi_read_config(path, buffer, sizeof(buffer));
    if (ret < 0)
        return ret;
    ret = net_wifi_parse_config(buffer, &parsed);
    if (ret < 0)
        return ret;
    if (!parsed.have_country)
        return -ENOENT;
    country[0] = parsed.profile.country[0];
    country[1] = parsed.profile.country[1];
    country[2] = '\0';
    return 0;
}

static void net_wifi_inherit_global_country(const char *path,
                                            net_wifi_profile_t *profile)
{
    char country[NET_WIFI_COUNTRY_SIZE + 1u];

    if (!profile || strcmp(profile->country, "00") != 0 ||
        strcmp(path, NET_WIFI_DEFAULT_CONFIG) == 0)
        return;
    if (net_wifi_country_load(NET_WIFI_DEFAULT_CONFIG, country) == 0) {
        profile->country[0] = country[0];
        profile->country[1] = country[1];
    }
}

int net_wifi_profile_load(const char *path, net_wifi_profile_t *profile,
                          char *resolved_path, uint32_t resolved_capacity)
{
    net_wifi_parsed_config_t parsed;
    net_wifi_parsed_config_t selected;
    char buffer[NET_WIFI_CONFIG_MAX + 1u];
    char profile_buffer[NET_WIFI_CONFIG_MAX + 1u];
    char selected_path[NET_WIFI_PROFILE_PATH_MAX];
    int ret;

    if (!path || !profile)
        return -EINVAL;
    ret = net_wifi_read_config(path, buffer, sizeof(buffer));
    if (ret < 0)
        return ret;
    ret = net_wifi_parse_config(buffer, &parsed);
    if (ret < 0)
        return ret;

    if (parsed.default_profile[0] != '\0') {
        ret = snprintf(selected_path, sizeof(selected_path), "%s/%s.conf",
                       NET_WIFI_PROFILE_DIRECTORY, parsed.default_profile);
        if (ret < 0 || (uint32_t)ret >= sizeof(selected_path))
            return -ENAMETOOLONG;
        ret = net_wifi_read_config(selected_path, profile_buffer,
                                   sizeof(profile_buffer));
        if (ret < 0)
            return ret;
        ret = net_wifi_parse_config(profile_buffer, &selected);
        if (ret < 0 || selected.default_profile[0] != '\0')
            return ret < 0 ? ret : -EINVAL;
        if (!selected.have_country && parsed.have_country) {
            selected.profile.country[0] = parsed.profile.country[0];
            selected.profile.country[1] = parsed.profile.country[1];
        }
        *profile = selected.profile;
    } else {
        *profile = parsed.profile;
        ret = net_wifi_copy(selected_path, sizeof(selected_path), path);
        if (ret < 0)
            return ret;
    }

    net_wifi_inherit_global_country(path, profile);
    ret = net_wifi_validate_profile(profile);
    if (ret < 0)
        return ret;
    if (resolved_path && resolved_capacity != 0u)
        return net_wifi_copy(resolved_path, resolved_capacity, selected_path);
    return 0;
}

bool net_wifi_supported(const net_device_t *device)
{
    return device && device->ops && device->ops->wifi_connect &&
           device->ops->wifi_disconnect;
}

int net_wifi_set_country(net_device_t *device, const char country[3])
{
    char normalized[NET_WIFI_COUNTRY_SIZE + 1u];
    uint32_t index;

    if (!net_wifi_supported(device) || !device->ops->wifi_set_country)
        return -ENOTSUP;
    if (!country || country[0] == '\0' || country[1] == '\0' ||
        country[2] != '\0')
        return -EINVAL;
    for (index = 0u; index < NET_WIFI_COUNTRY_SIZE; index++) {
        char value = country[index];

        if (value >= 'a' && value <= 'z')
            value = (char)(value - 'a' + 'A');
        if (value < 'A' || value > 'Z')
            return -EINVAL;
        normalized[index] = value;
    }
    normalized[NET_WIFI_COUNTRY_SIZE] = '\0';
    return device->ops->wifi_set_country(device, normalized);
}

int net_wifi_scan(net_device_t *device, net_wifi_scan_result_t *results,
                  uint32_t capacity, uint32_t *count)
{
    if (!net_wifi_supported(device) || !device->ops->wifi_scan ||
        !results || !count || capacity == 0u)
        return -ENOTSUP;
    return device->ops->wifi_scan(device, results, capacity, count);
}

int net_wifi_connect_profile(net_device_t *device, const char *path,
                             char *resolved_path, uint32_t resolved_capacity)
{
    net_wifi_profile_t profile;
    int ret;

    if (!net_wifi_supported(device))
        return -ENOTSUP;
    ret = net_wifi_profile_load(path, &profile, resolved_path,
                                resolved_capacity);
    if (ret < 0)
        return ret;
    ret = device->ops->wifi_connect(device, &profile);
    if (ret < 0) {
        (void)net_stack_interface_down(device);
        return ret;
    }
    return net_stack_restart_dhcp(device);
}

static bool net_wifi_scan_contains(const net_wifi_scan_result_t *results,
                                   uint32_t count, const char *ssid)
{
    uint32_t index;

    for (index = 0u; index < count; index++) {
        if (strcmp(results[index].ssid, ssid) == 0)
            return true;
    }
    return false;
}

static int net_wifi_connect_visible(net_device_t *device, const char *path,
                                    const net_wifi_scan_result_t *results,
                                    uint32_t count, char *ssid,
                                    uint32_t ssid_capacity)
{
    net_wifi_profile_t profile;
    int ret;

    ret = net_wifi_profile_load(path, &profile, NULL, 0u);
    if (ret < 0)
        return ret;
    if (!net_wifi_scan_contains(results, count, profile.ssid))
        return -ENETUNREACH;
    ret = device->ops->wifi_connect(device, &profile);
    if (ret < 0) {
        (void)net_stack_interface_down(device);
        return ret;
    }
    ret = net_stack_restart_dhcp(device);
    if (ret < 0)
        return ret;
    if (ssid && ssid_capacity != 0u)
        return net_wifi_copy(ssid, ssid_capacity, profile.ssid);
    return 0;
}

int net_wifi_autoconnect(net_device_t *device, const char *default_path,
                         char *ssid, uint32_t ssid_capacity)
{
    net_wifi_scan_result_t results[NET_WIFI_SCAN_MAX];
    kernel_file_t directory;
    dirent_t entry;
    char preferred_path[NET_WIFI_PROFILE_PATH_MAX];
    char profile_path[NET_WIFI_PROFILE_PATH_MAX];
    uint32_t count = 0u;
    bool preferred_valid = false;
    bool found_visible = false;
    int last_error = -ENOENT;
    int ret;

    if (!net_wifi_supported(device))
        return -ENOTSUP;
    if (ssid && ssid_capacity != 0u)
        ssid[0] = '\0';

    ret = net_wifi_scan(device, results, NET_WIFI_SCAN_MAX, &count);
    if (ret < 0)
        return ret;

    if (default_path) {
        net_wifi_profile_t preferred;

        ret = net_wifi_profile_load(default_path, &preferred, preferred_path,
                                    sizeof(preferred_path));
        if (ret == 0) {
            preferred_valid = true;
            if (net_wifi_scan_contains(results, count, preferred.ssid)) {
                found_visible = true;
                ret = net_wifi_connect_visible(device, default_path, results,
                                               count, ssid, ssid_capacity);
                if (ret == 0)
                    return 0;
                last_error = ret;
            }
        }
    }

    ret = vfs_kernel_dir_open(NET_WIFI_PROFILE_DIRECTORY, &directory);
    if (ret < 0)
        return found_visible ? last_error : -ENOENT;
    while ((ret = vfs_kernel_dir_read(&directory, &entry)) > 0) {
        uint32_t name_length = (uint32_t)strlen(entry.d_name);
        int written;

        if (entry.d_type != DT_REG ||
            name_length <= strlen(NET_WIFI_PROFILE_SUFFIX) ||
            strcmp(entry.d_name + name_length -
                   strlen(NET_WIFI_PROFILE_SUFFIX),
                   NET_WIFI_PROFILE_SUFFIX) != 0)
            continue;
        written = snprintf(profile_path, sizeof(profile_path), "%s/%s",
                           NET_WIFI_PROFILE_DIRECTORY, entry.d_name);
        if (written < 0 || (uint32_t)written >= sizeof(profile_path))
            continue;
        if (preferred_valid && strcmp(profile_path, preferred_path) == 0)
            continue;
        {
            net_wifi_profile_t profile;

            if (net_wifi_profile_load(profile_path, &profile, NULL, 0u) < 0 ||
                !net_wifi_scan_contains(results, count, profile.ssid))
                continue;
        }
        found_visible = true;
        last_error = net_wifi_connect_visible(device, profile_path, results,
                                              count, ssid, ssid_capacity);
        if (last_error == 0) {
            vfs_kernel_file_close(&directory);
            return 0;
        }
    }
    vfs_kernel_file_close(&directory);
    if (ret < 0)
        return ret;
    return found_visible ? last_error : -ENOENT;
}

int net_wifi_disconnect(net_device_t *device)
{
    int ret;

    if (!net_wifi_supported(device))
        return -ENOTSUP;
    ret = device->ops->wifi_disconnect(device);
    (void)net_stack_interface_down(device);
    return ret;
}
