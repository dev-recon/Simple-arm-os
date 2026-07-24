/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/net/control.c
 * Layer: Kernel / network control device
 *
 * Responsibilities:
 * - Present interface state through /dev/netctl reads.
 * - Execute bounded ICMP echo requests requested by userland utilities.
 * - Control optional Wi-Fi devices without exposing driver-specific ioctls.
 * - Keep command presentation separate from NIC and protocol internals.
 *
 * Notes:
 * - Commands use a textual ABI so early userland does not depend on native
 *   structure alignment. A socket ABI can supersede this compatibility shim.
 */

#include <kernel/memory.h>
#include <kernel/net/control.h>
#include <kernel/net/device.h>
#include <kernel/net/stack.h>
#include <kernel/net/wifi.h>
#include <kernel/string.h>
#include <kernel/task.h>
#include <kernel/timer.h>

#define NET_CONTROL_BUFFER_SIZE 4096u

typedef struct net_control_file {
    char response[NET_CONTROL_BUFFER_SIZE];
    uint32_t length;
} net_control_file_t;

extern file_t *create_file(void);
extern inode_t *create_inode(void);

static uint32_t net_control_parse_u32(const char *text, uint32_t fallback)
{
    uint32_t value = 0u;

    if (!text || *text == '\0')
        return fallback;
    while (*text != '\0') {
        if (*text < '0' || *text > '9')
            return fallback;
        value = value * 10u + (uint32_t)(*text - '0');
        text++;
    }
    return value;
}

static int net_control_show(net_control_file_t *control, const char *name)
{
    int length = net_stack_format_interfaces(control->response,
                                             sizeof(control->response), name);

    if (length < 0) {
        control->length = (uint32_t)snprintf(control->response,
                                            sizeof(control->response),
                                            "error %d\n", length);
        return length;
    }
    control->length = (uint32_t)length;
    return 0;
}

static net_device_t *net_control_device(const char *name)
{
    if (name && *name)
        return net_device_find(name);
    return net_device_get_default();
}

static void net_control_error(net_control_file_t *control, int error)
{
    control->length = (uint32_t)snprintf(control->response,
        sizeof(control->response), "error %d\n", error);
}

static int net_control_wifi_scan(net_control_file_t *control,
                                 net_device_t *device)
{
    net_wifi_scan_result_t results[NET_WIFI_SCAN_MAX];
    uint32_t count = 0u;
    uint32_t index;
    uint32_t length;
    int ret;

    ret = net_wifi_scan(device, results, NET_WIFI_SCAN_MAX, &count);
    if (ret < 0) {
        net_control_error(control, ret);
        return ret;
    }
    length = (uint32_t)snprintf(control->response,
        sizeof(control->response),
        "SSID                             SECURITY SIGNAL CHANNEL BSSID\n");
    for (index = 0u; index < count; index++) {
        net_wifi_scan_result_t *result = &results[index];
        int written;

        written = snprintf(control->response + length,
            sizeof(control->response) - length,
            "%-32s %-8s %6d %7u %02X:%02X:%02X:%02X:%02X:%02X\n",
            result->ssid[0] ? result->ssid : "<hidden>",
            result->security == NET_WIFI_SECURITY_OPEN ? "open" : "secured",
            result->signal_dbm, result->channel,
            result->bssid[0], result->bssid[1], result->bssid[2],
            result->bssid[3], result->bssid[4], result->bssid[5]);
        if (written < 0 ||
            (uint32_t)written >= sizeof(control->response) - length) {
            net_control_error(control, -ENOSPC);
            return -ENOSPC;
        }
        length += (uint32_t)written;
    }
    control->length = length;
    return 0;
}

static int net_control_wifi(net_control_file_t *control, const char *action,
                            const char *interface, const char *argument)
{
    net_device_t *device = net_control_device(interface);
    char resolved[NET_WIFI_PROFILE_PATH_MAX];
    int ret;

    if (!action || !device || !net_wifi_supported(device)) {
        net_control_error(control, !device ? -ENODEV : -ENOTSUP);
        return !device ? -ENODEV : -ENOTSUP;
    }
    if (strcmp(action, "status") == 0)
        return net_control_show(control, device->name);
    if (strcmp(action, "scan") == 0)
        return net_control_wifi_scan(control, device);
    if (current_uid() != 0u) {
        net_control_error(control, -EPERM);
        return -EPERM;
    }
    if (strcmp(action, "country") == 0) {
        if (!argument) {
            net_control_error(control, -EINVAL);
            return -EINVAL;
        }
        ret = net_wifi_set_country(device, argument);
        if (ret == 0) {
            control->length = (uint32_t)snprintf(control->response,
                sizeof(control->response), "%s country %s active\n",
                device->name, argument);
            return 0;
        }
    } else if (strcmp(action, "disconnect") == 0) {
        ret = net_wifi_disconnect(device);
        if (ret == 0) {
            control->length = (uint32_t)snprintf(control->response,
                sizeof(control->response), "%s disconnected\n",
                device->name);
            return 0;
        }
    } else if (strcmp(action, "reload") == 0 ||
               strcmp(action, "connect") == 0) {
        const char *path = strcmp(action, "reload") == 0 ?
            NET_WIFI_DEFAULT_CONFIG : argument;

        if (!path) {
            net_control_error(control, -EINVAL);
            return -EINVAL;
        }
        ret = net_wifi_connect_profile(device, path, resolved,
                                       sizeof(resolved));
        if (ret == 0) {
            control->length = (uint32_t)snprintf(control->response,
                sizeof(control->response),
                "%s associated using %s; DHCP started\n",
                device->name, resolved);
            return 0;
        }
    } else {
        ret = -EINVAL;
    }
    net_control_error(control, ret);
    return ret;
}

static ssize_t net_control_read(file_t *file, void *buffer, size_t count)
{
    net_control_file_t *control;
    uint32_t remaining;

    if (!file || !buffer)
        return -EINVAL;
    control = file->private_data;
    if (!control)
        return -EINVAL;
    if (file->offset >= control->length)
        return 0;
    remaining = control->length - file->offset;
    if (count > remaining)
        count = remaining;
    memcpy(buffer, control->response + file->offset, count);
    file->offset += count;
    return (ssize_t)count;
}

static ssize_t net_control_write(file_t *file, const void *buffer,
                                 size_t count)
{
    net_control_file_t *control;
    char command[256];
    char *save = NULL;
    char *verb;
    char *first;
    char *second;
    char *third;
    char *fourth;
    net_device_t *device;
    uint32_t address;
    uint32_t sequence = 1u;
    uint32_t timeout_ms = 1000u;
    net_ping_result_t result;
    int ret;

    if (!file || !buffer || count == 0u)
        return -EINVAL;
    control = file->private_data;
    if (!control)
        return -EINVAL;
    if (count >= sizeof(command))
        return -E2BIG;
    memcpy(command, buffer, count);
    command[count] = '\0';
    verb = strtok_r(command, " \t\r\n", &save);
    first = strtok_r(NULL, " \t\r\n", &save);
    second = strtok_r(NULL, " \t\r\n", &save);
    third = strtok_r(NULL, " \t\r\n", &save);
    fourth = strtok_r(NULL, " \t\r\n", &save);
    file->offset = 0u;

    if (verb && strcmp(verb, "show") == 0) {
        (void)net_control_show(control, first);
        return (ssize_t)count;
    }
    if (verb && strcmp(verb, "wifi") == 0) {
        (void)net_control_wifi(control, first, second, third);
        return (ssize_t)count;
    }
    if (!verb || strcmp(verb, "ping") != 0 || !first) {
        control->length = (uint32_t)snprintf(control->response,
            sizeof(control->response), "error invalid command\n");
        return (ssize_t)count;
    }

    device = net_device_get_default();
    if (second && net_device_find(first)) {
        device = net_device_find(first);
        first = second;
        second = third;
        third = fourth;
    }
    if (!device || net_stack_parse_ipv4(first, &address) < 0) {
        control->length = (uint32_t)snprintf(control->response,
            sizeof(control->response), "error invalid address or interface\n");
        return (ssize_t)count;
    }
    if (second)
        sequence = net_control_parse_u32(second, sequence);
    if (third)
        timeout_ms = net_control_parse_u32(third, timeout_ms);
    if (timeout_ms == 0u || timeout_ms > 30000u)
        timeout_ms = 1000u;

    ret = net_stack_ping(device, address, sequence, timeout_ms, &result);
    if (ret == 0 && result.received) {
        char text[20];

        net_stack_format_ipv4(result.address, text, sizeof(text));
        control->length = (uint32_t)snprintf(control->response,
            sizeof(control->response),
            "64 bytes from %s: icmp_seq=%u ttl=%u time=%u ms\n",
            text, result.sequence, result.ttl, result.elapsed_ms);
    } else if (ret == -ETIMEDOUT) {
        control->length = (uint32_t)snprintf(control->response,
            sizeof(control->response),
            "timeout icmp_seq=%u\n", sequence);
    } else {
        control->length = (uint32_t)snprintf(control->response,
            sizeof(control->response), "error %d\n", ret);
    }
    return (ssize_t)count;
}

static int net_control_close(file_t *file)
{
    if (file && file->private_data) {
        kfree(file->private_data);
        file->private_data = NULL;
    }
    return 0;
}

static off_t net_control_lseek(file_t *file, off_t offset, int whence)
{
    net_control_file_t *control;
    off_t position;

    if (!file || !file->private_data)
        return -EINVAL;
    control = file->private_data;
    if (whence == 0)
        position = offset;
    else if (whence == 1)
        position = (off_t)file->offset + offset;
    else if (whence == 2)
        position = (off_t)control->length + offset;
    else
        return -EINVAL;
    if (position < 0 || (uint32_t)position > control->length)
        return -EINVAL;
    file->offset = (uint32_t)position;
    return position;
}

static file_operations_t net_control_file_ops = {
    .read = net_control_read,
    .write = net_control_write,
    .open = NULL,
    .close = net_control_close,
    .lseek = net_control_lseek,
    .readdir = NULL,
    .truncate = NULL,
};

bool is_net_control_device_path(const char *path)
{
    return path && strcmp(path, "/dev/netctl") == 0;
}

void fill_net_control_device_stat(struct stat *st)
{
    uint32_t now;

    if (!st)
        return;
    now = get_current_time();
    memset(st, 0, sizeof(*st));
    st->st_ino = DEV_NETCTL_RDEV;
    st->st_mode = S_IFCHR | 0666;
    st->st_nlink = 1u;
    st->st_rdev = DEV_NETCTL_RDEV;
    st->st_blksize = 1024u;
    st->st_atime = now;
    st->st_mtime = now;
    st->st_ctime = now;
}

file_t *create_net_control_device_file(const char *name, int flags)
{
    file_t *file;
    inode_t *inode;
    net_control_file_t *control;
    uint32_t now;

    if (net_device_count() == 0u)
        return NULL;
    file = create_file();
    inode = create_inode();
    control = kmalloc(sizeof(*control));
    if (!file || !inode || !control) {
        if (file)
            kfree(file);
        if (inode)
            kfree(inode);
        if (control)
            kfree(control);
        return NULL;
    }
    memset(control, 0, sizeof(*control));
    (void)net_control_show(control, NULL);
    now = get_current_time();
    inode->mode = S_IFCHR | 0666;
    inode->uid = 0u;
    inode->gid = 0u;
    inode->nlink = 1u;
    inode->parent_cluster = DEV_NETCTL_RDEV;
    inode->atime = now;
    inode->mtime = now;
    inode->ctime = now;
    inode->f_op = &net_control_file_ops;
    file->f_op = &net_control_file_ops;
    file->flags = flags;
    file->type = FILE_TYPE_NETCTL;
    file->inode = inode;
    file->private_data = control;
    if (name) {
        strncpy(file->name, name, sizeof(file->name) - 1u);
        file->name[sizeof(file->name) - 1u] = '\0';
    }
    return file;
}
