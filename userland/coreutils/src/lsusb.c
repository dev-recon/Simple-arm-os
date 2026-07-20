/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: userland/coreutils/src/lsusb.c
 * Layer: Userland / system utilities
 *
 * Responsibilities:
 * - List USB devices published by the architecture-neutral kernel USB core.
 * - Present compact, detailed, and topology-oriented views.
 * - Keep controller-specific diagnostics out of user-facing output.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LSUSB_MAX_DEVICES 32
#define LSUSB_PROC_SIZE   16384
#define LSUSB_FIELD_COUNT 21

typedef struct usb_entry {
    unsigned bus;
    unsigned address;
    unsigned parent;
    unsigned port;
    unsigned max_packet;
    unsigned device_class;
    unsigned subclass;
    unsigned protocol;
    unsigned usb_version;
    unsigned vendor;
    unsigned product_id;
    unsigned device_version;
    unsigned configurations;
    unsigned interfaces;
    unsigned ports;
    unsigned keyboards;
    unsigned mice;
    char speed[12];
    char manufacturer[64];
    char product[96];
    char serial[64];
} usb_entry_t;

static char proc_data[LSUSB_PROC_SIZE];
static usb_entry_t devices[LSUSB_MAX_DEVICES];

static void usage(void)
{
    printf("usage: lsusb [-t|-v]\n"
           "  -t  show the USB topology tree\n"
           "  -v  show device descriptor details\n");
}

static unsigned parse_number(const char *text, int base)
{
    if (!text || !*text)
        return 0;
    return (unsigned)strtoul(text, NULL, base);
}

static int split_fields(char *line, char **fields, int capacity)
{
    int count = 0;
    char *field = line;

    if (!line || capacity <= 0)
        return 0;

    for (char *p = line;; p++) {
        if (*p == '|' || *p == '\0') {
            if (count < capacity)
                fields[count++] = field;
            if (*p == '\0')
                break;
            *p = '\0';
            field = p + 1;
        }
    }
    return count;
}

static int read_topology(void)
{
    char *line;
    char *save;
    ssize_t total = 0;
    int fd;
    int count = 0;

    fd = open("/proc/usb", O_RDONLY, 0);
    if (fd < 0) {
        fprintf(stderr, "lsusb: cannot open /proc/usb: %s\n",
                strerror(errno));
        return -1;
    }

    while ((size_t)total + 1u < sizeof(proc_data)) {
        ssize_t got = read(fd, proc_data + total,
                           sizeof(proc_data) - (size_t)total - 1u);
        if (got < 0) {
            fprintf(stderr, "lsusb: cannot read /proc/usb: %s\n",
                    strerror(errno));
            close(fd);
            return -1;
        }
        if (got == 0)
            break;
        total += got;
    }
    close(fd);
    proc_data[total] = '\0';

    line = strtok_r(proc_data, "\n", &save);
    while ((line = strtok_r(NULL, "\n", &save)) != NULL &&
           count < LSUSB_MAX_DEVICES) {
        char *fields[LSUSB_FIELD_COUNT];
        usb_entry_t *dev = &devices[count];

        if (split_fields(line, fields, LSUSB_FIELD_COUNT) !=
            LSUSB_FIELD_COUNT)
            continue;

        memset(dev, 0, sizeof(*dev));
        dev->bus = parse_number(fields[0], 10);
        dev->address = parse_number(fields[1], 10);
        dev->parent = parse_number(fields[2], 10);
        dev->port = parse_number(fields[3], 10);
        snprintf(dev->speed, sizeof(dev->speed), "%s", fields[4]);
        dev->max_packet = parse_number(fields[5], 10);
        dev->device_class = parse_number(fields[6], 16);
        dev->subclass = parse_number(fields[7], 16);
        dev->protocol = parse_number(fields[8], 16);
        dev->usb_version = parse_number(fields[9], 16);
        dev->vendor = parse_number(fields[10], 16);
        dev->product_id = parse_number(fields[11], 16);
        dev->device_version = parse_number(fields[12], 16);
        dev->configurations = parse_number(fields[13], 10);
        dev->interfaces = parse_number(fields[14], 10);
        dev->ports = parse_number(fields[15], 10);
        dev->keyboards = parse_number(fields[16], 10);
        dev->mice = parse_number(fields[17], 10);
        snprintf(dev->manufacturer, sizeof(dev->manufacturer), "%s",
                 fields[18]);
        snprintf(dev->product, sizeof(dev->product), "%s", fields[19]);
        snprintf(dev->serial, sizeof(dev->serial), "%s", fields[20]);
        count++;
    }
    return count;
}

static const char *class_name(const usb_entry_t *dev)
{
    if (dev->device_class == 0x09u)
        return "Hub";
    if (dev->device_class == 0x03u || dev->keyboards || dev->mice)
        return "Human Interface Device";
    switch (dev->device_class) {
    case 0x00u: return "Defined at Interface";
    case 0x01u: return "Audio";
    case 0x02u: return "Communications";
    case 0x06u: return "Imaging";
    case 0x08u: return "Mass Storage";
    case 0x0au: return "CDC Data";
    case 0xe0u: return "Wireless";
    case 0xffu: return "Vendor Specific";
    default:    return "Unknown";
    }
}

static const char *driver_name(const usb_entry_t *dev)
{
    if (dev->device_class == 0x09u)
        return "hub";
    if (dev->keyboards || dev->mice)
        return "usbhid";
    return "-";
}

static const char *speed_rate(const usb_entry_t *dev)
{
    if (strcmp(dev->speed, "super") == 0)
        return "5000M";
    if (strcmp(dev->speed, "high") == 0)
        return "480M";
    if (strcmp(dev->speed, "full") == 0)
        return "12M";
    if (strcmp(dev->speed, "low") == 0)
        return "1.5M";
    return "?";
}

static void show_list(int count)
{
    for (int i = 0; i < count; i++) {
        const usb_entry_t *dev = &devices[i];

        printf("Bus %03u Device %03u: ID %04x:%04x",
               dev->bus, dev->address, dev->vendor, dev->product_id);
        if (dev->manufacturer[0])
            printf(" %s", dev->manufacturer);
        if (dev->product[0])
            printf(" %s", dev->product);
        else
            printf(" %s", class_name(dev));
        printf("\n");
    }
}

static void show_version(unsigned bcd)
{
    printf("%x.%02x", (bcd >> 8) & 0xffu, bcd & 0xffu);
}

static void show_verbose(int count)
{
    for (int i = 0; i < count; i++) {
        const usb_entry_t *dev = &devices[i];

        printf("Bus %03u Device %03u: ID %04x:%04x\n",
               dev->bus, dev->address, dev->vendor, dev->product_id);
        printf("  Parent %03u Port %u  Speed %s (%s)\n",
               dev->parent, dev->port, dev->speed, speed_rate(dev));
        printf("  USB version ");
        show_version(dev->usb_version);
        printf("  Device version ");
        show_version(dev->device_version);
        printf("  EP0 packet size %u\n", dev->max_packet);
        printf("  Class %02x %s  Subclass %02x  Protocol %02x\n",
               dev->device_class, class_name(dev), dev->subclass,
               dev->protocol);
        printf("  Configurations %u  Interfaces %u",
               dev->configurations, dev->interfaces);
        if (dev->ports)
            printf("  Hub ports %u", dev->ports);
        printf("\n");
        if (dev->manufacturer[0])
            printf("  Manufacturer: %s\n", dev->manufacturer);
        if (dev->product[0])
            printf("  Product:      %s\n", dev->product);
        if (dev->serial[0])
            printf("  Serial:       %s\n", dev->serial);
        if (dev->keyboards || dev->mice)
            printf("  HID:          %u keyboard, %u mouse interface(s)\n",
                   dev->keyboards, dev->mice);
        printf("\n");
    }
}

static void show_tree_children(int count, unsigned parent, unsigned depth)
{
    if (depth > 8u)
        return;

    for (int i = 0; i < count; i++) {
        const usb_entry_t *dev = &devices[i];

        if (dev->parent != parent)
            continue;
        for (unsigned level = 0; level < depth; level++)
            printf("    ");
        printf("|__ Port %u: Dev %u, Class=%s, Driver=%s, %s\n",
               dev->port, dev->address, class_name(dev), driver_name(dev),
               speed_rate(dev));
        show_tree_children(count, dev->address, depth + 1u);
    }
}

static void show_tree(int count)
{
    if (count == 0) {
        printf("/:  No USB devices\n");
        return;
    }

    printf("/:  Bus 01, Driver=host, %u device(s)\n", count);
    show_tree_children(count, 0u, 1u);
}

int main(int argc, char **argv)
{
    enum { VIEW_LIST, VIEW_TREE, VIEW_VERBOSE } view = VIEW_LIST;
    int count;

    if (argc > 2) {
        usage();
        return 1;
    }
    if (argc == 2) {
        if (strcmp(argv[1], "-t") == 0)
            view = VIEW_TREE;
        else if (strcmp(argv[1], "-v") == 0)
            view = VIEW_VERBOSE;
        else if (strcmp(argv[1], "-h") == 0 ||
                 strcmp(argv[1], "--help") == 0) {
            usage();
            return 0;
        } else {
            usage();
            return 1;
        }
    }

    count = read_topology();
    if (count < 0)
        return 1;
    if (view == VIEW_TREE)
        show_tree(count);
    else if (view == VIEW_VERBOSE)
        show_verbose(count);
    else
        show_list(count);
    return 0;
}
