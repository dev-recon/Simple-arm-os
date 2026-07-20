/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/video/raspberrypi_hdmi.c
 * Layer: Kernel / Raspberry Pi display driver
 *
 * Responsibilities:
 * - Configure and allocate a 32-bit HDMI framebuffer through VideoCore.
 * - Make CPU-rendered dirty rectangles visible to the firmware display scanout.
 *
 * Notes:
 * - This is the firmware framebuffer path, intentionally preceding a native
 *   VC4/KMS driver. It supports ordinary HDMI monitors without a GPU stack.
 */

#include <kernel/address_space.h>
#include <kernel/arch_barrier.h>
#include <kernel/kprintf.h>
#include <kernel/raspberrypi_hdmi.h>
#include <kernel/raspberrypi_mailbox.h>

#define RPI_TAG_SET_PHYSICAL_SIZE 0x00048003u
#define RPI_TAG_SET_VIRTUAL_SIZE  0x00048004u
#define RPI_TAG_SET_DEPTH         0x00048005u
#define RPI_TAG_SET_PIXEL_ORDER   0x00048006u
#define RPI_TAG_SET_VIRTUAL_OFF   0x00048009u
#define RPI_TAG_ALLOCATE_BUFFER   0x00040001u
#define RPI_TAG_GET_PITCH         0x00040008u
#define RPI_PIXEL_ORDER_RGB       1u
#define RPI_GPU_BUS_ADDRESS_MASK  0x3fffffffu

static volatile uint32_t hdmi_message[35] __attribute__((aligned(16)));
static raspberrypi_hdmi_info_t hdmi;
static bool hdmi_ready;

static bool hdmi_request_mode(uint32_t width, uint32_t height,
                              raspberrypi_hdmi_info_t *result)
{
    raspberrypi_hdmi_info_t candidate;
    uint32_t bus_address;

    if (!width || !height || !result)
        return false;

    for (uint32_t i = 0; i < 35u; i++)
        hdmi_message[i] = 0;

    hdmi_message[0] = sizeof(hdmi_message);
    hdmi_message[1] = 0;
    hdmi_message[2] = RPI_TAG_SET_PHYSICAL_SIZE;
    hdmi_message[3] = 8; hdmi_message[4] = 0;
    hdmi_message[5] = width; hdmi_message[6] = height;
    hdmi_message[7] = RPI_TAG_SET_VIRTUAL_SIZE;
    hdmi_message[8] = 8; hdmi_message[9] = 0;
    hdmi_message[10] = width; hdmi_message[11] = height;
    hdmi_message[12] = RPI_TAG_SET_VIRTUAL_OFF;
    hdmi_message[13] = 8; hdmi_message[14] = 0;
    hdmi_message[15] = 0; hdmi_message[16] = 0;
    hdmi_message[17] = RPI_TAG_SET_DEPTH;
    hdmi_message[18] = 4; hdmi_message[19] = 0; hdmi_message[20] = 32;
    hdmi_message[21] = RPI_TAG_SET_PIXEL_ORDER;
    hdmi_message[22] = 4; hdmi_message[23] = 0;
    hdmi_message[24] = RPI_PIXEL_ORDER_RGB;
    hdmi_message[25] = RPI_TAG_ALLOCATE_BUFFER;
    hdmi_message[26] = 8; hdmi_message[27] = 0;
    hdmi_message[28] = 4096; hdmi_message[29] = 0;
    hdmi_message[30] = RPI_TAG_GET_PITCH;
    hdmi_message[31] = 4; hdmi_message[32] = 0; hdmi_message[33] = 0;
    hdmi_message[34] = 0;

    if (!raspberrypi_property_call(hdmi_message, sizeof(hdmi_message)))
        return false;

    bus_address = hdmi_message[28];
    candidate.width = hdmi_message[5];
    candidate.height = hdmi_message[6];
    candidate.bpp = hdmi_message[20];
    candidate.size = hdmi_message[29];
    candidate.pitch = hdmi_message[33];
    candidate.physical = (paddr_t)(bus_address & RPI_GPU_BUS_ADDRESS_MASK);
    candidate.virtual_address = (uint8_t *)phys_to_virt(candidate.physical);

    if (!bus_address || !candidate.size || candidate.bpp != 32u ||
        candidate.width != width || candidate.height != height ||
        candidate.pitch != candidate.width * 4u ||
        !phys_in_direct_map(candidate.physical) ||
        !phys_in_direct_map(candidate.physical + candidate.size - 1u)) {
        KERROR("HDMI: invalid firmware framebuffer bus=0x%08X phys=%p %ux%u pitch=%u size=%u\n",
               bus_address, (void *)(uintptr_t)candidate.physical,
               candidate.width, candidate.height,
               candidate.pitch, candidate.size);
        return false;
    }

    *result = candidate;
    return true;
}

static int hdmi_flush_rect(const uint8_t *framebuffer, uint32_t pitch,
                           uint32_t x, uint32_t y,
                           uint32_t width, uint32_t height)
{
    if (!hdmi_ready || !framebuffer || !pitch)
        return -ENODEV;
    if (!width || !height || x >= hdmi.width || y >= hdmi.height)
        return 0;
    if (x + width > hdmi.width)
        width = hdmi.width - x;
    if (y + height > hdmi.height)
        height = hdmi.height - y;

    for (uint32_t row = 0; row < height; row++) {
        const uint8_t *start = framebuffer + (y + row) * pitch + x * 4u;
        arch_clean_dcache_by_mva(start, width * 4u);
    }
    arch_data_sync_barrier();
    return 0;
}

static int hdmi_set_mode(uint32_t width, uint32_t height,
                         display_backend_mode_t *mode)
{
    raspberrypi_hdmi_info_t previous;
    raspberrypi_hdmi_info_t requested;
    raspberrypi_hdmi_info_t restored;

    if (!hdmi_ready || !mode)
        return -ENODEV;
    if (!width || !height)
        return -EINVAL;
    if (width == hdmi.width && height == hdmi.height) {
        requested = hdmi;
    } else {
        previous = hdmi;
        if (!hdmi_request_mode(width, height, &requested)) {
            if (hdmi_request_mode(previous.width, previous.height, &restored))
                hdmi = restored;
            return -EIO;
        }
        hdmi = requested;
    }

    mode->width = requested.width;
    mode->height = requested.height;
    mode->pitch = requested.pitch;
    mode->bpp = requested.bpp;
    mode->size = requested.size;
    mode->physical = requested.physical;
    mode->virtual_address = requested.virtual_address;
    return 0;
}

static const display_backend_ops_t hdmi_backend = {
    .name = "raspberrypi-hdmi",
    .flush_rect = hdmi_flush_rect,
    .check_resize = NULL,
    .set_orientation = NULL,
    .set_mode = hdmi_set_mode,
};

bool raspberrypi_hdmi_init(uint32_t width, uint32_t height)
{
    if (hdmi_ready)
        return true;
    if (!hdmi_request_mode(width, height, &hdmi))
        return false;

    hdmi_ready = true;
    return true;
}

const raspberrypi_hdmi_info_t *raspberrypi_hdmi_get_info(void)
{
    return hdmi_ready ? &hdmi : NULL;
}

const display_backend_ops_t *raspberrypi_hdmi_display_backend(void)
{
    return &hdmi_backend;
}
