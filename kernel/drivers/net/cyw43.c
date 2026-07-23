/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/net/cyw43.c
 * Layer: Kernel / network device drivers
 *
 * Responsibilities:
 * - Prepare the CYW43 SDIO backplane for register access.
 * - Identify and start the CYW43455 used by Raspberry Pi 3 B+ boards.
 * - Load firmware and board NVRAM after the root filesystem is mounted.
 * - Exchange SDPCM/BCDC control messages and load CLM regulatory data.
 * - Keep Broadcom chip policy independent from the Raspberry Pi SDIO host.
 *
 * Notes:
 * - Ethernet frames are intentionally deferred to the common network core.
 * - Register sequencing follows public brcmfmac, ZeroWi and UltiboWiFi work.
 */

#include <kernel/arch_barrier.h>
#include <kernel/arch_cpu.h>
#include <kernel/device_service.h>
#include <kernel/kprintf.h>
#include <kernel/memory.h>
#include <kernel/mmc/bcm2835_sdio.h>
#include <kernel/net/cyw43.h>
#include <kernel/net/device.h>
#include <kernel/net/stack.h>
#include <kernel/spinlock.h>
#include <kernel/string.h>
#include <kernel/task.h>
#include <kernel/timer.h>
#include <kernel/types.h>
#include <kernel/vfs.h>

#define CYW43_SDIO_FUNCTION_BACKPLANE       1u

#define CYW43_F1_BLOCK_SIZE_LOW             0x110u
#define CYW43_F1_BLOCK_SIZE_HIGH            0x111u
#define CYW43_F1_BACKPLANE_ADDRESS_LOW      0x1000au
#define CYW43_F1_BACKPLANE_ADDRESS_MID      0x1000bu
#define CYW43_F1_BACKPLANE_ADDRESS_HIGH     0x1000cu
#define CYW43_F1_CHIP_CLOCK_CSR             0x1000eu
#define CYW43_F1_SDIO_PULLUP                0x1000fu
#define CYW43_F1_SLEEP_CSR                  0x1001fu

#define CYW43_BACKPLANE_ENUM_BASE           0x18000000u
#define CYW43_EROM_POINTER_OFFSET            0x000000fcu
#define CYW43_BACKPLANE_WINDOW_MASK         0xffff8000u
#define CYW43_BACKPLANE_OFFSET_MASK         0x00007fffu
#define CYW43_BACKPLANE_32BIT_ACCESS        0x00008000u

#define CYW43_CLOCK_FORCE_ALP                0x01u
#define CYW43_CLOCK_FORCE_HT                 0x02u
#define CYW43_CLOCK_ALP_AVAILABLE_REQUEST    0x08u
#define CYW43_CLOCK_HT_AVAILABLE_REQUEST     0x10u
#define CYW43_CLOCK_FORCE_HW_REQUEST_OFF     0x20u
#define CYW43_CLOCK_ALP_AVAILABLE            0x40u
#define CYW43_CLOCK_HT_AVAILABLE             0x80u
#define CYW43_CLOCK_AVAILABILITY_BITS        0xc0u

#define CYW43_CHIP_ID_MASK                   0x0000ffffu
#define CYW43_CHIP_REVISION_SHIFT            16u
#define CYW43_CHIP_REVISION_MASK             0x000f0000u
#define CYW43_CHIP_PACKAGE_SHIFT             20u
#define CYW43_CHIP_PACKAGE_MASK              0x00f00000u
#define CYW4345_CHIP_ID                      0x4345u

#define CYW43_BACKPLANE_BLOCK_SIZE           64u
#define CYW43_RADIO_BLOCK_SIZE               512u
#define CYW43_ALP_TIMEOUT_MS                 20u
#define CYW43_HT_TIMEOUT_MS                  100u
#define CYW43_FUNCTION_TIMEOUT_MS            1000u
#define CYW43_FIRMWARE_READY_TIMEOUT_MS      2000u
#define CYW43_CONTROL_TIMEOUT_MS             2000u
#define CYW43_CONTROL_POLL_MS                20u
#define CYW43_KSO_TIMEOUT_MS                 1000u
#define CYW43_KSO_RETRY_US                   50u
#define CYW43_KSO_WAKE_DELAY_US              2000u
#define CYW43_SLEEP_CSR_KSO                  0x01u
#define CYW43_SLEEP_CSR_DEVICE_ON            0x02u
#define CYW43_SHARED_VERSION_MASK             0x00ffu
#define CYW43_SHARED_VERSION_MAX              3u
#define CYW43_SHARED_FLAGS_ASSERT_BUILT       0x0100u
#define CYW43_SHARED_FLAGS_ASSERT             0x0200u
#define CYW43_SHARED_FLAGS_TRAP               0x0400u
#define CYW43_SHARED_CONSOLE_OFFSET           20u
#define CYW43_CONSOLE_LOG_BUF_OFFSET          8u
#define CYW43_CONSOLE_MAX_SIZE                2024u
#define CYW43_TRAP_INFO_SIZE                  80u
#define CYW43_TX_WINDOW_MAX_ADVANCE          0x40u
#define CYW43_EROM_SIZE                      512u
#define CYW43_FIRMWARE_CHUNK_SIZE            512u
#define CYW43_SDPCM_PACKET_SIZE              2048u
#define CYW43_SDPCM_FRAME_TAG_SIZE           4u
#define CYW43_SDPCM_SOFTWARE_HEADER_SIZE     8u
#define CYW43_SDPCM_HEADER_SIZE              12u
#define CYW43_BCDC_CONTROL_HEADER_SIZE       16u
#define CYW43_BCDC_DATA_OFFSET               28u
#define CYW43_F2_FIFO_ADDRESS                0x8000u
#define CYW43_SDPCM_CONTROL_CHANNEL          0u
#define CYW43_SDPCM_EVENT_CHANNEL            1u
#define CYW43_SDPCM_DATA_CHANNEL             2u
#define CYW43_BCDC_DATA_HEADER_SIZE          4u
#define CYW43_BCDC_DATA_FRAME_OFFSET         16u
#define CYW43_BCDC_PROTOCOL_VERSION          2u
#define CYW43_BCDC_VERSION_SHIFT             4u
#define CYW43_BCDC_FLAG_ERROR                0x00000001u
#define CYW43_BCDC_FLAG_SET                  0x00000002u
#define CYW43_WLC_UP                         2u
#define CYW43_WLC_SET_INFRA                  20u
#define CYW43_WLC_SET_AUTH                   22u
#define CYW43_WLC_GET_BSSID                  23u
#define CYW43_WLC_SET_SSID                   26u
#define CYW43_WLC_SET_PM                     86u
#define CYW43_WLC_SET_WSEC                   134u
#define CYW43_WLC_SET_WPA_AUTH               165u
#define CYW43_WLC_GET_VAR                    262u
#define CYW43_WLC_SET_VAR                    263u
#define CYW43_WLC_SET_WSEC_PMK               268u
#define CYW43_WSEC_AES                       0x00000004u
#define CYW43_WPA2_AUTH_PSK                  0x00000080u
#define CYW43_MFP_NONE                       0u
#define CYW43_WSEC_PASSPHRASE                1u

#define CYW43_EVENT_SET_SSID                 0u
#define CYW43_EVENT_AUTH                     3u
#define CYW43_EVENT_DEAUTH                   5u
#define CYW43_EVENT_DEAUTH_IND               6u
#define CYW43_EVENT_ASSOC                    7u
#define CYW43_EVENT_DISASSOC                 11u
#define CYW43_EVENT_DISASSOC_IND             12u
#define CYW43_EVENT_LINK                     16u
#define CYW43_EVENT_PSK_SUP                  46u
#define CYW43_EVENT_MASK_SIZE                26u
#define CYW43_EVENT_STATUS_SUCCESS           0u
#define CYW43_SUP_KEYED                      6u
#define CYW43_EVENT_FLAG_LINK                0x0001u
#define CYW43_EVENT_ETHERNET_SIZE            14u
#define CYW43_EVENT_VENDOR_HEADER_SIZE       10u
#define CYW43_EVENT_MESSAGE_MIN_SIZE         30u
#define CYW43_EVENT_ETHERTYPE                0x886cu
#define CYW43_CLM_HEADER_SIZE                12u
#define CYW43_CLM_CHUNK_SIZE                 400u
#define CYW43_CLM_FLAG_HANDLER               (1u << 12)
#define CYW43_CLM_FLAG_FIRST                 (1u << 1)
#define CYW43_CLM_FLAG_LAST                  (1u << 2)

#define CYW43_WIFI_CONFIG_PATH               "/etc/wifi.conf"
#define CYW43_WIFI_CONFIG_MAX                512u
#define CYW43_WIFI_SSID_MAX                  32u
#define CYW43_WIFI_PASSWORD_MAX              64u
#define CYW43_WIFI_JOIN_TIMEOUT_MS           15000u

#define CYW43_EROM_COMPONENT_TAG             0x01u
#define CYW43_EROM_ADDRESS_TAG               0x05u
#define CYW43_EROM_END_TAG                   0x0fu
#define CYW43_EROM_CORE_ID_MASK              0x0fffu
#define CYW43_EROM_ADDRESS_MASK              0xfffff000u
#define CYW43_EROM_WRAPPER_MASK              0xc0u

#define CYW43_CORE_CHIPCOMMON                0x800u
#define CYW43_CORE_ARM7                      0x825u
#define CYW43_CORE_SDIO                      0x829u
#define CYW43_CORE_ARM_CM3                   0x82au
#define CYW43_CORE_D11                       0x812u
#define CYW43_CORE_ARM_CR4                   0x83eu

#define CYW43_AI_IO_CONTROL_OFFSET           0x408u
#define CYW43_AI_RESET_CONTROL_OFFSET        0x800u
#define CYW43_AI_IO_CORE_CLOCK               0x01u
#define CYW43_AI_IO_CORE_BITS                0x03u
#define CYW43_AI_RESET                       0x01u
#define CYW43_ARM_CR4_CAP_OFFSET             0x004u
#define CYW43_ARM_CR4_BANK_INDEX_OFFSET      0x040u
#define CYW43_ARM_CR4_BANK_INFO_OFFSET       0x044u
#define CYW43_ARM_CR4_CPU_HALT               0x020u
#define CYW4345_RAM_BASE                     0x00198000u
#define CYW43_CORE_TIMEOUT_US                1000u

#define CYW43_SDIO_INT_STATUS_OFFSET         0x020u
#define CYW43_SDIO_INT_MASK_OFFSET           0x024u
#define CYW43_SDIO_TO_SB_MAILBOX_OFFSET      0x040u
#define CYW43_SDIO_TO_SB_MAILBOX_DATA_OFFSET 0x048u
#define CYW43_SDIO_TO_HOST_MAILBOX_OFFSET    0x04cu
#define CYW43_SDIO_INT_FLOW_CHANGE           (1u << 5)
#define CYW43_SDIO_INT_FRAME                 (1u << 6)
#define CYW43_SDIO_INT_MAILBOX               (1u << 7)
#define CYW43_SDIO_MAILBOX_FIRMWARE_READY    (1u << 3)
#define CYW43_SDPCM_PROTOCOL_VERSION         4u

#define CYW43_CCCR_IO_ENABLE                 0x002u
#define CYW43_CCCR_IO_READY                  0x003u
#define CYW43_CCCR_INTERRUPT_ENABLE          0x004u
#define CYW43_CCCR_FUNCTION2_ENABLE          (1u << 2)
#define CYW43_CCCR_INTERRUPT_MASTER          (1u << 0)
#define CYW43_CCCR_INTERRUPT_FUNCTION1       (1u << 1)
#define CYW43_CCCR_INTERRUPT_FUNCTION2       (1u << 2)
#define CYW43_F2_BLOCK_SIZE_LOW              0x210u
#define CYW43_F2_BLOCK_SIZE_HIGH             0x211u

#define CYW43_FIRMWARE_PATH "/lib/firmware/brcm/brcmfmac43455-sdio.bin"
#define CYW43_NVRAM_PATH "/lib/firmware/brcm/brcmfmac43455-sdio.txt"
#define CYW43_CLM_PATH "/lib/firmware/brcm/brcmfmac43455-sdio.clm_blob"

typedef struct cyw43_state {
    net_device_t device;
    cyw43_identity_t identity;
    uint32_t backplane_window;
    bool present;
    bool firmware_files_ready;
    bool firmware_running;
    bool radio_ready;
    bool regulatory_ready;
    bool associated;
    bool device_registered;
    uint8_t tx_sequence;
    uint8_t tx_max;
    uint8_t wireless_flow_control;
    uint16_t ioctl_request_id;
    uint8_t mac_address[6];
    uint8_t bssid[6];
    bool join_in_progress;
    bool join_expect_psk;
    bool join_set_ssid;
    bool join_link;
    bool join_psk;
    bool join_failed;
    uint32_t join_failure_event;
    uint32_t join_failure_status;
    uint32_t join_failure_reason;
} cyw43_state_t;

typedef enum cyw43_wifi_security {
    CYW43_WIFI_OPEN = 0,
    CYW43_WIFI_WPA2,
} cyw43_wifi_security_t;

typedef struct cyw43_wifi_config {
    char country[3];
    char ssid[CYW43_WIFI_SSID_MAX + 1u];
    char password[CYW43_WIFI_PASSWORD_MAX + 1u];
    cyw43_wifi_security_t security;
} cyw43_wifi_config_t;

static cyw43_state_t cyw43_state;
static spinlock_t cyw43_data_lock = SPINLOCK_INIT("cyw43_data");

static int cyw43_backplane_read(uint32_t address, void *buffer,
                                uint32_t length);
static int cyw43_backplane_write(uint32_t address, const void *buffer,
                                 uint32_t length);

static uint64_t cyw43_counter_delta(uint32_t timeout_ms)
{
    uint32_t frequency = arch_timer_frequency();
    uint32_t per_ms;
    uint32_t remainder;
    uint32_t delta;

    if (frequency == 0u)
        frequency = TIMER_FALLBACK_FREQ;
    per_ms = frequency / 1000u;
    remainder = frequency % 1000u;
    delta = per_ms * timeout_ms +
        (remainder * timeout_ms + 999u) / 1000u;
    return delta ? delta : 1u;
}

static bool cyw43_deadline_expired(uint64_t start, uint32_t timeout_ms)
{
    return arch_timer_counter() - start >= cyw43_counter_delta(timeout_ms);
}

static void cyw43_delay_us(uint32_t microseconds)
{
    uint32_t frequency = arch_timer_frequency();
    uint32_t per_us;
    uint32_t remainder;
    uint64_t duration;
    uint64_t start;

    if (frequency == 0u)
        frequency = TIMER_FALLBACK_FREQ;
    per_us = frequency / 1000000u;
    remainder = frequency % 1000000u;
    duration = (uint64_t)per_us * microseconds +
        (remainder * microseconds + 999999u) / 1000000u;
    if (duration == 0u)
        duration = 1u;

    start = arch_timer_counter();
    while (arch_timer_counter() - start < duration)
        arch_cpu_relax();
}

static void cyw43_delay_ms(uint32_t milliseconds)
{
    while (milliseconds > 0u) {
        uint32_t slice = milliseconds > 1000u ? 1000u : milliseconds;

        cyw43_delay_us(slice * 1000u);
        milliseconds -= slice;
    }
}

static int cyw43_set_backplane_window(uint32_t address)
{
    uint32_t window = address & CYW43_BACKPLANE_WINDOW_MASK;
    uint32_t encoded;
    int ret;

    if (window == cyw43_state.backplane_window)
        return 0;

    encoded = window >> 8;
    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_BACKPLANE_ADDRESS_LOW,
                              (uint8_t)(encoded & 0xffu));
    if (ret < 0)
        return ret;
    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_BACKPLANE_ADDRESS_MID,
                              (uint8_t)((encoded >> 8) & 0xffu));
    if (ret < 0)
        return ret;
    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_BACKPLANE_ADDRESS_HIGH,
                              (uint8_t)((encoded >> 16) & 0xffu));
    if (ret < 0)
        return ret;

    cyw43_state.backplane_window = window;
    return 0;
}

static int cyw43_backplane_read32(uint32_t address, uint32_t *value)
{
    uint8_t bytes[4];
    int ret;

    if (!value)
        return -EINVAL;
    ret = cyw43_backplane_read(address, bytes, sizeof(bytes));
    if (ret < 0)
        return ret;

    *value = (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
    return 0;
}

static int cyw43_backplane_write32(uint32_t address, uint32_t value)
{
    uint8_t bytes[4];

    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)((value >> 8) & 0xffu);
    bytes[2] = (uint8_t)((value >> 16) & 0xffu);
    bytes[3] = (uint8_t)((value >> 24) & 0xffu);
    return cyw43_backplane_write(address, bytes, sizeof(bytes));
}

static int cyw43_backplane_transfer(bool write, uint32_t address,
                                    void *buffer, uint32_t length)
{
    uint8_t *bytes = (uint8_t *)buffer;

    if (!buffer || length == 0u)
        return -EINVAL;
    while (length > 0u) {
        uint32_t window_remaining = 0x8000u -
            (address & CYW43_BACKPLANE_OFFSET_MASK);
        uint32_t chunk = length;
        uint32_t sdio_address;
        int ret;

        if (chunk > window_remaining)
            chunk = window_remaining;
        if (chunk > 512u)
            chunk = 512u;
        if (chunk > CYW43_BACKPLANE_BLOCK_SIZE &&
            chunk % CYW43_BACKPLANE_BLOCK_SIZE != 0u)
            chunk -= chunk % CYW43_BACKPLANE_BLOCK_SIZE;
        ret = cyw43_set_backplane_window(address);
        if (ret < 0)
            return ret;
        sdio_address = address & CYW43_BACKPLANE_OFFSET_MASK;
        if (chunk >= sizeof(uint32_t))
            sdio_address |= CYW43_BACKPLANE_32BIT_ACCESS;
        if (write) {
            ret = bcm2835_sdio_write(CYW43_SDIO_FUNCTION_BACKPLANE,
                                      sdio_address, bytes, chunk, true);
        } else {
            ret = bcm2835_sdio_read(CYW43_SDIO_FUNCTION_BACKPLANE,
                                     sdio_address, bytes, chunk, true);
        }
        if (ret < 0)
            return ret;
        address += chunk;
        bytes += chunk;
        length -= chunk;
    }
    return 0;
}

static int cyw43_backplane_read(uint32_t address, void *buffer,
                                uint32_t length)
{
    return cyw43_backplane_transfer(false, address, buffer, length);
}

static int cyw43_backplane_write(uint32_t address, const void *buffer,
                                 uint32_t length)
{
    return cyw43_backplane_transfer(true, address, (void *)buffer, length);
}

static int cyw43_core_disable(uint32_t wrapper, uint32_t pre,
                              uint32_t io_control)
{
    uint32_t value;
    uint32_t elapsed = 0u;
    int ret;

    ret = cyw43_backplane_read32(wrapper + CYW43_AI_RESET_CONTROL_OFFSET,
                                 &value);
    if (ret < 0)
        return ret;
    if (value & CYW43_AI_RESET) {
        ret = cyw43_backplane_write32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                      CYW43_AI_IO_CORE_BITS | io_control);
        if (ret < 0)
            return ret;
        return cyw43_backplane_read32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                      &value);
    }

    ret = cyw43_backplane_write32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                  CYW43_AI_IO_CORE_BITS | pre);
    if (ret < 0)
        return ret;
    ret = cyw43_backplane_read32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                 &value);
    if (ret < 0)
        return ret;
    ret = cyw43_backplane_write32(wrapper + CYW43_AI_RESET_CONTROL_OFFSET,
                                  CYW43_AI_RESET);
    if (ret < 0)
        return ret;

    do {
        cyw43_delay_us(10u);
        elapsed += 10u;
        ret = cyw43_backplane_read32(
            wrapper + CYW43_AI_RESET_CONTROL_OFFSET, &value);
        if (ret < 0)
            return ret;
        if (value & CYW43_AI_RESET)
            break;
    } while (elapsed < CYW43_CORE_TIMEOUT_US);
    if (!(value & CYW43_AI_RESET))
        return -ETIMEDOUT;

    ret = cyw43_backplane_write32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                  CYW43_AI_IO_CORE_BITS | io_control);
    if (ret < 0)
        return ret;
    return cyw43_backplane_read32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                  &value);
}

static int cyw43_core_reset(uint32_t wrapper, uint32_t pre,
                            uint32_t io_control)
{
    uint32_t value;
    uint32_t elapsed = 0u;
    int ret;

    ret = cyw43_core_disable(wrapper, pre, io_control);
    if (ret < 0)
        return ret;
    do {
        ret = cyw43_backplane_write32(
            wrapper + CYW43_AI_RESET_CONTROL_OFFSET, 0u);
        if (ret < 0)
            return ret;
        cyw43_delay_us(40u);
        elapsed += 40u;
        ret = cyw43_backplane_read32(
            wrapper + CYW43_AI_RESET_CONTROL_OFFSET, &value);
        if (ret < 0)
            return ret;
        if (!(value & CYW43_AI_RESET))
            break;
    } while (elapsed < CYW43_CORE_TIMEOUT_US);
    if (value & CYW43_AI_RESET)
        return -ETIMEDOUT;

    ret = cyw43_backplane_write32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                  CYW43_AI_IO_CORE_CLOCK | io_control);
    if (ret < 0)
        return ret;
    return cyw43_backplane_read32(wrapper + CYW43_AI_IO_CONTROL_OFFSET,
                                  &value);
}

static int cyw43_scan_cr4_ram(void)
{
    uint32_t capabilities;
    uint32_t banks;
    uint32_t size = 0u;
    int ret;

    if (cyw43_state.identity.arm_core != CYW43_CORE_ARM_CR4)
        return -ENOTSUP;
    ret = cyw43_backplane_read32(cyw43_state.identity.arm_registers +
                                  CYW43_ARM_CR4_CAP_OFFSET,
                                  &capabilities);
    if (ret < 0)
        return ret;
    banks = (capabilities & 0x0fu) + ((capabilities >> 4) & 0x0fu);
    if (banks == 0u || banks > 32u)
        return -EINVAL;

    for (uint32_t bank = 0u; bank < banks; ++bank) {
        uint32_t information;

        ret = cyw43_backplane_write32(cyw43_state.identity.arm_registers +
                                       CYW43_ARM_CR4_BANK_INDEX_OFFSET,
                                       bank);
        if (ret < 0)
            return ret;
        ret = cyw43_backplane_read32(cyw43_state.identity.arm_registers +
                                      CYW43_ARM_CR4_BANK_INFO_OFFSET,
                                      &information);
        if (ret < 0)
            return ret;
        size += 8192u * ((information & 0x3fu) + 1u);
    }
    if (size < 512u * 1024u || size > 8u * 1024u * 1024u)
        return -EINVAL;

    cyw43_state.identity.ram_base = CYW4345_RAM_BASE;
    cyw43_state.identity.ram_size = size;
    return 0;
}

static int cyw43_scan_cores(void)
{
    uint8_t erom[CYW43_EROM_SIZE];
    uint32_t core_id = 0u;
    uint32_t erom_address;
    int ret;

    ret = cyw43_backplane_read32(CYW43_BACKPLANE_ENUM_BASE +
                                  CYW43_EROM_POINTER_OFFSET,
                                  &erom_address);
    if (ret < 0)
        return ret;
    if ((erom_address & 3u) != 0u || erom_address == 0u)
        return -EINVAL;
    cyw43_state.identity.erom_address = erom_address;

    ret = cyw43_backplane_read(erom_address, erom, sizeof(erom));
    if (ret < 0)
        return ret;

    for (uint32_t offset = 0u; offset + 7u < sizeof(erom); offset += 4u) {
        uint8_t tag = erom[offset] & 0x0fu;

        if (tag == CYW43_EROM_END_TAG)
            break;
        if (tag == CYW43_EROM_COMPONENT_TAG) {
            if ((erom[offset + 4u] & 0x0fu) !=
                CYW43_EROM_COMPONENT_TAG)
                return -EINVAL;
            core_id = ((uint32_t)erom[offset + 1u] |
                       ((uint32_t)erom[offset + 2u] << 8)) &
                CYW43_EROM_CORE_ID_MASK;
            offset += 4u;
            continue;
        }
        if (tag == CYW43_EROM_ADDRESS_TAG && core_id != 0u) {
            uint32_t core_address =
                ((uint32_t)erom[offset + 1u] << 8) |
                ((uint32_t)erom[offset + 2u] << 16) |
                ((uint32_t)erom[offset + 3u] << 24);
            bool wrapper = (erom[offset] & CYW43_EROM_WRAPPER_MASK) != 0u;

            core_address &= CYW43_EROM_ADDRESS_MASK;
            switch (core_id) {
            case CYW43_CORE_CHIPCOMMON:
                if (!wrapper)
                    cyw43_state.identity.chipcommon = core_address;
                break;
            case CYW43_CORE_ARM7:
            case CYW43_CORE_ARM_CM3:
            case CYW43_CORE_ARM_CR4:
                cyw43_state.identity.arm_core = core_id;
                if (wrapper && !cyw43_state.identity.arm_wrapper)
                    cyw43_state.identity.arm_wrapper = core_address;
                else if (!wrapper && !cyw43_state.identity.arm_registers)
                    cyw43_state.identity.arm_registers = core_address;
                break;
            case CYW43_CORE_SDIO:
                if (!wrapper)
                    cyw43_state.identity.sdio_registers = core_address;
                break;
            case CYW43_CORE_D11:
                if (wrapper && !cyw43_state.identity.d11_wrapper)
                    cyw43_state.identity.d11_wrapper = core_address;
                break;
            default:
                break;
            }
        }
    }

    if (!cyw43_state.identity.chipcommon ||
        !cyw43_state.identity.arm_core ||
        !cyw43_state.identity.arm_wrapper ||
        !cyw43_state.identity.arm_registers ||
        !cyw43_state.identity.sdio_registers ||
        !cyw43_state.identity.d11_wrapper)
        return -ENODEV;
    return 0;
}

static int cyw43_configure_backplane_function(void)
{
    uint8_t clock;
    uint64_t start;
    int ret;

    ret = bcm2835_sdio_writeb(0u, CYW43_F1_BLOCK_SIZE_LOW,
                              CYW43_BACKPLANE_BLOCK_SIZE);
    if (ret < 0)
        return ret;
    ret = bcm2835_sdio_writeb(0u, CYW43_F1_BLOCK_SIZE_HIGH, 0u);
    if (ret < 0)
        return ret;

    clock = CYW43_CLOCK_FORCE_HW_REQUEST_OFF |
        CYW43_CLOCK_ALP_AVAILABLE_REQUEST;
    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_CHIP_CLOCK_CSR, clock);
    if (ret < 0)
        return ret;
    ret = bcm2835_sdio_readb(CYW43_SDIO_FUNCTION_BACKPLANE,
                             CYW43_F1_CHIP_CLOCK_CSR, &clock);
    if (ret < 0)
        return ret;
    if ((clock & ~CYW43_CLOCK_AVAILABILITY_BITS) !=
        (CYW43_CLOCK_FORCE_HW_REQUEST_OFF |
         CYW43_CLOCK_ALP_AVAILABLE_REQUEST))
        return -EACCES;

    start = arch_timer_counter();
    do {
        ret = bcm2835_sdio_readb(CYW43_SDIO_FUNCTION_BACKPLANE,
                                 CYW43_F1_CHIP_CLOCK_CSR, &clock);
        if (ret < 0)
            return ret;
        if (clock & CYW43_CLOCK_ALP_AVAILABLE)
            break;
        arch_cpu_relax();
    } while (!cyw43_deadline_expired(start, CYW43_ALP_TIMEOUT_MS));
    if (!(clock & CYW43_CLOCK_ALP_AVAILABLE))
        return -ETIMEDOUT;

    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_CHIP_CLOCK_CSR,
                              CYW43_CLOCK_FORCE_HW_REQUEST_OFF |
                              CYW43_CLOCK_FORCE_ALP);
    if (ret < 0)
        return ret;

    /* The chip needs time to settle after ALP is forced. */
    cyw43_delay_us(65u);
    return bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                               CYW43_F1_SDIO_PULLUP, 0u);
}

bool cyw43_probe(cyw43_identity_t *identity)
{
    uint32_t signature;
    int ret;

    cyw43_state.present = false;
    cyw43_state.firmware_files_ready = false;
    cyw43_state.firmware_running = false;
    cyw43_state.radio_ready = false;
    cyw43_state.regulatory_ready = false;
    cyw43_state.associated = false;
    cyw43_state.device_registered = false;
    /* One bootstrap control credit: 0 - 255 wraps to one SDPCM slot. */
    cyw43_state.tx_sequence = 0xffu;
    cyw43_state.tx_max = 0u;
    cyw43_state.wireless_flow_control = 0u;
    cyw43_state.ioctl_request_id = 0u;
    memset(cyw43_state.mac_address, 0, sizeof(cyw43_state.mac_address));
    cyw43_state.backplane_window = 0xffffffffu;
    cyw43_state.identity.chip_id_register = 0u;
    cyw43_state.identity.erom_address = 0u;
    cyw43_state.identity.chipcommon = 0u;
    cyw43_state.identity.arm_core = 0u;
    cyw43_state.identity.arm_registers = 0u;
    cyw43_state.identity.arm_wrapper = 0u;
    cyw43_state.identity.sdio_registers = 0u;
    cyw43_state.identity.d11_wrapper = 0u;
    cyw43_state.identity.ram_base = 0u;
    cyw43_state.identity.ram_size = 0u;
    cyw43_state.identity.chip_id = 0u;
    cyw43_state.identity.chip_revision = 0u;
    cyw43_state.identity.package = 0u;

    if (!bcm2835_sdio_is_ready()) {
        KERROR("CYW43: SDIO transport is not ready\n");
        return false;
    }
    ret = cyw43_configure_backplane_function();
    if (ret < 0) {
        KERROR("CYW43: function 1/ALP setup failed (%d)\n", ret);
        return false;
    }
    ret = cyw43_backplane_read32(CYW43_BACKPLANE_ENUM_BASE, &signature);
    if (ret < 0) {
        KERROR("CYW43: chip ID backplane read failed (%d)\n", ret);
        return false;
    }

    cyw43_state.identity.chip_id_register = signature;
    cyw43_state.identity.chip_id =
        (uint16_t)(signature & CYW43_CHIP_ID_MASK);
    cyw43_state.identity.chip_revision = (uint8_t)
        ((signature & CYW43_CHIP_REVISION_MASK) >>
         CYW43_CHIP_REVISION_SHIFT);
    cyw43_state.identity.package = (uint8_t)
        ((signature & CYW43_CHIP_PACKAGE_MASK) >>
         CYW43_CHIP_PACKAGE_SHIFT);
    if (cyw43_state.identity.chip_id != CYW4345_CHIP_ID) {
        KERROR("CYW43: unsupported chip signature 0x%08X\n", signature);
        return false;
    }
    ret = cyw43_scan_cores();
    if (ret < 0) {
        KERROR("CYW43: EROM core scan failed (%d) erom=0x%08X\n",
               ret, cyw43_state.identity.erom_address);
        return false;
    }
    ret = cyw43_core_reset(cyw43_state.identity.arm_wrapper,
                           CYW43_ARM_CR4_CPU_HALT,
                           CYW43_ARM_CR4_CPU_HALT);
    if (ret < 0) {
        KERROR("CYW43: failed to halt CR4 core (%d)\n", ret);
        return false;
    }
    ret = cyw43_core_reset(cyw43_state.identity.d11_wrapper, 8u | 4u, 4u);
    if (ret < 0) {
        KERROR("CYW43: failed to reset D11 core (%d)\n", ret);
        return false;
    }
    ret = cyw43_scan_cr4_ram();
    if (ret < 0) {
        KERROR("CYW43: CR4 RAM scan failed (%d)\n", ret);
        return false;
    }

    cyw43_state.present = true;
    ret = device_service_register("CYW43455", cyw43_start);
    if (ret < 0) {
        KERROR("CYW43: late service registration failed (%d)\n", ret);
        cyw43_state.present = false;
        return false;
    }
    if (identity)
        *identity = cyw43_state.identity;
    return true;
}

bool cyw43_is_present(void)
{
    return cyw43_state.present;
}

static int cyw43_check_firmware_file(const char *path, uint32_t *size)
{
    kernel_file_t file;
    int ret;

    ret = vfs_kernel_file_open(path, &file);
    if (ret < 0)
        return ret;
    *size = vfs_kernel_file_size(&file);
    vfs_kernel_file_close(&file);
    return *size ? 0 : -EINVAL;
}

static uint32_t cyw43_get_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
        ((uint32_t)bytes[1] << 8) |
        ((uint32_t)bytes[2] << 16) |
        ((uint32_t)bytes[3] << 24);
}

static uint16_t cyw43_get_le16(const uint8_t *bytes)
{
    return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8);
}

static uint16_t cyw43_get_be16(const uint8_t *bytes)
{
    return ((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1];
}

static uint32_t cyw43_get_be32(const uint8_t *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
        ((uint32_t)bytes[1] << 16) |
        ((uint32_t)bytes[2] << 8) |
        (uint32_t)bytes[3];
}

static void cyw43_put_le16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)(value >> 8);
}

static void cyw43_put_le32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value & 0xffu);
    bytes[1] = (uint8_t)((value >> 8) & 0xffu);
    bytes[2] = (uint8_t)((value >> 16) & 0xffu);
    bytes[3] = (uint8_t)((value >> 24) & 0xffu);
}

static char *cyw43_trim(char *text)
{
    char *end;

    while (*text && isspace((unsigned char)*text))
        text++;
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return text;
}

static int cyw43_copy_config_value(char *destination, uint32_t capacity,
                                   const char *value)
{
    uint32_t length = (uint32_t)strlen(value);

    if (length >= capacity)
        return -EFBIG;
    memcpy(destination, value, length + 1u);
    return 0;
}

static int cyw43_load_wifi_config(cyw43_wifi_config_t *config)
{
    kernel_file_t file;
    char buffer[CYW43_WIFI_CONFIG_MAX + 1u];
    char *line;
    uint32_t size;
    ssize_t got;
    int ret;

    if (!config)
        return -EINVAL;
    memset(config, 0, sizeof(*config));
    config->country[0] = '0';
    config->country[1] = '0';
    config->security = CYW43_WIFI_WPA2;

    ret = vfs_kernel_file_open(CYW43_WIFI_CONFIG_PATH, &file);
    if (ret < 0)
        return ret;
    size = vfs_kernel_file_size(&file);
    if (size == 0u || size > CYW43_WIFI_CONFIG_MAX) {
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

    line = buffer;
    while (*line) {
        char *next = strchr(line, '\n');
        char *separator;
        char *key;
        char *value;

        if (next)
            *next++ = '\0';
        key = cyw43_trim(line);
        if (*key != '\0' && *key != '#') {
            separator = strchr(key, '=');
            if (!separator)
                return -EINVAL;
            *separator++ = '\0';
            key = cyw43_trim(key);
            value = cyw43_trim(separator);
            if (strcmp(key, "country") == 0) {
                if (strlen(value) != 2u)
                    return -EINVAL;
                config->country[0] = toupper(value[0]);
                config->country[1] = toupper(value[1]);
            } else if (strcmp(key, "ssid") == 0) {
                ret = cyw43_copy_config_value(config->ssid,
                                               sizeof(config->ssid), value);
                if (ret < 0)
                    return ret;
            } else if (strcmp(key, "password") == 0) {
                ret = cyw43_copy_config_value(config->password,
                                               sizeof(config->password),
                                               value);
                if (ret < 0)
                    return ret;
            } else if (strcmp(key, "security") == 0) {
                if (strcmp(value, "open") == 0)
                    config->security = CYW43_WIFI_OPEN;
                else if (strcmp(value, "wpa2") == 0)
                    config->security = CYW43_WIFI_WPA2;
                else
                    return -EINVAL;
            } else {
                return -EINVAL;
            }
        }
        if (!next)
            break;
        line = next;
    }

    if (config->ssid[0] == '\0')
        return -EINVAL;
    if (config->security == CYW43_WIFI_WPA2) {
        size_t password_length = strlen(config->password);

        if (password_length < 8u ||
            password_length > CYW43_WIFI_PASSWORD_MAX)
            return -EINVAL;
    }
    return 0;
}

static int cyw43_load_firmware(uint32_t firmware_size,
                               uint32_t *reset_vector)
{
    kernel_file_t file;
    uint8_t buffer[CYW43_FIRMWARE_CHUNK_SIZE];
    uint32_t offset = 0u;
    uint32_t aligned_size = (firmware_size + 3u) & ~3u;
    int ret;

    if (!reset_vector || firmware_size < sizeof(uint32_t) ||
        aligned_size > cyw43_state.identity.ram_size)
        return -EINVAL;
    ret = vfs_kernel_file_open(CYW43_FIRMWARE_PATH, &file);
    if (ret < 0)
        return ret;

    while (offset < aligned_size) {
        uint32_t remaining = firmware_size -
            (offset < firmware_size ? offset : firmware_size);
        uint32_t read_size = remaining;
        uint32_t write_size;
        ssize_t got;

        if (read_size > sizeof(buffer))
            read_size = sizeof(buffer);
        memset(buffer, 0, sizeof(buffer));
        got = read_size ? vfs_kernel_file_read(&file, buffer, read_size) : 0;
        if (got < 0) {
            ret = (int)got;
            goto out;
        }
        if ((uint32_t)got != read_size) {
            ret = -EIO;
            goto out;
        }
        if (offset == 0u)
            *reset_vector = cyw43_get_le32(buffer);

        write_size = read_size;
        if (offset + write_size == firmware_size)
            write_size = (write_size + 3u) & ~3u;
        ret = cyw43_backplane_write(cyw43_state.identity.ram_base + offset,
                                     buffer, write_size);
        if (ret < 0)
            goto out;
        offset += write_size;
    }
    ret = 0;
out:
    vfs_kernel_file_close(&file);
    return ret;
}

static uint32_t cyw43_condense_nvram(uint8_t *buffer, uint32_t input_size,
                                     uint32_t capacity)
{
    uint32_t input = 0u;
    uint32_t output = 0u;
    uint32_t line_start = 0u;
    bool comment = false;

    while (input < input_size) {
        uint8_t value = buffer[input++];

        if (value == '#') {
            comment = true;
        } else if (value == '\n' || value == '\0') {
            comment = false;
            if (output != line_start) {
                buffer[output++] = 0u;
                line_start = output;
            }
        } else if (value != '\r' && !comment) {
            buffer[output++] = value;
        }
    }
    if (!comment && output != line_start)
        buffer[output++] = 0u;
    if (output >= capacity)
        return 0u;
    buffer[output++] = 0u;
    while ((output & 3u) != 0u) {
        if (output >= capacity)
            return 0u;
        buffer[output++] = 0u;
    }
    return output;
}

static int cyw43_load_nvram(uint32_t nvram_file_size,
                            uint32_t firmware_size)
{
    kernel_file_t file;
    uint8_t *buffer;
    uint32_t capacity;
    uint32_t nvram_size;
    uint32_t nvram_address;
    uint32_t token;
    ssize_t got;
    int ret;

    if (nvram_file_size > cyw43_state.identity.ram_size - 8u)
        return -EFBIG;
    capacity = nvram_file_size + 8u;
    buffer = kmalloc(capacity);
    if (!buffer)
        return -ENOMEM;
    memset(buffer, 0, capacity);

    ret = vfs_kernel_file_open(CYW43_NVRAM_PATH, &file);
    if (ret < 0)
        goto out_free;
    got = vfs_kernel_file_read(&file, buffer, nvram_file_size);
    vfs_kernel_file_close(&file);
    if (got < 0) {
        ret = (int)got;
        goto out_free;
    }
    if ((uint32_t)got != nvram_file_size) {
        ret = -EIO;
        goto out_free;
    }

    nvram_size = cyw43_condense_nvram(buffer, nvram_file_size, capacity);
    if (nvram_size == 0u || nvram_size + 4u > cyw43_state.identity.ram_size) {
        ret = -EINVAL;
        goto out_free;
    }
    nvram_address = cyw43_state.identity.ram_base +
        cyw43_state.identity.ram_size - nvram_size - 4u;
    if (nvram_address < cyw43_state.identity.ram_base +
        ((firmware_size + 3u) & ~3u)) {
        ret = -EFBIG;
        goto out_free;
    }
    ret = cyw43_backplane_write(nvram_address, buffer, nvram_size);
    if (ret < 0)
        goto out_free;

    token = nvram_size / 4u;
    token = (token & 0xffffu) | ((~token & 0xffffu) << 16);
    ret = cyw43_backplane_write32(cyw43_state.identity.ram_base +
                                   cyw43_state.identity.ram_size - 4u,
                                   token);
out_free:
    kfree(buffer);
    return ret;
}

static int cyw43_boot_firmware(uint32_t firmware_size, uint32_t nvram_size)
{
    uint32_t reset_vector = 0u;
    int ret;

    ret = cyw43_load_firmware(firmware_size, &reset_vector);
    if (ret < 0)
        return ret;
    ret = cyw43_load_nvram(nvram_size, firmware_size);
    if (ret < 0)
        return ret;

    ret = cyw43_backplane_write32(cyw43_state.identity.sdio_registers +
                                   CYW43_SDIO_INT_STATUS_OFFSET,
                                   0xffffffffu);
    if (ret < 0)
        return ret;
    if (reset_vector != 0u) {
        ret = cyw43_backplane_write32(0u, reset_vector);
        if (ret < 0)
            return ret;
    }
    return cyw43_core_reset(cyw43_state.identity.arm_wrapper,
                            CYW43_ARM_CR4_CPU_HALT, 0u);
}

static int cyw43_enable_ht_clock(void)
{
    uint8_t clock;
    uint64_t start;
    int ret;

    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_CHIP_CLOCK_CSR, 0u);
    if (ret < 0)
        return ret;
    cyw43_delay_us(1000u);
    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_CHIP_CLOCK_CSR,
                              CYW43_CLOCK_HT_AVAILABLE_REQUEST);
    if (ret < 0)
        return ret;

    start = arch_timer_counter();
    do {
        ret = bcm2835_sdio_readb(CYW43_SDIO_FUNCTION_BACKPLANE,
                                 CYW43_F1_CHIP_CLOCK_CSR, &clock);
        if (ret < 0)
            return ret;
        if (clock & CYW43_CLOCK_HT_AVAILABLE)
            break;
        arch_cpu_relax();
    } while (!cyw43_deadline_expired(start, CYW43_HT_TIMEOUT_MS));
    if (!(clock & CYW43_CLOCK_HT_AVAILABLE))
        return -ETIMEDOUT;
    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_CHIP_CLOCK_CSR,
                              clock | CYW43_CLOCK_FORCE_HT);
    if (ret < 0)
        return ret;
    cyw43_delay_us(10000u);
    return 0;
}

static int cyw43_keep_bus_awake(void)
{
    uint8_t sleep_csr = 0u;
    uint64_t start;
    uint32_t access_errors = 0u;
    int ret;

    ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                              CYW43_F1_SLEEP_CSR,
                              CYW43_SLEEP_CSR_KSO);
    if (ret < 0)
        return ret;

    cyw43_delay_us(CYW43_KSO_WAKE_DELAY_US);
    start = arch_timer_counter();
    do {
        ret = bcm2835_sdio_readb(CYW43_SDIO_FUNCTION_BACKPLANE,
                                 CYW43_F1_SLEEP_CSR, &sleep_csr);
        if (ret == 0) {
            access_errors = 0u;
            if ((sleep_csr & (CYW43_SLEEP_CSR_KSO |
                              CYW43_SLEEP_CSR_DEVICE_ON)) ==
                (CYW43_SLEEP_CSR_KSO | CYW43_SLEEP_CSR_DEVICE_ON))
                return 0;
        } else if (++access_errors > 5u) {
            return ret;
        }

        cyw43_delay_us(CYW43_KSO_RETRY_US);
        ret = bcm2835_sdio_writeb(CYW43_SDIO_FUNCTION_BACKPLANE,
                                  CYW43_F1_SLEEP_CSR,
                                  CYW43_SLEEP_CSR_KSO);
        if (ret < 0 && ++access_errors > 5u)
            return ret;
    } while (!cyw43_deadline_expired(start, CYW43_KSO_TIMEOUT_MS));

    KWARN("CYW43: KSO wake timeout sleep_csr=0x%02X\n", sleep_csr);
    return -ETIMEDOUT;
}

static int cyw43_enable_radio_function(void)
{
    uint8_t value;
    uint64_t start;
    int ret;

    ret = bcm2835_sdio_writeb(0u, CYW43_F2_BLOCK_SIZE_LOW,
                              (uint8_t)(CYW43_RADIO_BLOCK_SIZE & 0xffu));
    if (ret < 0)
        return ret;
    ret = bcm2835_sdio_writeb(0u, CYW43_F2_BLOCK_SIZE_HIGH,
                              (uint8_t)(CYW43_RADIO_BLOCK_SIZE >> 8));
    if (ret < 0)
        return ret;
    ret = cyw43_backplane_write32(cyw43_state.identity.sdio_registers +
                                   CYW43_SDIO_TO_SB_MAILBOX_DATA_OFFSET,
                                   CYW43_SDPCM_PROTOCOL_VERSION << 16);
    if (ret < 0)
        return ret;
    ret = cyw43_backplane_write32(cyw43_state.identity.sdio_registers +
                                   CYW43_SDIO_INT_MASK_OFFSET,
                                   CYW43_SDIO_INT_FLOW_CHANGE |
                                   CYW43_SDIO_INT_FRAME |
                                   CYW43_SDIO_INT_MAILBOX);
    if (ret < 0)
        return ret;

    ret = bcm2835_sdio_readb(0u, CYW43_CCCR_IO_ENABLE, &value);
    if (ret < 0)
        return ret;
    ret = bcm2835_sdio_writeb(0u, CYW43_CCCR_IO_ENABLE,
                              value | CYW43_CCCR_FUNCTION2_ENABLE);
    if (ret < 0)
        return ret;

    start = arch_timer_counter();
    do {
        ret = bcm2835_sdio_readb(0u, CYW43_CCCR_IO_READY, &value);
        if (ret < 0)
            return ret;
        if (value & CYW43_CCCR_FUNCTION2_ENABLE)
            break;
        arch_cpu_relax();
    } while (!cyw43_deadline_expired(start, CYW43_FUNCTION_TIMEOUT_MS));
    if (!(value & CYW43_CCCR_FUNCTION2_ENABLE))
        return -ETIMEDOUT;

    return bcm2835_sdio_writeb(0u, CYW43_CCCR_INTERRUPT_ENABLE,
                               CYW43_CCCR_INTERRUPT_MASTER |
                               CYW43_CCCR_INTERRUPT_FUNCTION1 |
                               CYW43_CCCR_INTERRUPT_FUNCTION2);
}

static int cyw43_wait_firmware_ready(void)
{
    uint64_t start = arch_timer_counter();

    do {
        uint32_t interrupts;
        int ret = cyw43_backplane_read32(
            cyw43_state.identity.sdio_registers +
            CYW43_SDIO_INT_STATUS_OFFSET, &interrupts);

        if (ret < 0)
            return ret;
        if (interrupts != 0u) {
            ret = cyw43_backplane_write32(
                cyw43_state.identity.sdio_registers +
                CYW43_SDIO_INT_STATUS_OFFSET, interrupts);
            if (ret < 0)
                return ret;
        }
        if (interrupts & CYW43_SDIO_INT_MAILBOX) {
            uint32_t mailbox;

            ret = cyw43_backplane_read32(
                cyw43_state.identity.sdio_registers +
                CYW43_SDIO_TO_HOST_MAILBOX_OFFSET, &mailbox);
            if (ret < 0)
                return ret;
            ret = cyw43_backplane_write32(
                cyw43_state.identity.sdio_registers +
                CYW43_SDIO_TO_SB_MAILBOX_OFFSET, 2u);
            if (ret < 0)
                return ret;
            if (mailbox & CYW43_SDIO_MAILBOX_FIRMWARE_READY)
                return 0;
        }
        arch_cpu_relax();
    } while (!cyw43_deadline_expired(start,
                                     CYW43_FIRMWARE_READY_TIMEOUT_MS));
    return -ETIMEDOUT;
}

static int cyw43_wait_frame_interrupt(uint32_t timeout_ms)
{
    uint64_t start = arch_timer_counter();

    do {
        uint32_t interrupts;
        int ret = cyw43_backplane_read32(
            cyw43_state.identity.sdio_registers +
            CYW43_SDIO_INT_STATUS_OFFSET, &interrupts);

        if (ret < 0)
            return ret;
        if (interrupts != 0u) {
            ret = cyw43_backplane_write32(
                cyw43_state.identity.sdio_registers +
                CYW43_SDIO_INT_STATUS_OFFSET, interrupts);
            if (ret < 0)
                return ret;
        }
        if (interrupts & CYW43_SDIO_INT_MAILBOX) {
            ret = cyw43_backplane_write32(
                cyw43_state.identity.sdio_registers +
                CYW43_SDIO_TO_SB_MAILBOX_OFFSET, 2u);
            if (ret < 0)
                return ret;
        }
        if (interrupts & CYW43_SDIO_INT_FRAME)
            return 0;
        arch_cpu_relax();
    } while (!cyw43_deadline_expired(start, timeout_ms));
    return -ETIMEDOUT;
}

static int cyw43_f2_write_packet(const uint8_t *packet,
                                 uint32_t protocol_length)
{
    uint32_t transfer_length = (protocol_length + 3u) & ~3u;

    if (!packet || protocol_length < CYW43_BCDC_DATA_OFFSET ||
        transfer_length > CYW43_SDPCM_PACKET_SIZE)
        return -EINVAL;
    return bcm2835_sdio_write(2u, CYW43_F2_FIFO_ADDRESS, packet,
                              transfer_length, false);
}

static int cyw43_f2_drain(uint32_t length)
{
    uint8_t scratch[64];

    while (length > 0u) {
        uint32_t chunk = length;
        int ret;

        if (chunk > sizeof(scratch))
            chunk = sizeof(scratch);
        ret = bcm2835_sdio_read(2u, CYW43_F2_FIFO_ADDRESS, scratch,
                                chunk, false);
        if (ret < 0)
            return ret;
        length -= chunk;
    }
    return 0;
}

static void cyw43_update_sdpcm_flow(const uint8_t *header, uint32_t length)
{
    uint8_t channel;
    uint8_t window;

    if (!header || length < CYW43_SDPCM_HEADER_SIZE)
        return;

    cyw43_state.wireless_flow_control = header[8];
    channel = header[5] & 0x0fu;
    if (channel >= 3u)
        return;
    window = header[9];

    /*
     * The firmware advertises an absolute, exclusive transmit window.
     * Validate it relative to the next sequence ArmOS will transmit, as the
     * SDPCM contract requires.  Comparing it with the previous window leaves
     * a stale grant behind as soon as an update crosses the 8-bit wrap.
     */
    if ((uint8_t)(window - cyw43_state.tx_sequence) >
        CYW43_TX_WINDOW_MAX_ADVANCE) {
        //KWARN("CYW43: SDPCM window clamp raw=%u txseq=%u rxseq=%u\n",
        //      window, cyw43_state.tx_sequence, header[4]);
        //window = (uint8_t)(cyw43_state.tx_sequence + 2u);
    }
    if (window != cyw43_state.tx_max) {
        //KWARN("CYW43: SDPCM window %u -> %u txseq=%u rxseq=%u "
        //      "channel=%u fc=0x%02X\n",
        //      cyw43_state.tx_max, window, cyw43_state.tx_sequence,
        //      header[4], channel, header[8]);
        for(int i=0; i<10000; i++);   // Delay to allow the firmware to process the window change
        cyw43_state.tx_max = window;
    }
}

static int cyw43_f2_read_packet(uint8_t *packet, uint32_t capacity,
                                bool wait_for_interrupt, uint32_t timeout_ms,
                                uint32_t *packet_length)
{
    uint8_t overflow_header[CYW43_SDPCM_HEADER_SIZE];
    uint16_t length;
    uint16_t inverse;
    int ret;

    if (!packet || capacity < CYW43_SDPCM_FRAME_TAG_SIZE || !packet_length)
        return -EINVAL;
    *packet_length = 0u;
    if (wait_for_interrupt) {
        ret = cyw43_wait_frame_interrupt(timeout_ms);
        if (ret < 0)
            return ret;
    }
    ret = bcm2835_sdio_read(2u, CYW43_F2_FIFO_ADDRESS, packet,
                            CYW43_SDPCM_FRAME_TAG_SIZE, false);
    if (ret < 0)
        return ret;

    length = cyw43_get_le16(packet);
    inverse = cyw43_get_le16(packet + 2u);
    if (length == 0u)
        return -EAGAIN;
    if ((uint16_t)(length ^ inverse) != 0xffffu ||
        length < CYW43_SDPCM_HEADER_SIZE)
        return -EIO;
    if (length > capacity) {
        memcpy(overflow_header, packet, CYW43_SDPCM_FRAME_TAG_SIZE);
        ret = bcm2835_sdio_read(2u, CYW43_F2_FIFO_ADDRESS,
                                overflow_header + CYW43_SDPCM_FRAME_TAG_SIZE,
                                CYW43_SDPCM_HEADER_SIZE -
                                CYW43_SDPCM_FRAME_TAG_SIZE, false);
        if (ret < 0)
            return ret;
        cyw43_update_sdpcm_flow(overflow_header, sizeof(overflow_header));
        ret = cyw43_f2_drain(length - CYW43_SDPCM_HEADER_SIZE);
        return ret < 0 ? ret : -EFBIG;
    }
    if (length > CYW43_SDPCM_FRAME_TAG_SIZE) {
        ret = bcm2835_sdio_read(2u, CYW43_F2_FIFO_ADDRESS,
                                packet + CYW43_SDPCM_FRAME_TAG_SIZE,
                                length - CYW43_SDPCM_FRAME_TAG_SIZE, false);
        if (ret < 0)
            return ret;
    }
    cyw43_update_sdpcm_flow(packet, length);
    *packet_length = length;
    return 0;
}

static void cyw43_set_join_failure(uint32_t event, uint32_t status,
                                   uint32_t reason)
{
    if (!cyw43_state.join_in_progress || cyw43_state.join_failed)
        return;
    cyw43_state.join_failed = true;
    cyw43_state.join_failure_event = event;
    cyw43_state.join_failure_status = status;
    cyw43_state.join_failure_reason = reason;
}

static int cyw43_process_event_packet(const uint8_t *packet, uint32_t length)
{
    const uint8_t *event;
    uint32_t header_length;
    uint32_t payload_offset;
    uint32_t event_type;
    uint32_t status;
    uint32_t reason;
    uint16_t flags;

    if (!packet || length < CYW43_SDPCM_HEADER_SIZE)
        return -EINVAL;
    header_length = packet[7];
    if (header_length < CYW43_SDPCM_HEADER_SIZE ||
        header_length + CYW43_BCDC_DATA_HEADER_SIZE > length)
        return -EIO;
    payload_offset = header_length + CYW43_BCDC_DATA_HEADER_SIZE +
        (uint32_t)packet[header_length + 3u] * 4u;
    if (payload_offset + CYW43_EVENT_ETHERNET_SIZE +
        CYW43_EVENT_VENDOR_HEADER_SIZE + CYW43_EVENT_MESSAGE_MIN_SIZE >
        length)
        return -EIO;
    if (cyw43_get_be16(packet + payload_offset + 12u) !=
        CYW43_EVENT_ETHERTYPE)
        return -EIO;

    event = packet + payload_offset + CYW43_EVENT_ETHERNET_SIZE +
        CYW43_EVENT_VENDOR_HEADER_SIZE;
    flags = cyw43_get_be16(event + 2u);
    event_type = cyw43_get_be32(event + 4u);
    status = cyw43_get_be32(event + 8u);
    reason = cyw43_get_be32(event + 12u);

    if (!cyw43_state.join_in_progress)
        return 0;
    switch (event_type) {
    case CYW43_EVENT_SET_SSID:
        if (status == CYW43_EVENT_STATUS_SUCCESS)
            cyw43_state.join_set_ssid = true;
        else
            cyw43_set_join_failure(event_type, status, reason);
        break;
    case CYW43_EVENT_LINK:
        if (status == CYW43_EVENT_STATUS_SUCCESS &&
            (flags & CYW43_EVENT_FLAG_LINK) != 0u) {
            cyw43_state.join_link = true;
            memcpy(cyw43_state.bssid, event + 24u,
                   sizeof(cyw43_state.bssid));
        } else {
            cyw43_set_join_failure(event_type, status, reason);
        }
        break;
    case CYW43_EVENT_PSK_SUP:
        if (status == CYW43_SUP_KEYED)
            cyw43_state.join_psk = true;
        else if (status == 7u)
            cyw43_set_join_failure(event_type, status, reason);
        break;
    case CYW43_EVENT_DEAUTH:
    case CYW43_EVENT_DEAUTH_IND:
    case CYW43_EVENT_DISASSOC:
    case CYW43_EVENT_DISASSOC_IND:
        cyw43_set_join_failure(event_type, status, reason);
        break;
    default:
        break;
    }
    return 0;
}

static int cyw43_process_data_packet(const uint8_t *packet, uint32_t length)
{
    uint32_t header_length;
    uint32_t payload_offset;
    uint32_t frame_length;

    if (!packet || length < CYW43_SDPCM_HEADER_SIZE)
        return -EINVAL;
    header_length = packet[7];
    if (header_length < CYW43_SDPCM_HEADER_SIZE ||
        header_length + CYW43_BCDC_DATA_HEADER_SIZE > length)
        return -EIO;
    payload_offset = header_length + CYW43_BCDC_DATA_HEADER_SIZE +
        (uint32_t)packet[header_length + 3u] * 4u;
    if (payload_offset > length)
        return -EIO;
    frame_length = length - payload_offset;
    if (frame_length < 14u)
        return -EIO;
    if (cyw43_state.device_registered)
        net_device_receive(&cyw43_state.device, packet + payload_offset,
                           frame_length);
    return 0;
}

static bool cyw43_txctl_window_open(void)
{
    uint8_t available = (uint8_t)(cyw43_state.tx_max -
                                  cyw43_state.tx_sequence);

    return available != 0u && (available & 0x80u) == 0u;
}

/*
 * Control traffic consumes the same SDPCM transmit window as data traffic.
 * While a control slot is unavailable, drain firmware frames so a window
 * update or an asynchronous event cannot remain queued behind the waiter.
 */
static int cyw43_wait_txctl_window(void)
{
    uint8_t packet[CYW43_SDPCM_PACKET_SIZE];
    uint64_t start;
    bool wait_for_interrupt = true;

    if (cyw43_txctl_window_open())
        return 0;

    start = arch_timer_counter();
    while (!cyw43_deadline_expired(start, CYW43_CONTROL_TIMEOUT_MS)) {
        uint32_t packet_length;
        uint8_t channel;
        int ret;

        ret = cyw43_f2_read_packet(packet, sizeof(packet),
                                   wait_for_interrupt,
                                   CYW43_CONTROL_POLL_MS, &packet_length);
        if (ret == -ETIMEDOUT || ret == -EAGAIN) {
            wait_for_interrupt = true;
            continue;
        }
        if (ret < 0)
            return ret;

        wait_for_interrupt = false;
        channel = packet[5] & 0x0fu;
        if (channel == CYW43_SDPCM_EVENT_CHANNEL) {
            ret = cyw43_process_event_packet(packet, packet_length);
            if (ret < 0)
                return ret;
        } else if (channel == CYW43_SDPCM_DATA_CHANNEL) {
            ret = cyw43_process_data_packet(packet, packet_length);
            if (ret < 0)
                return ret;
        }
        if (cyw43_txctl_window_open())
            return 0;
    }

    KWARN("CYW43: SDPCM control window timeout txseq=%u txmax=%u "
          "fc=0x%02X\n",
          cyw43_state.tx_sequence, cyw43_state.tx_max,
          cyw43_state.wireless_flow_control);
    return -ETIMEDOUT;
}

static bool cyw43_ram_address_valid(uint32_t address, uint32_t span)
{
    uint32_t base = cyw43_state.identity.ram_base;
    uint32_t size = cyw43_state.identity.ram_size;

    return address >= base && span <= size && address - base <= size - span;
}

static void cyw43_read_firmware_string(uint32_t address, char *text,
                                       uint32_t capacity)
{
    uint32_t index;

    text[0] = '\0';
    if (address == 0u || capacity == 0u ||
        !cyw43_ram_address_valid(address, capacity))
        return;
    if (cyw43_backplane_read(address, text, capacity) < 0) {
        text[0] = '\0';
        return;
    }
    text[capacity - 1u] = '\0';
    for (index = 0u; text[index] != '\0'; ++index) {
        uint8_t value = (uint8_t)text[index];

        if (value < 0x20u || value >= 0x7fu) {
            text[index] = '\0';
            break;
        }
    }
}

static void cyw43_dump_firmware_trap(uint32_t trap_addr)
{
    uint8_t data[CYW43_TRAP_INFO_SIZE];

    if (!cyw43_ram_address_valid(trap_addr, sizeof(data)) ||
        cyw43_backplane_read(trap_addr, data, sizeof(data)) < 0) {
        KWARN("CYW43: firmware trap record unavailable at 0x%08X\n",
              trap_addr);
        return;
    }
    KWARN("CYW43: dongle trap type=0x%08X epc=0x%08X cpsr=0x%08X "
          "spsr=0x%08X\n",
          cyw43_get_le32(data), cyw43_get_le32(data + 4u),
          cyw43_get_le32(data + 8u), cyw43_get_le32(data + 12u));
    KWARN("CYW43: dongle trap sp=0x%08X lr=0x%08X pc=0x%08X "
          "r0=0x%08X r1=0x%08X\n",
          cyw43_get_le32(data + 68u), cyw43_get_le32(data + 72u),
          cyw43_get_le32(data + 76u), cyw43_get_le32(data + 16u),
          cyw43_get_le32(data + 20u));
}

static void cyw43_dump_firmware_console(uint32_t console_addr)
{
    uint8_t header[12];
    uint32_t log_buffer;
    uint32_t log_size;
    uint32_t log_index;
    uint32_t offset;
    uint32_t line_length = 0u;
    uint8_t *data;
    char line[120];

    if (!cyw43_ram_address_valid(console_addr +
                                  CYW43_CONSOLE_LOG_BUF_OFFSET,
                                  sizeof(header)) ||
        cyw43_backplane_read(console_addr + CYW43_CONSOLE_LOG_BUF_OFFSET,
                             header, sizeof(header)) < 0)
        return;
    log_buffer = cyw43_get_le32(header);
    log_size = cyw43_get_le32(header + 4u);
    log_index = cyw43_get_le32(header + 8u);
    if (log_size == 0u || log_size > CYW43_CONSOLE_MAX_SIZE ||
        log_index > log_size ||
        !cyw43_ram_address_valid(log_buffer, log_size)) {
        KWARN("CYW43: firmware console unavailable buf=0x%08X size=%u "
              "idx=%u\n", log_buffer, log_size, log_index);
        return;
    }
    if (log_index == log_size)
        log_index = 0u;
    data = kmalloc(log_size);
    if (!data) {
        KWARN("CYW43: firmware console allocation failed (%u bytes)\n",
              log_size);
        return;
    }
    if (cyw43_backplane_read(log_buffer, data, log_size) < 0)
        goto out;

    KWARN("CYW43: firmware console (%u bytes, oldest first):\n", log_size);
    for (offset = 0u; offset < log_size; ++offset) {
        uint8_t value = data[(log_index + offset) % log_size];

        if (value == '\n') {
            if (line_length != 0u) {
                line[line_length] = '\0';
                kprintf("CYW43 fw> %s\n", line);
                line_length = 0u;
            }
            continue;
        }
        if (value < 0x20u || value >= 0x7fu)
            continue;
        if (line_length == sizeof(line) - 1u) {
            line[line_length] = '\0';
            kprintf("CYW43 fw> %s\n", line);
            line_length = 0u;
        }
        line[line_length++] = (char)value;
    }
    if (line_length != 0u) {
        line[line_length] = '\0';
        kprintf("CYW43 fw> %s\n", line);
    }
out:
    kfree(data);
}

/*
 * The running firmware replaces the NVRAM token in the last RAM word with
 * the address of its SDPCM shared area.  Read it only on a control timeout:
 * trap/assert state distinguishes a firmware failure from a lost host TX
 * frame, while the console usually records the last accepted operation.
 */
static void cyw43_dump_firmware_state(void)
{
    uint8_t shared[28];
    uint32_t shared_addr = 0u;
    uint32_t console_addr;
    uint32_t flags;
    uint32_t version;
    uint8_t clock = 0xffu;

    (void)bcm2835_sdio_readb(CYW43_SDIO_FUNCTION_BACKPLANE,
                             CYW43_F1_CHIP_CLOCK_CSR, &clock);
    KWARN("CYW43: bus state clock_csr=0x%02X\n", clock);

    if (cyw43_backplane_read32(cyw43_state.identity.ram_base +
                               cyw43_state.identity.ram_size - 4u,
                               &shared_addr) < 0)
        return;
    if ((shared_addr & 3u) != 0u ||
        !cyw43_ram_address_valid(shared_addr, sizeof(shared))) {
        KWARN("CYW43: firmware shared area pointer invalid (0x%08X)\n",
              shared_addr);
        return;
    }
    if (cyw43_backplane_read(shared_addr, shared, sizeof(shared)) < 0)
        return;

    flags = cyw43_get_le32(shared);
    version = flags & CYW43_SHARED_VERSION_MASK;
    KWARN("CYW43: firmware shared=0x%08X flags=0x%08X version=%u "
          "assert-built=%u assert=%u trap=%u\n",
          shared_addr, flags, version,
          (flags & CYW43_SHARED_FLAGS_ASSERT_BUILT) ? 1u : 0u,
          (flags & CYW43_SHARED_FLAGS_ASSERT) ? 1u : 0u,
          (flags & CYW43_SHARED_FLAGS_TRAP) ? 1u : 0u);
    if (version > CYW43_SHARED_VERSION_MAX) {
        KWARN("CYW43: unsupported firmware shared version %u\n", version);
        return;
    }
    if (flags & CYW43_SHARED_FLAGS_TRAP)
        cyw43_dump_firmware_trap(cyw43_get_le32(shared + 4u));
    if (flags & CYW43_SHARED_FLAGS_ASSERT) {
        char expression[80];
        char file[80];

        cyw43_read_firmware_string(cyw43_get_le32(shared + 8u),
                                   expression, sizeof(expression));
        cyw43_read_firmware_string(cyw43_get_le32(shared + 12u),
                                   file, sizeof(file));
        KWARN("CYW43: firmware assert \"%s\" at %s:%u\n", expression,
              file, cyw43_get_le32(shared + 16u));
    }
    console_addr = cyw43_get_le32(shared + CYW43_SHARED_CONSOLE_OFFSET);
    if (console_addr != 0u)
        cyw43_dump_firmware_console(console_addr);
}

static void cyw43_log_control_timeout(uint32_t command, const char *name,
                                      uint16_t request_id)
{
    uint32_t interrupts = 0xdeadbeefu;
    uint8_t tag[CYW43_SDPCM_FRAME_TAG_SIZE] = {0};
    uint8_t sleep_csr = 0xffu;
    uint16_t length;
    uint16_t inverse;
    bool valid_tag;
    int status_ret;
    int tag_ret;

    status_ret = cyw43_backplane_read32(
        cyw43_state.identity.sdio_registers +
        CYW43_SDIO_INT_STATUS_OFFSET, &interrupts);
    (void)bcm2835_sdio_readb(CYW43_SDIO_FUNCTION_BACKPLANE,
                             CYW43_F1_SLEEP_CSR, &sleep_csr);
    tag_ret = bcm2835_sdio_read(2u, CYW43_F2_FIFO_ADDRESS, tag,
                                sizeof(tag), false);
    length = cyw43_get_le16(tag);
    inverse = cyw43_get_le16(tag + 2u);
    valid_tag = tag_ret == 0 && length >= CYW43_SDPCM_HEADER_SIZE &&
        (uint16_t)(length ^ inverse) == 0xffffu;

    KWARN("CYW43: control timeout command=%u iovar=%s request=%u "
          "txseq=%u txmax=%u fc=0x%02X intstatus=0x%08X (%d) "
          "sleep=0x%02X tag=%02X%02X%02X%02X valid=%u (%d)\n",
          command, name ? name : "-", request_id,
          cyw43_state.tx_sequence, cyw43_state.tx_max,
          cyw43_state.wireless_flow_control, interrupts, status_ret,
          sleep_csr, tag[0], tag[1], tag[2], tag[3],
          valid_tag ? 1u : 0u, tag_ret);
    cyw43_dump_firmware_state();
}

static int cyw43_bcdc_ioctl(uint32_t command, const char *name,
                            bool write, const void *input,
                            uint32_t input_length, void *response,
                            uint32_t response_length)
{
    uint8_t transmit[CYW43_SDPCM_PACKET_SIZE];
    uint8_t receive[CYW43_SDPCM_PACKET_SIZE];
    uint32_t name_length = name ? (uint32_t)strlen(name) + 1u : 0u;
    uint32_t data_span = write ? name_length + input_length : name_length;
    uint32_t receive_span = name_length > response_length ?
        name_length : response_length;
    uint32_t wire_data_span;
    uint32_t protocol_length;
    uint32_t flags;
    uint16_t request_id;
    int ret;

    if ((input_length != 0u && !input) ||
        (response_length != 0u && !response))
        return -EINVAL;
    if (!write && receive_span > data_span)
        data_span = receive_span;
    /*
     * The firmware consumes a 32-bit-aligned BCDC payload.  The alignment is
     * part of the SDPCM frame contract, not merely padding added by CMD53:
     * both the CDC outlen field and the SDPCM frame tag must include it.
     */
    wire_data_span = (data_span + 3u) & ~3u;
    protocol_length = CYW43_BCDC_DATA_OFFSET + wire_data_span;
    if (protocol_length > sizeof(transmit))
        return -EFBIG;

    ret = cyw43_wait_txctl_window();
    if (ret < 0)
        return ret;

    memset(transmit, 0, sizeof(transmit));
    cyw43_put_le16(transmit, (uint16_t)protocol_length);
    cyw43_put_le16(transmit + 2u, (uint16_t)~protocol_length);
    transmit[4] = cyw43_state.tx_sequence;
    transmit[5] = CYW43_SDPCM_CONTROL_CHANNEL;
    transmit[7] = CYW43_SDPCM_HEADER_SIZE;
    cyw43_put_le32(transmit + 12u, command);
    cyw43_put_le16(transmit + 16u, (uint16_t)wire_data_span);

    request_id = ++cyw43_state.ioctl_request_id;
    if (request_id == 0u) {
        request_id = 1u;
        cyw43_state.ioctl_request_id = request_id;
    }
    flags = (uint32_t)request_id << 16;
    if (write)
        flags |= CYW43_BCDC_FLAG_SET;
    cyw43_put_le32(transmit + 20u, flags);
    if (name_length != 0u)
        memcpy(transmit + CYW43_BCDC_DATA_OFFSET, name, name_length);
    if (write && input_length != 0u) {
        memcpy(transmit + CYW43_BCDC_DATA_OFFSET + name_length,
               input, input_length);
    }

    /* The response serializes control traffic after the window grant. */
    ret = cyw43_f2_write_packet(transmit, protocol_length);
    if (ret < 0)
        return ret;
    cyw43_state.tx_sequence++;
    {
        uint64_t response_start = arch_timer_counter();

        bool wait_for_interrupt = true;

        while (!cyw43_deadline_expired(response_start,
                                       CYW43_CONTROL_TIMEOUT_MS)) {
            uint32_t received_length;
            uint32_t header_length;
            uint32_t response_command;
            uint32_t response_flags;
            uint32_t response_status;
            uint32_t payload_offset;
            uint32_t available;

            ret = cyw43_f2_read_packet(receive, sizeof(receive),
                                       wait_for_interrupt,
                                       CYW43_CONTROL_POLL_MS,
                                       &received_length);
            if (ret == -ETIMEDOUT) {
                /*
                 * A direct FIFO probe can time out instead of returning the
                 * zero tag used by the firmware to mark an empty queue.  In
                 * either case, rearm the frame indication before retrying.
                 */
                wait_for_interrupt = true;
                continue;
            }
            if (ret == -EAGAIN) {
                wait_for_interrupt = true;
                continue;
            }
            if (ret < 0)
                return ret;
            /*
             * One frame indication can cover several queued SDPCM frames.
             * Drain one frame at a time until a zero tag or an empty-FIFO
             * timeout tells us to rearm the interrupt.  nextlen is only a
             * batching hint and does not reliably announce async frames.
             */
            wait_for_interrupt = false;
            if (received_length == CYW43_SDPCM_HEADER_SIZE)
                continue;
            if ((receive[5] & 0x0fu) == CYW43_SDPCM_EVENT_CHANNEL) {
                ret = cyw43_process_event_packet(receive, received_length);
                if (ret < 0)
                    return ret;
                continue;
            }
            if ((receive[5] & 0x0fu) == CYW43_SDPCM_DATA_CHANNEL) {
                ret = cyw43_process_data_packet(receive, received_length);
                if (ret < 0)
                    return ret;
                continue;
            }
            if ((receive[5] & 0x0fu) != CYW43_SDPCM_CONTROL_CHANNEL)
                continue;
            header_length = receive[7];
            if (header_length < CYW43_SDPCM_HEADER_SIZE ||
                header_length + CYW43_BCDC_CONTROL_HEADER_SIZE >
                received_length)
                return -EIO;
            response_command = cyw43_get_le32(receive + header_length);
            response_flags = cyw43_get_le32(receive + header_length + 8u);
            response_status = cyw43_get_le32(receive + header_length + 12u);
            if ((uint16_t)(response_flags >> 16) != request_id ||
                response_command != command)
                continue;
            if ((response_flags & CYW43_BCDC_FLAG_ERROR) != 0u ||
                response_status != 0u) {
                if (write) {
                    KWARN("CYW43: control set command=%u iovar=%s rejected "
                          "flags=0x%08X status=0x%08X\n",
                          command, name ? name : "-", response_flags,
                          response_status);
                }
                return -EIO;
            }

            payload_offset = header_length + CYW43_BCDC_CONTROL_HEADER_SIZE;
            available = received_length - payload_offset;
            if (!write && response_length != 0u) {
                if (available < response_length)
                    return -EIO;
                memcpy(response, receive + payload_offset, response_length);
            }
            return 0;
        }
    }
    cyw43_log_control_timeout(command, name, request_id);
    return -ETIMEDOUT;
}

static int cyw43_set_var(const char *name, const void *data,
                         uint32_t length)
{
    return cyw43_bcdc_ioctl(CYW43_WLC_SET_VAR, name, true, data, length,
                            NULL, 0u);
}

static int cyw43_get_var(const char *name, void *data, uint32_t length)
{
    return cyw43_bcdc_ioctl(CYW43_WLC_GET_VAR, name, false, NULL, 0u,
                            data, length);
}

static int cyw43_set_ioctl_u32(uint32_t command, uint32_t value)
{
    uint8_t data[4];

    cyw43_put_le32(data, value);
    return cyw43_bcdc_ioctl(command, NULL, true, data, sizeof(data),
                            NULL, 0u);
}

static int cyw43_set_var_u32(const char *name, uint32_t value)
{
    uint8_t data[4];

    cyw43_put_le32(data, value);
    return cyw43_set_var(name, data, sizeof(data));
}

static int cyw43_set_var_u32_u32(const char *name, uint32_t first,
                                 uint32_t second)
{
    uint8_t data[8];

    cyw43_put_le32(data, first);
    cyw43_put_le32(data + 4u, second);
    return cyw43_set_var(name, data, sizeof(data));
}

static void cyw43_try_set_var_u32(const char *name, uint32_t value)
{
    int ret = cyw43_set_var_u32(name, value);

    if (ret < 0)
        KWARN("CYW43: optional station iovar %s unavailable (%d)\n",
              name, ret);
}

static void cyw43_event_mask_set(uint8_t mask[CYW43_EVENT_MASK_SIZE],
                                 uint32_t event)
{
    if (event < CYW43_EVENT_MASK_SIZE * 8u)
        mask[event / 8u] |= (uint8_t)(1u << (event & 7u));
}

static int cyw43_enable_station_events(void)
{
    uint8_t mask[CYW43_EVENT_MASK_SIZE];

    memset(mask, 0, sizeof(mask));
    cyw43_event_mask_set(mask, CYW43_EVENT_SET_SSID);
    cyw43_event_mask_set(mask, CYW43_EVENT_AUTH);
    cyw43_event_mask_set(mask, CYW43_EVENT_DEAUTH);
    cyw43_event_mask_set(mask, CYW43_EVENT_DEAUTH_IND);
    cyw43_event_mask_set(mask, CYW43_EVENT_ASSOC);
    cyw43_event_mask_set(mask, CYW43_EVENT_DISASSOC);
    cyw43_event_mask_set(mask, CYW43_EVENT_DISASSOC_IND);
    cyw43_event_mask_set(mask, CYW43_EVENT_LINK);
    cyw43_event_mask_set(mask, CYW43_EVENT_PSK_SUP);
    return cyw43_set_var("event_msgs", mask, sizeof(mask));
}

static int cyw43_prepare_station(const char country[3])
{
    uint8_t country_data[12];
    uint32_t country_code;
    int ret;

    country_code = (uint8_t)country[0] | ((uint32_t)(uint8_t)country[1] << 8);
    cyw43_put_le32(country_data, country_code);
    cyw43_put_le32(country_data + 4u, 0xffffffffu);
    cyw43_put_le32(country_data + 8u, country_code);
    ret = cyw43_set_var("country", country_data, sizeof(country_data));
    if (ret < 0) {
        KWARN("CYW43: station setup stage country failed (%d)\n", ret);
        return ret;
    }
    cyw43_delay_ms(50u);

    ret = cyw43_bcdc_ioctl(CYW43_WLC_UP, NULL, true, NULL, 0u,
                            NULL, 0u);
    if (ret < 0) {
        KWARN("CYW43: station setup stage up failed (%d)\n", ret);
        return ret;
    }
    cyw43_delay_ms(50u);

    ret = cyw43_enable_station_events();
    if (ret < 0) {
        KWARN("CYW43: station setup stage event_msgs failed (%d)\n", ret);
        return ret;
    }
    ret = cyw43_set_ioctl_u32(CYW43_WLC_SET_PM, 0u);
    if (ret < 0) {
        KWARN("CYW43: station setup stage pm failed (%d)\n", ret);
        return ret;
    }
    ret = cyw43_set_var_u32("assoc_listen", 10u);
    if (ret < 0) {
        KWARN("CYW43: station setup stage assoc_listen failed (%d)\n", ret);
        return ret;
    }
    ret = cyw43_set_var_u32("bus:txglom", 0u);
    if (ret < 0) {
        KWARN("CYW43: station setup stage txglom failed (%d)\n", ret);
        return ret;
    }
    cyw43_try_set_var_u32("bus:rxglom", 0u);
    ret = cyw43_set_var_u32("bcn_timeout", 10u);
    if (ret < 0) {
        KWARN("CYW43: station setup stage bcn_timeout failed (%d)\n", ret);
        return ret;
    }
    ret = cyw43_set_var_u32("assoc_retry_max", 3u);
    if (ret < 0) {
        KWARN("CYW43: station setup stage assoc_retry_max failed (%d)\n",
              ret);
        return ret;
    }
    ret = cyw43_set_var_u32("roam_off", 1u);
    if (ret < 0) {
        KWARN("CYW43: station setup stage roam_off failed (%d)\n", ret);
        return ret;
    }
    return 0;
}

static int cyw43_join_failed(const char *stage, int error)
{
    KWARN("CYW43: association stage %s failed (%d)\n", stage, error);
    return error;
}

static int cyw43_join_network(const cyw43_wifi_config_t *config)
{
    uint8_t pmk[4u + CYW43_WIFI_PASSWORD_MAX];
    uint8_t ssid[4u + CYW43_WIFI_SSID_MAX];
    uint32_t security;
    uint32_t wpa_auth;
    uint32_t ssid_length;
    int ret;

    if (!config)
        return -EINVAL;
    security = config->security == CYW43_WIFI_WPA2 ? CYW43_WSEC_AES : 0u;
    wpa_auth = config->security == CYW43_WIFI_WPA2 ?
        CYW43_WPA2_AUTH_PSK : 0u;

    /* Aggregation is configured once by cyw43_prepare_station(). */
    ret = cyw43_set_ioctl_u32(CYW43_WLC_SET_INFRA, 1u);
    if (ret < 0)
        return cyw43_join_failed("infra", ret);
    ret = cyw43_set_ioctl_u32(CYW43_WLC_SET_AUTH, 0u);
    if (ret < 0)
        return cyw43_join_failed("auth", ret);
    ret = cyw43_set_ioctl_u32(CYW43_WLC_SET_WSEC, security);
    if (ret < 0)
        return cyw43_join_failed("wsec", ret);
    ret = cyw43_set_var_u32_u32("bsscfg:sup_wpa", 0u,
                                security ? 1u : 0u);
    if (ret < 0)
        return cyw43_join_failed("sup_wpa", ret);
    ret = cyw43_set_var_u32_u32("bsscfg:sup_wpa2_eapver", 0u,
                                0xffffffffu);
    if (ret < 0)
        return cyw43_join_failed("sup_wpa2_eapver", ret);
    ret = cyw43_set_var_u32_u32("bsscfg:sup_wpa_tmo", 0u, 2500u);
    if (ret < 0)
        return cyw43_join_failed("sup_wpa_tmo", ret);

    if (config->security == CYW43_WIFI_WPA2) {
        uint16_t password_length = (uint16_t)strlen(config->password);

        memset(pmk, 0, sizeof(pmk));
        cyw43_put_le16(pmk, password_length);
        cyw43_put_le16(pmk + 2u, CYW43_WSEC_PASSPHRASE);
        memcpy(pmk + 4u, config->password, password_length);
        ret = cyw43_set_ioctl_u32(CYW43_WLC_SET_WPA_AUTH, wpa_auth);
        if (ret < 0)
            return cyw43_join_failed("wpa_auth", ret);
        cyw43_delay_ms(10u);
        ret = cyw43_bcdc_ioctl(CYW43_WLC_SET_WSEC_PMK, NULL, true,
                                pmk, sizeof(pmk), NULL, 0u);
        if (ret < 0)
            return cyw43_join_failed("wsec_pmk", ret);
        ret = cyw43_set_var_u32("mfp", CYW43_MFP_NONE);
        if (ret < 0)
            return cyw43_join_failed("mfp", ret);
    } else {
        ret = cyw43_set_ioctl_u32(CYW43_WLC_SET_WPA_AUTH, 0u);
        if (ret < 0)
            return cyw43_join_failed("wpa_auth", ret);
    }

    memset(ssid, 0, sizeof(ssid));
    ssid_length = (uint32_t)strlen(config->ssid);
    cyw43_put_le32(ssid, ssid_length);
    memcpy(ssid + 4u, config->ssid, ssid_length);
    cyw43_state.join_in_progress = true;
    cyw43_state.join_expect_psk = config->security == CYW43_WIFI_WPA2;
    cyw43_state.join_set_ssid = false;
    cyw43_state.join_link = false;
    cyw43_state.join_psk = false;
    cyw43_state.join_failed = false;
    cyw43_state.join_failure_event = 0u;
    cyw43_state.join_failure_status = 0u;
    cyw43_state.join_failure_reason = 0u;
    memset(cyw43_state.bssid, 0, sizeof(cyw43_state.bssid));
    ret = cyw43_bcdc_ioctl(CYW43_WLC_SET_SSID, NULL, true,
                           ssid, sizeof(ssid), NULL, 0u);
    if (ret < 0) {
        cyw43_state.join_in_progress = false;
        return cyw43_join_failed("set_ssid", ret);
    }
    return 0;
}

static bool cyw43_valid_bssid(const uint8_t bssid[6])
{
    bool all_zero = true;
    bool all_ff = true;

    for (uint32_t index = 0u; index < 6u; index++) {
        all_zero &= bssid[index] == 0u;
        all_ff &= bssid[index] == 0xffu;
    }
    return !all_zero && !all_ff;
}

static int cyw43_wait_association(void)
{
    uint8_t packet[CYW43_SDPCM_PACKET_SIZE];
    uint64_t start = arch_timer_counter();
    bool wait_for_interrupt = true;

    while (!cyw43_deadline_expired(start, CYW43_WIFI_JOIN_TIMEOUT_MS)) {
        uint32_t packet_length;
        bool complete;
        int ret;

        complete = cyw43_state.join_set_ssid && cyw43_state.join_link &&
            (!cyw43_state.join_expect_psk || cyw43_state.join_psk);
        if (complete) {
            uint8_t bssid[6];

            cyw43_state.join_in_progress = false;
            if (cyw43_valid_bssid(cyw43_state.bssid)) {
                cyw43_state.associated = true;
                return 0;
            }
            memset(bssid, 0, sizeof(bssid));
            ret = cyw43_bcdc_ioctl(CYW43_WLC_GET_BSSID, NULL, false,
                                    NULL, 0u, bssid, sizeof(bssid));
            if (ret < 0 || !cyw43_valid_bssid(bssid))
                return ret < 0 ? ret : -EIO;
            memcpy(cyw43_state.bssid, bssid, sizeof(bssid));
            cyw43_state.associated = true;
            return 0;
        }
        if (cyw43_state.join_failed) {
            KWARN("CYW43: association event=%u status=%u reason=%u\n",
                  cyw43_state.join_failure_event,
                  cyw43_state.join_failure_status,
                  cyw43_state.join_failure_reason);
            cyw43_state.join_in_progress = false;
            return -EIO;
        }

        ret = cyw43_f2_read_packet(packet, sizeof(packet),
                                   wait_for_interrupt,
                                   CYW43_CONTROL_POLL_MS, &packet_length);
        if (ret == -ETIMEDOUT) {
            wait_for_interrupt = true;
            continue;
        }
        if (ret == -EAGAIN) {
            wait_for_interrupt = true;
            continue;
        }
        if (ret < 0) {
            cyw43_state.join_in_progress = false;
            return ret;
        }
        wait_for_interrupt = false;
        if ((packet[5] & 0x0fu) == CYW43_SDPCM_EVENT_CHANNEL) {
            ret = cyw43_process_event_packet(packet, packet_length);
            if (ret < 0) {
                cyw43_state.join_in_progress = false;
                return ret;
            }
        } else if ((packet[5] & 0x0fu) == CYW43_SDPCM_DATA_CHANNEL) {
            ret = cyw43_process_data_packet(packet, packet_length);
            if (ret < 0) {
                cyw43_state.join_in_progress = false;
                return ret;
            }
        }
    }
    KWARN("CYW43: association timeout set_ssid=%u link=%u psk=%u\n",
          cyw43_state.join_set_ssid ? 1u : 0u,
          cyw43_state.join_link ? 1u : 0u,
          cyw43_state.join_psk ? 1u : 0u);
    cyw43_state.join_in_progress = false;
    return -ETIMEDOUT;
}

static int cyw43_prime_control_channel(void)
{
    uint8_t packet[64];

    memset(packet, 0, sizeof(packet));
    return bcm2835_sdio_read(2u, CYW43_F2_FIFO_ADDRESS, packet,
                             sizeof(packet), false);
}

static int cyw43_upload_clm(uint32_t clm_size)
{
    kernel_file_t file;
    uint8_t request[CYW43_CLM_HEADER_SIZE + CYW43_CLM_CHUNK_SIZE + 8u];
    uint32_t consumed = 0u;
    int ret;

    if (clm_size == 0u)
        return -ENOENT;
    ret = vfs_kernel_file_open(CYW43_CLM_PATH, &file);
    if (ret < 0)
        return ret;
    while (consumed < clm_size) {
        uint32_t remaining = clm_size - consumed;
        uint32_t chunk = remaining;
        uint32_t transfer_length;
        uint16_t clm_flags = CYW43_CLM_FLAG_HANDLER;
        ssize_t got;

        if (chunk > CYW43_CLM_CHUNK_SIZE)
            chunk = CYW43_CLM_CHUNK_SIZE;
        memset(request, 0, sizeof(request));
        got = vfs_kernel_file_read(&file, request + CYW43_CLM_HEADER_SIZE,
                                   chunk);
        if (got < 0) {
            ret = (int)got;
            goto out;
        }
        if ((uint32_t)got != chunk) {
            ret = -EIO;
            goto out;
        }
        if (consumed == 0u)
            clm_flags |= CYW43_CLM_FLAG_FIRST;
        if (consumed + chunk == clm_size)
            clm_flags |= CYW43_CLM_FLAG_LAST;

        transfer_length = chunk;
        if (clm_flags & CYW43_CLM_FLAG_LAST)
            transfer_length = (transfer_length + 7u) & ~7u;
        cyw43_put_le16(request, clm_flags);
        cyw43_put_le16(request + 2u, 2u);
        cyw43_put_le32(request + 4u, transfer_length);
        cyw43_put_le32(request + 8u, 0u);
        ret = cyw43_set_var("clmload", request,
                            CYW43_CLM_HEADER_SIZE + transfer_length);
        if (ret < 0)
            goto out;
        consumed += chunk;
    }
    ret = 0;
out:
    vfs_kernel_file_close(&file);
    return ret;
}

bool cyw43_is_radio_ready(void)
{
    return cyw43_state.radio_ready && cyw43_state.regulatory_ready;
}

int cyw43_get_mac_address(uint8_t address[6])
{
    if (!address)
        return -EINVAL;
    if (!cyw43_is_radio_ready())
        return -ENODEV;
    memcpy(address, cyw43_state.mac_address, 6u);
    return 0;
}

static void cyw43_receive_frame(net_device_t *device, const uint8_t *frame,
                                uint32_t length)
{
    (void)net_stack_receive(device, frame, length);
}

static int cyw43_device_poll(net_device_t *device)
{
    uint8_t packet[CYW43_SDPCM_PACKET_SIZE];
    bool wait_for_interrupt = true;
    uint32_t processed = 0u;

    (void)device;
    while (processed < 8u) {
        uint32_t packet_length = 0u;
        uint8_t channel;
        unsigned long flags;
        int ret;

        spin_lock_irqsave(&cyw43_data_lock, &flags);
        ret = cyw43_f2_read_packet(packet, sizeof(packet),
                                   wait_for_interrupt, 1u,
                                   &packet_length);
        spin_unlock_irqrestore(&cyw43_data_lock, flags);
        if (ret == -ETIMEDOUT || ret == -EAGAIN)
            return 0;
        if (ret < 0)
            return ret;
        wait_for_interrupt = false;
        processed++;
        channel = packet[5] & 0x0fu;
        if (channel == CYW43_SDPCM_EVENT_CHANNEL)
            ret = cyw43_process_event_packet(packet, packet_length);
        else if (channel == CYW43_SDPCM_DATA_CHANNEL)
            ret = cyw43_process_data_packet(packet, packet_length);
        else
            ret = 0;
        if (ret < 0)
            return ret;
    }
    return (int)processed;
}

static int cyw43_device_transmit(net_device_t *device, const uint8_t *frame,
                                 uint32_t length)
{
    uint8_t packet[CYW43_SDPCM_PACKET_SIZE];
    uint32_t protocol_length;
    uint32_t start;

    if (!device || !frame || length < 14u || length > device->mtu + 14u)
        return -EINVAL;
    protocol_length = CYW43_BCDC_DATA_FRAME_OFFSET + length;
    if (protocol_length > sizeof(packet))
        return -EFBIG;

    start = get_time_ms();
    while ((uint32_t)(get_time_ms() - start) < CYW43_CONTROL_TIMEOUT_MS) {
        unsigned long flags;
        int ret;

        spin_lock_irqsave(&cyw43_data_lock, &flags);
        if (!cyw43_txctl_window_open()) {
            spin_unlock_irqrestore(&cyw43_data_lock, flags);
            (void)cyw43_device_poll(device);
            task_sleep_ms(1u);
            continue;
        }
        memset(packet, 0, protocol_length);
        cyw43_put_le16(packet, (uint16_t)protocol_length);
        cyw43_put_le16(packet + 2u, (uint16_t)~protocol_length);
        packet[4] = cyw43_state.tx_sequence;
        packet[5] = CYW43_SDPCM_DATA_CHANNEL;
        packet[7] = CYW43_SDPCM_HEADER_SIZE;
        packet[CYW43_SDPCM_HEADER_SIZE] =
            CYW43_BCDC_PROTOCOL_VERSION << CYW43_BCDC_VERSION_SHIFT;
        memcpy(packet + CYW43_BCDC_DATA_FRAME_OFFSET, frame, length);
        ret = cyw43_f2_write_packet(packet, protocol_length);
        if (ret == 0)
            cyw43_state.tx_sequence++;
        spin_unlock_irqrestore(&cyw43_data_lock, flags);
        return ret;
    }
    return -ETIMEDOUT;
}

static void cyw43_device_shutdown(net_device_t *device)
{
    (void)device;
    cyw43_shutdown();
}

static const net_device_ops_t cyw43_device_ops = {
    .transmit = cyw43_device_transmit,
    .poll = cyw43_device_poll,
    .shutdown = cyw43_device_shutdown,
};

static int cyw43_register_network_device(void)
{
    int ret;

    if (cyw43_state.device_registered)
        return 0;
    memset(&cyw43_state.device, 0, sizeof(cyw43_state.device));
    cyw43_state.device.name = "wlan0";
    memcpy(cyw43_state.device.mac, cyw43_state.mac_address, 6u);
    cyw43_state.device.mtu = NET_DEVICE_DEFAULT_MTU;
    cyw43_state.device.ops = &cyw43_device_ops;
    cyw43_state.device.receive = cyw43_receive_frame;
    cyw43_state.device.driver_data = &cyw43_state;
    ret = net_device_register(&cyw43_state.device);
    if (ret < 0)
        return ret;
    ret = net_stack_attach(&cyw43_state.device, NET_CONFIG_DHCP, NULL);
    if (ret < 0)
        return ret;
    cyw43_state.device_registered = true;
    return 0;
}

int cyw43_start(void)
{
    cyw43_wifi_config_t wifi_config;
    uint32_t firmware_size;
    uint32_t nvram_size;
    uint32_t clm_size;
    bool have_wifi_config = false;
    int ret;

    if (!cyw43_state.present)
        return -ENODEV;
    ret = cyw43_check_firmware_file(CYW43_FIRMWARE_PATH, &firmware_size);
    if (ret < 0) {
        KBOOT_WARNF("WiFi: missing firmware %s", CYW43_FIRMWARE_PATH);
        return ret;
    }
    ret = cyw43_check_firmware_file(CYW43_NVRAM_PATH, &nvram_size);
    if (ret < 0) {
        KBOOT_WARNF("WiFi: missing NVRAM %s", CYW43_NVRAM_PATH);
        return ret;
    }
    ret = cyw43_check_firmware_file(CYW43_CLM_PATH, &clm_size);
    if (ret < 0)
        clm_size = 0u;

    cyw43_state.firmware_files_ready = true;
    ret = cyw43_boot_firmware(firmware_size, nvram_size);
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 firmware upload failed (%d)", ret);
        return ret;
    }
    cyw43_state.firmware_running = true;
    ret = cyw43_enable_ht_clock();
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 HT clock failed (%d)", ret);
        return ret;
    }
    ret = cyw43_enable_radio_function();
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 function 2 failed (%d)", ret);
        return ret;
    }
    ret = cyw43_wait_firmware_ready();
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 firmware ready timeout (%d)", ret);
        return ret;
    }
    ret = cyw43_keep_bus_awake();
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 KSO wake failed (%d)", ret);
        return ret;
    }
    ret = cyw43_prime_control_channel();
    if (ret < 0)
        KWARN("CYW43: initial function 2 read failed (%d)\n", ret);
    ret = cyw43_upload_clm(clm_size);
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 CLM upload failed (%d)", ret);
        return ret;
    }
    cyw43_state.regulatory_ready = true;
    ret = cyw43_get_var("cur_etheraddr", cyw43_state.mac_address,
                        sizeof(cyw43_state.mac_address));
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 MAC query failed (%d)", ret);
        return ret;
    }
    ret = cyw43_load_wifi_config(&wifi_config);
    if (ret == 0) {
        have_wifi_config = true;
    } else if (ret != -ENOENT) {
        KBOOT_WARNF("WiFi: invalid %s (%d)", CYW43_WIFI_CONFIG_PATH, ret);
        memset(&wifi_config, 0, sizeof(wifi_config));
        wifi_config.country[0] = '0';
        wifi_config.country[1] = '0';
    }
    ret = cyw43_prepare_station(wifi_config.country);
    if (ret < 0) {
        KBOOT_WARNF("WiFi: CYW43455 station setup failed (%d)", ret);
        return ret;
    }
    cyw43_state.radio_ready = true;
    KBOOT_OKF("WiFi: CYW43455 ready %02X:%02X:%02X:%02X:%02X:%02X",
              cyw43_state.mac_address[0], cyw43_state.mac_address[1],
              cyw43_state.mac_address[2], cyw43_state.mac_address[3],
              cyw43_state.mac_address[4], cyw43_state.mac_address[5]);
    KBOOT_OKF("WiFi: firmware %uK, NVRAM %u, CLM %u bytes",
              firmware_size / 1024u, nvram_size, clm_size);
    ret = cyw43_register_network_device();
    if (ret < 0) {
        KBOOT_WARNF("Net: CYW43455 device registration failed (%d)", ret);
        return ret;
    }
    if (!have_wifi_config) {
        net_device_set_link(&cyw43_state.device, NET_LINK_DOWN);
        KBOOT_WARNF("WiFi: no valid %s, radio idle",
                    CYW43_WIFI_CONFIG_PATH);
        KBOOT_WARN("Net: wlan0 waiting for WiFi association");
        return 0;
    }

    net_device_set_link(&cyw43_state.device, NET_LINK_ASSOCIATING);
    KBOOT_WARNF("WiFi: associating with %s", wifi_config.ssid);
    ret = cyw43_join_network(&wifi_config);
    if (ret < 0) {
        KBOOT_WARNF("WiFi: association request failed (%d)", ret);
        return ret;
    }
    ret = cyw43_wait_association();
    if (ret < 0) {
        KBOOT_WARNF("WiFi: association with %s timed out", wifi_config.ssid);
        return ret;
    }
    KBOOT_OKF("WiFi: associated with %s, BSSID %02X:%02X:%02X:%02X:%02X:%02X",
              wifi_config.ssid,
              cyw43_state.bssid[0], cyw43_state.bssid[1],
              cyw43_state.bssid[2], cyw43_state.bssid[3],
              cyw43_state.bssid[4], cyw43_state.bssid[5]);
    cyw43_state.associated = true;
    net_device_set_link(&cyw43_state.device, NET_LINK_UP);
    KBOOT_OK("Net: wlan0 Ethernet data path ready");
    return 0;
}

void cyw43_shutdown(void)
{
    cyw43_state.present = false;
    cyw43_state.firmware_files_ready = false;
    cyw43_state.firmware_running = false;
    cyw43_state.radio_ready = false;
    cyw43_state.regulatory_ready = false;
    cyw43_state.associated = false;
    cyw43_state.join_in_progress = false;
    cyw43_state.join_expect_psk = false;
    cyw43_state.join_set_ssid = false;
    cyw43_state.join_link = false;
    cyw43_state.join_psk = false;
    cyw43_state.join_failed = false;
    memset(cyw43_state.mac_address, 0, sizeof(cyw43_state.mac_address));
    memset(cyw43_state.bssid, 0, sizeof(cyw43_state.bssid));
    cyw43_state.backplane_window = 0xffffffffu;
}
