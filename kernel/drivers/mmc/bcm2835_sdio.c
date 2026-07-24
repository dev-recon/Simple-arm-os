/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/mmc/bcm2835_sdio.c
 * Layer: Kernel / SDIO host controllers
 *
 * Responsibilities:
 * - Drive the BCM2837 Arasan controller as the Raspberry Pi 3 SDIO host.
 * - Negotiate the on-board Broadcom radio and expose CMD52/CMD53 transfers.
 * - Discover the SDIO identity without embedding Wi-Fi firmware policy.
 *
 * Notes:
 * - The system SD card must use BCM2835 SDHOST before this driver starts.
 * - Transfers are polling PIO while the CYW43455 transport is brought up.
 */

#include <kernel/arch_barrier.h>
#include <kernel/arch_cpu.h>
#include <kernel/arch_platform.h>
#include <kernel/gpio.h>
#include <kernel/kprintf.h>
#include <kernel/mmc/bcm2835_sdio.h>
#include <kernel/raspberrypi_mailbox.h>
#include <kernel/spinlock.h>
#include <kernel/task.h>
#include <kernel/timer.h>
#include <kernel/types.h>

#define SDIO_ARG2                    0x00u
#define SDIO_BLKSIZECNT              0x04u
#define SDIO_ARG1                    0x08u
#define SDIO_CMDTM                   0x0cu
#define SDIO_RESP0                   0x10u
#define SDIO_RESP1                   0x14u
#define SDIO_RESP2                   0x18u
#define SDIO_RESP3                   0x1cu
#define SDIO_DATA                    0x20u
#define SDIO_STATUS                  0x24u
#define SDIO_CONTROL0                0x28u
#define SDIO_CONTROL1                0x2cu
#define SDIO_INTERRUPT               0x30u
#define SDIO_IRPT_MASK               0x34u
#define SDIO_IRPT_EN                 0x38u

#define SDIO_STATUS_CMD_INHIBIT      (1u << 0)
#define SDIO_STATUS_DAT_INHIBIT      (1u << 1)

#define SDIO_CONTROL0_HCTL_DWIDTH    (1u << 1)
#define SDIO_CONTROL0_POWER_330_ON   (0x0fu << 8)

#define SDIO_CONTROL1_CLK_INTLEN     (1u << 0)
#define SDIO_CONTROL1_CLK_STABLE     (1u << 1)
#define SDIO_CONTROL1_CLK_EN         (1u << 2)
#define SDIO_CONTROL1_CLK_FREQ_MS2   (3u << 6)
#define SDIO_CONTROL1_CLK_FREQ8      (0xffu << 8)
#define SDIO_CONTROL1_DATA_TIMEOUT   (0xeu << 16)
#define SDIO_CONTROL1_SRST_HC        (1u << 24)
#define SDIO_CONTROL1_SRST_CMD       (1u << 25)
#define SDIO_CONTROL1_SRST_DATA      (1u << 26)

#define SDIO_INT_CMD_DONE            (1u << 0)
#define SDIO_INT_DATA_DONE           (1u << 1)
#define SDIO_INT_WRITE_RDY           (1u << 4)
#define SDIO_INT_READ_RDY            (1u << 5)
#define SDIO_INT_ERROR_MASK          0xffff8000u
#define SDIO_INT_ALL                 0xffffffffu

#define SDIO_CMD_RSP_NONE            0u
#define SDIO_CMD_RSP_48              (2u << 16)
#define SDIO_CMD_RSP_48_BUSY         (3u << 16)
#define SDIO_CMD_CRCCHK              (1u << 19)
#define SDIO_CMD_IXCHK               (1u << 20)
#define SDIO_CMD_ISDATA              (1u << 21)
#define SDIO_CMD_BLKCNT_EN           (1u << 1)
#define SDIO_CMD_READ                (1u << 4)
#define SDIO_CMD_MULTI_BLOCK         (1u << 5)

#define SDIO_BASE_CLOCK_HZ           250000000u
#define SDIO_INIT_CLOCK_HZ           400000u
#define SDIO_TRANSFER_CLOCK_HZ       25000000u
#define SDIO_TIMEOUT_MS              1000u
#define SDIO_POWER_OFF_MS            20u
#define SDIO_POWER_ON_MS             200u
#define SDIO_FIRMWARE_GPIO_WL_ON     129u

#define SDIO_CCCR_REVISION           0x00u
#define SDIO_CCCR_IO_ENABLE          0x02u
#define SDIO_CCCR_IO_READY           0x03u
#define SDIO_CCCR_BUS_INTERFACE      0x07u
#define SDIO_CCCR_CIS_POINTER        0x09u
#define SDIO_CCCR_SPEED              0x13u
#define SDIO_FBR_CIS_POINTER         0x09u
#define SDIO_FBR_BLOCK_SIZE_LOW      0x10u
#define SDIO_FBR_BLOCK_SIZE_HIGH     0x11u
#define SDIO_FBR_STRIDE              0x100u
#define SDIO_CISTPL_NULL             0x00u
#define SDIO_CISTPL_MANFID           0x20u
#define SDIO_CISTPL_END              0xffu

#define SDIO_R4_READY                (1u << 31)
#define SDIO_R4_FUNCTIONS_MASK       (7u << 28)
#define SDIO_R4_OCR_MASK             0x00ffffffu
#define SDIO_R5_ERROR_MASK           0x0000cb00u

#define SDIO_CMD52_WRITE             (1u << 31)
#define SDIO_CMD53_WRITE             (1u << 31)
#define SDIO_CMD53_BLOCK_MODE        (1u << 27)
#define SDIO_CMD53_INCREMENT         (1u << 26)
#define SDIO_ADDRESS_MASK            0x1ffffu
#define SDIO_MAX_FUNCTION            7u
#define SDIO_MAX_BYTE_TRANSFER       512u

typedef struct bcm2835_sdio_state {
    volatile uint8_t *base;
    bcm2835_sdio_identity_t identity;
    uint16_t function_block_size[SDIO_MAX_FUNCTION + 1u];
    bool ready;
    bool busy;
    task_t *owner;
} bcm2835_sdio_state_t;

static bcm2835_sdio_state_t sdio_state;
static spinlock_t sdio_lock = SPINLOCK_INIT("bcm_sdio");

static inline uint32_t sdio_read_reg(uint32_t offset)
{
    return *(volatile uint32_t *)(sdio_state.base + offset);
}

static inline void sdio_write_reg(uint32_t offset, uint32_t value)
{
    *(volatile uint32_t *)(sdio_state.base + offset) = value;
    arch_data_memory_barrier();
}

static inline void sdio_write_reg16(uint32_t offset, uint16_t value)
{
    *(volatile uint16_t *)(sdio_state.base + offset) = value;
    arch_data_memory_barrier();
}

static void sdio_write_cmdtm(uint32_t cmdtm)
{
    sdio_write_reg16(SDIO_CMDTM, (uint16_t)(cmdtm & 0xffffu));
    sdio_write_reg16(SDIO_CMDTM + 2u, (uint16_t)(cmdtm >> 16));
}

static uint64_t sdio_counter_delta(uint32_t timeout_ms)
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

static bool sdio_deadline_expired(uint64_t start, uint32_t timeout_ms)
{
    return arch_timer_counter() - start >= sdio_counter_delta(timeout_ms);
}

static void sdio_delay_ms(uint32_t delay_ms)
{
    uint64_t start = arch_timer_counter();

    while (!sdio_deadline_expired(start, delay_ms))
        arch_cpu_relax();
}

static bool sdio_wait_clear(uint32_t offset, uint32_t mask,
                            uint32_t timeout_ms)
{
    uint64_t start = arch_timer_counter();

    while (sdio_read_reg(offset) & mask) {
        if (sdio_deadline_expired(start, timeout_ms))
            return false;
        arch_cpu_relax();
    }
    return true;
}

static bool sdio_wait_set(uint32_t offset, uint32_t mask,
                          uint32_t timeout_ms)
{
    uint64_t start = arch_timer_counter();

    while ((sdio_read_reg(offset) & mask) != mask) {
        if (sdio_deadline_expired(start, timeout_ms))
            return false;
        arch_cpu_relax();
    }
    return true;
}

static int sdio_wait_interrupt(uint32_t mask, uint32_t timeout_ms)
{
    uint64_t start = arch_timer_counter();

    for (;;) {
        uint32_t interrupt = sdio_read_reg(SDIO_INTERRUPT);

        if (interrupt & SDIO_INT_ERROR_MASK)
            return -EIO;
        if (interrupt & mask)
            return 0;
        if (sdio_deadline_expired(start, timeout_ms))
            return -ETIMEDOUT;
        arch_cpu_relax();
    }
}

static void sdio_reset_command_data(void)
{
    uint32_t control = sdio_read_reg(SDIO_CONTROL1);

    control |= SDIO_CONTROL1_SRST_CMD | SDIO_CONTROL1_SRST_DATA;
    sdio_write_reg(SDIO_CONTROL1, control);
    (void)sdio_wait_clear(SDIO_CONTROL1,
                          SDIO_CONTROL1_SRST_CMD |
                          SDIO_CONTROL1_SRST_DATA,
                          SDIO_TIMEOUT_MS);
    sdio_write_reg(SDIO_INTERRUPT, SDIO_INT_ALL);
}

static bool sdio_set_clock(uint32_t target_hz)
{
    uint32_t divisor;
    uint32_t control;

    if (target_hz == 0u)
        return false;

    control = sdio_read_reg(SDIO_CONTROL1);
    control &= ~SDIO_CONTROL1_CLK_EN;
    sdio_write_reg(SDIO_CONTROL1, control);

    divisor = (SDIO_BASE_CLOCK_HZ + target_hz - 1u) / target_hz;
    if (divisor == 0u)
        divisor = 1u;
    if (divisor > 0x3ffu)
        divisor = 0x3ffu;

    control &= ~(SDIO_CONTROL1_CLK_FREQ8 |
                 SDIO_CONTROL1_CLK_FREQ_MS2);
    control |= SDIO_CONTROL1_CLK_INTLEN |
               SDIO_CONTROL1_DATA_TIMEOUT;
    control |= (divisor & 0xffu) << 8;
    control |= ((divisor >> 8) & 3u) << 6;
    sdio_write_reg(SDIO_CONTROL1, control);

    if (!sdio_wait_set(SDIO_CONTROL1, SDIO_CONTROL1_CLK_STABLE,
                       SDIO_TIMEOUT_MS))
        return false;
    sdio_write_reg(SDIO_CONTROL1, control | SDIO_CONTROL1_CLK_EN);
    return true;
}

static bool sdio_reset_host(void)
{
    uint32_t control;

    sdio_write_reg(SDIO_CONTROL0, 0u);
    sdio_write_reg(SDIO_IRPT_EN, 0u);
    sdio_write_reg(SDIO_IRPT_MASK, 0u);
    sdio_write_reg(SDIO_INTERRUPT, SDIO_INT_ALL);

    control = sdio_read_reg(SDIO_CONTROL1);
    sdio_write_reg(SDIO_CONTROL1, control | SDIO_CONTROL1_SRST_HC);
    if (!sdio_wait_clear(SDIO_CONTROL1, SDIO_CONTROL1_SRST_HC,
                         SDIO_TIMEOUT_MS)) {
        KERROR("bcm_sdio: host reset timeout\n");
        return false;
    }

    sdio_write_reg(SDIO_CONTROL0, SDIO_CONTROL0_POWER_330_ON);
    sdio_write_reg(SDIO_IRPT_EN, 0u);
    sdio_write_reg(SDIO_IRPT_MASK, SDIO_INT_ALL);
    sdio_write_reg(SDIO_INTERRUPT, SDIO_INT_ALL);
    return sdio_set_clock(SDIO_INIT_CLOCK_HZ);
}

static int sdio_send_command(uint32_t command, uint32_t argument,
                             uint32_t flags, uint32_t *response)
{
    uint32_t inhibit = SDIO_STATUS_CMD_INHIBIT;
    int ret;

    if (flags & SDIO_CMD_ISDATA)
        inhibit |= SDIO_STATUS_DAT_INHIBIT;
    if (!sdio_wait_clear(SDIO_STATUS, inhibit, SDIO_TIMEOUT_MS))
        return -ETIMEDOUT;

    sdio_write_reg(SDIO_INTERRUPT, SDIO_INT_ALL);
    sdio_write_reg(SDIO_ARG1, argument);
    sdio_write_cmdtm((command << 24) | flags);

    ret = sdio_wait_interrupt(SDIO_INT_CMD_DONE, SDIO_TIMEOUT_MS);
    if (ret < 0) {
        KERROR("bcm_sdio: CMD%u failed ret=%d irq=0x%08X "
               "status=0x%08X\n",
               command, ret, sdio_read_reg(SDIO_INTERRUPT),
               sdio_read_reg(SDIO_STATUS));
        sdio_reset_command_data();
        return ret;
    }

    if (response) {
        response[0] = sdio_read_reg(SDIO_RESP0);
        response[1] = sdio_read_reg(SDIO_RESP1);
        response[2] = sdio_read_reg(SDIO_RESP2);
        response[3] = sdio_read_reg(SDIO_RESP3);
    }
    sdio_write_reg(SDIO_INTERRUPT, SDIO_INT_CMD_DONE);

    if ((flags & SDIO_CMD_RSP_48_BUSY) == SDIO_CMD_RSP_48_BUSY &&
        !sdio_wait_clear(SDIO_STATUS, SDIO_STATUS_DAT_INHIBIT,
                         SDIO_TIMEOUT_MS))
        return -ETIMEDOUT;
    return 0;
}

static int sdio_cmd52(bool write, uint8_t function, uint32_t address,
                      uint8_t input, uint8_t *output)
{
    uint32_t response[4] = {0};
    uint32_t argument;
    int ret;

    if (function > SDIO_MAX_FUNCTION || address > SDIO_ADDRESS_MASK)
        return -EINVAL;

    argument = (write ? SDIO_CMD52_WRITE : 0u) |
        ((uint32_t)function << 28) |
        ((address & SDIO_ADDRESS_MASK) << 9) |
        input;
    ret = sdio_send_command(52u, argument,
                            SDIO_CMD_RSP_48 | SDIO_CMD_CRCCHK |
                            SDIO_CMD_IXCHK, response);
    if (ret < 0)
        return ret;
    if (response[0] & SDIO_R5_ERROR_MASK)
        return -EIO;
    if (output)
        *output = (uint8_t)(response[0] & 0xffu);
    if (write && function == 0u) {
        uint32_t fbr_function = address / SDIO_FBR_STRIDE;
        uint32_t fbr_offset = address % SDIO_FBR_STRIDE;

        if (fbr_function > 0u && fbr_function <= SDIO_MAX_FUNCTION) {
            if (fbr_offset == SDIO_FBR_BLOCK_SIZE_LOW) {
                sdio_state.function_block_size[fbr_function] =
                    (sdio_state.function_block_size[fbr_function] &
                     0xff00u) | input;
            } else if (fbr_offset == SDIO_FBR_BLOCK_SIZE_HIGH) {
                sdio_state.function_block_size[fbr_function] =
                    (sdio_state.function_block_size[fbr_function] &
                     0x00ffu) | ((uint16_t)input << 8);
            }
        }
    }
    return 0;
}

static int sdio_cmd53(bool write, uint8_t function, uint32_t address,
                      void *buffer, uint32_t length,
                      bool increment_address)
{
    uint8_t *bytes = (uint8_t *)buffer;
    uint32_t argument;
    uint32_t block_count;
    uint32_t block_size;
    uint32_t count;
    uint32_t ready_interrupt;
    uint32_t command_flags;
    uint32_t failed_block = 0u;
    bool block_mode = false;
    int ret;

    if (!buffer || function == 0u || function > SDIO_MAX_FUNCTION ||
        address > SDIO_ADDRESS_MASK || length == 0u ||
        length > SDIO_MAX_BYTE_TRANSFER)
        return -EINVAL;

    block_size = sdio_state.function_block_size[function];
    if (block_size != 0u && length >= block_size &&
        length % block_size == 0u) {
        block_mode = true;
        block_count = length / block_size;
        if (block_count > 512u)
            return -EINVAL;
        count = block_count == 512u ? 0u : block_count;
    } else {
        block_size = length;
        block_count = 1u;
        count = length == SDIO_MAX_BYTE_TRANSFER ? 0u : length;
    }
    argument = (write ? SDIO_CMD53_WRITE : 0u) |
        ((uint32_t)function << 28) |
        (block_mode ? SDIO_CMD53_BLOCK_MODE : 0u) |
        (increment_address ? SDIO_CMD53_INCREMENT : 0u) |
        ((address & SDIO_ADDRESS_MASK) << 9) | count;
    command_flags = SDIO_CMD_RSP_48 | SDIO_CMD_CRCCHK |
        SDIO_CMD_IXCHK | SDIO_CMD_ISDATA | SDIO_CMD_BLKCNT_EN;
    if (!write)
        command_flags |= SDIO_CMD_READ;
    if (block_count > 1u)
        command_flags |= SDIO_CMD_MULTI_BLOCK;

    sdio_write_reg(SDIO_BLKSIZECNT,
                   block_size | (block_count << 16));
    ret = sdio_send_command(53u, argument, command_flags, NULL);
    if (ret < 0)
        return ret;

    ready_interrupt = write ? SDIO_INT_WRITE_RDY : SDIO_INT_READ_RDY;
    for (uint32_t block = 0u; block < block_count; block++) {
        uint32_t block_offset = block * block_size;

        failed_block = block;
        ret = sdio_wait_interrupt(ready_interrupt, SDIO_TIMEOUT_MS);
        if (ret < 0)
            goto fail;
        sdio_write_reg(SDIO_INTERRUPT, ready_interrupt);

        for (uint32_t offset = 0u; offset < block_size; offset += 4u) {
            uint32_t absolute = block_offset + offset;
            uint32_t remaining = block_size - offset;

            if (write) {
                uint32_t word = bytes[absolute];

                if (remaining > 1u)
                    word |= (uint32_t)bytes[absolute + 1u] << 8;
                if (remaining > 2u)
                    word |= (uint32_t)bytes[absolute + 2u] << 16;
                if (remaining > 3u)
                    word |= (uint32_t)bytes[absolute + 3u] << 24;
                sdio_write_reg(SDIO_DATA, word);
            } else {
                uint32_t word = sdio_read_reg(SDIO_DATA);

                bytes[absolute] = (uint8_t)(word & 0xffu);
                if (remaining > 1u)
                    bytes[absolute + 1u] =
                        (uint8_t)((word >> 8) & 0xffu);
                if (remaining > 2u)
                    bytes[absolute + 2u] =
                        (uint8_t)((word >> 16) & 0xffu);
                if (remaining > 3u)
                    bytes[absolute + 3u] =
                        (uint8_t)((word >> 24) & 0xffu);
            }
        }
    }

    ret = sdio_wait_interrupt(SDIO_INT_DATA_DONE, SDIO_TIMEOUT_MS);
    if (ret < 0)
        goto fail;
    sdio_write_reg(SDIO_INTERRUPT, SDIO_INT_DATA_DONE);
    return 0;

fail:
    KERROR("bcm_sdio: CMD53 %s failed ret=%d fn=%u addr=0x%05X "
           "length=%u mode=%s block=%u/%u irq=0x%08X status=0x%08X\n",
           write ? "write" : "read", ret, function, address, length,
           block_mode ? "block" : "byte", failed_block + 1u,
           block_count, sdio_read_reg(SDIO_INTERRUPT),
           sdio_read_reg(SDIO_STATUS));
    sdio_reset_command_data();
    return ret;
}

static void sdio_acquire(void)
{
    for (;;) {
        task_t *task = task_current_local();
        unsigned long flags;

        spin_lock_irqsave(&sdio_lock, &flags);
        if (!sdio_state.busy) {
            sdio_state.busy = true;
            sdio_state.owner = task;
            spin_unlock_irqrestore(&sdio_lock, flags);
            return;
        }
        spin_unlock_irqrestore(&sdio_lock, flags);
        if (task)
            yield();
        else
            arch_cpu_relax();
    }
}

static void sdio_release(void)
{
    unsigned long flags;

    spin_lock_irqsave(&sdio_lock, &flags);
    sdio_state.busy = false;
    sdio_state.owner = NULL;
    spin_unlock_irqrestore(&sdio_lock, flags);
}

static int sdio_read_cis_pointer(uint32_t base, uint32_t *pointer)
{
    uint8_t byte0;
    uint8_t byte1;
    uint8_t byte2;
    int ret;

    ret = sdio_cmd52(false, 0u, base, 0u, &byte0);
    if (ret < 0)
        return ret;
    ret = sdio_cmd52(false, 0u, base + 1u, 0u, &byte1);
    if (ret < 0)
        return ret;
    ret = sdio_cmd52(false, 0u, base + 2u, 0u, &byte2);
    if (ret < 0)
        return ret;
    *pointer = (uint32_t)byte0 | ((uint32_t)byte1 << 8) |
        ((uint32_t)byte2 << 16);
    return 0;
}

static bool sdio_find_manfid(uint32_t pointer,
                             bcm2835_sdio_identity_t *identity)
{
    uint32_t traversed = 0u;

    while (pointer && pointer <= SDIO_ADDRESS_MASK && traversed < 512u) {
        uint8_t tuple;
        uint8_t length;

        if (sdio_cmd52(false, 0u, pointer++, 0u, &tuple) < 0)
            return false;
        traversed++;
        if (tuple == SDIO_CISTPL_END)
            break;
        if (tuple == SDIO_CISTPL_NULL)
            continue;
        if (sdio_cmd52(false, 0u, pointer++, 0u, &length) < 0)
            return false;
        traversed++;
        if (tuple == SDIO_CISTPL_MANFID && length >= 4u) {
            uint8_t data[4];

            for (uint32_t i = 0u; i < 4u; i++) {
                if (sdio_cmd52(false, 0u, pointer + i, 0u,
                               &data[i]) < 0)
                    return false;
            }
            identity->manufacturer =
                (uint16_t)data[0] | ((uint16_t)data[1] << 8);
            identity->product =
                (uint16_t)data[2] | ((uint16_t)data[3] << 8);
            return true;
        }
        pointer += length;
        traversed += length;
    }
    return false;
}

static void sdio_discover_identity(bcm2835_sdio_identity_t *identity)
{
    uint32_t pointer = 0u;

    if (sdio_read_cis_pointer(SDIO_CCCR_CIS_POINTER, &pointer) == 0 &&
        sdio_find_manfid(pointer, identity))
        return;

    pointer = 0u;
    if (sdio_read_cis_pointer(SDIO_FBR_STRIDE + SDIO_FBR_CIS_POINTER,
                              &pointer) == 0)
        (void)sdio_find_manfid(pointer, identity);
}

static bool sdio_configure_pins(void)
{
    if (!bcm283x_gpio_init())
        return false;
    if (gpio_configure(34u, GPIO_FUNCTION_ALT3, GPIO_PULL_NONE) < 0)
        return false;
    for (uint32_t pin = 35u; pin <= 39u; pin++) {
        if (gpio_configure(pin, GPIO_FUNCTION_ALT3, GPIO_PULL_UP) < 0)
            return false;
    }
    return true;
}

static void sdio_power_cycle_radio(void)
{
    if (!raspberrypi_set_firmware_gpio(SDIO_FIRMWARE_GPIO_WL_ON, false))
        KWARN("bcm_sdio: WL_ON firmware GPIO control unavailable\n");
    sdio_delay_ms(SDIO_POWER_OFF_MS);
    if (!raspberrypi_set_firmware_gpio(SDIO_FIRMWARE_GPIO_WL_ON, true))
        KWARN("bcm_sdio: continuing with firmware-provided WL_ON state\n");
    sdio_delay_ms(SDIO_POWER_ON_MS);
}

static int sdio_enable_function1(void)
{
    uint8_t enabled;
    uint64_t start;
    int ret;

    ret = sdio_cmd52(false, 0u, SDIO_CCCR_IO_ENABLE, 0u, &enabled);
    if (ret < 0)
        return ret;
    ret = sdio_cmd52(true, 0u, SDIO_CCCR_IO_ENABLE,
                     (uint8_t)(enabled | (1u << 1)), NULL);
    if (ret < 0)
        return ret;

    start = arch_timer_counter();
    do {
        uint8_t ready;

        ret = sdio_cmd52(false, 0u, SDIO_CCCR_IO_READY, 0u, &ready);
        if (ret < 0)
            return ret;
        if (ready & (1u << 1))
            return 0;
        arch_cpu_relax();
    } while (!sdio_deadline_expired(start, SDIO_TIMEOUT_MS));
    return -ETIMEDOUT;
}

bool bcm2835_sdio_init(bcm2835_sdio_identity_t *identity)
{
    uint32_t response[4] = {0};
    uint32_t ocr;
    uint8_t revision;
    uint8_t bus;
    int ret;

    if (!arch_platform_has_emmc() ||
        !arch_platform_kernel_mmio_emmc_base())
        return false;

    sdio_state.base = (volatile uint8_t *)(uintptr_t)
        arch_platform_kernel_mmio_emmc_base();
    sdio_state.identity.manufacturer = 0u;
    sdio_state.identity.product = 0u;
    sdio_state.identity.rca = 0u;
    sdio_state.identity.functions = 0u;
    sdio_state.identity.cccr_revision = 0u;
    sdio_state.identity.sdio_revision = 0u;
    for (uint32_t function = 0u; function <= SDIO_MAX_FUNCTION;
         function++)
        sdio_state.function_block_size[function] = 0u;
    sdio_state.ready = false;
    sdio_state.busy = false;
    sdio_state.owner = NULL;

    if (!sdio_configure_pins()) {
        KERROR("bcm_sdio: GPIO34-39 configuration failed\n");
        return false;
    }
    sdio_power_cycle_radio();
    if (!sdio_reset_host())
        return false;

    ret = sdio_send_command(0u, 0u, SDIO_CMD_RSP_NONE, NULL);
    if (ret < 0)
        return false;

    ret = sdio_send_command(5u, 0u, SDIO_CMD_RSP_48, response);
    if (ret < 0)
        return false;
    ocr = response[0] & SDIO_R4_OCR_MASK;
    if (ocr == 0u)
        ocr = 0x00200000u;

    for (uint32_t retry = 0u; retry < 1000u; retry++) {
        ret = sdio_send_command(5u, ocr, SDIO_CMD_RSP_48, response);
        if (ret < 0)
            return false;
        if (response[0] & SDIO_R4_READY)
            break;
        sdio_delay_ms(1u);
    }
    if (!(response[0] & SDIO_R4_READY)) {
        KERROR("bcm_sdio: radio did not leave idle state r4=0x%08X\n",
               response[0]);
        return false;
    }
    sdio_state.identity.functions =
        (uint8_t)((response[0] & SDIO_R4_FUNCTIONS_MASK) >> 28);

    ret = sdio_send_command(3u, 0u,
                            SDIO_CMD_RSP_48 | SDIO_CMD_CRCCHK |
                            SDIO_CMD_IXCHK, response);
    if (ret < 0)
        return false;
    sdio_state.identity.rca = (uint16_t)(response[0] >> 16);

    ret = sdio_send_command(7u,
                            (uint32_t)sdio_state.identity.rca << 16,
                            SDIO_CMD_RSP_48_BUSY | SDIO_CMD_CRCCHK |
                            SDIO_CMD_IXCHK, NULL);
    if (ret < 0)
        return false;

    ret = sdio_cmd52(false, 0u, SDIO_CCCR_REVISION, 0u, &revision);
    if (ret < 0)
        return false;
    sdio_state.identity.cccr_revision = revision & 0x0fu;
    sdio_state.identity.sdio_revision = revision >> 4;

    ret = sdio_cmd52(false, 0u, SDIO_CCCR_BUS_INTERFACE, 0u, &bus);
    if (ret < 0)
        return false;
    ret = sdio_cmd52(true, 0u, SDIO_CCCR_BUS_INTERFACE,
                     (uint8_t)((bus & ~3u) | 2u), NULL);
    if (ret < 0)
        return false;
    sdio_write_reg(SDIO_CONTROL0,
                   sdio_read_reg(SDIO_CONTROL0) |
                   SDIO_CONTROL0_HCTL_DWIDTH);
    if (!sdio_set_clock(SDIO_TRANSFER_CLOCK_HZ))
        return false;

    sdio_discover_identity(&sdio_state.identity);
    ret = sdio_enable_function1();
    if (ret < 0) {
        KERROR("bcm_sdio: function 1 enable failed ret=%d\n", ret);
        return false;
    }

    sdio_state.ready = true;
    if (identity)
        *identity = sdio_state.identity;
    return true;
}

bool bcm2835_sdio_is_ready(void)
{
    return sdio_state.ready;
}

void bcm2835_sdio_shutdown(void)
{
    if (!sdio_state.base)
        return;
    sdio_state.ready = false;
    sdio_reset_command_data();
    (void)raspberrypi_set_firmware_gpio(SDIO_FIRMWARE_GPIO_WL_ON, false);
}

int bcm2835_sdio_readb(uint8_t function, uint32_t address, uint8_t *value)
{
    int ret;

    if (!sdio_state.ready || !value)
        return -ENODEV;
    sdio_acquire();
    ret = sdio_cmd52(false, function, address, 0u, value);
    sdio_release();
    return ret;
}

int bcm2835_sdio_writeb(uint8_t function, uint32_t address, uint8_t value)
{
    int ret;

    if (!sdio_state.ready)
        return -ENODEV;
    sdio_acquire();
    ret = sdio_cmd52(true, function, address, value, NULL);
    sdio_release();
    return ret;
}

int bcm2835_sdio_read(uint8_t function, uint32_t address, void *buffer,
                      uint32_t length, bool increment_address)
{
    int ret;

    if (!sdio_state.ready)
        return -ENODEV;
    sdio_acquire();
    ret = sdio_cmd53(false, function, address, buffer, length,
                     increment_address);
    sdio_release();
    return ret;
}

int bcm2835_sdio_write(uint8_t function, uint32_t address,
                       const void *buffer, uint32_t length,
                       bool increment_address)
{
    int ret;

    if (!sdio_state.ready)
        return -ENODEV;
    sdio_acquire();
    ret = sdio_cmd53(true, function, address, (void *)buffer, length,
                     increment_address);
    sdio_release();
    return ret;
}
