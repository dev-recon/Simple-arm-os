/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: include/kernel/ide.h
 * Layer: Kernel / public internal interface
 *
 * Responsibilities:
 * - Declare kernel types, constants, and subsystem contracts.
 * - Keep cross-module ABI and structure expectations explicit.
 *
 * Notes:
 * - Header changes can ripple across kernel and user ABI glue.
 */

#ifndef _KERNEL_IDE_H
#define _KERNEL_IDE_H

#include <kernel/arch_platform.h>
#include <kernel/types.h>

/* Legacy IDE fallback window selected by the current platform. */
#define IDE_PRIMARY_BASE    ARMOS_PLATFORM_IDE_PRIMARY_BASE
#define IDE_PRIMARY_CTRL    ARMOS_PLATFORM_IDE_PRIMARY_CTRL
#define IDE_PRIMARY_IRQ     ARMOS_PLATFORM_IDE_PRIMARY_IRQ

/* PCIe PIO legacy port aliases. */
#define IDE_PCIE_BASE       ARMOS_PLATFORM_PCIE_PIO_BASE
#define IDE_LEGACY_IO_BASE  ARMOS_PLATFORM_IDE_LEGACY_IO_BASE

/* IDE registers, relative to IDE_PRIMARY_BASE. */
#define IDE_REG_DATA        0x00    /* Data register */
#define IDE_REG_ERROR       0x01    /* Error register (read) */
#define IDE_REG_FEATURES    0x01    /* Features register (write) */
#define IDE_REG_SECCOUNT    0x02    /* Sector count */
#define IDE_REG_LBA_LOW     0x03    /* LBA bits 0-7 */
#define IDE_REG_LBA_MID     0x04    /* LBA bits 8-15 */
#define IDE_REG_LBA_HIGH    0x05    /* LBA bits 16-23 */
#define IDE_REG_DRIVE       0x06    /* Drive/Head register */
#define IDE_REG_STATUS      0x07    /* Status register (read) */
#define IDE_REG_COMMAND     0x07    /* Command register (write) */

/* Control registers, relative to IDE_PRIMARY_CTRL. */
#define IDE_REG_CTRL        0x00    /* Control register */
#define IDE_REG_ALTSTATUS   0x00    /* Alternate status */

/* IDE commands. */
#define IDE_CMD_READ_SECTORS    0x20
#define IDE_CMD_WRITE_SECTORS   0x30
#define IDE_CMD_IDENTIFY        0xEC

/* STATUS register bits. */
#define IDE_STATUS_BSY      0x80    /* Busy */
#define IDE_STATUS_DRDY     0x40    /* Drive ready */
#define IDE_STATUS_DF       0x20    /* Drive fault */
#define IDE_STATUS_DSC      0x10    /* Drive seek complete */
#define IDE_STATUS_DRQ      0x08    /* Data request */
#define IDE_STATUS_CORR     0x04    /* Correctable error */
#define IDE_STATUS_IDX      0x02    /* Index */
#define IDE_STATUS_ERR      0x01    /* Error */

/* DRIVE register bits. */
#define IDE_DRIVE_MASTER    0xA0    /* Master drive */
#define IDE_DRIVE_SLAVE     0xB0    /* Slave drive */
#define IDE_DRIVE_LBA       0x40    /* Use LBA addressing */

/* Automatic storage type detection. */
typedef enum {
    STORAGE_TYPE_NONE,
    STORAGE_TYPE_IDE,
    STORAGE_TYPE_VIRTIO_BLOCK,
    STORAGE_TYPE_AHCI
} storage_type_t;

/* Public entry points. */
void ide_irq_handler(void);
bool init_ide(void);
void ide_comprehensive_test(void);

/* Generic storage entry points. */
storage_type_t detect_storage_type(void);
bool init_storage(void);
bool storage_read_sector(uint32_t lba, uint8_t* buffer);
bool storage_write_sector(uint32_t lba, const uint8_t* buffer);

/* Generic storage test. */
void storage_comprehensive_test(void);

#endif
