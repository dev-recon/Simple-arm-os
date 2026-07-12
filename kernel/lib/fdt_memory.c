/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dependency-free FDT memory topology reader for early boot.
 */

#include <kernel/fdt.h>

#define FDT_MAX_DEPTH 16u

enum fdt_node_kind {
    FDT_NODE_OTHER = 0,
    FDT_NODE_MEMORY,
    FDT_NODE_RESERVED_CONTAINER,
    FDT_NODE_RESERVED_CHILD,
};

static uint32_t read_be32(const void *pointer)
{
    uint32_t value = *(const uint32_t *)pointer;
    return __builtin_bswap32(value);
}

static uint64_t read_be64(const void *pointer)
{
    uint64_t value = *(const uint64_t *)pointer;
    return __builtin_bswap64(value);
}

static bool ranges_fit(uint32_t offset, uint32_t length, uint32_t total)
{
    return offset <= total && length <= total - offset;
}

static bool name_equals(const char *name, uint32_t available,
                        const char *expected)
{
    uint32_t index = 0;

    while (index < available && expected[index] != '\0') {
        if (name[index] != expected[index])
            return false;
        index++;
    }
    return index < available && expected[index] == '\0' && name[index] == '\0';
}

static bool node_matches(const char *name, uint32_t available,
                         const char *prefix)
{
    uint32_t index = 0;

    while (index < available && prefix[index] != '\0') {
        if (name[index] != prefix[index])
            return false;
        index++;
    }
    return index < available && prefix[index] == '\0' &&
           (name[index] == '\0' || name[index] == '@');
}

static bool find_terminated_name(const uint8_t *start, const uint8_t *end,
                                 uint32_t *length)
{
    const uint8_t *cursor = start;

    while (cursor < end && *cursor != '\0')
        cursor++;
    if (cursor == end)
        return false;

    *length = (uint32_t)(cursor - start) + 1u;
    return true;
}

static bool decode_cells(const uint8_t *data, uint32_t cells, uint64_t *value)
{
    if (cells == 1) {
        *value = read_be32(data);
        return true;
    }
    if (cells == 2) {
        *value = ((uint64_t)read_be32(data) << 32) | read_be32(data + 4);
        return true;
    }
    return false;
}

static bool value_fits_paddr(uint64_t value)
{
    return (uint64_t)(paddr_t)value == value;
}

static bool append_range(fdt_memory_range_t *ranges, uint32_t *count,
                         uint32_t capacity, uint64_t start, uint64_t size)
{
    if (size == 0)
        return true;
    if (*count >= capacity || !value_fits_paddr(start) ||
        !value_fits_paddr(size) || start + size < start ||
        !value_fits_paddr(start + size - 1u))
        return false;

    ranges[*count].start = (paddr_t)start;
    ranges[*count].size = (paddr_t)size;
    (*count)++;
    return true;
}

static bool decode_reg_ranges(const uint8_t *data, uint32_t length,
                              uint32_t address_cells, uint32_t size_cells,
                              fdt_memory_range_t *ranges, uint32_t *count,
                              uint32_t capacity)
{
    uint32_t tuple_cells = address_cells + size_cells;
    uint32_t tuple_bytes;
    uint32_t offset;

    if (tuple_cells == 0 || tuple_cells > 4)
        return false;
    tuple_bytes = tuple_cells * 4u;
    if (length == 0 || length % tuple_bytes != 0)
        return false;

    for (offset = 0; offset < length; offset += tuple_bytes) {
        uint64_t start;
        uint64_t size;

        if (!decode_cells(data + offset, address_cells, &start) ||
            !decode_cells(data + offset + address_cells * 4u,
                          size_cells, &size) ||
            !append_range(ranges, count, capacity, start, size))
            return false;
    }
    return true;
}

static bool read_reservation_map(const uint8_t *blob, uint32_t limit,
                                 uint32_t offset, fdt_memory_layout_t *layout)
{
    const uint8_t *cursor;
    const uint8_t *end = blob + limit;

    if (!ranges_fit(offset, 16u, limit))
        return false;
    cursor = blob + offset;

    while (cursor + 16u <= end) {
        uint64_t start = read_be64(cursor);
        uint64_t size = read_be64(cursor + 8);
        cursor += 16;

        if (start == 0 && size == 0)
            return true;
        if (!append_range(layout->reserved, &layout->reserved_count,
                          FDT_RESERVED_MAX_RANGES, start, size))
            return false;
    }
    return false;
}

bool fdt_read_memory_layout(void *dtb_ptr, fdt_memory_layout_t *layout)
{
    const uint8_t *blob = (const uint8_t *)dtb_ptr;
    const struct fdt_header *header = (const struct fdt_header *)dtb_ptr;
    const uint8_t *cursor;
    const uint8_t *struct_end;
    const uint8_t *strings;
    uint32_t total;
    uint32_t struct_offset;
    uint32_t struct_size;
    uint32_t strings_offset;
    uint32_t strings_size;
    uint32_t address_cells = 2;
    uint32_t size_cells = 1;
    uint32_t reserved_address_cells = 2;
    uint32_t reserved_size_cells = 1;
    enum fdt_node_kind node_kinds[FDT_MAX_DEPTH];
    uint32_t depth = 0;
    bool have_root = false;

    if (!dtb_ptr || !layout || read_be32(&header->magic) != FDT_MAGIC)
        return false;

    total = read_be32(&header->totalsize);
    struct_offset = read_be32(&header->off_dt_struct);
    struct_size = read_be32(&header->size_dt_struct);
    strings_offset = read_be32(&header->off_dt_strings);
    strings_size = read_be32(&header->size_dt_strings);
    if (total < sizeof(*header) ||
        !ranges_fit(struct_offset, struct_size, total) ||
        !ranges_fit(strings_offset, strings_size, total))
        return false;

    layout->memory_count = 0;
    layout->reserved_count = 0;
    layout->dtb_start = (paddr_t)(uintptr_t)dtb_ptr;
    layout->dtb_size = (paddr_t)total;

    if (!read_reservation_map(blob, struct_offset,
                              read_be32(&header->off_mem_rsvmap), layout) ||
        !append_range(layout->reserved, &layout->reserved_count,
                      FDT_RESERVED_MAX_RANGES,
                      (uint64_t)(uintptr_t)dtb_ptr, total))
        return false;

    cursor = blob + struct_offset;
    struct_end = cursor + struct_size;
    strings = blob + strings_offset;

    while (cursor + 4u <= struct_end) {
        uint32_t token = read_be32(cursor);
        cursor += 4;

        if (token == FDT_BEGIN_NODE) {
            uint32_t name_length;
            enum fdt_node_kind kind = FDT_NODE_OTHER;

            if (depth >= FDT_MAX_DEPTH ||
                !find_terminated_name(cursor, struct_end, &name_length))
                return false;

            if (!have_root) {
                have_root = true;
            } else if (depth == 1 &&
                       node_matches((const char *)cursor, name_length, "memory")) {
                kind = FDT_NODE_MEMORY;
            } else if (depth == 1 &&
                       name_equals((const char *)cursor, name_length,
                                   "reserved-memory")) {
                kind = FDT_NODE_RESERVED_CONTAINER;
                reserved_address_cells = address_cells;
                reserved_size_cells = size_cells;
            } else if (depth > 0 &&
                       node_kinds[depth - 1] == FDT_NODE_RESERVED_CONTAINER) {
                kind = FDT_NODE_RESERVED_CHILD;
            }

            node_kinds[depth++] = kind;
            cursor += (name_length + 3u) & ~3u;
            if (cursor > struct_end)
                return false;
            continue;
        }

        if (token == FDT_END_NODE) {
            if (depth == 0)
                return false;
            depth--;
            continue;
        }

        if (token == FDT_PROP) {
            uint32_t length;
            uint32_t name_offset;
            const char *property_name;
            enum fdt_node_kind kind;

            if (depth == 0 || cursor + 8u > struct_end)
                return false;
            length = read_be32(cursor);
            name_offset = read_be32(cursor + 4);
            cursor += 8;
            if (length > (uint32_t)(struct_end - cursor) ||
                name_offset >= strings_size)
                return false;
            property_name = (const char *)(strings + name_offset);
            if (!find_terminated_name((const uint8_t *)property_name,
                                      strings + strings_size, &name_offset))
                return false;

            kind = node_kinds[depth - 1];
            if (depth == 1 && length >= 4 &&
                name_equals(property_name, name_offset, "#address-cells")) {
                address_cells = read_be32(cursor);
            } else if (depth == 1 && length >= 4 &&
                       name_equals(property_name, name_offset, "#size-cells")) {
                size_cells = read_be32(cursor);
            } else if (kind == FDT_NODE_RESERVED_CONTAINER && length >= 4 &&
                       name_equals(property_name, name_offset, "#address-cells")) {
                reserved_address_cells = read_be32(cursor);
            } else if (kind == FDT_NODE_RESERVED_CONTAINER && length >= 4 &&
                       name_equals(property_name, name_offset, "#size-cells")) {
                reserved_size_cells = read_be32(cursor);
            } else if (kind == FDT_NODE_MEMORY &&
                       name_equals(property_name, name_offset, "reg")) {
                if (!decode_reg_ranges(cursor, length, address_cells, size_cells,
                                       layout->memory, &layout->memory_count,
                                       FDT_MEMORY_MAX_RANGES))
                    return false;
            } else if (kind == FDT_NODE_RESERVED_CHILD &&
                       name_equals(property_name, name_offset, "reg")) {
                if (!decode_reg_ranges(cursor, length,
                                       reserved_address_cells,
                                       reserved_size_cells,
                                       layout->reserved,
                                       &layout->reserved_count,
                                       FDT_RESERVED_MAX_RANGES))
                    return false;
            }

            cursor += (length + 3u) & ~3u;
            if (cursor > struct_end)
                return false;
            continue;
        }

        if (token == FDT_NOP)
            continue;
        if (token == FDT_END)
            return depth == 0 && layout->memory_count != 0;
        return false;
    }

    return false;
}
