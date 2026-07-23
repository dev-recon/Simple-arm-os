/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/net/stack.c
 * Layer: Kernel / network core
 *
 * Responsibilities:
 * - Implement Ethernet ARP, IPv4, ICMP echo and a DHCPv4 client.
 * - Hold interface addressing independently from hardware drivers.
 * - Poll registered NICs from the common netd kernel task.
 *
 * Notes:
 * - The initial stack intentionally handles one IPv4 address and a compact
 *   ARP cache per interface. TCP remains in the existing VirtIO backend until
 *   the socket layer is extracted into this common subsystem.
 */

#include <kernel/address_space.h>
#include <kernel/arch_memory.h>
#include <kernel/kprintf.h>
#include <kernel/net/stack.h>
#include <kernel/process.h>
#include <kernel/stdarg.h>
#include <kernel/string.h>
#include <kernel/task.h>
#include <kernel/timer.h>

#define NET_STACK_MAX_INTERFACES 4u
#define NET_ETH_HEADER_SIZE      14u
#define NET_ETH_FRAME_MAX        1514u
#define NET_ETH_TYPE_IPV4        0x0800u
#define NET_ETH_TYPE_ARP         0x0806u
#define NET_ARP_HTYPE_ETHERNET   1u
#define NET_ARP_REQUEST          1u
#define NET_ARP_REPLY            2u
#define NET_IP_PROTO_ICMP        1u
#define NET_IP_PROTO_UDP         17u
#define NET_ICMP_ECHO_REPLY      0u
#define NET_ICMP_ECHO_REQUEST    8u
#define NET_DHCP_CLIENT_PORT     68u
#define NET_DHCP_SERVER_PORT     67u
#define NET_DHCP_MAGIC           0x63825363u
#define NET_DHCP_DISCOVER        1u
#define NET_DHCP_OFFER           2u
#define NET_DHCP_REQUEST         3u
#define NET_DHCP_ACK             5u
#define NET_DHCP_NAK             6u
#define NET_DHCP_TIMEOUT_MS      5000u
#define NET_DHCP_RETRY_MS        5000u
#define NET_ARP_TIMEOUT_MS       1000u
#define NETD_PRIORITY            9u

typedef struct net_eth_header {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed)) net_eth_header_t;

typedef struct net_arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t operation;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} __attribute__((packed)) net_arp_packet_t;

typedef struct net_ipv4_header {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t source[4];
    uint8_t destination[4];
} __attribute__((packed)) net_ipv4_header_t;

typedef struct net_udp_header {
    uint16_t source_port;
    uint16_t destination_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed)) net_udp_header_t;

typedef struct net_icmp_header {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed)) net_icmp_header_t;

typedef struct net_dhcp_packet {
    uint8_t operation;
    uint8_t hardware_type;
    uint8_t hardware_length;
    uint8_t hops;
    uint32_t xid;
    uint16_t seconds;
    uint16_t flags;
    uint8_t client_ip[4];
    uint8_t your_ip[4];
    uint8_t server_ip[4];
    uint8_t relay_ip[4];
    uint8_t client_mac[16];
    uint8_t server_name[64];
    uint8_t boot_file[128];
    uint32_t magic;
    uint8_t options[];
} __attribute__((packed)) net_dhcp_packet_t;

typedef enum net_dhcp_state {
    NET_DHCP_IDLE = 0,
    NET_DHCP_WAIT_OFFER,
    NET_DHCP_HAVE_OFFER,
    NET_DHCP_WAIT_ACK,
    NET_DHCP_BOUND,
    NET_DHCP_FAILED,
} net_dhcp_state_t;

typedef struct net_interface {
    net_device_t *device;
    net_config_method_t method;
    net_ipv4_config_t config;
    bool dhcp_pending;
    uint32_t dhcp_retry_at;
    uint32_t dhcp_xid;
    net_dhcp_state_t dhcp_state;
    net_ipv4_config_t offer;
    uint32_t offered_address;
    uint32_t arp_address;
    uint8_t arp_mac[6];
    bool arp_valid;
    bool ping_pending;
    bool ping_received;
    uint32_t ping_address;
    uint16_t ping_identifier;
    uint16_t ping_sequence;
    uint8_t ping_ttl;
    uint32_t ping_started_ms;
    uint32_t ping_elapsed_ms;
} net_interface_t;

static net_interface_t interfaces[NET_STACK_MAX_INTERFACES];
static uint32_t interface_count;
static task_t *netd_task;

static uint16_t net_be16(uint16_t value)
{
    return (uint16_t)((value << 8) | (value >> 8));
}

static uint32_t net_be32(uint32_t value)
{
    return ((value & 0x000000ffu) << 24) |
           ((value & 0x0000ff00u) << 8) |
           ((value & 0x00ff0000u) >> 8) |
           ((value & 0xff000000u) >> 24);
}

static uint16_t net_checksum(const void *data, uint32_t length)
{
    const uint8_t *bytes = data;
    uint32_t sum = 0u;

    while (length >= 2u) {
        sum += ((uint16_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        length -= 2u;
    }
    if (length != 0u)
        sum += (uint16_t)bytes[0] << 8;
    while ((sum >> 16) != 0u)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t net_ip_from_bytes(const uint8_t address[4])
{
    return ((uint32_t)address[0] << 24) |
           ((uint32_t)address[1] << 16) |
           ((uint32_t)address[2] << 8) |
           address[3];
}

static void net_ip_to_bytes(uint32_t address, uint8_t bytes[4])
{
    bytes[0] = (uint8_t)(address >> 24);
    bytes[1] = (uint8_t)(address >> 16);
    bytes[2] = (uint8_t)(address >> 8);
    bytes[3] = (uint8_t)address;
}

void net_stack_format_ipv4(uint32_t address, char *text, uint32_t capacity)
{
    if (!text || capacity == 0u)
        return;
    snprintf(text, capacity, "%u.%u.%u.%u",
             (address >> 24) & 0xffu, (address >> 16) & 0xffu,
             (address >> 8) & 0xffu, address & 0xffu);
}

int net_stack_parse_ipv4(const char *text, uint32_t *address)
{
    uint32_t parts[4] = {0};
    uint32_t part = 0u;
    uint32_t digits = 0u;
    const char *cursor;

    if (!text || !address || *text == '\0')
        return -EINVAL;
    cursor = text;
    while (*cursor != '\0') {
        if (*cursor >= '0' && *cursor <= '9') {
            digits++;
            parts[part] = parts[part] * 10u + (uint32_t)(*cursor - '0');
            if (digits > 3u || parts[part] > 255u)
                return -EINVAL;
        } else if (*cursor == '.' && part < 3u && digits != 0u) {
            part++;
            digits = 0u;
        } else {
            return -EINVAL;
        }
        cursor++;
    }
    if (part != 3u || digits == 0u)
        return -EINVAL;
    *address = (parts[0] << 24) | (parts[1] << 16) |
               (parts[2] << 8) | parts[3];
    return 0;
}

static net_interface_t *net_interface_for_device(net_device_t *device)
{
    uint32_t index;

    for (index = 0u; index < interface_count; index++) {
        if (interfaces[index].device == device)
            return &interfaces[index];
    }
    return NULL;
}

static int net_send_arp(net_interface_t *interface, uint16_t operation,
                        const uint8_t destination[6],
                        const uint8_t target_mac[6], uint32_t target_ip)
{
    uint8_t frame[NET_ETH_HEADER_SIZE + sizeof(net_arp_packet_t)];
    net_eth_header_t *ethernet = (net_eth_header_t *)frame;
    net_arp_packet_t *arp = (net_arp_packet_t *)(frame + NET_ETH_HEADER_SIZE);

    memcpy(ethernet->dst, destination, 6u);
    memcpy(ethernet->src, interface->device->mac, 6u);
    ethernet->type = net_be16(NET_ETH_TYPE_ARP);
    arp->htype = net_be16(NET_ARP_HTYPE_ETHERNET);
    arp->ptype = net_be16(NET_ETH_TYPE_IPV4);
    arp->hlen = 6u;
    arp->plen = 4u;
    arp->operation = net_be16(operation);
    memcpy(arp->sender_mac, interface->device->mac, 6u);
    net_ip_to_bytes(interface->config.address, arp->sender_ip);
    memcpy(arp->target_mac, target_mac, 6u);
    net_ip_to_bytes(target_ip, arp->target_ip);
    return net_device_transmit(interface->device, frame, sizeof(frame));
}

static int net_send_arp_request(net_interface_t *interface,
                                uint32_t address)
{
    static const uint8_t broadcast[6] =
        {0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu};
    static const uint8_t zero[6] = {0};

    return net_send_arp(interface, NET_ARP_REQUEST, broadcast, zero, address);
}

static int net_send_ipv4(net_interface_t *interface,
                         const uint8_t destination_mac[6],
                         uint32_t source, uint32_t destination,
                         uint8_t protocol, const uint8_t *payload,
                         uint32_t payload_length)
{
    uint8_t frame[NET_ETH_FRAME_MAX];
    net_eth_header_t *ethernet = (net_eth_header_t *)frame;
    net_ipv4_header_t *ip =
        (net_ipv4_header_t *)(frame + NET_ETH_HEADER_SIZE);
    uint32_t frame_length = NET_ETH_HEADER_SIZE + sizeof(*ip) + payload_length;

    if (!payload || frame_length > sizeof(frame))
        return -EFBIG;
    memcpy(ethernet->dst, destination_mac, 6u);
    memcpy(ethernet->src, interface->device->mac, 6u);
    ethernet->type = net_be16(NET_ETH_TYPE_IPV4);
    memset(ip, 0, sizeof(*ip));
    ip->version_ihl = 0x45u;
    ip->total_length = net_be16((uint16_t)(sizeof(*ip) + payload_length));
    ip->identification = net_be16((uint16_t)get_time_ms());
    ip->fragment = net_be16(0x4000u);
    ip->ttl = 64u;
    ip->protocol = protocol;
    net_ip_to_bytes(source, ip->source);
    net_ip_to_bytes(destination, ip->destination);
    ip->checksum = net_be16(net_checksum(ip, sizeof(*ip)));
    memcpy(frame + NET_ETH_HEADER_SIZE + sizeof(*ip), payload,
           payload_length);
    return net_device_transmit(interface->device, frame, frame_length);
}

static int net_send_dhcp(net_interface_t *interface, uint8_t message_type)
{
    uint8_t udp_payload[548];
    uint8_t transport[sizeof(net_udp_header_t) + sizeof(udp_payload)];
    net_udp_header_t *udp = (net_udp_header_t *)transport;
    net_dhcp_packet_t *dhcp =
        (net_dhcp_packet_t *)(transport + sizeof(*udp));
    uint8_t *option;
    uint32_t dhcp_length;
    uint32_t transport_length;
    static const uint8_t broadcast[6] =
        {0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu};

    memset(transport, 0, sizeof(transport));
    dhcp->operation = 1u;
    dhcp->hardware_type = 1u;
    dhcp->hardware_length = 6u;
    dhcp->xid = net_be32(interface->dhcp_xid);
    dhcp->flags = net_be16(0x8000u);
    memcpy(dhcp->client_mac, interface->device->mac, 6u);
    dhcp->magic = net_be32(NET_DHCP_MAGIC);
    option = dhcp->options;
    *option++ = 53u;
    *option++ = 1u;
    *option++ = message_type;
    *option++ = 61u;
    *option++ = 7u;
    *option++ = 1u;
    memcpy(option, interface->device->mac, 6u);
    option += 6u;
    if (message_type == NET_DHCP_REQUEST) {
        *option++ = 50u;
        *option++ = 4u;
        net_ip_to_bytes(interface->offered_address, option);
        option += 4u;
        if (interface->offer.dhcp_server != 0u) {
            *option++ = 54u;
            *option++ = 4u;
            net_ip_to_bytes(interface->offer.dhcp_server, option);
            option += 4u;
        }
    }
    *option++ = 55u;
    *option++ = 4u;
    *option++ = 1u;
    *option++ = 3u;
    *option++ = 6u;
    *option++ = 51u;
    *option++ = 57u;
    *option++ = 2u;
    *option++ = 0x05u;
    *option++ = 0xdcu;
    *option++ = 255u;
    dhcp_length = (uint32_t)(option - (uint8_t *)dhcp);
    udp->source_port = net_be16(NET_DHCP_CLIENT_PORT);
    udp->destination_port = net_be16(NET_DHCP_SERVER_PORT);
    udp->length = net_be16((uint16_t)(sizeof(*udp) + dhcp_length));
    udp->checksum = 0u;
    transport_length = sizeof(*udp) + dhcp_length;

    return net_send_ipv4(interface, broadcast, 0u, 0xffffffffu,
                         NET_IP_PROTO_UDP, transport, transport_length);
}

static bool net_dhcp_option_u32(const uint8_t *options, uint32_t length,
                                uint8_t wanted, uint32_t *value)
{
    uint32_t offset = 0u;

    while (offset < length) {
        uint8_t type = options[offset++];
        uint8_t span;

        if (type == 255u)
            break;
        if (type == 0u)
            continue;
        if (offset >= length)
            break;
        span = options[offset++];
        if (span > length - offset)
            break;
        if (type == wanted && span == 4u) {
            *value = net_ip_from_bytes(options + offset);
            return true;
        }
        offset += span;
    }
    return false;
}

static uint8_t net_dhcp_message_type(const uint8_t *options, uint32_t length)
{
    uint32_t offset = 0u;

    while (offset < length) {
        uint8_t type = options[offset++];
        uint8_t span;

        if (type == 255u)
            break;
        if (type == 0u)
            continue;
        if (offset >= length)
            break;
        span = options[offset++];
        if (span > length - offset)
            break;
        if (type == 53u && span == 1u)
            return options[offset];
        offset += span;
    }
    return 0u;
}

static bool net_receive_dhcp(net_interface_t *interface,
                             const uint8_t *payload, uint32_t length)
{
    const net_udp_header_t *udp;
    const net_dhcp_packet_t *dhcp;
    uint32_t udp_length;
    uint32_t dhcp_length;
    uint32_t options_length;
    uint8_t type;

    if (length < sizeof(*udp) + sizeof(*dhcp))
        return false;
    udp = (const net_udp_header_t *)payload;
    if (net_be16(udp->source_port) != NET_DHCP_SERVER_PORT ||
        net_be16(udp->destination_port) != NET_DHCP_CLIENT_PORT)
        return false;
    udp_length = net_be16(udp->length);
    if (udp_length < sizeof(*udp) + sizeof(*dhcp) || udp_length > length)
        return true;
    dhcp = (const net_dhcp_packet_t *)(payload + sizeof(*udp));
    dhcp_length = udp_length - sizeof(*udp);
    if (dhcp->operation != 2u || dhcp->hardware_type != 1u ||
        dhcp->hardware_length != 6u ||
        net_be32(dhcp->xid) != interface->dhcp_xid ||
        net_be32(dhcp->magic) != NET_DHCP_MAGIC ||
        memcmp(dhcp->client_mac, interface->device->mac, 6u) != 0)
        return true;
    options_length = dhcp_length - sizeof(*dhcp);
    type = net_dhcp_message_type(dhcp->options, options_length);
    if (type == NET_DHCP_OFFER &&
        interface->dhcp_state == NET_DHCP_WAIT_OFFER) {
        memset(&interface->offer, 0, sizeof(interface->offer));
        interface->offered_address = net_ip_from_bytes(dhcp->your_ip);
        (void)net_dhcp_option_u32(dhcp->options, options_length, 1u,
                                  &interface->offer.netmask);
        (void)net_dhcp_option_u32(dhcp->options, options_length, 3u,
                                  &interface->offer.gateway);
        (void)net_dhcp_option_u32(dhcp->options, options_length, 6u,
                                  &interface->offer.dns);
        (void)net_dhcp_option_u32(dhcp->options, options_length, 51u,
                                  &interface->offer.lease_seconds);
        (void)net_dhcp_option_u32(dhcp->options, options_length, 54u,
                                  &interface->offer.dhcp_server);
        interface->dhcp_state = NET_DHCP_HAVE_OFFER;
    } else if (type == NET_DHCP_ACK &&
               interface->dhcp_state == NET_DHCP_WAIT_ACK) {
        interface->config = interface->offer;
        interface->config.address = net_ip_from_bytes(dhcp->your_ip);
        if (interface->config.address == 0u)
            interface->config.address = interface->offered_address;
        interface->config.configured = true;
        interface->config.dhcp = true;
        interface->dhcp_state = NET_DHCP_BOUND;
    } else if (type == NET_DHCP_NAK) {
        interface->dhcp_state = NET_DHCP_FAILED;
    }
    return true;
}

static bool net_receive_arp(net_interface_t *interface,
                            const net_eth_header_t *ethernet,
                            const uint8_t *payload, uint32_t length)
{
    const net_arp_packet_t *arp;
    uint16_t operation;
    uint32_t sender_ip;
    uint32_t target_ip;

    (void)ethernet;
    if (length < sizeof(*arp))
        return true;
    arp = (const net_arp_packet_t *)payload;
    if (net_be16(arp->htype) != NET_ARP_HTYPE_ETHERNET ||
        net_be16(arp->ptype) != NET_ETH_TYPE_IPV4 ||
        arp->hlen != 6u || arp->plen != 4u)
        return true;
    operation = net_be16(arp->operation);
    sender_ip = net_ip_from_bytes(arp->sender_ip);
    target_ip = net_ip_from_bytes(arp->target_ip);
    if (sender_ip != 0u) {
        interface->arp_address = sender_ip;
        memcpy(interface->arp_mac, arp->sender_mac, 6u);
        interface->arp_valid = true;
    }
    if (operation == NET_ARP_REQUEST && interface->config.configured &&
        target_ip == interface->config.address) {
        (void)net_send_arp(interface, NET_ARP_REPLY, arp->sender_mac,
                           arp->sender_mac, sender_ip);
    }
    return true;
}

static bool net_receive_icmp(net_interface_t *interface,
                             const net_eth_header_t *ethernet,
                             const net_ipv4_header_t *ip,
                             const uint8_t *payload, uint32_t length)
{
    const net_icmp_header_t *icmp;

    if (length < sizeof(*icmp) || net_checksum(payload, length) != 0u)
        return true;
    icmp = (const net_icmp_header_t *)payload;
    if (icmp->type == NET_ICMP_ECHO_REPLY && icmp->code == 0u &&
        interface->ping_pending &&
        net_be16(icmp->identifier) == interface->ping_identifier &&
        net_be16(icmp->sequence) == interface->ping_sequence &&
        net_ip_from_bytes(ip->source) == interface->ping_address) {
        interface->ping_received = true;
        interface->ping_pending = false;
        interface->ping_ttl = ip->ttl;
        interface->ping_elapsed_ms = get_time_ms() - interface->ping_started_ms;
        return true;
    }
    if (icmp->type == NET_ICMP_ECHO_REQUEST && icmp->code == 0u &&
        interface->config.configured) {
        uint8_t response[NET_ETH_FRAME_MAX];
        net_icmp_header_t *reply = (net_icmp_header_t *)response;

        if (length > sizeof(response))
            return true;
        memcpy(response, payload, length);
        reply->type = NET_ICMP_ECHO_REPLY;
        reply->checksum = 0u;
        reply->checksum = net_be16(net_checksum(response, length));
        (void)net_send_ipv4(interface, ethernet->src,
                            interface->config.address,
                            net_ip_from_bytes(ip->source),
                            NET_IP_PROTO_ICMP, response, length);
    }
    return true;
}

bool net_stack_receive(net_device_t *device, const uint8_t *frame,
                       uint32_t length)
{
    net_interface_t *interface = net_interface_for_device(device);
    const net_eth_header_t *ethernet;
    const net_ipv4_header_t *ip;
    const uint8_t *payload;
    uint32_t payload_length;
    uint32_t ip_length;
    uint32_t ihl;
    uint16_t type;

    if (!interface || !frame || length < NET_ETH_HEADER_SIZE)
        return false;
    ethernet = (const net_eth_header_t *)frame;
    type = net_be16(ethernet->type);
    payload = frame + NET_ETH_HEADER_SIZE;
    payload_length = length - NET_ETH_HEADER_SIZE;
    if (type == NET_ETH_TYPE_ARP)
        return net_receive_arp(interface, ethernet, payload, payload_length);
    if (type != NET_ETH_TYPE_IPV4 || payload_length < sizeof(*ip))
        return false;
    ip = (const net_ipv4_header_t *)payload;
    ihl = (uint32_t)(ip->version_ihl & 0x0fu) * 4u;
    ip_length = net_be16(ip->total_length);
    if ((ip->version_ihl >> 4) != 4u || ihl < sizeof(*ip) ||
        ihl > payload_length || ip_length < ihl || ip_length > payload_length ||
        net_checksum(ip, ihl) != 0u)
        return true;
    if (interface->config.configured &&
        net_ip_from_bytes(ip->destination) != interface->config.address &&
        net_ip_from_bytes(ip->destination) != 0xffffffffu)
        return false;
    payload += ihl;
    payload_length = ip_length - ihl;
    if (ip->protocol == NET_IP_PROTO_UDP)
        return net_receive_dhcp(interface, payload, payload_length);
    if (ip->protocol == NET_IP_PROTO_ICMP)
        return net_receive_icmp(interface, ethernet, ip, payload,
                                payload_length);
    return false;
}

int net_stack_attach(net_device_t *device, net_config_method_t method,
                     const net_ipv4_config_t *initial)
{
    net_interface_t *interface;

    if (!device)
        return -EINVAL;
    interface = net_interface_for_device(device);
    if (interface)
        return 0;
    if (interface_count >= NET_STACK_MAX_INTERFACES)
        return -ENOSPC;
    interface = &interfaces[interface_count++];
    memset(interface, 0, sizeof(*interface));
    interface->device = device;
    interface->method = method;
    if (initial)
        interface->config = *initial;
    if (method == NET_CONFIG_DHCP) {
        interface->config.dhcp = true;
        interface->dhcp_pending = true;
        interface->dhcp_state = NET_DHCP_IDLE;
    }
    return 0;
}

int net_stack_get_config(net_device_t *device, net_ipv4_config_t *config)
{
    net_interface_t *interface = net_interface_for_device(device);

    if (!interface || !config)
        return -ENODEV;
    *config = interface->config;
    return 0;
}

static int net_stack_wait_state(net_interface_t *interface,
                                net_dhcp_state_t wanted,
                                uint32_t timeout_ms)
{
    uint32_t start = get_time_ms();

    while ((uint32_t)(get_time_ms() - start) < timeout_ms) {
        if (interface->dhcp_state == wanted)
            return 0;
        if (interface->dhcp_state == NET_DHCP_FAILED)
            return -EIO;
        if (interface->device->ops && interface->device->ops->poll)
            (void)interface->device->ops->poll(interface->device);
        task_sleep_ms(1u);
    }
    return -ETIMEDOUT;
}

static int net_stack_dhcp(net_interface_t *interface)
{
    int ret;

    interface->dhcp_xid = (0x41524d00u ^ get_time_ms() ^
        ((uint32_t)interface->device->mac[4] << 8)) |
        interface->device->mac[5];
    interface->dhcp_state = NET_DHCP_WAIT_OFFER;
    ret = net_send_dhcp(interface, NET_DHCP_DISCOVER);
    if (ret < 0)
        return ret;
    ret = net_stack_wait_state(interface, NET_DHCP_HAVE_OFFER,
                               NET_DHCP_TIMEOUT_MS);
    if (ret < 0)
        return ret;
    interface->dhcp_state = NET_DHCP_WAIT_ACK;
    ret = net_send_dhcp(interface, NET_DHCP_REQUEST);
    if (ret < 0)
        return ret;
    return net_stack_wait_state(interface, NET_DHCP_BOUND,
                                NET_DHCP_TIMEOUT_MS);
}

static int net_wait_for_arp(net_interface_t *interface, uint32_t address,
                            uint8_t mac[6])
{
    uint32_t start;
    int ret;

    if (interface->arp_valid && interface->arp_address == address) {
        memcpy(mac, interface->arp_mac, 6u);
        return 0;
    }
    interface->arp_valid = false;
    ret = net_send_arp_request(interface, address);
    if (ret < 0)
        return ret;
    start = get_time_ms();
    while ((uint32_t)(get_time_ms() - start) < NET_ARP_TIMEOUT_MS) {
        if (interface->arp_valid && interface->arp_address == address) {
            memcpy(mac, interface->arp_mac, 6u);
            return 0;
        }
        task_sleep_ms(1u);
    }
    return -ETIMEDOUT;
}

int net_stack_ping(net_device_t *device, uint32_t address,
                   uint32_t sequence, uint32_t timeout_ms,
                   net_ping_result_t *result)
{
    net_interface_t *interface = net_interface_for_device(device);
    uint8_t target_mac[6];
    uint8_t packet[56];
    net_icmp_header_t *icmp = (net_icmp_header_t *)packet;
    uint32_t next_hop;
    uint32_t start;
    int ret;

    if (!interface || !result)
        return -ENODEV;
    memset(result, 0, sizeof(*result));
    result->address = address;
    result->sequence = sequence;
    if (!interface->config.configured)
        return -ENETDOWN;
    next_hop = address;
    if ((address & interface->config.netmask) !=
        (interface->config.address & interface->config.netmask))
        next_hop = interface->config.gateway;
    if (next_hop == 0u)
        return -ENETDOWN;
    ret = net_wait_for_arp(interface, next_hop, target_mac);
    if (ret < 0)
        return ret;

    memset(packet, 0, sizeof(packet));
    icmp->type = NET_ICMP_ECHO_REQUEST;
    icmp->identifier = net_be16((uint16_t)(0x4100u | (get_time_ms() & 0xffu)));
    icmp->sequence = net_be16((uint16_t)sequence);
    for (uint32_t index = sizeof(*icmp); index < sizeof(packet); index++)
        packet[index] = (uint8_t)index;
    icmp->checksum = net_be16(net_checksum(packet, sizeof(packet)));
    interface->ping_pending = true;
    interface->ping_received = false;
    interface->ping_address = address;
    interface->ping_identifier = net_be16(icmp->identifier);
    interface->ping_sequence = (uint16_t)sequence;
    interface->ping_started_ms = get_time_ms();
    ret = net_send_ipv4(interface, target_mac, interface->config.address,
                        address, NET_IP_PROTO_ICMP, packet, sizeof(packet));
    if (ret < 0) {
        interface->ping_pending = false;
        return ret;
    }
    start = get_time_ms();
    while ((uint32_t)(get_time_ms() - start) < timeout_ms) {
        if (interface->ping_received) {
            result->received = true;
            result->ttl = interface->ping_ttl;
            result->elapsed_ms = interface->ping_elapsed_ms;
            return 0;
        }
        task_sleep_ms(1u);
    }
    interface->ping_pending = false;
    return -ETIMEDOUT;
}

static const char *net_link_name(net_link_state_t state)
{
    switch (state) {
    case NET_LINK_UP: return "UP";
    case NET_LINK_ASSOCIATING: return "ASSOCIATING";
    default: return "DOWN";
    }
}

int net_stack_format_interfaces(char *buffer, uint32_t capacity,
                                const char *name)
{
    uint32_t length = 0u;
    uint32_t index;

    if (!buffer || capacity == 0u)
        return -EINVAL;
    buffer[0] = '\0';
    for (index = 0u; index < interface_count; index++) {
        net_interface_t *interface = &interfaces[index];
        net_device_t *device = interface->device;
        char address[20];
        char netmask[20];
        char gateway[20];
        char dns[20];
        int written;

        if (name && name[0] != '\0' && strcmp(name, device->name) != 0)
            continue;
        net_stack_format_ipv4(interface->config.address, address,
                              sizeof(address));
        net_stack_format_ipv4(interface->config.netmask, netmask,
                              sizeof(netmask));
        net_stack_format_ipv4(interface->config.gateway, gateway,
                              sizeof(gateway));
        net_stack_format_ipv4(interface->config.dns, dns, sizeof(dns));
        written = snprintf(buffer + length, capacity - length,
            "%s: flags=<%s,BROADCAST,MULTICAST> mtu %u\n"
            "        ether %02X:%02X:%02X:%02X:%02X:%02X\n",
            device->name, net_link_name(device->link_state), device->mtu,
            device->mac[0], device->mac[1], device->mac[2],
            device->mac[3], device->mac[4], device->mac[5]);
        if (written < 0 || (uint32_t)written >= capacity - length)
            return -ENOSPC;
        length += (uint32_t)written;
        if (interface->config.configured) {
            written = snprintf(buffer + length, capacity - length,
                "        inet %s netmask %s gateway %s\n"
                "        dns %s method %s lease %us\n",
                address, netmask, gateway, dns,
                interface->config.dhcp ? "dhcp" : "static",
                interface->config.lease_seconds);
        } else {
            written = snprintf(buffer + length, capacity - length,
                "        inet unavailable method %s state %s\n",
                interface->method == NET_CONFIG_DHCP ? "dhcp" : "static",
                interface->dhcp_pending ? "configuring" : "unconfigured");
        }
        if (written < 0 || (uint32_t)written >= capacity - length)
            return -ENOSPC;
        length += (uint32_t)written;
        written = snprintf(buffer + length, capacity - length,
            "        RX packets %llu bytes %llu dropped %llu\n"
            "        TX packets %llu bytes %llu dropped %llu\n",
            (unsigned long long)device->rx_packets,
            (unsigned long long)device->rx_bytes,
            (unsigned long long)device->rx_drops,
            (unsigned long long)device->tx_packets,
            (unsigned long long)device->tx_bytes,
            (unsigned long long)device->tx_drops);
        if (written < 0 || (uint32_t)written >= capacity - length)
            return -ENOSPC;
        length += (uint32_t)written;
    }
    return (int)length;
}

static void netd_main(void *argument)
{
    (void)argument;

    for (;;) {
        uint32_t now = get_time_ms();
        uint32_t index;

        for (index = 0u; index < interface_count; index++) {
            net_interface_t *interface = &interfaces[index];

            if (interface->dhcp_pending &&
                interface->device->link_state == NET_LINK_UP &&
                (int32_t)(now - interface->dhcp_retry_at) >= 0) {
                int ret = net_stack_dhcp(interface);

                if (ret == 0) {
                    char address[20];

                    interface->dhcp_pending = false;
                    net_stack_format_ipv4(interface->config.address, address,
                                          sizeof(address));
                    KINFO("Net: %s DHCP address %s\n",
                          interface->device->name, address);
                } else {
                    interface->dhcp_state = NET_DHCP_IDLE;
                    interface->dhcp_retry_at = get_time_ms() +
                        NET_DHCP_RETRY_MS;
                    KINFO("Net: %s DHCP failed (%d), retrying\n",
                          interface->device->name, ret);
                }
            }
            if (interface->device->ops && interface->device->ops->poll)
                (void)interface->device->ops->poll(interface->device);
        }
        task_sleep_ms(1u);
    }
}

int net_start_daemon(void)
{
    if (interface_count == 0u)
        return 0;
    if (netd_task)
        return 1;
    netd_task = task_create_process("netd", netd_main, NULL, NETD_PRIORITY,
                                    TASK_TYPE_KERNEL);
    if (!netd_task)
        return -ENOMEM;
    arch_task_context_mark_first_run(&netd_task->context);
    arch_task_context_set_address_space(&netd_task->context,
                                        arch_kernel_address_space_context(),
                                        ASID_KERNEL);
    arch_task_context_set_returns_to_user(&netd_task->context, false);
    add_to_ready_queue(netd_task);
    return 1;
}
