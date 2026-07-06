/*
 * ArmOS
 * Copyright (c) 2026 Mohamed Ennassiri
 *
 * Licensed under the Apache License, Version 2.0.
 * See LICENSE for details.
 *
 * File: kernel/drivers/virtio_net.c
 * Layer: Kernel / VirtIO drivers
 *
 * Responsibilities:
 * - Probe a VirtIO network device from the QEMU-provided DTB.
 * - Negotiate a minimal feature set and expose MAC/IRQ/status diagnostics.
 *
 * Notes:
 * - This is still bring-up code: it is intentionally not a full network
 *   stack. It proves VirtIO RX/TX, ARP, and minimal IPv4/ICMP handling before
 *   sockets and TCP state machines are introduced.
 */

#include <kernel/types.h>
#include <kernel/address_space.h>
#include <kernel/fdt.h>
#include <kernel/virtio_net.h>
#include <kernel/virtio_block.h>
#include <kernel/memory.h>
#include <kernel/string.h>
#include <kernel/kprintf.h>
#include <kernel/interrupt.h>
#include <kernel/file.h>
#include <kernel/vfs.h>
#include <kernel/timer.h>
#include <kernel/task.h>

#define VIRTIO_NET_F_MAC      (1u << 5)

#define VNET_CFG_MAC          (VIRTIO_MMIO_CONFIG + 0x00)
#define VIRTIO_NET_VQ_RX      0
#define VIRTIO_NET_VQ_TX      1
#define VIRTIO_NET_RX_QSIZE   32
#define VIRTIO_NET_TX_QSIZE   8
#define VIRTIO_NET_RX_BUFSZ   2048
#define VIRTIO_NET_TX_BUFSZ   2048
#define VIRTIO_NET_IP         0x0A00020Fu /* 10.0.2.15, QEMU user-net default guest IP. */
#define VIRTIO_NET_GW_IP      0x0A000202u /* 10.0.2.2, QEMU user-net default gateway. */
#define ETH_TYPE_ARP          0x0806u
#define ETH_TYPE_IPV4         0x0800u
#define ARP_HTYPE_ETHERNET    1u
#define ARP_OPER_REQUEST      1u
#define ARP_OPER_REPLY        2u
#define IP_PROTO_ICMP         1u
#define IP_PROTO_TCP          6u
#define ICMP_ECHO_REPLY       0u
#define ICMP_ECHO_REQUEST     8u
#define NET_ETH_FRAME_MAX     1514u
#define NETECHO_PORT          2323u
#define NET_TCP_FIN           0x01u
#define NET_TCP_SYN           0x02u
#define NET_TCP_RST           0x04u
#define NET_TCP_PSH           0x08u
#define NET_TCP_ACK           0x10u
#define DEV_NETECHO_RDEV      ((1u << 8) | 232u)
#define AF_INET               2
#define SOCK_STREAM           1
#define NET_SOCKET_RX_SIZE    4096u

typedef enum {
    NET_SOCK_CREATED = 0,
    NET_SOCK_BOUND,
    NET_SOCK_LISTEN,
    NET_SOCK_CONNECTED,
    NET_SOCK_CLOSED,
} net_socket_state_t;

typedef struct {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} __attribute__((packed)) virtio_net_hdr_t;

typedef struct {
    uint8_t bytes[VIRTIO_NET_RX_BUFSZ];
} __attribute__((aligned(64))) virtio_net_rx_buf_t;

typedef struct {
    uint8_t bytes[VIRTIO_NET_TX_BUFSZ];
} __attribute__((aligned(64))) virtio_net_tx_buf_t;

typedef struct {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
} __attribute__((packed)) eth_hdr_t;

typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    uint8_t sha[6];
    uint8_t spa[4];
    uint8_t tha[6];
    uint8_t tpa[4];
} __attribute__((packed)) arp_pkt_t;

typedef struct {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t src[4];
    uint8_t dst[4];
} __attribute__((packed)) ipv4_hdr_t;

typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t ident;
    uint16_t seq;
} __attribute__((packed)) icmp_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed)) tcp_hdr_t;

typedef struct {
    uint16_t sa_family;
    char sa_data[14];
} __attribute__((packed)) net_sockaddr_t;

typedef struct {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t sin_zero[8];
} __attribute__((packed)) net_sockaddr_in_t;

typedef struct net_socket {
    net_socket_state_t state;
    uint16_t local_port;
    uint16_t peer_port;
    uint32_t peer_ip;
    uint8_t peer_mac[6];
    uint32_t local_seq;
    uint32_t peer_seq_next;
    bool peer_closed;
    uint8_t rx_buf[NET_SOCKET_RX_SIZE];
    uint32_t rx_len;
} net_socket_t;

typedef struct {
    paddr_t phys;
    uint32_t irq;
    volatile uint32_t *mmio;
    vq_legacy_t rx_vq;
    vq_legacy_t tx_vq;
    virtio_net_rx_buf_t rx_bufs[VIRTIO_NET_RX_QSIZE] __attribute__((aligned(64)));
    virtio_net_tx_buf_t tx_bufs[VIRTIO_NET_TX_QSIZE] __attribute__((aligned(64)));
    bool tx_in_use[VIRTIO_NET_TX_QSIZE];
    uint16_t tx_next;
    uint8_t mac[6];
    bool initialized;
    bool irq_edge_triggered;
    uint32_t irq_count;
    uint32_t last_irq_status;
    uint32_t rx_packets;
    uint32_t rx_bytes;
    uint32_t rx_drops;
    uint32_t rx_last_len;
    uint32_t tx_packets;
    uint32_t tx_bytes;
    uint32_t tx_drops;
    uint32_t rx_arp;
    uint32_t tx_arp;
    uint32_t rx_ipv4;
    uint32_t rx_icmp;
    uint32_t tx_icmp;
    uint32_t rx_tcp;
    uint32_t tx_tcp;
    uint32_t tcp_echo;
    bool echo_enabled;
    bool tcp_established;
    uint8_t peer_mac[6];
    uint32_t peer_ip;
    uint16_t peer_port;
    uint32_t peer_seq_next;
    uint32_t local_seq;
    net_socket_t *listener;
    net_socket_t *accepted;
    bool pending_accept;
    uint8_t pending_mac[6];
    uint32_t pending_ip;
    uint16_t pending_port;
    uint32_t pending_peer_seq_next;
    uint32_t pending_local_seq;
    bool pending_peer_closed;
    uint8_t pending_rx_buf[NET_SOCKET_RX_SIZE];
    uint32_t pending_rx_len;
} virtio_net_state_t;

static virtio_net_state_t net = {0};

static inline uint16_t net_bswap16(uint16_t x)
{
    return (uint16_t)((x << 8) | (x >> 8));
}

static inline uint32_t net_bswap32(uint32_t x)
{
    return ((x & 0x000000FFu) << 24) |
           ((x & 0x0000FF00u) << 8) |
           ((x & 0x00FF0000u) >> 8) |
           ((x & 0xFF000000u) >> 24);
}

static void net_ip_to_bytes(uint32_t ip, uint8_t out[4])
{
    out[0] = (uint8_t)(ip >> 24);
    out[1] = (uint8_t)(ip >> 16);
    out[2] = (uint8_t)(ip >> 8);
    out[3] = (uint8_t)ip;
}

static uint32_t net_ip_from_bytes(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) |
           ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) |
           (uint32_t)in[3];
}

static uint16_t net_checksum(const void *data, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }

    if (len)
        sum += ((uint16_t)p[0] << 8);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)~sum;
}

static void net_checksum_add_bytes(uint32_t *sum, const uint8_t *p, uint32_t len)
{
    while (len > 1) {
        *sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }

    if (len)
        *sum += ((uint16_t)p[0] << 8);
}

static uint16_t net_tcp_checksum(const ipv4_hdr_t *ip, const uint8_t *tcp,
                                 uint32_t tcp_len)
{
    uint32_t sum = 0;
    uint8_t pseudo[12];

    memcpy(&pseudo[0], ip->src, 4);
    memcpy(&pseudo[4], ip->dst, 4);
    pseudo[8] = 0;
    pseudo[9] = IP_PROTO_TCP;
    pseudo[10] = (uint8_t)(tcp_len >> 8);
    pseudo[11] = (uint8_t)tcp_len;

    net_checksum_add_bytes(&sum, pseudo, sizeof(pseudo));
    net_checksum_add_bytes(&sum, tcp, tcp_len);

    while (sum >> 16)
        sum = (sum & 0xFFFFu) + (sum >> 16);

    return (uint16_t)~sum;
}

static struct vring_desc *net_desc_ptr(vq_legacy_t *vq, unsigned i)
{
    return (struct vring_desc *)((uint8_t *)(uintptr_t)vq->va_desc +
                                 i * sizeof(struct vring_desc));
}

static struct vring_avail *net_avail_ptr(vq_legacy_t *vq)
{
    return (struct vring_avail *)((uint8_t *)(uintptr_t)vq->va_avail);
}

static struct vring_used *net_used_ptr(vq_legacy_t *vq)
{
    return (struct vring_used *)((uint8_t *)(uintptr_t)vq->va_used);
}

static bool net_vq_alloc(vq_legacy_t *vq, uint16_t qsize)
{
    uint32_t desc_sz = 16u * qsize;
    uint32_t avail_sz = ALIGN_UP(6u + 2u * qsize, 2u);
    uint32_t used_sz = ALIGN_UP(6u + 8u * qsize, VQ_ALIGN);
    uint32_t total = ALIGN_UP(desc_sz, 16) +
                     ALIGN_UP(avail_sz, 2) +
                     ALIGN_UP(used_sz, VQ_ALIGN);
    size_t npages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
    paddr_t pa_base = (paddr_t)allocate_pages(npages);
    uint8_t *va_base = pa_base ? (uint8_t *)phys_to_virt(pa_base) : NULL;
    uint32_t off = 0;

    if (!va_base)
        return false;

    memset(va_base, 0, npages * PAGE_SIZE);

    vq->pa_base = pa_base;
    vq->va_base = (uintptr_t)va_base;

    vq->pa_desc = pa_base + off;
    vq->va_desc = (uintptr_t)(va_base + off);
    vq->desc_size = desc_sz;
    off = ALIGN_UP(off + desc_sz, 16);

    vq->pa_avail = pa_base + off;
    vq->va_avail = (uintptr_t)(va_base + off);
    vq->avail_size = avail_sz;
    off = ALIGN_UP(off + avail_sz, 2);

    off = ALIGN_UP(off, VQ_ALIGN);
    vq->pa_used = pa_base + off;
    vq->va_used = (uintptr_t)(va_base + off);
    vq->used_size = used_sz;
    vq->qsize = qsize;
    vq->last_used_idx = 0;

    clean_dcache_by_mva(va_base, npages * PAGE_SIZE);
    return true;
}

static bool net_irq_from_mmio(paddr_t phys, uint32_t *out_irq)
{
    if (!out_irq)
        return false;
    if (phys < VIRT_VIRTIO_BASE)
        return false;
    if (((phys - VIRT_VIRTIO_BASE) % VIRT_VIRTIO_SIZE) != 0)
        return false;

    uint32_t index = (phys - VIRT_VIRTIO_BASE) / VIRT_VIRTIO_SIZE;
    *out_irq = VIRT_VIRTIO_IRQ(index);
    return true;
}

static bool net_probe_from_dtb(paddr_t *out_phys, uint32_t *out_irq, bool *out_edge)
{
    paddr_t phys = 0;

    if (!fdt_find_virtio_mmio_device(VIRTIO_ID_NETWORK, &phys, out_irq, out_edge))
        return false;

    *out_phys = phys;
    return true;
}

static bool net_probe_fallback(paddr_t *out_phys, uint32_t *out_irq, bool *out_edge)
{
    paddr_t phys = VIRT_VIRTIO_NET;
    volatile uint32_t *base = (volatile uint32_t *)KERNEL_MMIO_VIRTIO_ADDR(phys);

    if (!out_phys || !out_irq)
        return false;
    if (mmio_read32(base, VIRTIO_MMIO_MAGIC) != 0x74726976)
        return false;
    if (mmio_read32(base, VIRTIO_MMIO_DEVICE_ID) != VIRTIO_ID_NETWORK)
        return false;

    *out_phys = phys;
    if (!net_irq_from_mmio(phys, out_irq))
        *out_irq = VIRT_VIRTIO_NET_IRQ;
    if (out_edge)
        *out_edge = true;
    return true;
}

static void net_read_mac(volatile uint32_t *mmio, uint8_t mac[6])
{
    for (uint32_t i = 0; i < 6; i++)
        mac[i] = (uint8_t)mmio_read32(mmio, VNET_CFG_MAC + i);
}

static void net_rx_post_desc(uint16_t id)
{
    struct vring_avail *avail = net_avail_ptr(&net.rx_vq);
    uint16_t idx = avail->idx;

    /*
     * RX buffers are owned by the device after being placed in avail->ring.
     * Clean+invalidate before posting so QEMU sees a coherent buffer and the
     * CPU later reloads the packet contents after the device writes them.
     */
    clean_invalidate_dcache_by_mva(&net.rx_bufs[id], sizeof(net.rx_bufs[id]));
    avail->ring[idx % net.rx_vq.qsize] = id;
    clean_dcache_by_mva((void *)net.rx_vq.va_avail, net.rx_vq.avail_size);
    data_memory_barrier_inner_shareable();
    avail->idx = idx + 1;
    clean_dcache_by_mva(&avail->idx, sizeof(avail->idx));
    data_sync_barrier_inner_shareable_write();
}

static void net_rx_post_all(void)
{
    for (uint16_t i = 0; i < net.rx_vq.qsize; i++)
        net_rx_post_desc(i);
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO_NET_VQ_RX);
}

static bool net_rx_queue_init(void)
{
    mmio_write32(net.mmio, VIRTIO_REG_GUEST_PAGE_SIZE, PAGE_SIZE);
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_SEL, VIRTIO_NET_VQ_RX);

    uint32_t qmax = mmio_read32(net.mmio, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (qmax == 0) {
        KERROR("virtio_net: RX queue unavailable\n");
        return false;
    }

    uint16_t qsize = VIRTIO_NET_RX_QSIZE <= qmax ?
        VIRTIO_NET_RX_QSIZE : (uint16_t)qmax;
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_NUM, qsize);
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_ALIGN_OFF, VQ_ALIGN);

    if (!net_vq_alloc(&net.rx_vq, qsize)) {
        KERROR("virtio_net: RX virtqueue allocation failed\n");
        return false;
    }

    for (uint16_t i = 0; i < qsize; i++) {
        struct vring_desc *desc = net_desc_ptr(&net.rx_vq, i);
        desc->addr = (uint64_t)virt_to_phys((vaddr_t)&net.rx_bufs[i]);
        desc->len = sizeof(net.rx_bufs[i]);
        /* Device writes complete virtio-net frames into RX descriptors. */
        desc->flags = VRING_DESC_F_WRITE;
        desc->next = 0;
    }
    clean_dcache_by_mva((void *)net.rx_vq.va_desc, sizeof(struct vring_desc) * qsize);

    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_PFN, net.rx_vq.pa_base >> 12);
    net_rx_post_all();
    return true;
}

static bool net_tx_queue_init(void)
{
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_SEL, VIRTIO_NET_VQ_TX);

    uint32_t qmax = mmio_read32(net.mmio, VIRTIO_MMIO_QUEUE_NUM_MAX);
    if (qmax == 0) {
        KERROR("virtio_net: TX queue unavailable\n");
        return false;
    }

    uint16_t qsize = VIRTIO_NET_TX_QSIZE <= qmax ?
        VIRTIO_NET_TX_QSIZE : (uint16_t)qmax;
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_NUM, qsize);
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_ALIGN_OFF, VQ_ALIGN);

    if (!net_vq_alloc(&net.tx_vq, qsize)) {
        KERROR("virtio_net: TX virtqueue allocation failed\n");
        return false;
    }

    for (uint16_t i = 0; i < qsize; i++) {
        struct vring_desc *desc = net_desc_ptr(&net.tx_vq, i);
        desc->addr = (uint64_t)virt_to_phys((vaddr_t)&net.tx_bufs[i]);
        desc->len = 0;
        desc->flags = 0;
        desc->next = 0;
        net.tx_in_use[i] = false;
    }
    clean_dcache_by_mva((void *)net.tx_vq.va_desc, sizeof(struct vring_desc) * qsize);

    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_PFN, net.tx_vq.pa_base >> 12);
    return true;
}

static void net_tx_process_used(void)
{
    vq_legacy_t *vq = &net.tx_vq;

    if (!vq->qsize)
        return;

    invalidate_dcache_by_mva((void *)vq->va_used,
        sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));
    data_memory_barrier_inner_shareable();

    struct vring_used *used = net_used_ptr(vq);
    while (vq->last_used_idx != used->idx) {
        struct vring_used_elem *elem = &used->ring[vq->last_used_idx % vq->qsize];
        uint16_t id = (uint16_t)elem->id;

        if (id < vq->qsize)
            net.tx_in_use[id] = false;
        vq->last_used_idx++;
    }
}

static int net_tx_alloc_desc(void)
{
    uint16_t qsize = net.tx_vq.qsize;

    net_tx_process_used();
    for (uint16_t n = 0; n < qsize; n++) {
        uint16_t id = (uint16_t)((net.tx_next + n) % qsize);
        if (!net.tx_in_use[id]) {
            net.tx_in_use[id] = true;
            net.tx_next = (uint16_t)((id + 1) % qsize);
            return id;
        }
    }

    net.tx_drops++;
    return -1;
}

static int net_send_frame(const uint8_t *frame, uint32_t frame_len)
{
    if (!frame || frame_len == 0)
        return -EINVAL;
    if (frame_len + sizeof(virtio_net_hdr_t) > VIRTIO_NET_TX_BUFSZ) {
        net.tx_drops++;
        return -EINVAL;
    }

    int id = net_tx_alloc_desc();
    if (id < 0)
        return -EAGAIN;

    uint8_t *buf = net.tx_bufs[id].bytes;
    memset(buf, 0, sizeof(virtio_net_hdr_t));
    memcpy(buf + sizeof(virtio_net_hdr_t), frame, frame_len);

    struct vring_desc *desc = net_desc_ptr(&net.tx_vq, (unsigned)id);
    desc->addr = (uint64_t)virt_to_phys((vaddr_t)buf);
    desc->len = sizeof(virtio_net_hdr_t) + frame_len;
    desc->flags = 0;
    desc->next = 0;
    clean_dcache_by_mva(desc, sizeof(*desc));
    clean_dcache_by_mva(buf, desc->len);

    struct vring_avail *avail = net_avail_ptr(&net.tx_vq);
    uint16_t idx = avail->idx;
    avail->ring[idx % net.tx_vq.qsize] = (uint16_t)id;
    clean_dcache_by_mva((void *)net.tx_vq.va_avail, net.tx_vq.avail_size);
    data_memory_barrier_inner_shareable();
    avail->idx = idx + 1;
    clean_dcache_by_mva(&avail->idx, sizeof(avail->idx));
    data_sync_barrier_inner_shareable_write();

    net.tx_packets++;
    net.tx_bytes += frame_len;
    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO_NET_VQ_TX);
    return 0;
}

static void net_build_arp(uint8_t *frame, const uint8_t dst_mac[6],
                          const uint8_t target_mac[6], uint32_t op,
                          uint32_t sender_ip, uint32_t target_ip)
{
    eth_hdr_t *eth = (eth_hdr_t *)frame;
    arp_pkt_t *arp = (arp_pkt_t *)(frame + sizeof(*eth));

    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, net.mac, 6);
    eth->ethertype = net_bswap16(ETH_TYPE_ARP);

    arp->htype = net_bswap16(ARP_HTYPE_ETHERNET);
    arp->ptype = net_bswap16(ETH_TYPE_IPV4);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = net_bswap16((uint16_t)op);
    memcpy(arp->sha, net.mac, 6);
    net_ip_to_bytes(sender_ip, arp->spa);
    memcpy(arp->tha, target_mac, 6);
    net_ip_to_bytes(target_ip, arp->tpa);
}

static void net_send_arp_request(uint32_t target_ip)
{
    uint8_t frame[sizeof(eth_hdr_t) + sizeof(arp_pkt_t)];
    static const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const uint8_t zero[6] = { 0, 0, 0, 0, 0, 0 };

    net_build_arp(frame, bcast, zero, ARP_OPER_REQUEST,
                  VIRTIO_NET_IP, target_ip);
    if (net_send_frame(frame, sizeof(frame)) == 0)
        net.tx_arp++;
}

static void net_send_arp_reply(const arp_pkt_t *request)
{
    uint8_t frame[sizeof(eth_hdr_t) + sizeof(arp_pkt_t)];

    net_build_arp(frame, request->sha, request->sha, ARP_OPER_REPLY,
                  VIRTIO_NET_IP, net_ip_from_bytes(request->spa));
    if (net_send_frame(frame, sizeof(frame)) == 0)
        net.tx_arp++;
}

static void net_send_icmp_echo_reply(const eth_hdr_t *rx_eth,
                                     const ipv4_hdr_t *rx_ip,
                                     const uint8_t *rx_icmp,
                                     uint32_t icmp_len)
{
    uint8_t frame[NET_ETH_FRAME_MAX];
    uint32_t ip_len = sizeof(ipv4_hdr_t) + icmp_len;
    uint32_t frame_len = sizeof(eth_hdr_t) + ip_len;

    if (!rx_eth || !rx_ip || !rx_icmp)
        return;
    if (icmp_len < sizeof(icmp_hdr_t) || frame_len > sizeof(frame)) {
        net.tx_drops++;
        return;
    }

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    ipv4_hdr_t *ip = (ipv4_hdr_t *)(frame + sizeof(*eth));
    uint8_t *icmp = frame + sizeof(*eth) + sizeof(*ip);

    memcpy(eth->dst, rx_eth->src, 6);
    memcpy(eth->src, net.mac, 6);
    eth->ethertype = net_bswap16(ETH_TYPE_IPV4);

    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->total_len = net_bswap16((uint16_t)ip_len);
    ip->id = rx_ip->id;
    ip->ttl = 64;
    ip->protocol = IP_PROTO_ICMP;
    net_ip_to_bytes(VIRTIO_NET_IP, ip->src);
    memcpy(ip->dst, rx_ip->src, sizeof(ip->dst));
    ip->checksum = 0;
    ip->checksum = net_bswap16(net_checksum(ip, sizeof(*ip)));

    memcpy(icmp, rx_icmp, icmp_len);
    icmp_hdr_t *icmp_hdr = (icmp_hdr_t *)icmp;
    icmp_hdr->type = ICMP_ECHO_REPLY;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = net_bswap16(net_checksum(icmp, icmp_len));

    if (net_send_frame(frame, frame_len) == 0)
        net.tx_icmp++;
}

static void net_send_tcp_packet(const uint8_t dst_mac[6], uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack,
                                uint8_t flags,
                                const uint8_t *payload,
                                uint32_t payload_len)
{
    uint8_t frame[NET_ETH_FRAME_MAX];
    uint32_t tcp_len = sizeof(tcp_hdr_t) + payload_len;
    uint32_t ip_len = sizeof(ipv4_hdr_t) + tcp_len;
    uint32_t frame_len = sizeof(eth_hdr_t) + ip_len;

    if (!dst_mac)
        return;
    if (frame_len > sizeof(frame)) {
        net.tx_drops++;
        return;
    }

    eth_hdr_t *eth = (eth_hdr_t *)frame;
    ipv4_hdr_t *ip = (ipv4_hdr_t *)(frame + sizeof(*eth));
    tcp_hdr_t *tcp = (tcp_hdr_t *)(frame + sizeof(*eth) + sizeof(*ip));
    uint8_t *out_payload = (uint8_t *)tcp + sizeof(*tcp);

    memcpy(eth->dst, dst_mac, 6);
    memcpy(eth->src, net.mac, 6);
    eth->ethertype = net_bswap16(ETH_TYPE_IPV4);

    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl = 0x45;
    ip->total_len = net_bswap16((uint16_t)ip_len);
    ip->ttl = 64;
    ip->protocol = IP_PROTO_TCP;
    net_ip_to_bytes(VIRTIO_NET_IP, ip->src);
    net_ip_to_bytes(dst_ip, ip->dst);
    ip->checksum = 0;
    ip->checksum = net_bswap16(net_checksum(ip, sizeof(*ip)));

    memset(tcp, 0, sizeof(*tcp));
    tcp->src_port = net_bswap16(src_port);
    tcp->dst_port = net_bswap16(dst_port);
    tcp->seq = net_bswap32(seq);
    tcp->ack = net_bswap32(ack);
    tcp->data_offset = (uint8_t)((sizeof(*tcp) / 4u) << 4);
    tcp->flags = flags;
    tcp->window = net_bswap16(4096);
    if (payload_len && payload)
        memcpy(out_payload, payload, payload_len);
    tcp->checksum = 0;
    tcp->checksum = net_bswap16(net_tcp_checksum(ip, (const uint8_t *)tcp, tcp_len));

    if (net_send_frame(frame, frame_len) == 0)
        net.tx_tcp++;
}

static void net_reset_tcp_echo_state(void)
{
    net.tcp_established = false;
    net.peer_ip = 0;
    net.peer_port = 0;
    net.peer_seq_next = 0;
    net.local_seq = 0x41524D00u; /* "ARM\0": deterministic and easy to spot. */
    memset(net.peer_mac, 0, sizeof(net.peer_mac));
}

static void net_socket_close_state(net_socket_t *sock)
{
    if (!sock)
        return;

    if (net.listener == sock)
        net.listener = NULL;
    if (net.accepted == sock)
        net.accepted = NULL;
    if (net.pending_accept && net.listener == NULL) {
        net.pending_accept = false;
        net.pending_rx_len = 0;
        net.pending_peer_closed = false;
    }
    sock->state = NET_SOCK_CLOSED;
}

static void net_socket_queue_rx(net_socket_t *sock, const uint8_t *payload,
                                uint32_t payload_len)
{
    if (!sock || !payload || payload_len == 0)
        return;

    uint32_t space = NET_SOCKET_RX_SIZE - sock->rx_len;
    if (payload_len > space) {
        net.rx_drops++;
        payload_len = space;
    }
    if (!payload_len)
        return;

    memcpy(sock->rx_buf + sock->rx_len, payload, payload_len);
    sock->rx_len += payload_len;
}

static ssize_t net_socket_read(file_t* file, void* buffer, size_t count)
{
    net_socket_t *sock = file ? (net_socket_t *)file->private_data : NULL;
    uint32_t n;

    if (!sock || !buffer)
        return -EINVAL;
    if (sock->state != NET_SOCK_CONNECTED)
        return -ENOTCONN;

    while (sock->rx_len == 0 && !sock->peer_closed)
        task_sleep_ms(1);

    if (sock->rx_len == 0 && sock->peer_closed)
        return 0;

    n = (uint32_t)count < sock->rx_len ? (uint32_t)count : sock->rx_len;
    memcpy(buffer, sock->rx_buf, n);
    if (n < sock->rx_len) {
        uint32_t remaining = sock->rx_len - n;
        for (uint32_t i = 0; i < remaining; i++)
            sock->rx_buf[i] = sock->rx_buf[n + i];
    }
    sock->rx_len -= n;
    return (ssize_t)n;
}

static ssize_t net_socket_write(file_t* file, const void* buffer, size_t count)
{
    net_socket_t *sock = file ? (net_socket_t *)file->private_data : NULL;

    if (!sock || !buffer)
        return -EINVAL;
    if (sock->state != NET_SOCK_CONNECTED)
        return -ENOTCONN;
    if (count == 0)
        return 0;
    if (count > NET_ETH_FRAME_MAX - sizeof(eth_hdr_t) -
                sizeof(ipv4_hdr_t) - sizeof(tcp_hdr_t))
        count = NET_ETH_FRAME_MAX - sizeof(eth_hdr_t) -
                sizeof(ipv4_hdr_t) - sizeof(tcp_hdr_t);

    net_send_tcp_packet(sock->peer_mac, sock->peer_ip, sock->local_port,
                        sock->peer_port, sock->local_seq, sock->peer_seq_next,
                        NET_TCP_ACK | NET_TCP_PSH, (const uint8_t *)buffer,
                        (uint32_t)count);
    sock->local_seq += (uint32_t)count;
    net.tcp_echo += (uint32_t)count;
    return (ssize_t)count;
}

static int net_socket_close(file_t* file)
{
    net_socket_t *sock = file ? (net_socket_t *)file->private_data : NULL;

    if (!sock)
        return 0;

    if (sock->state == NET_SOCK_CONNECTED && !sock->peer_closed) {
        net_send_tcp_packet(sock->peer_mac, sock->peer_ip, sock->local_port,
                            sock->peer_port, sock->local_seq,
                            sock->peer_seq_next, NET_TCP_FIN | NET_TCP_ACK,
                            NULL, 0);
        sock->local_seq++;
    }

    net_socket_close_state(sock);
    kfree(sock);
    file->private_data = NULL;
    return 0;
}

static off_t net_socket_lseek(file_t* file, off_t offset, int whence)
{
    (void)file;
    (void)offset;
    (void)whence;
    return -ESPIPE;
}

static file_operations_t net_socket_file_ops = {
    .read = net_socket_read,
    .write = net_socket_write,
    .open = NULL,
    .close = net_socket_close,
    .lseek = net_socket_lseek,
    .readdir = NULL,
    .truncate = NULL,
};

extern inode_t* create_inode(void);

static file_t *net_socket_create_file(net_socket_t *sock)
{
    file_t *file;
    inode_t *inode;
    uint32_t now;

    if (!sock)
        return NULL;

    file = create_file();
    if (!file)
        return NULL;

    inode = create_inode();
    if (!inode) {
        kfree(file);
        return NULL;
    }

    now = get_current_time();
    inode->mode = S_IFSOCK | 0666;
    inode->uid = current_uid();
    inode->gid = current_gid();
    inode->size = 0;
    inode->blocks = 0;
    inode->nlink = 1;
    inode->first_cluster = 0;
    inode->parent_cluster = 0;
    inode->atime = now;
    inode->mtime = now;
    inode->ctime = now;
    inode->i_op = NULL;
    inode->f_op = &net_socket_file_ops;

    file->f_op = &net_socket_file_ops;
    file->flags = O_RDWR;
    file->type = FILE_TYPE_SOCKET;
    file->inode = inode;
    file->private_data = sock;
    strncpy(file->name, "socket", sizeof(file->name) - 1);
    file->name[sizeof(file->name) - 1] = '\0';
    return file;
}

int sys_socket(int domain, int type, int protocol)
{
    task_t *task = task_current_local();

    if (!task || !task->process)
        return -ENODEV;
    if (domain != AF_INET || type != SOCK_STREAM || protocol != 0)
        return -EINVAL;
    if (!net.initialized)
        return -ENODEV;

    net_socket_t *sock = kmalloc(sizeof(*sock));
    if (!sock)
        return -ENOMEM;
    memset(sock, 0, sizeof(*sock));
    sock->state = NET_SOCK_CREATED;
    sock->local_seq = 0x41524D00u;

    file_t *file = net_socket_create_file(sock);
    if (!file) {
        kfree(sock);
        return -ENOMEM;
    }

    int fd = allocate_fd(task);
    if (fd < 0) {
        close_file(file);
        return fd;
    }

    task->process->files[fd] = file;
    task->process->fd_flags[fd] = 0;
    return fd;
}

int sys_bind(int sockfd, const void* addr, uint32_t addrlen)
{
    task_t *task = task_current_local();

    if (!task || !task->process)
        return -ENODEV;
    if (sockfd < 0 || sockfd >= MAX_FILES || !addr)
        return -EINVAL;
    if (addrlen < sizeof(net_sockaddr_in_t))
        return -EINVAL;

    file_t *file = task->process->files[sockfd];
    if (!file || file->type != FILE_TYPE_SOCKET)
        return -ENOTCONN;

    net_socket_t *sock = (net_socket_t *)file->private_data;
    if (!sock || sock->state != NET_SOCK_CREATED)
        return -EINVAL;

    net_sockaddr_in_t sin;
    if (copy_from_user(&sin, addr, sizeof(sin)) < 0)
        return -EFAULT;
    if (sin.sin_family != AF_INET)
        return -EINVAL;

    uint16_t port = net_bswap16(sin.sin_port);
    if (port != NETECHO_PORT)
        return -EINVAL;
    if (net.listener && net.listener != sock)
        return -EADDRINUSE;

    sock->local_port = port;
    sock->state = NET_SOCK_BOUND;
    return 0;
}

int sys_connect(int sockfd, const void* addr, uint32_t addrlen)
{
    task_t *task = task_current_local();

    if (!task || !task->process)
        return -ENODEV;
    if (sockfd < 0 || sockfd >= MAX_FILES)
        return -EBADF;
    if (!addr || addrlen < sizeof(net_sockaddr_in_t))
        return -EINVAL;

    file_t *file = task->process->files[sockfd];
    if (!file || file->type != FILE_TYPE_SOCKET)
        return -ENOTCONN;

    /*
     * The current virtio-net stack implements passive TCP for netecho
     * (bind/listen/accept). Active open needs an outgoing SYN state machine,
     * peer ARP tracking and retransmission policy, so expose the syscall but
     * fail clearly until that client path exists.
     */
    return -ENOSYS;
}

int sys_listen(int sockfd, int backlog)
{
    task_t *task = task_current_local();

    (void)backlog;

    if (!task || !task->process)
        return -ENODEV;
    if (sockfd < 0 || sockfd >= MAX_FILES)
        return -EBADF;
    file_t *file = task->process->files[sockfd];
    if (!file || file->type != FILE_TYPE_SOCKET)
        return -ENOTCONN;

    net_socket_t *sock = (net_socket_t *)file->private_data;
    if (!sock || sock->state != NET_SOCK_BOUND)
        return -EINVAL;
    if (net.listener && net.listener != sock)
        return -EADDRINUSE;

    sock->state = NET_SOCK_LISTEN;
    net.listener = sock;
    net.pending_accept = false;
    return 0;
}

int sys_accept(int sockfd, void* addr, uint32_t* addrlen)
{
    task_t *task = task_current_local();

    if (!task || !task->process)
        return -ENODEV;
    if (sockfd < 0 || sockfd >= MAX_FILES)
        return -EBADF;
    file_t *listen_file = task->process->files[sockfd];
    if (!listen_file || listen_file->type != FILE_TYPE_SOCKET)
        return -ENOTCONN;

    net_socket_t *listener = (net_socket_t *)listen_file->private_data;
    if (!listener || listener->state != NET_SOCK_LISTEN || net.listener != listener)
        return -EINVAL;

    while (!net.pending_accept)
        task_sleep_ms(1);

    net_socket_t *conn = kmalloc(sizeof(*conn));
    if (!conn)
        return -ENOMEM;
    memset(conn, 0, sizeof(*conn));
    conn->state = NET_SOCK_CONNECTED;
    conn->local_port = listener->local_port;
    conn->peer_port = net.pending_port;
    conn->peer_ip = net.pending_ip;
    conn->peer_seq_next = net.pending_peer_seq_next;
    conn->local_seq = net.pending_local_seq;
    conn->peer_closed = net.pending_peer_closed;
    if (net.pending_rx_len) {
        memcpy(conn->rx_buf, net.pending_rx_buf, net.pending_rx_len);
        conn->rx_len = net.pending_rx_len;
    }
    memcpy(conn->peer_mac, net.pending_mac, sizeof(conn->peer_mac));

    file_t *conn_file = net_socket_create_file(conn);
    if (!conn_file) {
        kfree(conn);
        return -ENOMEM;
    }

    int fd = allocate_fd(task);
    if (fd < 0) {
        close_file(conn_file);
        return fd;
    }

    if (addr && addrlen) {
        uint32_t user_len = 0;
        if (copy_from_user(&user_len, addrlen, sizeof(user_len)) < 0) {
            close_file(conn_file);
            free_fd(task, fd);
            return -EFAULT;
        }
        if (user_len >= sizeof(net_sockaddr_in_t)) {
            net_sockaddr_in_t sin;
            memset(&sin, 0, sizeof(sin));
            sin.sin_family = AF_INET;
            sin.sin_port = net_bswap16(conn->peer_port);
            sin.sin_addr = net_bswap32(conn->peer_ip);
            uint32_t out_len = sizeof(sin);
            if (copy_to_user(addr, &sin, sizeof(sin)) < 0 ||
                copy_to_user(addrlen, &out_len, sizeof(out_len)) < 0) {
                close_file(conn_file);
                free_fd(task, fd);
                return -EFAULT;
            }
        }
    }

    net.accepted = conn;
    net.pending_accept = false;
    net.pending_rx_len = 0;
    net.pending_peer_closed = false;
    task->process->files[fd] = conn_file;
    task->process->fd_flags[fd] = 0;
    return fd;
}

static void net_handle_tcp_echo(const eth_hdr_t *eth, const ipv4_hdr_t *ip,
                                const uint8_t *tcp_payload,
                                uint32_t tcp_len)
{
    if (!eth || !ip || !tcp_payload || tcp_len < sizeof(tcp_hdr_t))
        return;

    const tcp_hdr_t *tcp = (const tcp_hdr_t *)tcp_payload;
    uint16_t src_port = net_bswap16(tcp->src_port);
    uint16_t dst_port = net_bswap16(tcp->dst_port);
    uint32_t seq = net_bswap32(tcp->seq);
    uint8_t tcp_hlen = (uint8_t)((tcp->data_offset >> 4) * 4u);

    if (dst_port != NETECHO_PORT)
        return;
    if (!net.echo_enabled)
        return;
    if (tcp_hlen < sizeof(tcp_hdr_t) || tcp_hlen > tcp_len)
        return;
    if (net_tcp_checksum(ip, tcp_payload, tcp_len) != 0)
        return;

    uint32_t src_ip = net_ip_from_bytes(ip->src);
    const uint8_t *payload = tcp_payload + tcp_hlen;
    uint32_t payload_len = tcp_len - tcp_hlen;

    if (tcp->flags & NET_TCP_RST) {
        net_reset_tcp_echo_state();
        return;
    }

    if (tcp->flags & NET_TCP_SYN) {
        memcpy(net.peer_mac, eth->src, 6);
        net.peer_ip = src_ip;
        net.peer_port = src_port;
        net.peer_seq_next = seq + 1;
        net.local_seq = 0x41524D00u;
        net.tcp_established = true;
        net_send_tcp_packet(eth->src, src_ip, NETECHO_PORT, src_port,
                            net.local_seq, net.peer_seq_next,
                            NET_TCP_SYN | NET_TCP_ACK, NULL, 0);
        net.local_seq++;
        return;
    }

    if (!net.tcp_established ||
        src_ip != net.peer_ip ||
        src_port != net.peer_port) {
        return;
    }

    if (payload_len) {
        net.peer_seq_next = seq + payload_len;
        net_send_tcp_packet(net.peer_mac, net.peer_ip, NETECHO_PORT,
                            net.peer_port, net.local_seq, net.peer_seq_next,
                            NET_TCP_ACK | NET_TCP_PSH, payload, payload_len);
        net.local_seq += payload_len;
        net.tcp_echo += payload_len;
        return;
    }

    if (tcp->flags & NET_TCP_FIN) {
        net.peer_seq_next = seq + 1;
        net_send_tcp_packet(net.peer_mac, net.peer_ip, NETECHO_PORT,
                            net.peer_port, net.local_seq, net.peer_seq_next,
                            NET_TCP_FIN | NET_TCP_ACK, NULL, 0);
        net.local_seq++;
        net_reset_tcp_echo_state();
        return;
    }
}

static void net_handle_tcp_socket(const eth_hdr_t *eth, const ipv4_hdr_t *ip,
                                  const uint8_t *tcp_payload,
                                  uint32_t tcp_len)
{
    if (!eth || !ip || !tcp_payload || tcp_len < sizeof(tcp_hdr_t))
        return;

    const tcp_hdr_t *tcp = (const tcp_hdr_t *)tcp_payload;
    uint16_t src_port = net_bswap16(tcp->src_port);
    uint16_t dst_port = net_bswap16(tcp->dst_port);
    uint32_t seq = net_bswap32(tcp->seq);
    uint8_t tcp_hlen = (uint8_t)((tcp->data_offset >> 4) * 4u);

    if (!net.listener || net.listener->state != NET_SOCK_LISTEN)
        return;
    if (dst_port != net.listener->local_port)
        return;
    if (tcp_hlen < sizeof(tcp_hdr_t) || tcp_hlen > tcp_len)
        return;
    if (net_tcp_checksum(ip, tcp_payload, tcp_len) != 0)
        return;

    uint32_t src_ip = net_ip_from_bytes(ip->src);
    const uint8_t *payload = tcp_payload + tcp_hlen;
    uint32_t payload_len = tcp_len - tcp_hlen;

    if (net.pending_accept &&
        src_ip == net.pending_ip &&
        src_port == net.pending_port) {
        if (payload_len) {
            uint32_t space = NET_SOCKET_RX_SIZE - net.pending_rx_len;
            if (payload_len > space) {
                net.rx_drops++;
                payload_len = space;
            }
            if (payload_len) {
                memcpy(net.pending_rx_buf + net.pending_rx_len, payload, payload_len);
                net.pending_rx_len += payload_len;
                net.pending_peer_seq_next = seq + payload_len;
                net_send_tcp_packet(net.pending_mac, net.pending_ip,
                                    net.listener->local_port, net.pending_port,
                                    net.pending_local_seq,
                                    net.pending_peer_seq_next, NET_TCP_ACK,
                                    NULL, 0);
            }
            return;
        }
        if (tcp->flags & NET_TCP_FIN) {
            net.pending_peer_seq_next = seq + 1;
            net.pending_peer_closed = true;
            net_send_tcp_packet(net.pending_mac, net.pending_ip,
                                net.listener->local_port, net.pending_port,
                                net.pending_local_seq, net.pending_peer_seq_next,
                                NET_TCP_ACK, NULL, 0);
            return;
        }
    }

    if (tcp->flags & NET_TCP_RST) {
        if (net.accepted &&
            net.accepted->peer_ip == src_ip &&
            net.accepted->peer_port == src_port)
            net.accepted->peer_closed = true;
        return;
    }

    if (tcp->flags & NET_TCP_SYN) {
        if (net.accepted || net.pending_accept)
            return;

        memcpy(net.pending_mac, eth->src, 6);
        net.pending_ip = src_ip;
        net.pending_port = src_port;
        net.pending_peer_seq_next = seq + 1;
        net.pending_local_seq = 0x41524D00u;
        net.pending_peer_closed = false;
        net.pending_rx_len = 0;
        net.pending_accept = true;
        net_send_tcp_packet(eth->src, src_ip, net.listener->local_port,
                            src_port, net.pending_local_seq,
                            net.pending_peer_seq_next,
                            NET_TCP_SYN | NET_TCP_ACK, NULL, 0);
        net.pending_local_seq++;
        return;
    }

    net_socket_t *sock = net.accepted;
    if (!sock || sock->state != NET_SOCK_CONNECTED ||
        sock->peer_ip != src_ip || sock->peer_port != src_port)
        return;

    if (payload_len) {
        sock->peer_seq_next = seq + payload_len;
        net_socket_queue_rx(sock, payload, payload_len);
        net_send_tcp_packet(sock->peer_mac, sock->peer_ip, sock->local_port,
                            sock->peer_port, sock->local_seq,
                            sock->peer_seq_next, NET_TCP_ACK, NULL, 0);
        return;
    }

    if (tcp->flags & NET_TCP_FIN) {
        sock->peer_seq_next = seq + 1;
        sock->peer_closed = true;
        net_send_tcp_packet(sock->peer_mac, sock->peer_ip, sock->local_port,
                            sock->peer_port, sock->local_seq,
                            sock->peer_seq_next, NET_TCP_ACK, NULL, 0);
    }
}

static void net_handle_ipv4(const eth_hdr_t *eth, const uint8_t *payload,
                            uint32_t len)
{
    if (!eth || !payload || len < sizeof(ipv4_hdr_t))
        return;

    const ipv4_hdr_t *ip = (const ipv4_hdr_t *)payload;
    uint8_t version = ip->ver_ihl >> 4;
    uint32_t ihl = (uint32_t)(ip->ver_ihl & 0x0F) * 4u;

    if (version != 4 || ihl < sizeof(ipv4_hdr_t) || ihl > len)
        return;

    uint32_t total_len = net_bswap16(ip->total_len);
    if (total_len < ihl || total_len > len)
        return;

    if (net_ip_from_bytes(ip->dst) != VIRTIO_NET_IP)
        return;

    /*
     * Keep this strict even during bring-up: accepting malformed IPv4 headers
     * would make later TCP debugging much harder because bad packets would
     * silently flow into upper layers.
     */
    if (net_checksum(ip, ihl) != 0)
        return;

    net.rx_ipv4++;

    if (ip->protocol == IP_PROTO_TCP) {
        net.rx_tcp++;
        if (net.listener) {
            net_handle_tcp_socket(eth, ip, payload + ihl, total_len - ihl);
            return;
        }
        net_handle_tcp_echo(eth, ip, payload + ihl, total_len - ihl);
        return;
    }

    if (ip->protocol != IP_PROTO_ICMP)
        return;

    uint32_t icmp_len = total_len - ihl;
    if (icmp_len < sizeof(icmp_hdr_t))
        return;

    const uint8_t *icmp = payload + ihl;
    const icmp_hdr_t *icmp_hdr = (const icmp_hdr_t *)icmp;
    if (net_checksum(icmp, icmp_len) != 0)
        return;

    net.rx_icmp++;
    if (icmp_hdr->type == ICMP_ECHO_REQUEST && icmp_hdr->code == 0)
        net_send_icmp_echo_reply(eth, ip, icmp, icmp_len);
}

static void net_handle_frame(const uint8_t *frame, uint32_t len)
{
    if (!frame || len < sizeof(eth_hdr_t))
        return;

    const eth_hdr_t *eth = (const eth_hdr_t *)frame;
    uint16_t ethertype = net_bswap16(eth->ethertype);

    if (ethertype == ETH_TYPE_IPV4) {
        net_handle_ipv4(eth, frame + sizeof(eth_hdr_t),
                        len - sizeof(eth_hdr_t));
        return;
    }

    if (ethertype != ETH_TYPE_ARP)
        return;
    if (len < sizeof(eth_hdr_t) + sizeof(arp_pkt_t))
        return;

    const arp_pkt_t *arp = (const arp_pkt_t *)(frame + sizeof(eth_hdr_t));
    if (net_bswap16(arp->htype) != ARP_HTYPE_ETHERNET ||
        net_bswap16(arp->ptype) != ETH_TYPE_IPV4 ||
        arp->hlen != 6 || arp->plen != 4)
        return;

    net.rx_arp++;
    if (net_bswap16(arp->oper) == ARP_OPER_REQUEST &&
        net_ip_from_bytes(arp->tpa) == VIRTIO_NET_IP) {
        net_send_arp_reply(arp);
    }
}

static void net_rx_process_used(void)
{
    vq_legacy_t *vq = &net.rx_vq;

    invalidate_dcache_by_mva((void *)vq->va_used,
        sizeof(struct vring_used) + vq->qsize * sizeof(struct vring_used_elem));
    data_memory_barrier_inner_shareable();

    struct vring_used *used = net_used_ptr(vq);
    while (vq->last_used_idx != used->idx) {
        struct vring_used_elem *elem = &used->ring[vq->last_used_idx % vq->qsize];
        uint16_t id = (uint16_t)elem->id;
        uint32_t len = elem->len;

        if (id >= vq->qsize) {
            net.rx_drops++;
            vq->last_used_idx++;
            continue;
        }

        invalidate_dcache_by_mva(&net.rx_bufs[id], sizeof(net.rx_bufs[id]));
        net.rx_last_len = len;
        /*
         * VirtIO-net prepends struct virtio_net_hdr to every received frame.
         * Upper network layers should consume only the Ethernet payload after
         * that header; for this bring-up step we only count bytes/packets.
         */
        if (len > sizeof(virtio_net_hdr_t)) {
            net.rx_packets++;
            net.rx_bytes += len - sizeof(virtio_net_hdr_t);
            net_handle_frame(net.rx_bufs[id].bytes + sizeof(virtio_net_hdr_t),
                             len - sizeof(virtio_net_hdr_t));
        } else {
            net.rx_drops++;
        }

        net_rx_post_desc(id);
        vq->last_used_idx++;
    }

    mmio_write32(net.mmio, VIRTIO_MMIO_QUEUE_NOTIFY, VIRTIO_NET_VQ_RX);
}

static ssize_t net_echo_read(file_t* file, void* buffer, size_t count)
{
    (void)file;
    (void)buffer;
    (void)count;
    return 0;
}

static ssize_t net_echo_write(file_t* file, const void* buffer, size_t count)
{
    (void)file;
    (void)buffer;
    return (ssize_t)count;
}

static int net_echo_close(file_t* file)
{
    (void)file;
    net.echo_enabled = false;
    net_reset_tcp_echo_state();
    return 0;
}

static off_t net_echo_lseek(file_t* file, off_t offset, int whence)
{
    (void)file;
    (void)offset;
    (void)whence;
    return 0;
}

static file_operations_t net_echo_file_ops = {
    .read = net_echo_read,
    .write = net_echo_write,
    .open = NULL,
    .close = net_echo_close,
    .lseek = net_echo_lseek,
    .readdir = NULL,
    .truncate = NULL,
};

extern file_t* create_file(void);
extern inode_t* create_inode(void);

bool is_net_echo_device_path(const char* path)
{
    return path && strcmp(path, "/dev/netecho") == 0;
}

void fill_net_echo_device_stat(struct stat* st)
{
    uint32_t now;

    if (!st) return;

    now = get_current_time();
    memset(st, 0, sizeof(*st));
    st->st_dev = 0;
    st->st_ino = DEV_NETECHO_RDEV;
    st->st_mode = S_IFCHR | 0666;
    st->st_nlink = 1;
    st->st_uid = 0;
    st->st_gid = 0;
    st->st_rdev = DEV_NETECHO_RDEV;
    st->st_size = 0;
    st->st_blksize = 1024;
    st->st_blocks = 0;
    st->st_atime = now;
    st->st_mtime = now;
    st->st_ctime = now;
}

file_t* create_net_echo_device_file(const char* name, int flags)
{
    file_t* file;
    inode_t* inode;
    uint32_t now;

    if (!net.initialized)
        return NULL;

    file = create_file();
    if (!file) return NULL;

    inode = create_inode();
    if (!inode) {
        kfree(file);
        return NULL;
    }

    now = get_current_time();
    inode->mode = S_IFCHR | 0666;
    inode->uid = 0;
    inode->gid = 0;
    inode->size = 0;
    inode->blocks = 0;
    inode->nlink = 1;
    inode->first_cluster = 0;
    inode->parent_cluster = DEV_NETECHO_RDEV;
    inode->atime = now;
    inode->mtime = now;
    inode->ctime = now;
    inode->i_op = NULL;
    inode->f_op = &net_echo_file_ops;

    file->f_op = &net_echo_file_ops;
    file->flags = flags;
    file->type = FILE_TYPE_NETECHO;
    file->pos = 0;
    file->offset = 0;
    file->inode = inode;
    if (name) {
        strncpy(file->name, name, sizeof(file->name) - 1);
        file->name[sizeof(file->name) - 1] = '\0';
    }

    net.echo_enabled = true;
    net_reset_tcp_echo_state();
    return file;
}

bool virtio_net_init(void)
{
    paddr_t phys = 0;
    uint32_t irq = 0;
    bool edge = true;
    uint32_t features;
    uint32_t magic;
    uint32_t version;
    uint32_t devid;

    memset(&net, 0, sizeof(net));

    if (!net_probe_from_dtb(&phys, &irq, &edge) &&
        !net_probe_fallback(&phys, &irq, &edge)) {
        return false;
    }

    net.phys = phys;
    net.irq = irq;
    net.irq_edge_triggered = edge;
    net.mmio = (volatile uint32_t *)KERNEL_MMIO_VIRTIO_ADDR(phys);

    magic = mmio_read32(net.mmio, VIRTIO_MMIO_MAGIC);
    version = mmio_read32(net.mmio, VIRTIO_MMIO_VERSION);
    devid = mmio_read32(net.mmio, VIRTIO_MMIO_DEVICE_ID);
    if (magic != 0x74726976 || version != 1 || devid != VIRTIO_ID_NETWORK) {
        KERROR("virtio_net: bad device magic=0x%08X version=%u id=%u\n",
               magic, version, devid);
        return false;
    }

    mmio_write32(net.mmio, VIRTIO_MMIO_STATUS, 0);
    mmio_write32(net.mmio, VIRTIO_MMIO_STATUS, VIRTIO_STATUS_ACK);
    mmio_write32(net.mmio, VIRTIO_MMIO_STATUS,
                 mmio_read32(net.mmio, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER);

    features = mmio_read32(net.mmio, VIRTIO_MMIO_DEVICE_FEATURES);
    mmio_write32(net.mmio, VIRTIO_MMIO_DRIVER_FEATURES, features & VIRTIO_NET_F_MAC);
    mmio_write32(net.mmio, VIRTIO_MMIO_STATUS,
                 mmio_read32(net.mmio, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_FEATURES_OK);
    if (!(mmio_read32(net.mmio, VIRTIO_MMIO_STATUS) & VIRTIO_STATUS_FEATURES_OK)) {
        KERROR("virtio_net: features rejected\n");
        return false;
    }

    if (features & VIRTIO_NET_F_MAC) {
        net_read_mac(net.mmio, net.mac);
    } else {
        net.mac[0] = 0x52;
        net.mac[1] = 0x54;
        net.mac[2] = 0x00;
        net.mac[3] = 0x12;
        net.mac[4] = 0x34;
        net.mac[5] = 0x56;
    }

    if (!net_rx_queue_init())
        return false;
    if (!net_tx_queue_init())
        return false;

    /*
     * DRIVER_OK is set only after RX buffers are posted. Otherwise QEMU may
     * deliver packets before the guest has descriptors available, causing
     * early drops that are painful to diagnose during bring-up.
     */
    mmio_write32(net.mmio, VIRTIO_MMIO_STATUS,
                 mmio_read32(net.mmio, VIRTIO_MMIO_STATUS) | VIRTIO_STATUS_DRIVER_OK);
    net.initialized = true;

    if (net.irq_edge_triggered)
        enable_irq(net.irq);
    else
        enable_irq_level(net.irq);

    net_send_arp_request(VIRTIO_NET_GW_IP);

    KINFO("VirtIO net initialized: phys=0x%08X irq=%u %s rxq=%u txq=%u mac=%02X:%02X:%02X:%02X:%02X:%02X\n",
          net.phys, net.irq,
          net.irq_edge_triggered ? "edge" : "level",
          net.rx_vq.qsize,
          net.tx_vq.qsize,
          net.mac[0], net.mac[1], net.mac[2],
          net.mac[3], net.mac[4], net.mac[5]);
    return true;
}

bool virtio_net_is_initialized(void)
{
    return net.initialized;
}

uint32_t virtio_net_get_irq(void)
{
    return net.initialized ? net.irq : 0;
}

void virtio_net_irq_handler(void)
{
    if (!net.initialized)
        return;

    uint32_t irq_status = mmio_read32(net.mmio, VIRTIO_MMIO_INTERRUPT_STATUS);
    net.irq_count++;
    net.last_irq_status = irq_status;
    if (irq_status)
        mmio_write32(net.mmio, VIRTIO_MMIO_INTERRUPT_ACK, irq_status);

    net_tx_process_used();
    net_rx_process_used();
}

void virtio_net_get_mac(uint8_t mac[6])
{
    if (!mac)
        return;
    memcpy(mac, net.mac, 6);
}

void virtio_net_get_stats(uint32_t *irq_count, uint32_t *last_irq_status,
                          uint32_t *status, uint32_t *phys, uint32_t *irq,
                          uint32_t *rx_packets, uint32_t *rx_bytes,
                          uint32_t *rx_drops, uint32_t *rx_last_len,
                          uint32_t *tx_packets, uint32_t *tx_bytes,
                          uint32_t *tx_drops, uint32_t *rx_arp,
                          uint32_t *tx_arp, uint32_t *rx_ipv4,
                          uint32_t *rx_icmp, uint32_t *tx_icmp,
                          uint32_t *rx_tcp, uint32_t *tx_tcp,
                          uint32_t *tcp_echo, uint32_t *echo_enabled)
{
    if (irq_count)
        *irq_count = net.irq_count;
    if (last_irq_status)
        *last_irq_status = net.last_irq_status;
    if (status)
        *status = net.mmio ? mmio_read32(net.mmio, VIRTIO_MMIO_STATUS) : 0;
    if (phys)
        *phys = net.phys;
    if (irq)
        *irq = net.irq;
    if (rx_packets)
        *rx_packets = net.rx_packets;
    if (rx_bytes)
        *rx_bytes = net.rx_bytes;
    if (rx_drops)
        *rx_drops = net.rx_drops;
    if (rx_last_len)
        *rx_last_len = net.rx_last_len;
    if (tx_packets)
        *tx_packets = net.tx_packets;
    if (tx_bytes)
        *tx_bytes = net.tx_bytes;
    if (tx_drops)
        *tx_drops = net.tx_drops;
    if (rx_arp)
        *rx_arp = net.rx_arp;
    if (tx_arp)
        *tx_arp = net.tx_arp;
    if (rx_ipv4)
        *rx_ipv4 = net.rx_ipv4;
    if (rx_icmp)
        *rx_icmp = net.rx_icmp;
    if (tx_icmp)
        *tx_icmp = net.tx_icmp;
    if (rx_tcp)
        *rx_tcp = net.rx_tcp;
    if (tx_tcp)
        *tx_tcp = net.tx_tcp;
    if (tcp_echo)
        *tcp_echo = net.tcp_echo;
    if (echo_enabled)
        *echo_enabled = net.echo_enabled ? 1u : 0u;
}

static uint32_t net_tcp_state_for_proc(net_socket_state_t state)
{
    switch (state) {
        case NET_SOCK_LISTEN:    return 0x0A; /* Linux /proc/net/tcp LISTEN */
        case NET_SOCK_CONNECTED: return 0x01; /* ESTABLISHED */
        case NET_SOCK_CLOSED:    return 0x07; /* CLOSE */
        default:                 return 0;
    }
}

void virtio_net_get_tcp_diag(uint32_t *local_ip, uint16_t *local_port,
                             uint32_t *listener_state,
                             uint32_t *pending_accept,
                             uint32_t *accepted_state)
{
    /*
     * Diagnostic snapshot used by procfs. Keep it read-only and compact so the
     * network driver does not expose its internal socket objects to procfs.
     */
    if (local_ip)
        *local_ip = VIRTIO_NET_IP;
    if (local_port)
        *local_port = NETECHO_PORT;
    if (listener_state)
        *listener_state = net.listener ? net_tcp_state_for_proc(net.listener->state) : 0;
    if (pending_accept)
        *pending_accept = net.pending_accept ? 1u : 0u;
    if (accepted_state)
        *accepted_state = net.accepted ? net_tcp_state_for_proc(net.accepted->state) : 0;
}
