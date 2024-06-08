#ifndef _FD_DBG_H_
#define _FD_DBG_H_

// *INDENT-OFF*
#ifdef __cplusplus
extern "C" {
#endif
// *INDENT-ON*

#ifdef WITH_DBG

#ifdef __KERNEL__

#include <linux/slab.h>
#include <linux/in.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#ifndef DBG
#define DBG(fmt, arg...) \
    printk(fmt, ##arg)
#endif //DBG

#ifndef FDBG
#define FDBG(fmt, arg...)    do {\
    printk("<%d> %s(): ", __LINE__, __FUNCTION__); \
    printk(fmt, ##arg); \
    if (fmt[strlen(fmt) - 1] != '\n') \
        printk("\n"); \
} while (0)
#endif //FDBG

static inline void DBG_IP_PKT(const char *desc, struct iphdr *iph)
{
    char saddr_str[20], daddr_str[20];
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    struct icmphdr *icmph = NULL;

    ip2str(iph->saddr, saddr_str);
    ip2str(iph->daddr, daddr_str);
    DBG("%s\n", desc);
    DBG("IP {%s->%s [id %u, total len %u, frag_off %04X, offset %u, check %04X] ", saddr_str, daddr_str, ntohs(iph->id), ntohs(iph->tot_len), ntohs(iph->frag_off), ntohs(iph->frag_off & htons(IP_OFFSET)) * 8, ntohs(iph->check));
    if (iph->frag_off & htons(IP_OFFSET)) {
        DBG("}\n");
        return;
    }
    switch (iph->protocol) {
    case IPPROTO_TCP:
        tcph = (struct tcphdr *) ((__u32 *) iph + iph->ihl);
        DBG("TCP {%u->%u [%s%s%s%s%s%s, seq %u, ack %u, win %u, csum %04X]}}\n", ntohs(tcph->source), ntohs(tcph->dest), tcph->syn ? "S" : "", tcph->ack ? "A" : "", tcph->fin ? "F" : "", tcph->rst ? "R" : "", tcph->psh ? "P" : "", tcph->urg ? "U" : "", ntohl(tcph->seq), ntohl(tcph->ack_seq), ntohs(tcph->window), ntohs(tcph->check));
        break;
    case IPPROTO_UDP:
        udph = (struct udphdr *) ((__u32 *) iph + iph->ihl);
        DBG("UDP {%u->%u [len %u, csum %04X]}}\n", ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len), ntohs(udph->check));
        break;
    case IPPROTO_ICMP:
        icmph = (struct icmphdr *) ((__u32 *) iph + iph->ihl);
        DBG("ICMP [type %u, code %u, ID %u, seq %u, csum %04X]}\n", icmph->type, icmph->code, ntohs(icmph->un.echo.id), ntohs(icmph->un.echo.sequence), ntohs(icmph->checksum));
        break;
    default:
        DBG("protocol %u}\n", iph->protocol);
        break;
    }
    return;
}

#else //__KERNEL__

#ifndef DBG
#define DBG(fmt, arg...) \
    fprintf(stderr, fmt, ##arg)
#endif //DBG

#ifndef FDBG
#define FDBG(fmt, arg...)    do {\
    fprintf(stderr, "%s<%d> %s(): ", __FILE__, __LINE__, __FUNCTION__); \
    fprintf(stderr, fmt, ##arg); \
    if (fmt[strlen(fmt) - 1] != '\n') \
        fprintf(stderr, "\n"); \
} while (0)
#endif //FDBG

#define DBG_IP_PKT(desc, iph) \
    do { } while (0)

#endif //__KERNEL__

static inline void _DBG_DUMP(const unsigned char *data, size_t len)
{
    const char hexdig[] = "0123456789ABCDEF";
    const unsigned char *dp;
    char h[80];
    char c[80];
    int i;
    int n;

    if (len == 0)
        return;

    i = 0;
    n = 0;
    for (dp = data; dp < (data + len); dp++) {
        if (i == 0) {
            memset(h, 0, sizeof(h));
            memset(c, 0, sizeof(c));
            sprintf(h, "0x%04X: ", n);
            memset(c, ' ', strlen(h));
            i += strlen(h);
        }
        n++;
        h[i] = hexdig[(*dp >> 4) & 0x0F];
        c[i++] = ' ';
        h[i] = hexdig[(*dp) & 0x0F];
        if (*dp < 32 || *dp > 126)
            c[i++] = '.';
        else
            c[i++] = *dp;
        h[i] = ' ';
        c[i++] = ' ';
        if ((n % 4) == 0) {
            h[i] = ' ';
            c[i++] = ' ';
        }
        if ((n % 16) == 0) {
            DBG("%s\n", h);
            DBG("%s\n", c);
            DBG("\n");
            i = 0;
        }
    }
    if (i) {
        DBG("%s\n", h);
        DBG("%s\n", c);
        DBG("\n");
    }
    return;
}

#define DBG_DUMP(desc, data, len)    do {\
    FDBG("%s (%d bytes @ %p)", desc, len, data);\
    _DBG_DUMP((unsigned char *)data, len);\
} while (0)

static inline void _DBG_DUMP_SIMPLE(const unsigned char *data, size_t len)
{
    const char hexdig[] = "0123456789ABCDEF";
    const unsigned char *dp;
    char h[80];
    int i;
    int n;

    if (len == 0)
        return;

    i = 0;
    n = 0;
    for (dp = data; dp < (data + len); dp++) {
        if (i == 0) {
            memset(h, 0, sizeof(h));
            sprintf(h, "0x%04X: ", n);
            i += strlen(h);
        }
        n++;
        h[i++] = hexdig[(*dp >> 4) & 0x0F];
        h[i++] = hexdig[(*dp) & 0x0F];
        h[i++] = ' ';
        if ((n % 4) == 0)
            h[i++] = ' ';
        if ((n % 16) == 0) {
            DBG("%s\n", h);
            i = 0;
        }
    }
    if (i) {
        DBG("%s\n", h);
    }
    DBG("\n");
    return;
}

#define DBG_DUMP_SIMPLE(desc, data, len)    do {\
    FDBG("%s (%d bytes @ %p)", desc, len, data);\
    _DBG_DUMP_SIMPLE((unsigned char *)data, len);\
} while (0)

#else //WITH_DBG

#define DBG(fmt, arg...) \
    do { } while (0)

#define FDBG(fmt, arg...) \
    do { } while (0)

#define DBG_IP_PKT(desc, iph) \
    do { } while (0)

#define DBG_DUMP(desc, data, len) \
    do { } while (0)

#define DBG_DUMP_SIMPLE(desc, data, len) \
    do { } while (0)

#endif //WITH_DBG

// *INDENT-OFF*
#ifdef __cplusplus
}
#endif
// *INDENT-ON*

#endif //_FD_DBG_H_
