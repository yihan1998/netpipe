/*****************************************************************************/
/* "NetPIPE" -- Network Protocol Independent Performance Evaluator.          */
/* Copyright 1997, 1998 Iowa State University Research Foundation, Inc.      */
/*                                                                           */
/* This program is free software; you can redistribute it and/or modify      */
/* it under the terms of the GNU General Public License as published by      */
/* the Free Software Foundation.  You should have received a copy of the     */
/* GNU General Public License along with this program; if not, write to the  */
/* Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.   */
/*                                                                           */
/*     * tcp.c              ---- TCP calls source                            */
/*     * tcp.h              ---- Include file for TCP calls and data structs */
/*****************************************************************************/
#include    "netpipe.h"

#define _GNU_SOURCE
#include <sched.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include <assert.h>

#include <net/if.h>

#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_pdump.h>

#if defined (MPLITE)
#include "mplite.h"
#endif

/*----------------------------------------------------------------------------*/
#define ETHER_STRING "%02x:%02x:%02x:%02x:%02x:%02x"
#define ETHER_FMT(m) m[0],m[1],m[2],m[3],m[4],m[5]

#define ETH_ADDR_LEN 	6

/*-----------------------------------------------------------------------------*/
#define IP_STRING	"%hhu.%hhu.%hhu.%hhu"

#define LE_IP_FMT(ip)   ((uint8_t *)&(ip))[3], \
					    ((uint8_t *)&(ip))[2], \
 					    ((uint8_t *)&(ip))[1], \
				        ((uint8_t *)&(ip))[0]

#define BE_IP_FMT(ip)   ((uint8_t *)&(ip))[0], \
					    ((uint8_t *)&(ip))[1], \
 					    ((uint8_t *)&(ip))[2], \
				        ((uint8_t *)&(ip))[3]

#if __BYTE_ORDER == __LITTLE_ENDIAN
#	define HOST_IP_FMT(ip)	LE_IP_FMT(ip)
#elif __BYTE_ORDER == __BIG_ENDIAN
#	define HOST_IP_FMT(ip)	BE_IP_FMT(ip)
#endif

#define IFACE_NAME_LEN 	16

struct iface_info {
	char                name[IFACE_NAME_LEN];

    int                 port_id;
    
    uint8_t             mac_addr[ETH_ADDR_LEN];
    
    uint32_t            ip_addr;
    uint32_t            netmask;
};

struct iface_info iface;

#define MEMPOOL_CACHE_SIZE  256
#define N_MBUF              8192
#define BUF_SIZE            2048
#define MBUF_SIZE           (BUF_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define RTE_TEST_RX_DESC_DEFAULT    128
#define RTE_TEST_TX_DESC_DEFAULT    128

#define MAX_PKT_BURST   64

/* Packet memory buffer */
struct mbuf_table {
	uint16_t len;
	struct rte_mbuf * m_table[MAX_PKT_BURST];
} __rte_cache_aligned;

struct dpdk_context {
    struct rte_mempool * mempool;
    struct mbuf_table rx_mbufs[RTE_MAX_ETHPORTS];
    struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
};

struct dpdk_context dpdk_context;

static struct rte_mempool * core_mempool;

int doing_reset = 0;

static int print_iface() {
    fprintf(stdout, " displaying interface");

    fprintf(stdout, " %s info: ", iface.name);
    fprintf(stdout, " \t [port id] : %d\n", iface.port_id);
    fprintf(stdout, " \t [MAC address] : " ETHER_STRING "\n", ETHER_FMT(iface.mac_addr));
    fprintf(stdout, " \t [IP address] : " IP_STRING "\n", HOST_IP_FMT(iface.ip_addr));
    fprintf(stdout, " \t [netmask] : " IP_STRING "\n", HOST_IP_FMT(iface.netmask));

    return 0;
}

static int probe_iface() {
    /* We are probing interfaces through I/O module */
    int port_id;
    RTE_ETH_FOREACH_DEV(port_id) {
        // struct iface_info * iface = (struct iface_info *)calloc(1, IFACE_INFO_SIZE);
        iface.port_id = port_id;

        struct rte_ether_addr ether_addr;
        rte_eth_macaddr_get(port_id, &ether_addr);

        memcpy(iface.mac_addr, ether_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

        break;
    }

    /** 
     * By now we have a list of probed ifaces with port id and MAC address, 
     * we still need to do ioctl() to get iface name
     */

    struct ifaddrs * addrs, * addr;
	getifaddrs(&addrs);
	for (addr = addrs; addr != NULL; addr = addr->ifa_next) {
		if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET) {
            struct ifreq if_req;
            strcpy(if_req.ifr_name, addr->ifa_name);

            /* Create Socket */
            int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
            if(sock == -1) {
                fprintf(stdout, " [%s on core %d] socket allocation failed!", __func__, rte_lcore_id());
                exit(1);
            }

            char mac_addr[ETH_ADDR_LEN];

            if(ioctl(sock, SIOCGIFHWADDR, &if_req) == 0) {
                /* Get MAC address */
                memcpy(mac_addr, if_req.ifr_addr.sa_data, ETH_ADDR_LEN);
            }

            close(sock);

            if (!memcmp(iface.mac_addr, mac_addr, ETH_ADDR_LEN)) {
                strcpy(iface.name, addr->ifa_name);
                break;
            }
		}
	}

	freeifaddrs(addrs);

    return 0;
}

void Init(ArgStruct *p, int* pargc, char*** pargv) {
    p->reset_conn = 0; /* Default to not resetting connection */
    p->prot.sndbufsz = p->prot.rcvbufsz = 0;
    p->tr = 0;     /* The transmitter will be set using the -h host flag. */
    p->rcv = 1;

    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set_t), &my_set);

    /**
     * Configure parameters for EAL
     *  -l <core_list> : (start core, end core]
     *  -n <number of channels> : Number of memory channels
     *  --proc-type : Set the type of the current process
     * -w <[domain:]bus:devid.func> : Add a PCI device in white list
     */
    int eal_argc = 6;
    char * eal_argv[16] =   {"",
                             "-l", "0",
                             "-n", "4",
                             "--proc-type=auto",
                            };

    /* Init environment abstraction layer */
    int ret;
    ret = rte_eal_init(eal_argc, eal_argv);

    if (ret < 0) {
        fprintf(stderr, " rte_eal_init() failed!\n");
        exit(1);
    }

    /* Find all available interfaces we can use */
    int avail_ethdev, total_ethdev;

    avail_ethdev = rte_eth_dev_count_avail();
    total_ethdev = rte_eth_dev_count_total();
    fprintf(stdout, " finding available devices(avail : %d / total : %d)\n", avail_ethdev, total_ethdev);
    
    if (!avail_ethdev) {
        /* We didn't find any available device! */
        fprintf(stderr, " No available ethernet device detected!\n");
        exit(1);
    }
    
    /* Probe all interfaces and add them to probed_iface_list */
    probe_iface();
}

static struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = 8,
		.hthresh = 8,
		.wthresh = 4,
	},
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 36,
		.hthresh = 0,
		.wthresh = 0,
	},
	.tx_free_thresh = 0,
	.tx_rs_thresh = 0,
};

void Setup(ArgStruct *p)
{
    core_mempool = rte_mempool_create("core_mempool", N_MBUF, 
                                MBUF_SIZE, MEMPOOL_CACHE_SIZE, 
                                sizeof(struct rte_pktmbuf_pool_private),
                                rte_pktmbuf_pool_init, NULL,
                                rte_pktmbuf_init, NULL, 
                                rte_socket_id(), MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);
    if (core_mempool == NULL) {
        rte_exit(EXIT_FAILURE, " cannot allocate mempool for core %d! err: %s\n", rte_lcore_id(), rte_lcore_id(), rte_strerror(rte_errno));
    } else {
        fprintf(stdout, " mempool for core %d: %p", __func__, rte_lcore_id(), core_mempool);
    }

    struct rte_eth_conf port_conf = {
    	.rxmode = {
        	.mq_mode        = ETH_MQ_RX_RSS,
	        .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
    		.split_hdr_size = 0,
	    },
    	.rx_adv_conf = {
	    	.rss_conf = {
		    	.rss_key = NULL,
			    .rss_hf = ETH_RSS_TCP | ETH_RSS_UDP | ETH_RSS_IP
    		},
	    },
        .txmode = {
            .mq_mode = ETH_MQ_TX_NONE,
        },
    };

#ifdef MLX_5
    static uint8_t key[] = {
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 10 */
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 20 */
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 30 */
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05  /* 40 */
    };
#else
    static uint8_t key[] = {
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 10 */
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 20 */
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 30 */
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 40 */
        0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 50 */
        0x05, 0x05  /* 60 - 8 */
    };
#endif

    port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)key;
    port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

    int ret;
    
    int port_id = iface.port_id;

    struct rte_eth_dev_info dev_info; 
    ret = rte_eth_dev_info_get(port_id, &dev_info);
    if (ret != 0) {
        rte_exit(EXIT_FAILURE,
            "Error during getting device (port %u) info: %s\n",
            port_id, strerror(-ret));
    }

    int nb_rx_queue, nb_tx_queue;
    nb_rx_queue = nb_tx_queue = 1;
    
    /* Re-adjust rss_hf */
    port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info.flow_type_rss_offloads;

    /* Configure DPDK device with number of rx/tx queues and port configuration */
    ret = rte_eth_dev_configure(port_id,
                nb_rx_queue, nb_tx_queue, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE,
            ":: cannot configure device: err=%d, port=%u\n",
            ret, port_id);
    }

    /* Set up RX queue for each core */
    for (int i = 0; i < nb_rx_queue; i++) {
        ret = rte_eth_rx_queue_setup(port_id, i, RTE_TEST_RX_DESC_DEFAULT,
                        rte_eth_dev_socket_id(port_id),
                        &rx_conf,
                        core_mempool);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, ":: Rx queue setup failed: err=%d, port=%u\n", ret, port_id);
        }
    }

    for (int i = 0; i < nb_tx_queue; i++) {
        ret = rte_eth_tx_queue_setup(port_id, i, RTE_TEST_TX_DESC_DEFAULT,
                rte_eth_dev_socket_id(port_id),
                &tx_conf);
        if (ret < 0) {
            rte_exit(EXIT_FAILURE, ":: Tx queue setup failed: err=%d, port=%u\n", ret, port_id);
        }
    }

    fprintf(stdout, " done RX/TX queue allocation", rte_lcore_id());
    
    ret = rte_eth_promiscuous_enable(port_id);
    if (ret != 0) {
        rte_exit(EXIT_FAILURE, " rte_eth_promiscuous_enable:err = %d, port = %u", ret, (unsigned) port_id);
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, " rte_eth_dev_start:err = %d, port = %u", ret, (unsigned) port_id);
    }

    dpdk_context.mempool = core_mempool;

    for (int i = 0; i < MAX_PKT_BURST; i++) {
        /* Allocate RX packet buffer in DPDK context memory pool */
        dpdk_context.rx_mbufs[iface.port_id].m_table[i] = rte_pktmbuf_alloc(dpdk_context.mempool);
        assert(dpdk_context.rx_mbufs[iface.port_id].m_table[i] != NULL);
    }

    dpdk_context.rx_mbufs[iface.port_id].len = 0;

    for (int i = 0; i < MAX_PKT_BURST; i++) {
        /* Allocate TX packet buffer in DPDK context memory pool */
        dpdk_context.tx_mbufs[iface.port_id].m_table[i] = rte_pktmbuf_alloc(dpdk_context.mempool);
        assert(dpdk_context.tx_mbufs[iface.port_id].m_table[i] != NULL);
    }

    dpdk_context.tx_mbufs[iface.port_id].len = 0;

    return 0;
}   

/*----------------------------------------------------------------------------*/
static void free_pkts(struct rte_mbuf ** pkts, int pkt_cnt) {
    for (int i = 0; i < pkt_cnt; i++) {
        /* Free packet pointer in packet memory buffer(pkts[i]) */
        rte_pktmbuf_free(pkts[i]);
        RTE_MBUF_PREFETCH_TO_FREE(pkts[i+1]);
    }
}

/*----------------------------------------------------------------------------*/
uint8_t * dpdk_get_rxpkt(int port_id, int index, uint16_t * pkt_size) {
    struct rte_mbuf * rx_pkt = dpdk_context.rx_mbufs[port_id].m_table[index];
    *pkt_size = rx_pkt->pkt_len;

    return rte_pktmbuf_mtod(rx_pkt, uint8_t *);
}

/*----------------------------------------------------------------------------*/
uint32_t dpdk_recv_pkts(int port_id) {
    if (dpdk_context.rx_mbufs[port_id].len != 0) {
        free_pkts(dpdk_context.rx_mbufs[port_id].m_table, dpdk_context.rx_mbufs[port_id].len);
        dpdk_context.rx_mbufs[port_id].len = 0;
    }

    int ret = rte_eth_rx_burst((uint8_t)port_id, rte_lcore_id(), dpdk_context.rx_mbufs[port_id].m_table, MAX_PKT_BURST);
    dpdk_context.rx_mbufs[port_id].len = ret;

    return ret;
}

/*----------------------------------------------------------------------------*/
uint8_t * dpdk_get_txpkt(int port_id, int pkt_size) {
    if (unlikely(dpdk_context.tx_mbufs[port_id].len == MAX_PKT_BURST)) {
        /* TX queue is full */
        return NULL;
    }
    
    int next_pkt = dpdk_context.tx_mbufs[port_id].len;
    struct rte_mbuf * tx_pkt = dpdk_context.tx_mbufs[port_id].m_table[next_pkt];

    tx_pkt->pkt_len = tx_pkt->data_len = pkt_size;
    tx_pkt->nb_segs = 1;
    tx_pkt->next = NULL;

    dpdk_context.tx_mbufs[port_id].len++;

    return rte_pktmbuf_mtod(tx_pkt, uint8_t *);
}

/*----------------------------------------------------------------------------*/
uint32_t dpdk_send_pkts(int port_id) {
    int total_pkt, pkt_cnt;
    total_pkt = pkt_cnt = dpdk_context.tx_mbufs[port_id].len;

    struct rte_mbuf ** pkts = dpdk_context.tx_mbufs[port_id].m_table;

    if (pkt_cnt > 0) {
        int ret;
        do {
            /* Send packets until there is none in TX queue */
            ret = rte_eth_tx_burst(port_id, rte_lcore_id(), pkts, pkt_cnt);
            pkts += ret;
            pkt_cnt -= ret;
        } while (pkt_cnt > 0);

        /* Allocate new packet memory buffer for TX queue (WHY NEED NEW BUFFER??) */
        for (int i = 0; i < dpdk_context.tx_mbufs[port_id].len; i++) {
            /* Allocate new buffer for sended packets */
            dpdk_context.tx_mbufs[port_id].m_table[i] = rte_pktmbuf_alloc(dpdk_context.mempool);
            if (unlikely(dpdk_context.tx_mbufs[port_id].m_table[i] == NULL)) {
                rte_exit(EXIT_FAILURE, "Failed to allocate %d:wmbuf[%d] on device %d!\n", rte_lcore_id(), i, port_id);
            }
        }

        dpdk_context.tx_mbufs[port_id].len = 0;
    }

    return total_pkt;
}

static int
readFully(int fd, void *obuf, int len)
{
    int bytesLeft = len;
    char *buf = (char *) obuf;
    int bytesRead = 0;

    while (bytesLeft > 0) {
        int recv_cnt = dpdk_recv_pkts(iface.port_id);
        if (recv_cnt > 0) {
            /* Receive packets */
            uint16_t len;
            uint8_t * pkt;

            /* Process received packets */
            for (int i = 0; i < recv_cnt; i++) {
                /* Go through received packets */
                pkt = dpdk_get_rxpkt(iface.port_id, i, &len);              
                memcpy(buf, pkt, len);
                bytesLeft -= bytesRead;
                buf += bytesRead;
            }
        }
    }
    if (bytesRead <= 0) return bytesRead;
    return len;
}

void Sync(ArgStruct *p)
{
    char s[] = "SyncMe", response[] = "      ";

    // if (write(p->commfd, s, strlen(s)) < 0 ||           /* Write to nbor */
    //     readFully(p->commfd, response, strlen(s)) < 0)  /* Read from nbor */
    //   {
    //     perror("NetPIPE: error writing or reading synchronization string");
    //     exit(3);
    //   }
    char * packet = (char *)dpdk_get_txpkt(iface.port_id, strlen(s));
    memcpy(packet, s, strlen(s));
    dpdk_send_pkts(iface.port_id);

    readFully(0, response, strlen(s));

    if (strncmp(s, response, strlen(s)))
      {
        fprintf(stderr, "NetPIPE: Synchronization string incorrect! |%s|\n", response);
        exit(3);
      }
}

void PrepareToReceive(ArgStruct *p)
{
        /*
            The Berkeley sockets interface doesn't have a method to pre-post
            a buffer for reception of data.
        */
}

void SendData(ArgStruct *p)
{
    int bytesWritten, bytesLeft;
    char *q;

    bytesLeft = p->bufflen;
    bytesWritten = 0;
    q = p->s_ptr;

    while (bytesLeft > 0) {
        char * packet = (char *)dpdk_get_txpkt(iface.port_id, bytesLeft);
        memcpy(packet, q, bytesLeft);
        dpdk_send_pkts(iface.port_id);

        bytesWritten = bytesLeft;
        bytesLeft -= bytesWritten;
        q += bytesWritten;
    }
    
    if (bytesWritten == -1)
      {
        printf("NetPIPE: write: error encountered, errno=%d\n", errno);
        exit(401);
      }
}

void RecvData(ArgStruct *p)
{
    int bytesLeft;
    int bytesRead;
    char *q;

    bytesLeft = p->bufflen;
    bytesRead = 0;
    q = p->r_ptr;

    while (bytesLeft > 0) {
        int recv_cnt = dpdk_recv_pkts(iface.port_id);
        if (recv_cnt > 0) {
            /* Receive packets */
            uint8_t * pkt;

            /* Process received packets */
            for (int i = 0; i < recv_cnt; i++) {
                /* Go through received packets */
                pkt = dpdk_get_rxpkt(iface.port_id, i, &bytesRead);              
                memcpy(q, pkt, bytesRead);
                bytesLeft -= bytesRead;
                q += bytesRead;
            }
        }
    }

    if (bytesLeft > 0 && bytesRead == 0)
      {
        printf("NetPIPE: \"end of file\" encountered on reading from socket\n");
      }
    else if (bytesRead == -1)
      {
        printf("NetPIPE: read: error encountered, errno=%d\n", errno);
        exit(401);
      }
}

/* uint32_t is used to insure that the integer size is the same even in tests 
 * between 64-bit and 32-bit architectures. */

void SendTime(ArgStruct *p, double *t)
{
    uint32_t ltime, ntime;

    /*
      Multiply the number of seconds by 1e8 to get time in 0.01 microseconds
      and convert value to an unsigned 32-bit integer.
      */
    ltime = (uint32_t)(*t * 1.e8);

    /* Send time in network order */
    ntime = htonl(ltime);
    if (write(p->commfd, (char *)&ntime, sizeof(uint32_t)) < 0)
      {
        printf("NetPIPE: write failed in SendTime: errno=%d\n", errno);
        exit(301);
      }
}

void RecvTime(ArgStruct *p, double *t)
{
    uint32_t ltime, ntime;
    int bytesRead;

    bytesRead = readFully(p->commfd, (void *)&ntime, sizeof(uint32_t));
    if (bytesRead < 0)
      {
        printf("NetPIPE: read failed in RecvTime: errno=%d\n", errno);
        exit(302);
      }
    else if (bytesRead != sizeof(uint32_t))
      {
        fprintf(stderr, "NetPIPE: partial read in RecvTime of %d bytes\n",
                bytesRead);
        exit(303);
      }
    ltime = ntohl(ntime);

        /* Result is ltime (in microseconds) divided by 1.0e8 to get seconds */

    *t = (double)ltime / 1.0e8;
}

void SendRepeat(ArgStruct *p, int rpt)
{
  uint32_t lrpt, nrpt;

  lrpt = rpt;
  /* Send repeat count as a long in network order */
  nrpt = htonl(lrpt);
  if (write(p->commfd, (void *) &nrpt, sizeof(uint32_t)) < 0)
    {
      printf("NetPIPE: write failed in SendRepeat: errno=%d\n", errno);
      exit(304);
    }
}

void RecvRepeat(ArgStruct *p, int *rpt)
{
  uint32_t lrpt, nrpt;
  int bytesRead;

  bytesRead = readFully(p->commfd, (void *)&nrpt, sizeof(uint32_t));
  if (bytesRead < 0)
    {
      printf("NetPIPE: read failed in RecvRepeat: errno=%d\n", errno);
      exit(305);
    }
  else if (bytesRead != sizeof(uint32_t))
    {
      fprintf(stderr, "NetPIPE: partial read in RecvRepeat of %d bytes\n",
              bytesRead);
      exit(306);
    }
  lrpt = ntohl(nrpt);

  *rpt = lrpt;
}

void CleanUp2(ArgStruct *p)
{
   char *quit="QUIT";

   if (p->tr) {

      write(p->commfd,quit, 5);
      read(p->commfd, quit, 5);
      close(p->commfd);

   } else if( p->rcv ) {

      read(p->commfd,quit, 5);
      write(p->commfd,quit,5);
      close(p->commfd);
      close(p->servicefd);

   }
}


void CleanUp(ArgStruct *p)
{
  if (p->tr) {
    close(p->commfd);
  } else if (p->rcv) {
    close(p->commfd);
    close(p->servicefd);
  }    
}


void Reset(ArgStruct *p)
{
  
  /* Reset sockets */

  if(p->reset_conn) {

    doing_reset = 1;

    /* Close the sockets */

    CleanUp2(p);

    /* Now open and connect new sockets */

    Setup(p);

  }

}

void AfterAlignmentInit(ArgStruct *p)
{

}

