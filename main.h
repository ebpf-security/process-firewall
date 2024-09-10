/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __TCPCONNLAT_H
#define __TCPCONNLAT_H

// #include <inttypes.h>
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define TASK_COMM_LEN 128

struct piddata {
	char comm[TASK_COMM_LEN];
	 __u64 ts;
	 __u32 tgid;
     __u32 pid;
};

struct net_id_t {
     __u16 protocol;
     __u16 block;
    
     __u16 src_port;
     __u16 dst_port;
        
     __u32 src_ip4;
     __u32 dst_ip4;
};


struct net6_id_t {
     __u16 protocol; 
    
     __u16 src_port;
     __u16 dst_port;        
     //__uint128_t src_ip6;    combined stack size of 2 calls is 544. Too large
     __u8 daddr_v6[16];
};

struct event {
    union {
        __u32 saddr_v4;
        __u8 saddr_v6[16];
    };
    union {
        __u32 daddr_v4;
        __u8 daddr_v6[16];
    };
    char comm[TASK_COMM_LEN];
    __u64 delta_us;
    __u64 ts_us;
    __u32 tgid;
    int af;
    __u16 lport;
    __u16 dport;
};

#endif /* __TCPCONNLAT_H_ */
