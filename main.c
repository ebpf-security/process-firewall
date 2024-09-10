// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)


#include "main.h"
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>
#include "skel.h"


#define PCAP_DONT_INCLUDE_PCAP_BPF_H 1

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>


#define OUTGOING        0x01
#define INGOING         0x02

static int 	linkoffset = 0;
static unsigned char    g_local_mac[6] = {0};
static unsigned int     g_local_addr4  = 0;
static unsigned short   g_dir          = INGOING;
static unsigned int     g_remote_addr4 = 0;
static int              ipv6 = 0;




/* Keep this in sync with /usr/src/linux/include/linux/route.h */
#define RTF_UP          0x0001          /* route usable                 */
#define RTF_GATEWAY     0x0002          /* destination is a gateway     */
#define RTF_HOST        0x0004          /* host entry (net otherwise)   */
#define RTF_REINSTATE   0x0008          /* reinstate route after tmout  */
#define RTF_DYNAMIC     0x0010          /* created dyn. (by redirect)   */
#define RTF_MODIFIED    0x0020          /* modified dyn. (by redirect)  */
#define RTF_MTU         0x0040          /* specific MTU for this route  */

static int filtersmap = -1;
static int procnamesmap = -1;
static int g_ssh_port   = 22;

static char	g_cRcvEth[32] = {0}; 
pcap_t *pcap_rcv = NULL;


#define PERF_BUFFER_PAGES 16
#define PERF_POLL_TIMEOUT_MS 1

static volatile sig_atomic_t exiting = 0;

static struct env {
    __u64 min_us;
    pid_t pid;
    bool timestamp;
    bool lport;
    bool verbose;
} env;

const char* argp_program_version = "ebpf-dump 0.1";

const char argp_program_doc[] =
    "\nTrace TCP connects and show Process name.\n"  ;

static const struct argp_option opts[] = {
    {"timestamp", 't', NULL, 0, "Include timestamp on output"},
    {"pid", 'p', "PID", 0, "Trace this PID only"},
    {"lport", 'L', NULL, 0, "Include LPORT on output"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static error_t parse_arg(int key, char* arg, struct argp_state* state) {
    static int pos_args;

    switch (key) {
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case 'v':
            env.verbose = true;
            break;
        case 'p':
            errno = 0;
            env.pid = strtol(arg, NULL, 10);
            if (errno) {
                fprintf(stderr, "invalid PID: %s\n", arg);
                argp_usage(state);
            }
            break;
        case 't':
            env.timestamp = true;
            break;
        case 'L':
            env.lport = true;
            break;
        case ARGP_KEY_ARG:
            if (pos_args++) {
                fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
                argp_usage(state);
            }
            errno = 0;
            env.min_us = strtod(arg, NULL) * 1000;
            if (errno || env.min_us <= 0) {
                fprintf(stderr, "Invalid delay (in us): %s\n", arg);
                argp_usage(state);
            }
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char* format,
                           va_list args) {
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_int(int signo) {
    exiting = 1;
    if (pcap_rcv != NULL) {
      pcap_breakloop(pcap_rcv);
    }
}

void handle_event(void* ctx, int cpu, void* data, __u32 data_sz) {
    const struct event* e = data;
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    union {
        struct in_addr x4;
        struct in6_addr x6;
    } s, d;
    static __u64 start_ts;

    if (env.timestamp) {
        if (start_ts == 0)
            start_ts = e->ts_us;
        printf("%-9.3f ", (e->ts_us - start_ts) / 1000000.0);
    }
    if (e->af == AF_INET) {
        s.x4.s_addr = e->saddr_v4;
        d.x4.s_addr = e->daddr_v4;
    } else if (e->af == AF_INET6) {
        memcpy(&s.x6.s6_addr, e->saddr_v6, sizeof(s.x6.s6_addr));
        memcpy(&d.x6.s6_addr, e->daddr_v6, sizeof(d.x6.s6_addr));
    } else {
        fprintf(stderr, "broken event: event->af=%d", e->af);
        return;
    }

    if (env.lport) {
        printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", e->tgid,
               e->comm, e->af == AF_INET ? 4 : 6,
               inet_ntop(e->af, &s, src, sizeof(src)), e->lport,
               inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
               e->delta_us / 1000.0);
    } else {
        printf("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f\n", e->tgid, e->comm,
               e->af == AF_INET ? 4 : 6, inet_ntop(e->af, &s, src, sizeof(src)),
               inet_ntop(e->af, &d, dst, sizeof(dst)), ntohs(e->dport),
               e->delta_us / 1000.0);
    }
}

void handle_lost_events(void* ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "lost %llu events on CPU #%d\n", lost_cnt, cpu);
}
static bool fentry_try_attach(int id) {
    int prog_fd, attach_fd;
    char error[4096];
    struct bpf_insn insns[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    LIBBPF_OPTS(bpf_prog_load_opts, opts,
                .expected_attach_type = BPF_TRACE_FENTRY, .attach_btf_id = id,
                .log_buf = error, .log_size = sizeof(error), );

    prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, "test", "GPL", insns,
                            sizeof(insns) / sizeof(struct bpf_insn), &opts);
    if (prog_fd < 0)
        return false;

    attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
    if (attach_fd >= 0)
        close(attach_fd);

    close(prog_fd);
    return attach_fd >= 0;
}
static bool fentry_can_attach(const char* name, const char* mod) {
    struct btf *btf, *vmlinux_btf, *module_btf = NULL;
    int err, id;

    vmlinux_btf = btf__load_vmlinux_btf();
    err = libbpf_get_error(vmlinux_btf);
    if (err)
        return false;

    btf = vmlinux_btf;

    if (mod) {
        module_btf = btf__load_module_btf(mod, vmlinux_btf);
        err = libbpf_get_error(module_btf);
        if (!err)
            btf = module_btf;
    }

    id = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC);

    btf__free(module_btf);
    btf__free(vmlinux_btf);
    return id > 0 && fentry_try_attach(id);
}


/**
 * Finds a BPF map's FD.
 * 
 * @param bpf_obj A pointer to the BPF object.
 * @param mapname The name of the map to retrieve.
 * 
 * @return The map's FD.
*/
int findmapfd(struct bpf_object *bpf_obj, const char *mapname)
{
    struct bpf_map *map;
    int fd = -1;

    map = bpf_object__find_map_by_name(bpf_obj, mapname);

    if (!map) 
    {
        fprintf(stderr, "Error finding eBPF map: %s\n", mapname);

        goto out;
    }

    fd = bpf_map__fd(map);

    out:
        return fd;
}


/* Caller must free return string. */

char *proc_gen_fmt(char *name, int more, FILE * fh,...)
{
    char buf[512], format[512] = "";
    char *title, *head, *hdr;
    va_list ap;

    if (!fgets(buf, (sizeof buf) - 1, fh))
	return NULL;
    strcat(buf, " ");

    va_start(ap, fh);
    title = va_arg(ap, char *);
    for (hdr = buf; hdr;) {
	while (isspace(*hdr) || *hdr == '|')
	    hdr++;
	head = hdr;
	hdr = strpbrk(hdr, "| \t\n");
	if (hdr)
	    *hdr++ = 0;

	if (!strcmp(title, head)) {
	    strcat(format, va_arg(ap, char *));
	    title = va_arg(ap, char *);
	    if (!title || !head)
		break;
	} else {
	    strcat(format, "%*s");	/* XXX */
	}
	strcat(format, " ");
    }
    va_end(ap);

    if (!more && title) {
	fprintf(stderr, "warning: %s does not contain required field %s\n",
		name, title);
	return NULL;
    }
    return strdup(format);
}


static void get_ssh_port(void) {
   
    FILE *fp = NULL;
    char buffer[256],*p;
    int  port;

    fp = fopen("/etc/ssh/sshd_config", "r"); 

    if (fp == NULL)
       return ;


    do {
          if (fgets(buffer, sizeof(buffer), fp)) { 
            p = buffer;
    		 /* ignore whitespace */
            while(isspace(*p) && *p != '\0')
    			p++;    
    		if (*p == '\0')
    			continue;
            if (*p == '#')
    			continue;
            if (strncasecmp(p, "port",4) == 0)  {
                p += 5;
                port = atoi(p);

                if (port > 0 && port < 65536) {
                   g_ssh_port = port;              
                }
                
                break;
            }
        
          }
    } while (!feof(fp));

    fclose(fp); 


}

static void get_best_iface(void) {

    char buff[1024], iface[17];
    char gate_addr[128], net_addr[128];
    char mask_addr[128];
    int num, iflags, metric, refcnt, use, mss, window, irtt;
    FILE *fp = fopen("/proc/net/route", "r");
    char *fmt;


	snprintf(g_cRcvEth, sizeof(g_cRcvEth), "%s", "eth0");

    if (fp == NULL)
        return;

    
    irtt = 0;
    window = 0;
    mss = 0;

     fmt = proc_gen_fmt("/proc/net/route", 0, fp,
		       "Iface", "%16s",
		       "Destination", "%127s",
		       "Gateway", "%127s",
		       "Flags", "%X",
		       "RefCnt", "%d",
		       "Use", "%d",
		       "Metric", "%d",
		       "Mask", "%127s",
		       "MTU", "%d",
		       "Window", "%d",
		       "IRTT", "%d",
		       NULL);
    /* "%16s %127s %127s %X %d %d %d %127s %d %d %d\n" */

    if (!fmt)
	   return; 

    while (fgets(buff, 1023, fp)) {
        num = sscanf(buff, fmt,
		     iface, net_addr, gate_addr,
		     &iflags, &refcnt, &use, &metric, mask_addr,
		     &mss, &window, &irtt);
	    if (num < 10 || !(iflags & RTF_UP) || !(iflags & RTF_GATEWAY))
	        continue;

 
        printf("iface=%s    ",iface);        
        //snprintf(g_cAttEth, sizeof(g_cAttEth), "%s", iface);
        snprintf(g_cRcvEth, sizeof(g_cRcvEth), "%s", iface);
        break;

   }


    free(fmt);
    (void) fclose(fp);


}



void udp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
    const unsigned char *data = packet_content + linkoffset;
    struct ip *this_iphdr = (struct ip *)data;
    struct udphdr *this_udphdr = (struct udphdr*)((u_char *)data + (this_iphdr->ip_hl*4));
        
    int iplen, ip_hl = this_iphdr->ip_hl * 4;
    unsigned short sport,dport,udp_len,payload_s;
    char source_ip[16],dest_ip[16];

    struct net_id_t conn_id = {0};  
    struct piddata  piddata = {0}; 
    

    sport = ntohs(this_udphdr->uh_sport);
	dport = ntohs(this_udphdr->uh_dport);
	snprintf(source_ip,16,"%s",inet_ntoa(this_iphdr->ip_src));
	snprintf(dest_ip,16,"%s",inet_ntoa(this_iphdr->ip_dst));

	
    iplen = ntohs(this_iphdr->ip_len);	
	udp_len = ntohs(this_udphdr->uh_ulen);

    if (iplen != (udp_len + ip_hl))
        return;

	payload_s = udp_len - 8;
    if (payload_s < 1)
        return;  

   if (g_dir != OUTGOING)
        return;
  
             
   conn_id.protocol = IPPROTO_UDP;
   conn_id.src_port = sport;
   conn_id.src_ip4  = 0;
   conn_id.dst_port = 0;
   conn_id.dst_ip4  = this_iphdr->ip_dst.s_addr;
    
   if (bpf_map_lookup_elem(filtersmap, &conn_id, &piddata) != 0)           {
        return;;
   }

   printf("UDP src_port=%d det_ip=%s:%d comm=%s\n",sport,dest_ip,dport,piddata.comm);


}


void tcp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {

	const unsigned char *data = packet_content + linkoffset;
	struct ip *this_iphdr = (struct ip *)data;
	struct tcphdr *this_tcphdr = (struct tcphdr *)(data+(this_iphdr->ip_hl*4));
	int iplen,datalen,ip_tcp_headlen;
    unsigned short dport,sport;
    char source_ip[16],dest_ip[16];
    struct net_id_t conn_id = {0};  
    struct piddata  piddata = {0}; 

    iplen = ntohs(this_iphdr->ip_len);	
	ip_tcp_headlen = this_iphdr->ip_hl*4+ 4 * this_tcphdr->th_off;
	if(ip_tcp_headlen > 100 || ip_tcp_headlen < 32 || iplen < ip_tcp_headlen) 
		return;

    snprintf(source_ip,16,"%s",inet_ntoa(this_iphdr->ip_src));
	snprintf(dest_ip,16,"%s",inet_ntoa(this_iphdr->ip_dst));
    
    dport = ntohs(this_tcphdr->th_dport);
    sport = ntohs(this_tcphdr->th_sport);
    
    datalen = iplen -ip_tcp_headlen;  

    if (g_dir != OUTGOING)
        return;
    if (sport == g_ssh_port) /*too more print*/
        return;
  
             
   conn_id.protocol = IPPROTO_TCP;
   conn_id.src_port = sport;
   conn_id.src_ip4  = 0;
   conn_id.dst_port = 0;
   conn_id.dst_ip4  = this_iphdr->ip_dst.s_addr;
    
   if (bpf_map_lookup_elem(filtersmap, &conn_id, &piddata) != 0)           {
        return;;
   }

   printf("TCP src_port=%d dst_ip=%s:%d   comm=%s\n",sport,dest_ip,dport,piddata.comm);

}





void ip_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {

	 struct iphdr *ipptr;

	 struct ip *this_iphdr;

    ipv6 = 0;
    g_dir = 0;
     
    if (memcmp(g_local_mac,packet_content + 6 ,6) == 0 )
			g_dir = OUTGOING;
    if (memcmp(g_local_mac,packet_content ,6) == 0 )
			g_dir = INGOING;

     	 /*ipv6*/
	 if(packet_content[linkoffset] == 0x60  && packet_content[linkoffset + 6] == 0x06) 	 {
         ipv6 = 1;             
		// tcp_v6_callback(argument,pcap_header,packet_content);
	     return;
	 }

	 if(packet_content[linkoffset] == 0x60  && packet_content[linkoffset + 6] == 0x11) 	 {
         ipv6 = 1;
		 //udp_v6_callback(argument,pcap_header,packet_content);		  
		 return; 
          
     }
		
     
	 
	 ipptr = (struct iphdr *)(packet_content + linkoffset);
	 this_iphdr = (struct ip *)(packet_content + linkoffset);
     
   
     if (this_iphdr->ip_dst.s_addr == g_local_addr4) {
         g_dir = INGOING;
         g_remote_addr4 = this_iphdr->ip_src.s_addr;
     }
     else  if (this_iphdr->ip_src.s_addr == g_local_addr4) {
         g_dir = OUTGOING;
         g_remote_addr4 = this_iphdr->ip_dst.s_addr;
     }
    // else
        //return;




	 switch(ipptr->protocol) {
		  case 6:
		   tcp_packet_callback(argument,pcap_header,packet_content);
		   break;	 
		  case 17:
		   udp_packet_callback(argument,pcap_header,packet_content);
		   break;
          case 1:
		   //icmp_packet_callback(argument,pcap_header,packet_content);
		   break;
		  default:
		   break;
	 }

}





void ethernet_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {


	if(pcap_header->len > 65536)
	   return;
    
	if(pcap_header->len < 40)
	   return;


    if (packet_content[12] == 0x08 && packet_content[13] == 0) {
	   	 /* Regular ethernet */
	   	 linkoffset = 14;	
	} else  if (packet_content[12] == 0x86 && packet_content[13] == 0xdd) {
	   	 /* Regular ethernet */
	   	 linkoffset = 14;	
	} 
	 
	else
	   	 /* non-ip frame */
	    	return;
	 
    
	ip_packet_callback(argument,pcap_header,packet_content);
	return;

	
}





pcap_t *
pcap_open_wmk(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
	pcap_t *p;
	int status;

	p = pcap_create(source, errbuf);
	if (p == NULL)
		return (NULL);
	status = pcap_set_snaplen(p, snaplen);
	if (status < 0)
		goto fail;
	status = pcap_set_promisc(p, promisc);
	if (status < 0)
		goto fail;
	status = pcap_set_timeout(p, to_ms);
	if (status < 0)
		goto fail;
	/*
	 * Mark this as opened with pcap_open_live(), so that, for
	 * example, we show the full list of DLT_ values, rather
	 * than just the ones that are compatible with capturing
	 * when not in monitor mode.  That allows existing applications
	 * to work the way they used to work, but allows new applications
	 * that know about the new open API to, for example, find out the
	 * DLT_ values that they can select without changing whether
	 * the adapter is in monitor mode or not.
	 */
	 status = pcap_set_buffer_size(p,4*1024*1024);
	if (status !=0)
		goto fail;
	
	//p->oldstyle = 1;
	status = pcap_activate(p);
	if (status < 0)
		goto fail;
	return (p);
fail:
	
	pcap_close(p);
	return (NULL);
}



int
get_mac(char *device)
{
	 int fd;
	 struct ifreq ifr;
	 int err;
	 char mac[20];

	 
	 fd = socket(AF_INET, SOCK_DGRAM, 0);
	 memset(&ifr,0,sizeof(ifr));
	 ifr.ifr_addr.sa_family = AF_INET;
	 strncpy(ifr.ifr_name, device, IFNAMSIZ-1);
	 err=ioctl(fd, SIOCGIFHWADDR, &ifr);
	 close(fd);
	 if(err>=0)
	 {		
		memcpy(g_local_mac,ifr.ifr_hwaddr.sa_data,6);
		         
		sprintf(mac,"%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		 (unsigned char)ifr.ifr_hwaddr.sa_data[0],
	         (unsigned char)ifr.ifr_hwaddr.sa_data[1],
	         (unsigned char)ifr.ifr_hwaddr.sa_data[2],
	         (unsigned char)ifr.ifr_hwaddr.sa_data[3],
	         (unsigned char)ifr.ifr_hwaddr.sa_data[4],
	         (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

		printf("MAC=%s \n",mac);
				 
	 	return 1;
	 }

	 return 0;
}


int main(int argc, char** argv) {
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };
    struct perf_buffer* pb = NULL;
    struct tcpconnlat_bpf* obj;
    int err;
    

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    obj = tcpconnlat_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open BPF object\n");
        return 1;
    }

    /* initialize global data (filtering options) */
    obj->rodata->targ_min_us = env.min_us;
    obj->rodata->targ_tgid = env.pid;

    if (fentry_can_attach("tcp_v4_connect", NULL)) {
        bpf_program__set_attach_target(obj->progs.tcp_connect, 0,
                                       "tcp_connect");
        bpf_program__set_attach_target(obj->progs.fentry_udp_sendmsg, 0,
                                      "udp_sendmsg");         
        bpf_program__set_attach_target(obj->progs.fentry_tcp_v6_connect, 0,
                                       "tcp_v6_connect");
        bpf_program__set_attach_target(obj->progs.fentry_tcp_rcv_state_process,
                                       0, "tcp_rcv_state_process");
        bpf_program__set_autoload(obj->progs.tcp_v4_connect, false);
        bpf_program__set_autoload(obj->progs.tcp_v6_connect, false);
        bpf_program__set_autoload(obj->progs.tcp_rcv_state_process, false);
   
    } else {
        bpf_program__set_autoload(obj->progs.fentry_tcp_v4_connect, false);
        bpf_program__set_autoload(obj->progs.fentry_tcp_v6_connect, false);
        bpf_program__set_autoload(obj->progs.fentry_tcp_rcv_state_process,
                                  false);
    }

    err = tcpconnlat_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = tcpconnlat_bpf__attach(obj);
    if (err) {
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
                          handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "failed to open perf buffer: %d\n", errno);
        goto cleanup;
    }


    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    if (signal(SIGTERM, sig_int) == SIG_ERR) {
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        err = 1;
        goto cleanup;
    }

    get_best_iface();
    get_ssh_port();   


	filtersmap = findmapfd(obj->obj, "hfw_network_map");
    
    // Check for valid maps.
    if (filtersmap < 0)    {
        printf("Error finding 'hfw_network_map' BPF map.\n");
        goto cleanup;
    }

    procnamesmap = findmapfd(obj->obj, "hash_proc_name");
    
    // Check for valid maps.
    if (procnamesmap < 0)    {
        printf("Error finding 'hash_proc_name' BPF map.\n");
        goto cleanup;
    }



    char errbuf[128];
    get_mac(g_cRcvEth);
	pcap_rcv = pcap_open_wmk(g_cRcvEth,65536,0,1,errbuf);
	if (pcap_rcv==NULL)	{
	    fprintf(stderr,"pcap_rcv open error :%s\n",errbuf);	 
	     goto cleanup;
	}
	
	//get_pid();	

	pcap_loop(pcap_rcv,-1,ethernet_packet_callback,NULL);	 
	pcap_close(pcap_rcv);



    /* main: poll */
    while (!exiting) {
        err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }
        /* reset err to return 0 if exiting */
        err = 0;
    }

    printf("exit cleanup....\n");

cleanup:
    perf_buffer__free(pb);

    tcpconnlat_bpf__destroy(obj);



    return err != 0;
}
