# eBPF-firewall: A Linux eBPF per program firewall
eBPF-firewall is an open source process firewall  built using eBPF, we makes BPF programs easier to build.
[![Build Status](https://drone.grafana.net/api/badges/grafana/beyla/status.svg?ref=refs/heads/main)](https://ebpf-security.github.io/navihtml/ebpf-dump.html)

## Requirements
Security monitoring purposes, It runs on/requires Linux Kernel >= 5.10 such as the following platforms:
* Ubuntu 22.04+
* Fedora 33+
* RHEL 9.0+
* Debian 12+
* Rocky Linux 9.0+
* OpenSUSE 15+
* ...

## Building & Running
```console
# Ubuntu
sudo apt-get install -y make gcc libelf-dev libpcap-dev

# RHEL
sudo yum install -y make gcc elfutils-libelf-devel libpcap-devel

$ make
  gcc -c -g -O2  -I./libbpf/    -c -o main.o main.c
  gcc  -o ebpf-dump  main.o   -lpthread  ./libbpf/libbpf.a -lelf -lz -lpcap  -lm

$ ./ebpf-dump 
  iface=ens33    MAC=00-0c-29-50-7b-b6 
  TCP src_port=34330 dst_ip=1.1.1.1:80   comm=/usr/bin/wget
  UDP src_port=41303 det_ip=192.168.21.1:53 comm=/usr/bin/ping
```
Loading eBPF program  requires root privileges 


## eBPF-firewall+
**eBPF-firewall+** is a paid version and completely open source too, main features are:
- Web interfaces
- Linux process name information associated with the packets
- Detailed logging of outbound traffic for all processes
- Detect high-risk traffic threats
- Pure-C eBPF implementation, IPv4 and IPv6 support

**Free Trial**

```console
$ wget https://ebpf-security.github.io/ebpf-firewall
$ chmod +x ./ebpf-firewall 
$ ./ebpf-firewall 
  1. Kill all of  processes...........................
  2. Init  ok.........................................
  3. System is running................................
```

After loading is complete, Open a browser to http://<host>:9998/ to access the Web UI.
Full Trial version available at [https://ebpf-security.github.io/navihtml/ebpf-firewall.html](https://ebpf-security.github.io/navihtml/ebpf-firewall.html)

How to stop?

```console
$ ./ebpf-firewall stop
```

<a href="https://github.com/ebpf-security/ebpf-security.github.io/blob/main/img/1.png"><img height="500" width="820" src="https://github.com/ebpf-security/ebpf-security.github.io/blob/main/img/1.png"></img></a>
&nbsp;


## Contact Us
* Mail to `ebpf-sec@hotmail.com`
Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

## License
This project is licensed under the terms of the
[MIT license](/LICENSE).
