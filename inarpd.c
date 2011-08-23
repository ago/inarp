/*
    inarpd.c
    Inverse ARP daemon for Linux
    Copyright (C) 2003 Krzysztof Halasa <khc@pm.waw.pl>

    This program is free software; you can redistribute it and/or modify
    it under the terms of version 2 of the GNU General Public License
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <asm/types.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#define __const__ /* avoid compiler warnings related to __const__ returns */
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>

#define INARP_DELAY 60
#define INARP_TIMEOUT 200
#define min(a, b) ((a) > (b) ? (b) : (a))
#define MAX_ADDRESSES 4

#define error(...) fprintf(stderr, __VA_ARGS__)

#define IP_ADDR_LEN 4
#define IP6_ADDR_LEN 16

#define GET_DEVICE_DONT_CREATE 1
#define GET_DEVICE_CREATE_NEW 2

typedef struct {
	__u16 hrd;
	__u16 pro;
	__u8 hln;
	__u8 pln;
	__u16 op;
	unsigned char data[2 * (IP6_ADDR_LEN + IFHWADDRLEN)];
}arp_packet;


typedef struct {
	unsigned short family;
	unsigned char addr[IP6_ADDR_LEN];
	unsigned char peer[IP6_ADDR_LEN];
	unsigned char bits;
	time_t peer_time;
}ip_t;


typedef struct {
	unsigned short family;
	unsigned char peer[IP6_ADDR_LEN];
	time_t peer_time;
}route_t;


typedef struct device {
	int active;
	int add_route;

	int index;
	int flags;
	int type;
	char name[IFNAMSIZ];
	unsigned char addr[IFHWADDRLEN];
	unsigned char bcast[IFHWADDRLEN];
	unsigned int addr_len;
	unsigned int has_name, has_addr, has_bcast;

	ip_t ip[MAX_ADDRESSES];
	route_t route[MAX_ADDRESSES];
	unsigned int ip_cnt, route_cnt;

	struct device *next;
}device;


static device *first = NULL;
static int add_rt = 0;
static int verbose = 0;
static int ifnum = 0;
static char **iflist = NULL;


void print_ip(int family, unsigned char *ip)
{
	unsigned int i;
	if (family == AF_INET)
		for (i = 0; i < IP_ADDR_LEN; i++)
			printf("%s%u", i == 0 ? "" : ".", ip[i]);
	else
		for (i = 0; i < IP6_ADDR_LEN; i++)
			printf("%s%02X", i == 0 ? "" : ":", ip[i]);
}


void subnet_addr(int family, int bits, unsigned char *ip)
{
	int i, len = (family == AF_INET ? IP_ADDR_LEN : IP6_ADDR_LEN);

	for (i = 0; i < len; i++, bits -= 8)
		if (bits < 8)
			ip[i] &= (0xFF00 >> bits);
}



device * get_device(int idx, int flags)
{
	static device **next_ptr = &first;
	device *dev = first;

	while (dev) {
		if (dev->index == idx) {
			if (flags & GET_DEVICE_CREATE_NEW)
				return NULL; /* already exists */
			return dev;
		}
		dev = dev->next;
	}

	if (flags & GET_DEVICE_DONT_CREATE)
		return NULL;

	dev = malloc(sizeof(device));
	if (!dev) {
		perror("inarpd: malloc() failed");
		exit(1);
	}

	memset(dev, 0, sizeof(dev));
	dev->index = idx;
	snprintf(dev->name, IFNAMSIZ, "#%i", idx);
	dev->name[IFNAMSIZ - 1] = '\x0';
	*next_ptr = dev;
	next_ptr = &(*next_ptr)->next;
	return dev;
}


int add_iface(const char *name, int add_route)
{
	device *dev = first;
	while (dev) {
		if (!strcmp(name, dev->name)) {
			if (dev->active) {
				error("Interface %s specified twice\n", name);
				return -1;
			}
			dev->active = 1;
			dev->add_route = add_route;
			return 0;
		}
		dev = dev->next;
	}

	error("Interface %s not found\n", name);
	return -1;
}


void parse_link(struct ifinfomsg *msg, int msglen)
{
	struct rtattr * rtptr = IFLA_RTA(msg);
	device *dev = get_device(msg->ifi_index, GET_DEVICE_CREATE_NEW);
	char *name = NULL;
	unsigned char *addr = NULL, *bcast = NULL;
	int i;

	if (!dev) {
		if (verbose > 0)
			printf("Device #%u already exists\n", msg->ifi_index);
		return;
	}
	
	while (msglen > 0) {
		if (!RTA_OK(rtptr, msglen)) {
			error("RTA %u not OK\n", rtptr->rta_type);
			break;
		}
		if (verbose > 2) {
			printf("RTA %u ", rtptr->rta_type);
			for (i = 0; (unsigned) i < RTA_PAYLOAD(rtptr);
			     i++)
				printf("%02X", ((unsigned char*)
						RTA_DATA(rtptr))[i]);
			putchar('\n');
		}

		switch(rtptr->rta_type) {
		case IFLA_IFNAME:
			name = RTA_DATA(rtptr);
			break;

		case IFLA_ADDRESS:
			if ((RTA_PAYLOAD(rtptr) > IFHWADDRLEN) ||
			    ((addr || bcast) &&
			     RTA_PAYLOAD(rtptr) != dev->addr_len)) {
				error("Device %s hw address length is"
				      "incorrect\n", dev->name);
				break;
			}
			addr = RTA_DATA(rtptr);
			dev->addr_len = RTA_PAYLOAD(rtptr);
			break;

		case IFLA_BROADCAST:
			if ((RTA_PAYLOAD(rtptr) > IFHWADDRLEN) ||
			    ((addr || bcast) &&
			     RTA_PAYLOAD(rtptr) != dev->addr_len)) {
				error("Device %s hw broadcast address length"
				      " is incorrect\n", dev->name);
				break;
			}
			bcast = RTA_DATA(rtptr);
			dev->addr_len = RTA_PAYLOAD(rtptr);
			break;
		}
		rtptr = RTA_NEXT(rtptr, msglen);
	}

	dev->type = msg->ifi_type;
	dev->flags = msg->ifi_flags;
	if (name) {
		strncpy(dev->name, name, IFNAMSIZ - 1);
		dev->name[IFNAMSIZ - 1] = '\x0';
		dev->has_name++;
	}
	if (addr) {
		memcpy(dev->addr, addr, dev->addr_len);
		dev->has_addr++;
	}
	if (bcast) {
		memcpy(dev->bcast, bcast, dev->addr_len);
		dev->has_bcast++;
	}
}



void parse_addr(struct ifaddrmsg *msg, int msglen)
{
	struct rtattr * rtptr = IFA_RTA(msg);
	device *dev = get_device(msg->ifa_index, GET_DEVICE_DONT_CREATE);
	unsigned char *addr = NULL, *peer = NULL;
	int i, len;

	if (!dev) {
		if (verbose > 0)
			printf("Device #%u has no link-level description\n",
			       msg->ifa_index);
		return;
	}

	if (verbose > 2)
		printf("family %u prefixlen %u\n", msg->ifa_family,
		       msg->ifa_prefixlen);

	while (msglen > 0) {
		if (!RTA_OK(rtptr, msglen)) {
			error("IFA %u not OK\n", rtptr->rta_type);
			break;
		}
		if (verbose > 2) {
			printf("IFA %u ", rtptr->rta_type);
			for (i = 0; (unsigned) i < RTA_PAYLOAD(rtptr);
			     i++)
				printf("%02X", ((unsigned char*)
						RTA_DATA(rtptr))[i]);
			putchar('\n');
		}

		switch(rtptr->rta_type) {
		case IFA_LOCAL:
		case IFA_ADDRESS:
			if ((msg->ifa_family == AF_INET &&
			     RTA_PAYLOAD(rtptr) != IP_ADDR_LEN) ||
			    (msg->ifa_family == AF_INET6 &&
			     RTA_PAYLOAD(rtptr) != IP6_ADDR_LEN)) {
				error("Device %s has incorrect IP address"
				      " length\n", dev->name);
				break;
			}
			if (msg->ifa_family != AF_INET &&
			    msg->ifa_family != AF_INET6)
				break; /* ignore non-IP adresses */

			switch(rtptr->rta_type) {
			case IFA_LOCAL: addr = RTA_DATA(rtptr); break;
			case IFA_ADDRESS: peer = RTA_DATA(rtptr); break;
			}
			break;
		}
		rtptr = RTA_NEXT(rtptr, msglen);
	}

	if (!addr && peer) {
		if (verbose > 0)
			printf("Device %s has an IP peer with no local"
			       " IP address\n", dev->name);
	}
	if (addr && !peer) {
		if (verbose > 0)
			printf("Device %s has a local IP address with no"
			       "IP destination submask\n", dev->name);
	}
	if (!addr)
		return;

	if (dev->ip_cnt >= MAX_ADDRESSES) {
		error("Device %s has more than %i IP addresses\n",
		      dev->name, MAX_ADDRESSES);
		return;
	}

	len = (msg->ifa_family == AF_INET ? IP_ADDR_LEN : IP6_ADDR_LEN);

	dev->ip[dev->ip_cnt].family = msg->ifa_family;
	memcpy(&dev->ip[dev->ip_cnt].addr, addr, len);
	subnet_addr(msg->ifa_family, msg->ifa_prefixlen, peer);
	memcpy(&dev->ip[dev->ip_cnt].peer, peer, len);
	dev->ip[dev->ip_cnt++].bits = msg->ifa_prefixlen;
}



void read_ifaces(void)
{
	struct sockaddr_nl addr;
	socklen_t addr_len = sizeof(addr);
	unsigned char buffer[4096];
	int sock, len;

	struct { 
                struct nlmsghdr nlh;
                struct rtgenmsg g;
        }req;

	if (verbose > 0)
		printf("Searching for network interfaces...\n");

        sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (sock < 0) {
                perror("socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE) failed");
		exit(1);
	}

        memset(&addr, 0, sizeof(addr)); 
	addr.nl_family = AF_NETLINK;

	if (bind(sock, (struct sockaddr*)&addr, addr_len) < 0) {
		perror("bind(AF_NETLINK) failed");
		exit(1);
	}

	req.nlh.nlmsg_len = sizeof(req);
        req.nlh.nlmsg_type = RTM_GETLINK;
        req.nlh.nlmsg_flags = NLM_F_ROOT | NLM_F_REQUEST;
        req.nlh.nlmsg_pid = 0;
        req.nlh.nlmsg_seq = 1;
        req.g.rtgen_family = AF_PACKET;

        if (sendto(sock, (void*)&req, sizeof(req), 0,
		   (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("inarpd: sendto(RTM_GETLINK) failed");
		exit(1);
	}

	while(1) {
		struct nlmsghdr *h = (struct nlmsghdr*)buffer;
		if ((len = recv(sock, buffer, sizeof(buffer), 0)) < 0) {
			perror("recv() failed");
			exit(1);
		}

		while (len > 0) {
			if (!NLMSG_OK(h, (unsigned) len)) {
				error("NLMSG 0x%X not OK\n", h->nlmsg_type);
				break;
			}

			if (verbose > 2)
				printf("NLMSG 0x%X\n", h->nlmsg_type);

			if (h->nlmsg_type == RTM_NEWLINK)
				parse_link(NLMSG_DATA(h), IFLA_PAYLOAD(h));

			else if (h->nlmsg_type == RTM_NEWADDR)
				parse_addr(NLMSG_DATA(h), IFA_PAYLOAD(h));

			else if (h->nlmsg_type == NLMSG_DONE) {
				if (req.nlh.nlmsg_type == RTM_GETADDR) {
					close(sock);
					return;
				}
				req.nlh.nlmsg_type = RTM_GETADDR;
				if (sendto(sock, (void*)&req, sizeof(req), 0,
					   (struct sockaddr*)&addr,
					   sizeof(addr)) < 0) {
					perror("inarpd: sendto(RTM_GETADDR)"
					       " failed");
					exit(1);
				}
				break;

			} else
				error("Unknown netlink message type 0x%X\n",
				       h->nlmsg_type);

			h = NLMSG_NEXT(h, len);
		}
	}
}



void send_inarp(int sock, device *dev, int family, int op,
		void *hw, void *peer_hw, void *ip, void *peer_ip)
{
	struct sockaddr_ll addr;
	arp_packet buffer;
	int ip_len = (family == AF_INET ? IP_ADDR_LEN : IP6_ADDR_LEN);
	int len = 8 + 2 * (dev->addr_len + ip_len);

	memset(&buffer, 0, len);

	buffer.hrd = htons(dev->type);
	buffer.pro = htons(family == AF_INET ? ETH_P_IP : ETH_P_IPV6);
	buffer.hln = dev->addr_len;
	buffer.pln = ip_len;
	buffer.op = htons(op);
	memcpy(buffer.data,			          hw, dev->addr_len);
	memcpy(buffer.data + dev->addr_len,	          ip, ip_len);
	memcpy(buffer.data + dev->addr_len + ip_len, peer_hw, dev->addr_len);
	if (peer_ip)
		memcpy(buffer.data + 2 * dev->addr_len + ip_len,
		       peer_ip, ip_len);

	if (verbose > 1) {
		int i;
		printf("Sending\t");
		for (i = 0; i < len; i++)
			printf(" %02X", ((unsigned char *)&buffer)[i]);
		putchar('\n');

	}

	bzero((char *)&addr, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ARP);
	addr.sll_ifindex = dev->index;
	addr.sll_halen = dev->addr_len;
	memcpy(addr.sll_addr, peer_hw, dev->addr_len);
	sendto(sock, &buffer, len, 0, (struct sockaddr*)&addr, sizeof(addr));
}



void send_requests(int sock)
{
	device *dev = first;
	unsigned int i;

	do {
		if (!dev->active)
			continue;
		if (verbose > 1)
			printf("Sending request on %s\n", dev->name);
		for (i = 0; i < dev->ip_cnt; i++)
			send_inarp(sock, dev, dev->ip[i].family,
				   ARPOP_InREQUEST, &dev->addr, &dev->bcast,
				   &dev->ip[i].addr, NULL);

	}while ((dev = dev->next) != NULL);
}



void add_route(device *dev, int family, unsigned char *ip)
{
	unsigned int i, len = (family == AF_INET ? IP_ADDR_LEN : IP6_ADDR_LEN);

	for (i = 0; i < dev->route_cnt; i++)
		if ((dev->route[i].family == family) &&
		    !memcmp(dev->route[i].peer, ip, len)) {
			dev->route[i].peer_time = time(NULL);
			return; /* already added */
		}

	if (i == MAX_ADDRESSES) {
		if (verbose > 1)
			printf("Too many peer IP addresses on device %s\n",
			       dev->name);
		return;
	}

	printf("Device %s peer IP is ", dev->name);
	print_ip(family, ip);
	putchar('\n');

	dev->route[dev->route_cnt].family = family;
	memcpy(dev->route[dev->route_cnt].peer, ip, len);
	dev->route[dev->route_cnt++].peer_time = time(NULL);
}


void expire_routes(void)
{
	device *dev = first;
	while (dev) {
		if (dev->active && dev->add_route) {
			unsigned int i = 0;
			while (i < dev->route_cnt) {
				if (time(NULL) - dev->route[i].peer_time >
				    INARP_TIMEOUT) {
					printf("Device %s peer ", dev->name);
					print_ip(dev->route[i].family,
						  dev->route[i].peer);
					printf(" is no longer active\n");
					dev->route_cnt--;
					memcpy(&dev->route[i],
					       &dev->route[i + 1],
					       (MAX_ADDRESSES - i - 1) *
					       sizeof(route_t));
					continue;
				}
				i++;
			}
		}
		dev = dev->next;
	}
}


void inbound_inarp(int sock, device *dev, arp_packet *buffer, int len)
{
	unsigned char *sha, *spa, *tha, *tpa;
	unsigned short family;
	int addr_len, i;

	if (!dev->active) {
		if (verbose > 2)
			printf("received packet on inactive device %s\n",
			       dev->name);
		return;
	}

	if (verbose > 1) {
		printf("%s:", dev->name);
		for (i = 0; i < len; i++)
			printf(" %02X", ((unsigned char*)buffer)[i]);
		putchar('\n');
	}

	buffer->hrd = ntohs(buffer->hrd);
	buffer->pro = ntohs(buffer->pro);
	buffer->op = ntohs(buffer->op);

	if (buffer->op != ARPOP_InREQUEST && buffer->op != ARPOP_InREPLY) {
		if (verbose > 2)
			printf("ignoring packet type 0x%X on %s\n",
			       buffer->op, dev->name);
		return;
	}

	if (buffer->hrd != dev->type) {
		if (verbose > 1)
			printf("wrong hw type 0x%X in packet on %s\n",
			       buffer->hrd, dev->name);
		return;
	}

	if (buffer->hln != dev->addr_len) {
		if (verbose > 1)
			printf("wrong hw address length %u in packet on %s\n",
			       buffer->hln, dev->name);
		return;
	}

	if (len < 8 + 2 * (buffer->hln + buffer->pln)) {
		if (verbose > 1)
			printf("packet is too short on %s\n", dev->name);
		return;
	}

	sha = &buffer->data[0];
	spa = sha + dev->addr_len;
	tha = spa + buffer->pln;
	tpa = tha + dev->addr_len;
	if (dev->type == ARPHRD_DLCI)
		sha = dev->bcast;

	if (buffer->pro != ETH_P_IP && buffer->pro != ETH_P_IPV6) {
		if (verbose > 2)
			printf("unknown protocol 0x%X in packet on %s\n",
			       buffer->pro, dev->name);
		return;
	}

	family = (buffer->pro == ETH_P_IP ? AF_INET : AF_INET6);
	addr_len = (buffer->pro == ETH_P_IP ? IP_ADDR_LEN : IP6_ADDR_LEN);

	if (buffer->pln != addr_len) {
		if (verbose > 1)
			printf("invalid protocol length in packet on %s\n",
			       dev->name);
		return;
	}

	/* FIXME - hw and IP address checks? */
	if (dev->add_route)
		add_route(dev, family, spa);

	if (buffer->op != ARPOP_InREQUEST)
		return;

	for (i = 0; (unsigned) i < dev->ip_cnt; i++) {
		unsigned char addr[IP6_ADDR_LEN];

		if (dev->ip[i].family != family)
			continue;
		if (!dev->add_route) {
			memcpy(addr, dev->ip[i].peer, addr_len);
			subnet_addr(family, dev->ip[i].bits, addr);
			if (memcmp(addr, dev->ip[i].peer, addr_len))
				continue;
		}

		send_inarp(sock, dev, family, ARPOP_InREPLY,
			   dev->addr, sha, dev->ip[i].addr, spa);
		return;
	}
	if (verbose > 1)
		printf("No valid IP address found for this request\n");
}

#define VERSION "0.17"

static void usage(char *prog)
{
	printf("inarpd version %s\n"
			"Copyright (C) 2003 Krzysztof Halasa <khc@pm.waw.pl>\n\n"
			"Usage: inarpd [options] [interfaces...]\n"
			"Options:\n"
			"   -r       = add host IP route for neighbours (default is not to add)\n"
			"   -v       = print info messages\n"
			"   -v -v    = print network packets\n"
			"   -v -v -v = print debug messages\n",
			VERSION, prog);
}

static void parse_args(int argc, char **argv)
{
	while (1)
	{
		int c;
		/* getopt_long stores the option index here. */
		int option_index = 0;
		static struct option long_options[] =
		{
			{"add-route",		no_argument,		0, 'r'},
			{"verbose",		no_argument,		0, 'v'},
			{"help",		no_argument,		0, 'h'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "rvh", long_options, &option_index);

		/* detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{
			case 'r': {
					add_rt = 1;
					break;
				}
			case 'v': {
					verbose++;
					break;
				}
			case 'h': {
					usage(argv[0]);
					exit(0);
					break;
				}
			case '?': {
					/* getopt_long already printed an error message. */
					usage(argv[0]);
					exit(1);
					break;
				}
			default: {
					exit(1);
				}
		}
	}

	if (argc == optind)
		return;

	ifnum = argc - optind;
	iflist = argv + optind;
}

int main(int argc, char *argv[])
{
	int sock, devs = 0, ok, i;
	time_t last_xmit;
	device *dev;

	parse_args(argc, argv);

	read_ifaces();

	ok = 1;
	while(ifnum > 0) {
		if (add_iface(iflist[0], add_rt))
			ok = 0;
		else
			devs = 1;

		iflist++;
		ifnum--;
	}

	if (!ok)
		exit(1);

	if (!devs) {
		dev = first;
		while (dev) {
			dev->active = 1;
			dev->add_route = add_rt;
			dev = dev->next;
		}
	}

	dev = first;
	ok = 0;
	if (!dev) {
		error("inarpd: no network interfaces found\n");
		exit(1);
	}

	do {
		int ip4_cnt = 0, ip6_cnt = 0, peer = 0;

		if (!dev->active)
			continue;

		if (dev->has_name != 1) {
			error("Device %s has no name\n", dev->name);
			dev->active = 0;
			continue;
		}
		if ((dev->flags & IFF_POINTOPOINT) == 0) {
			if (verbose > 0 || devs)
				printf("Device %s is not point-to-point\n",
				       dev->name);
			dev->active = 0;
			continue;
		}
		if (dev->has_addr != 1) {
			if (verbose > 0 || devs)
				printf("Device %s has no hw address\n",
				       dev->name);
			dev->active = 0;
			continue;
		}
		if (dev->has_bcast != 1) {
			if (verbose > 0 || devs)
				printf("Device %s has no peer hw address\n",
				       dev->name);
			dev->active = 0;
			continue;
		}
		if (dev->ip_cnt == 0) {
			if (verbose > 0 || devs)
				printf("Device %s has no IP address\n",
				       dev->name);
			dev->active = 0;
			continue;
		}

		ok = 1;

		if (dev->type == ARPHRD_DLCI)
			memset(dev->addr, 0, dev->addr_len);

		if (!dev->add_route)
		continue;

		for (i = 0; (unsigned) i < dev->ip_cnt; i++) {
			if (dev->ip[i].family == AF_INET) {
				if (memcmp(dev->ip[i].addr, dev->ip[i].peer,
					   IP_ADDR_LEN) ||
				    dev->ip[i].bits != IP_ADDR_LEN * 8)
					peer = 1;
				ip4_cnt++;
			}
			if (dev->ip[i].family == AF_INET6) {
				if (memcmp(dev->ip[i].addr, dev->ip[i].peer,
					   IP6_ADDR_LEN) ||
				    dev->ip[i].bits != IP6_ADDR_LEN * 8)
					peer = 1;
				ip6_cnt++;
			}
		}

		if (ip4_cnt > 1 || ip6_cnt > 1) {
			if (verbose > 0 || devs)
				printf("Can't automatically add routes for"
				       " device %s having more than 1 IP"
				       " address\n", dev->name);
			dev->add_route = 0;
		} else if (peer) {
			if (verbose > 0 || devs)
				printf("Can't automatically add routes for"
				       " device %s with peer address\n",
				       dev->name);
			dev->add_route = 0;
		}
	}while ((dev = dev->next) != NULL);

	if (!ok) {
		error("inarpd: no usable interfaces found\n");
		exit(1);
	}

	if (verbose > 0) {
		dev = first;
		printf("Interfaces:\n");
		do {
			if (!dev->active)
				continue;
			printf("   %s%s", dev->name,
			       dev->add_route ? "(r)" : "");

			if (verbose <= 1) {
				putchar('\n');
				continue;
			}

			if (dev->type == ARPHRD_DLCI)
				printf(" [Q922 ");
			else {
				printf(" [");
				for (i = 0; (unsigned) i < dev->addr_len; i++)
					printf("%s%02X", i == 0 ? "" : ":",
					       dev->addr[i]);
				printf("->");
			}
			for (i = 0; (unsigned) i < dev->addr_len; i++)
				printf("%s%02X", i == 0 ? "" : ":",
				       dev->bcast[i]);
			printf("]");

			for (i = 0; (unsigned) i < dev->ip_cnt; i++) {
				putchar(' ');
				print_ip(dev->ip[i].family, dev->ip[i].addr);
				printf("->");
				print_ip(dev->ip[i].family, dev->ip[i].peer);
				printf("/%u", dev->ip[i].bits);
			}
			putchar('\n');
		}while ((dev = dev->next) != NULL);
	}


	if ((sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP))) == -1) {
		perror("inarpd: socket() failed");
		exit(-1);
	}

	if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0)
		perror("fcntl() failed");

	last_xmit = 0;
	while(1) {
		fd_set set;
                FD_ZERO(&set);
                FD_SET(sock, &set);
		time_t now = time(NULL);
		struct timeval tm;
		arp_packet buffer;
		struct sockaddr_ll addr;
		socklen_t addr_len = sizeof(addr);

		tm.tv_sec = last_xmit + INARP_DELAY - now;
		tm.tv_usec = 0;

 		if (tm.tv_sec <= 0) {
			send_requests(sock);
			last_xmit = now;
			continue;
		}

		expire_routes();
		if (verbose > 2)
			printf("calling select()\n");
		if (select(sock + 1, &set, NULL, NULL, &tm) < 0) {
                        perror("select() failed");
			continue;
		}

                if (!FD_ISSET(sock, &set))
			continue;

		if (verbose > 2)
			printf("calling recv()\n");

		int len = recvfrom(sock, &buffer, sizeof(buffer), 0,
				   (struct sockaddr*)&addr, &addr_len);
		dev = get_device(addr.sll_ifindex, GET_DEVICE_DONT_CREATE);
		if (!dev) {
			if (verbose > 1)
				printf("received packet on unknown device\n");
			continue;
		}
		inbound_inarp(sock, dev, &buffer, len);
	}
}
