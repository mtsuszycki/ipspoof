/*  A very simple IP spoofer written to emulate port scanning with
 *  false IP source.
 *  Use it for educational purpose only.
 *  
 *  Michal Suszycki: 	mike@wizard.ae.krakow.pl
 *  			http://wizard.ae.krakow.pl/~mike
 */
   

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <string.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <time.h>

#define FROMPORT 1024

extern int errno;


struct ippkt
{
        struct iphdr ip;
	struct tcphdr tcp;
} pkt;

	
void usage(char **argv)
{
	fprintf(stdout,"\nSimple spoof by mike (<mike@wizard.ae.krakow.pl>).\n");
	fprintf(stdout,"Usage: %s -s sourceIP -d destIP -p lowport-hiport\n",argv[0]);
	fprintf(stdout,"\nexample: %s -s 1.2.3.4 -d 149.156.201.120 -p 2-100\n\n",argv[0]);
	exit(0);
}	

void main(int argc, char **argv)
{
	struct in_addr from,to;
	struct sockaddr_in sin;
	struct servent *serv;
	struct ippkt *wsk;
	int s, i = 0, opts, port = 1, maxport = 1,packet = 0;
	char host[64], *tmp;
	char fromhost[16];
	
	if (argc != 7)
		usage(argv);
		
	
	while ((opts =  getopt(argc,argv,"s:d:p:")) != EOF){
		switch(opts){
			case 's': 
				if (inet_addr(optarg) == -1){
					fprintf(stderr,"unknown host %s\n",optarg);
					exit (0);
				}
				strncpy(fromhost,optarg,16);
				break;
			case 'd':
				if (inet_addr(optarg) == -1){
					fprintf(stderr,"unknown host %s\n",optarg);
					exit (0);
				}
				strncpy(host,optarg,16);
				break;
			case 'p':
				if (!strstr(optarg,"-")){
					fprintf(stderr,"Bad format for ports\n");
					exit (0);
				}
				else{
					tmp = strtok(optarg,"-");
					port = atoi(tmp);
				}
				tmp = strtok(NULL,"-");
				maxport = atoi(tmp);
				break;	
			default: usage(argv);
		}
	}
	if (maxport < port || maxport > 65535){
		fprintf(stderr,"Port specification mismatch.\n");
		exit (0);
	}
	
	if (!inet_aton(fromhost,&from))
		perror("inet_aton");
	if (!inet_aton(host,&to))
		perror("inet_aton");
	pkt.ip.saddr = to.s_addr;
	pkt.ip.daddr = from.s_addr;
	
	bzero(&sin, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	
	
	pkt.tcp.th_sport = htons(FROMPORT);
	pkt.tcp.th_dport = sin.sin_port;
	pkt.tcp.th_seq = htonl(0x1);
	pkt.tcp.th_ack = 0;
	pkt.tcp.th_flags = TH_SYN;
	pkt.tcp.th_off = sizeof(struct tcphdr)/4;
	pkt.tcp.th_win = htons(2048);
	
	pkt.ip.ihl = sizeof(struct iphdr)/4;
	pkt.ip.version = 4;
	pkt.ip.tot_len = htons(sizeof pkt);
	pkt.ip.id = htons(0x1);
	pkt.ip.ttl = 255;
	pkt.ip.protocol = IPPROTO_TCP;
	bcopy(&from,&sin.sin_addr,sizeof(from));
	pkt.ip.saddr = sin.sin_addr.s_addr;
	bcopy(&to,&sin.sin_addr,sizeof(to));
	pkt.ip.daddr = sin.sin_addr.s_addr;
	
	wsk = &pkt;	
	if ((s = socket(AF_INET,SOCK_RAW,255)) == -1)
			perror("socket");
	for (packet = port; packet <= maxport; packet++){
		i++;
		sin.sin_port = htons(packet);
		pkt.tcp.th_dport = sin.sin_port;
		if (sendto(s,wsk,sizeof(*wsk),0,(struct sockaddr*) &sin, sizeof sin) == -1)
			perror("sendto");
	}
	close(s);
	fprintf(stdout,"\nOk. I've sent %d packets to host %s as host %s\n\n",i,host,fromhost);	
}