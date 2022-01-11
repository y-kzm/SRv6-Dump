#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/ioctl.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include	<linux/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/ip6.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/tcp.h>
#include	<netinet/udp.h>
#include 	"seg6.h"

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

char *my_ether_ntoa_r(u_char *hwaddr,char *buf,socklen_t size)
{
	snprintf(buf,size,"%02x:%02x:%02x:%02x:%02x:%02x",
		hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);

	return(buf);
}

char *arp_ip2str(u_int8_t *ip,char *buf,socklen_t size)
{
	snprintf(buf,size,"%u.%u.%u.%u",ip[0],ip[1],ip[2],ip[3]);

	return(buf);
}

char *ip_ip2str(u_int32_t ip,char *buf,socklen_t size)
{
struct in_addr	*addr;

	addr=(struct in_addr *)&ip;
	inet_ntop(AF_INET,addr,buf,size);

	return(buf);
}

int PrintEtherHeader(struct ether_header *eh,FILE *fp)															// 2章と全く同じ
{
char	buf[80];

	fprintf(fp,"\nether_header----------------------------\n");
	fprintf(fp,"ether_dhost=%s\n",my_ether_ntoa_r(eh->ether_dhost,buf,sizeof(buf)));
	fprintf(fp,"ether_shost=%s\n",my_ether_ntoa_r(eh->ether_shost,buf,sizeof(buf)));
	fprintf(fp,"ether_type=%02X",ntohs(eh->ether_type));
	switch(ntohs(eh->ether_type)){
		case	ETH_P_IP:
			fprintf(fp,"(IP)\n");
			break;
		case	ETH_P_IPV6:
			fprintf(fp,"(IPv6)\n");
			break;
		case	ETH_P_ARP:
			fprintf(fp,"(ARP)\n");
			break;
		default:
			fprintf(fp,"(unknown)\n");
			break;
	}

	return(0);
}

int PrintArp(struct ether_arp *arp,FILE *fp)
{
// ハードウェアタイプ(説明つきで表示するために宣言)
static char *hrd[]={
        "From KA9Q: NET/ROM pseudo.",
        "Ethernet 10/100Mbps.",
        "Experimental Ethernet.",
        "AX.25 Level 2.",
        "PROnet token ring.",
        "Chaosnet.",
        "IEEE 802.2 Ethernet/TR/TB.",
        "ARCnet.",
        "APPLEtalk.",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "Frame Relay DLCI.",
        "undefine",
        "undefine",
        "undefine",
        "ATM.",
        "undefine",
        "undefine",
        "undefine",
        "Metricom STRIP (new IANA id)."
};
// オペレーション(説明つきで表示するために宣言)
static char *op[]={
        "undefined",
        "ARP request.",
        "ARP reply.",
        "RARP request.",
        "RARP reply.",
        "undefined",
        "undefined",
        "undefined",
        "InARP request.",
        "InARP reply.",
        "(ATM)ARP NAK."
};
char	buf[80];

	fprintf(fp,"arp-------------------------------------\n");
	fprintf(fp,"arp_hrd=%u",ntohs(arp->arp_hrd));										// ハードウェアタイプを10進数で表示
																												// %u は unsigned int 符号なし整数を10進数表示
	if(ntohs(arp->arp_hrd)<=23){																// arp->arp_hrd ハードウェアタイプ
		fprintf(fp,"(%s),",hrd[ntohs(arp->arp_hrd)]);										// 23以下のタイプの説明 -> 上に hrd[] で定義
	}
	else{
		fprintf(fp,"(undefined),");
	}
	
	fprintf(fp,"arp_pro=%u",ntohs(arp->arp_pro));										// プロトコルタイプを10進数で表示
	switch(ntohs(arp->arp_pro)){																// ここで使われるプロトコルタイプはEtherヘッダの時と同じもの
		case	ETHERTYPE_IP:																		// 場合分けしてるけど、IPしか入らないのでは？？
			fprintf(fp,"(IP)\n");
			break;
		case	ETHERTYPE_ARP:
			fprintf(fp,"(Address resolution)\n");
			break;
		case	ETHERTYPE_REVARP:
			fprintf(fp,"(Reverse ARP)\n");
			break;
		case	ETHERTYPE_IPV6:
			fprintf(fp,"(IPv6)\n");
			break;
		default:
			fprintf(fp,"(unknown)\n");
			break;
	}
        fprintf(fp,"arp_hln=%u,",arp->arp_hln);											// 6 -> MACアドレスの長さ
        fprintf(fp,"arp_pln=%u,",arp->arp_pln);											// 4 -> IPアドレスの長さ
        fprintf(fp,"arp_op=%u",ntohs(arp->arp_op));									// オペレーション       
        if(ntohs(arp->arp_op)<=10){															// http://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml 
                fprintf(fp,"(%s)\n",op[ntohs(arp->arp_op)]);								// 0: リクエスト, 1: リプライ
        }
        else{
                fprintf(fp,"(undefine)\n");
        }
        // 各アドレス表示
        fprintf(fp,"arp_sha=%s\n",my_ether_ntoa_r(arp->arp_sha,buf,sizeof(buf)));
        fprintf(fp,"arp_spa=%s\n",arp_ip2str(arp->arp_spa,buf,sizeof(buf)));
        fprintf(fp,"arp_tha=%s\n",my_ether_ntoa_r(arp->arp_tha,buf,sizeof(buf)));
        fprintf(fp,"arp_tpa=%s\n",arp_ip2str(arp->arp_spa,buf,sizeof(buf)));

	return(0);
}

// プロトコルタイプ(説明つきで表示するために宣言)
// -> https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml 
static char     *Proto[]={
        "undefined",
        "ICMP",
        "IGMP",
        "undefined",
        "IPIP",
        "undefined",
        "TCP",
        "undefined",
        "EGP",
        "undefined",
        "undefined",
        "undefined",
        "PUP",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "UDP"
};

int PrintIpHeader(struct iphdr *iphdr,u_char *option,int optionLen,FILE *fp)
{
int	i;
char	buf[80];

	fprintf(fp,"ip--------------------------------------\n");																							// IPヘッダの表示
	fprintf(fp,"version=%u,",iphdr->version);
	fprintf(fp,"ihl=%u,",iphdr->ihl);
	fprintf(fp,"tos=%x,",iphdr->tos);
	fprintf(fp,"tot_len=%u,",ntohs(iphdr->tot_len));
	fprintf(fp,"id=%u\n",ntohs(iphdr->id));
	fprintf(fp,"frag_off=%x,%u,",(ntohs(iphdr->frag_off)>>13)&0x07,ntohs(iphdr->frag_off)&0x1FFF);
	fprintf(fp,"ttl=%u,",iphdr->ttl);
	fprintf(fp,"protocol=%u",iphdr->protocol);
	if(iphdr->protocol<=17){
		fprintf(fp,"(%s),",Proto[iphdr->protocol]);																								// プロトコルタイプ説明表示
	}
	else{
		fprintf(fp,"(undefined),");
	}
	fprintf(fp,"check=%x\n",iphdr->check);
	fprintf(fp,"saddr=%s,",ip_ip2str(iphdr->saddr,buf,sizeof(buf)));
	fprintf(fp,"daddr=%s\n",ip_ip2str(iphdr->daddr,buf,sizeof(buf)));
	if(optionLen>0){																																		// オプション表示
		fprintf(fp,"option:");
		for(i=0;i<optionLen;i++){
			if(i!=0){												// [00]:00:00 -> 表示上の問題解消のための場合わけ
				fprintf(fp,":%02x",option[i]);
			}
			else{
				fprintf(fp,"%02x",option[i]);
			}
		}
	}

	return(0);
}

int PrintIp6Header(struct ip6_hdr *ip6,FILE *fp)
{
char	buf[80];

	fprintf(fp,"ip6-------------------------------------\n");																						// IPv6ヘッダの表示
    fprintf(fp,"ip6_flow=%x\n",ip6->ip6_flow);																								// フローラブルの表示
    fprintf(fp,"ip6_plen=%d\n",ntohs(ip6->ip6_plen));																					// ペイロード長の表示
	fprintf(fp,"ip6_nxt=%u",ip6->ip6_nxt);																									// 次のヘッダの表示
        if(ip6->ip6_nxt<=17){
                fprintf(fp,"(%s)\n",Proto[ip6->ip6_nxt]);
        }
        else{
                fprintf(fp,"(undefined)\n");
        }
        fprintf(fp,"ip6_hlim=%d\n",ip6->ip6_hlim);																							// ホップリミットの表示

        fprintf(fp,"ip6_src=%s\n",inet_ntop(AF_INET6,&ip6->ip6_src,buf,sizeof(buf)));								// アドレス表示
        fprintf(fp,"ip6_dst=%s\n",inet_ntop(AF_INET6,&ip6->ip6_dst,buf,sizeof(buf)));

	return(0);
}

int PrintIcmp(struct icmp *icmp,FILE *fp)
{
// ICMPメッセージ(説明つきで表示するために宣言)
static char	*icmp_type[]={
	"Echo Reply",
	"undefined",
	"undefined",
	"Destination Unreachable",
	"Source Quench",
	"Redirect",
	"undefined",
	"undefined",
	"Echo Request",
	"Router Adverisement",
	"Router Selection",
	"Time Exceeded for Datagram",
	"Parameter Problem on Datagram",
	"Timestamp Request",
	"Timestamp Reply",
	"Information Request",
	"Information Reply",
	"Address Mask Request",
	"Address Mask Reply"
};

	fprintf(fp,"icmp------------------------------------\n");																// icmpヘッダ表示

	fprintf(fp,"icmp_type=%u",icmp->icmp_type);																	// メッセージタイプの表示(説明つきで)
	if(icmp->icmp_type<=18){
		fprintf(fp,"(%s),",icmp_type[icmp->icmp_type]);
	}
	else{
		fprintf(fp,"(undefined),");
	}
	fprintf(fp,"icmp_code=%u,",icmp->icmp_code);																// コードの表示 -> メッセージごとに定義されてる
	fprintf(fp,"icmp_cksum=%u\n",ntohs(icmp->icmp_cksum));											// チェックサムの表示

        if(icmp->icmp_type==0 || icmp->icmp_type==8){														// 0: Echo Reply ,8: Echo Request のとき、以下がフォーマットに追加
                fprintf(fp,"icmp_id=%u,",ntohs(icmp->icmp_id));													// -> id: 識別子
                fprintf(fp,"icmp_seq=%u\n",ntohs(icmp->icmp_seq));											// -> seq: シーケンス番号
	}																																		// http://win.kororo.jp/archi/tcp_ip/icmp.php

	return(0);
}

int PrintIcmp6(struct icmp6_hdr *icmp6,FILE *fp)
{

	fprintf(fp,"icmp6-----------------------------------\n");																// icmp6ヘッダ表示

	fprintf(fp,"icmp6_type=%u",icmp6->icmp6_type);															// 各タイプで場合わけ
	if(icmp6->icmp6_type==1){
		fprintf(fp,"(Destination Unreachable),");
	}
	else if(icmp6->icmp6_type==2){
		fprintf(fp,"(Packet too Big),");
	}
	else if(icmp6->icmp6_type==3){
		fprintf(fp,"(Time Exceeded),");
	}
	else if(icmp6->icmp6_type==4){
		fprintf(fp,"(Parameter Problem),");
	}
	else if(icmp6->icmp6_type==128){
		fprintf(fp,"(Echo Request),");
	}
	else if(icmp6->icmp6_type==129){
		fprintf(fp,"(Echo Reply),");
	}
	else{
		fprintf(fp,"(undefined),");
	}
	fprintf(fp,"icmp6_code=%u,",icmp6->icmp6_code);
	fprintf(fp,"icmp6_cksum=%u\n",ntohs(icmp6->icmp6_cksum));

        if(icmp6->icmp6_type==128 || icmp6->icmp6_type==129){										// icmpと同じで、エコー要求、応答の場合、以下がフォーマットに追加
                fprintf(fp,"icmp6_id=%u,",ntohs(icmp6->icmp6_id));	
                fprintf(fp,"icmp6_seq=%u\n",ntohs(icmp6->icmp6_seq));
	}																																		// https://www.infraexpert.com/study/ipv6z12.html

	return(0);
}

int PrintSrh(struct ipv6_sr_hdr *srh, FILE *fp)
{
	int i;
	char buf[80];

	fprintf(fp,"ip6_sr_hdr-----------------------------\n");																// icmp6ヘッダ表示

	fprintf(fp,"nexthdr=%u",srh->nexthdr);
	if(srh->nexthdr<=17){
        fprintf(fp,"(%s)\n",Proto[srh->nexthdr]);
    }
    else{
        fprintf(fp,"(undefined)\n");
    }
	fprintf(fp,"hdrlen=%u\n",srh->hdrlen);
	fprintf(fp,"type=%u",srh->type);
	if(srh->type==4){
		// https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml 
		fprintf(fp,"(SRH)\n");
    }
    else{
        fprintf(fp,"(undefined)\n");
    }
	fprintf(fp,"segment_left=%u\n",srh->segments_left);
	fprintf(fp,"last_entry=%u\n",srh->first_segment);
	fprintf(fp,"flags=%u\n",srh->flags);
	fprintf(fp,"tag=%u\n",srh->tag);		
	
	for (i=0; i<srh->first_segment+1; i++) {
		fprintf(fp,"segment_list[%d]=%s\n", i, inet_ntop(AF_INET6,&srh->segments[i],buf,sizeof(buf)));
	}																															// https://www.infraexpert.com/study/ipv6z12.html

	return(0);
}


int PrintTcp(struct tcphdr *tcphdr,FILE *fp)
{
	fprintf(fp,"tcp-------------------------------------\n");																	// tcpヘッダ表示

        fprintf(fp,"source=%u,",ntohs(tcphdr->source));
        fprintf(fp,"dest=%u\n",ntohs(tcphdr->dest));
        fprintf(fp,"seq=%u\n",ntohl(tcphdr->seq));
        fprintf(fp,"ack_seq=%u\n",ntohl(tcphdr->ack_seq));
        fprintf(fp,"doff=%u,",tcphdr->doff);
        fprintf(fp,"urg=%u,",tcphdr->urg);
        fprintf(fp,"ack=%u,",tcphdr->ack);
        fprintf(fp,"psh=%u,",tcphdr->psh);
        fprintf(fp,"rst=%u,",tcphdr->rst);
        fprintf(fp,"syn=%u,",tcphdr->syn);
        fprintf(fp,"fin=%u,",tcphdr->fin);
        fprintf(fp,"th_win=%u\n",ntohs(tcphdr->window));
        fprintf(fp,"th_sum=%u,",ntohs(tcphdr->check));
        fprintf(fp,"th_urp=%u\n",ntohs(tcphdr->urg_ptr));

	return(0);
}




int PrintUdp(struct udphdr *udphdr,FILE *fp)
{
	fprintf(fp,"udp-------------------------------------\n");

        fprintf(fp,"source=%u,",ntohs(udphdr->source));
        fprintf(fp,"dest=%u\n",ntohs(udphdr->dest));
        fprintf(fp,"len=%u,",ntohs(udphdr->len));
        fprintf(fp,"check=%x\n",ntohs(udphdr->check));

	return(0);
}


