#include <stdio.h> 
#include <stdlib.h>    
#include <string.h>    
#include <unistd.h>
#include <errno.h>
#include <netinet/ip_icmp.h>   
#include <netinet/udp.h>   
#include <netinet/tcp.h>   
#include <netinet/ip.h>
#include <netinet/igmp.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

void SolvePacket(unsigned char *, int);
void print_ether_header(unsigned char *buffer, int size);
void print_ip_header(unsigned char *, int);
void print_tcp_header(unsigned char *, int);
void print_udp_header(unsigned char *, int);
void print_icmp_header(unsigned char *, int);
void print_igmp_header(unsigned char *, int);
void PrintData(unsigned char *, int);

int sock_raw;
FILE *logfile;
int protocal_type[5] = {0, 0, 0, 0, 0};// tcp = 0  udp = 1  icmp = 2  others = 3  igmp = 4  total = 5
struct sockaddr_in source, dest;

void SolvePacket(unsigned char *buffer, int size) {
    print_ether_header(buffer, size);

    buffer = buffer + sizeof(struct ether_header);
    size = size - sizeof(struct ether_header);
    
    print_ip_header(buffer, size);
    struct iphdr *iph = (struct iphdr *) buffer;
    // 统计协议类型, 并且输出到文件, 这里只考虑了TCP, UDP, ICMP, IGMP, 其他的都归为Others
    protocal_type[5]++;
    if(iph->protocol == 1) {// ICMP
        protocal_type[2]++;
        print_icmp_header(buffer, size);
    }else if(iph->protocol == 2) {// IGMP
        protocal_type[4]++;
        print_igmp_header(buffer, size);
    }else if(iph->protocol == 6) {// TCP
        protocal_type[0]++;
        print_tcp_header(buffer, size);
    }else if(iph->protocol == 17) {// UDP
        protocal_type[1]++;
        print_udp_header(buffer, size);
    }else {// Others
        protocal_type[3]++;
    }
    printf("Count:: TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", protocal_type[0], protocal_type[1], protocal_type[2], protocal_type[4], protocal_type[3], protocal_type[5]);
    fprintf(logfile, "\n------------------------------------------------------------");
    fflush(logfile);
    fflush(stdout);
}

void print_ether_header(unsigned char *buffer, int size) {// 输出以太网头部
    struct ether_header *ethhdr = (struct ether_header *) buffer;
    fprintf(logfile, "\n");
    fprintf(logfile, "MAC Header\n");
    fprintf(logfile, "   |-> Destination Mac   : %02x:%02x:%02x:%02x:%02x:%02x\n",
            ethhdr->ether_dhost[0], ethhdr->ether_dhost[1], ethhdr->ether_dhost[2], ethhdr->ether_dhost[3],
            ethhdr->ether_dhost[4], ethhdr->ether_dhost[5]);
    fprintf(logfile, "   |-> Source Mac        : %02x:%02x:%02x:%02x:%02x:%02x\n",
            ethhdr->ether_shost[0], ethhdr->ether_shost[1], ethhdr->ether_shost[2], ethhdr->ether_shost[3],
            ethhdr->ether_shost[4], ethhdr->ether_shost[5]);
    fprintf(logfile, "   |-> Protocol          : %d\n", ethhdr->ether_type);
}

void print_ip_header(unsigned char *Buffer, int size) {// 输出IP头部
    unsigned short iphdrlen;
    // 获取IP头部及其长度
    struct iphdr *iph = (struct iphdr *) Buffer;
    iphdrlen = iph->ihl * 4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, "   |-> IP Version        : %d\n", (unsigned int) iph->version);
    fprintf(logfile, "   |-> IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int) iph->ihl,
            ((unsigned int) (iph->ihl)) * 4);
    fprintf(logfile, "   |-> Type Of Service   : %d\n", (unsigned int) iph->tos);
    fprintf(logfile, "   |-> IP Total Length   : %d  Bytes(size of Packet)\n", ntohs(iph->tot_len));
    fprintf(logfile, "   |-> Identification    : %d\n", ntohs(iph->id));

    fprintf(logfile, "   |-> TTL      : %d\n", (unsigned int) iph->ttl);
    fprintf(logfile, "   |-> Protocol : %d\n", (unsigned int) iph->protocol);
    fprintf(logfile, "   |-> Checksum : %d\n", ntohs(iph->check));
    fprintf(logfile, "   |-> Source IP        : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, "   |-> Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_header(unsigned char *Buffer, int size) {// 输出TCP头部
    unsigned short iphdrlen;
    // 获取IP头部及其长度
    struct iphdr *iph = (struct iphdr *) Buffer;
    iphdrlen = iph->ihl * 4;
    // 获取TCP头部
    struct tcphdr *tcph = (struct tcphdr *) (Buffer + iphdrlen);

    fprintf(logfile, "\n");
    fprintf(logfile, "TCP Header\n");
    fprintf(logfile, "   |-> Source Port      : %u\n", ntohs(tcph->source));
    fprintf(logfile, "   |-> Destination Port : %u\n", ntohs(tcph->dest));
    fprintf(logfile, "   |-> Sequence Number    : %u\n", ntohl(tcph->seq));
    fprintf(logfile, "   |-> Acknowledge Number : %u\n", ntohl(tcph->ack_seq));
    fprintf(logfile, "   |-> Header Length      : %d DWORDS or %d BYTES\n", (unsigned int) tcph->doff,
            (unsigned int) tcph->doff * 4);
    fprintf(logfile, "   |-> Urgent Flag          : %d\n", (unsigned int) tcph->urg);
    fprintf(logfile, "   |-> Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
    fprintf(logfile, "   |-> Push Flag            : %d\n", (unsigned int) tcph->psh);
    fprintf(logfile, "   |-> Reset Flag           : %d\n", (unsigned int) tcph->rst);
    fprintf(logfile, "   |-> Synchronise Flag     : %d\n", (unsigned int) tcph->syn);
    fprintf(logfile, "   |-> Finish Flag          : %d\n", (unsigned int) tcph->fin);
    fprintf(logfile, "   |-> Window         : %d\n", ntohs(tcph->window));
    fprintf(logfile, "   |-> Checksum       : %d\n", ntohs(tcph->check));
    fprintf(logfile, "   |-> Urgent Pointer : %d\n", tcph->urg_ptr);
    fprintf(logfile, "\n");
    fprintf(logfile, "                        DATA Dump                         ");
    fprintf(logfile, "\n");
    fprintf(logfile, "Data Payload\n");
    PrintData(Buffer + iphdrlen + tcph->doff * 4, (size - tcph->doff * 4 - iph->ihl * 4));
}

void print_udp_header(unsigned char *Buffer, int size) {// 输出UDP头部
    // 获取IP头部及其长度
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *) Buffer;
    iphdrlen = iph->ihl * 4;
    // 获取UDP头部
    struct udphdr *udph = (struct udphdr *) (Buffer + iphdrlen);

    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, "   |-> Source Port      : %d\n", ntohs(udph->source));
    fprintf(logfile, "   |-> Destination Port : %d\n", ntohs(udph->dest));
    fprintf(logfile, "   |-> UDP Length       : %d\n", ntohs(udph->len));
    fprintf(logfile, "   |-> UDP Checksum     : %d\n", ntohs(udph->check));
    fprintf(logfile, "Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof udph, (size - sizeof udph - iph->ihl * 4));
}

void print_igmp_header(unsigned char *Buffer, int size) {// 输出IGMP头部
    // 获取IP头部及其长度
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *) Buffer;
    iphdrlen = iph->ihl * 4;
    // 获取IGMP头部
    struct igmp *igmph = (struct igmphdr *) (Buffer + iphdrlen);

    fprintf(logfile, "\nIGMP Header\n");
    fprintf(logfile, "   |-> Type             : %d\n", (unsigned int) igmph->igmp_type);
    fprintf(logfile, "   |-> Max Resp Time    : %d\n", (unsigned int) igmph->igmp_code);
    fprintf(logfile, "   |-> Checksum         : %d\n", ntohs(igmph->igmp_cksum));
    fprintf(logfile, "   |-> Group Address    : %d\n", igmph->igmp_group);
    fprintf(logfile, "Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof igmph, (size - sizeof igmph - iph->ihl * 4));
}

void print_icmp_header(unsigned char *Buffer, int size) {// 输出ICMP头部
    // 获取IP头部及其长度
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *) Buffer;
    iphdrlen = iph->ihl * 4;
    // 获取ICMP头部
    struct icmphdr *icmph = (struct icmphdr *) (Buffer + iphdrlen);

    fprintf(logfile, "\nICMP Header\n");
    fprintf(logfile, "   |-> Type : %d", (unsigned int) (icmph->type));

    if ((unsigned int) (icmph->type) == 11)
        fprintf(logfile, "  (TTL Expired)\n");
    else if ((unsigned int) (icmph->type) == ICMP_ECHOREPLY)
        fprintf(logfile, "  (ICMP Echo Reply)\n");
    fprintf(logfile, "   |-> Code : %d\n", (unsigned int) (icmph->code));
    fprintf(logfile, "   |-> Checksum : %d\n", ntohs(icmph->checksum));
    fprintf(logfile, "\n");
    fprintf(logfile, "Data Payload\n");
    PrintData(Buffer + iphdrlen + sizeof icmph, (size - sizeof icmph - iph->ihl * 4));
}

void PrintData(unsigned char *data, int size) {// 输出数据
    int i, j;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0) {//输出数据对应的ASCII码
            fprintf(logfile, "         ");
            for (j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] <= 128)
                    fprintf(logfile, "%c", (unsigned char) data[j]);//如果是可打印字符，输出字符，否则输出点号
                else fprintf(logfile, "."); 
            }
            fprintf(logfile, "\n");
        }
        if (i % 16 == 0) fprintf(logfile, "   ");
		//输出数据
        fprintf(logfile, " %02X", (unsigned int) data[i]);
        if (i == size - 1) {//最后一行数据缺少时，将数据对齐
            for (j = 0; j < 15 - i % 16; j++) fprintf(logfile, "   "); 
            fprintf(logfile, "         ");
            for (j = i - i % 16; j <= i; j++) {
                if (data[j] > 31 && data[j] < 128) fprintf(logfile, "%c", (unsigned char) data[j]);
                else fprintf(logfile, ".");
            }
            fprintf(logfile, "\n");
        }
    }
}

int main() {
    int saddr_size, data_size;
    struct sockaddr saddr;
    struct in_addr in;
    unsigned char *buffer = (unsigned char *) malloc(65535); 

    logfile = fopen("log.txt", "w");
    if (logfile == NULL) 
        perror("fopen");
    printf("Starting!!!\n");

    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        printf("Socket Error: %s\n", strerror(errno));
        return 1;
    }
    while (1) {
        saddr_size = sizeof saddr;
        data_size = recvfrom(sock_raw, buffer, 65535, 0, &saddr, (socklen_t *) &saddr_size);
        if (data_size < 0) {
            printf("Recvfrom error: %s\n", strerror(errno));
            return 1;
        }
        SolvePacket(buffer, data_size);
    }
    close(sock_raw);
    printf("Finished!!!\n");
    return 0;
}
