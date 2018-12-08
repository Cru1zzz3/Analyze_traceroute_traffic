#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static pcap_t* p;

void list_devices(std::vector<pcap_if_t*> &devices){

    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int errcode;
    errcode = pcap_findalldevs(&device,errbuf);
    if (errcode == 0){
        while (device){
            devices.push_back(device);
            std::cout << "Name of device: " << device-> name << std::endl;
            std::cout << "Adresses of device: " << device -> addresses << std::endl;
            if (device -> description)
                std::cout << "Description of device: " << device -> description << std::endl << std::endl;
            else std::cout << "Device have not described" << std::endl << std::endl;

            device = device->next;
        }
    }
    else {
        std::cout << "Devices not found. Error code: " <<  errcode << std::endl;
    }
    pcap_freealldevs(device);
}

struct sniff_icmp{
    //u_char
};

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip {

    u_int  size_ip;

    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */


};

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};


void callback(u_char *user,const struct pcap_pkthdr *hdr,const u_char *packet){
    static int count = 1;
    std::cout << count << " packet header "<< std::endl;
    std::cout << "header captured length: "<< hdr->caplen << std::endl;
    std::cout << "header length of packet: "<< hdr->len << std::endl;
    std::cout << "timestamp: " << hdr->ts.tv_sec << std::endl; //struct timeval = usec + sec
    count++;

    pcap_dump(user,hdr,packet);
    /* datalink
    int dlt; //datalinkype
    const char* dltName;
    const char* dltDescr;
    dlt = pcap_datalink(p);
    dltName = pcap_datalink_val_to_name(dlt);
    dltDescr = pcap_datalink_val_to_description(dlt);

     */
    /* Trying pcap_list_datalinks
    int dltCount;
    int **dltBuffer;
    int *dltList;

    //dltCount = pcap_list_datalinks(p,dltBuffer);
    //0pcap_free_datalinks(dltList);

    //std::cout << "Layers count: " << dltCount << std::endl;

    //dltDescr = pcap_geterr(p);
    //dltDescr = pcap_statustostr(dltDescr);
    */

/*
   // #define SIZE_ETHERNET 14
  //  const struct ethernetStruct *ethernet = (struct ethernetStruct*)(packet);


//    const struct ipStruct *ip  =  (struct ipStruct*)(packet + SIZE_ETHERNET);

//    const struct ethernetStruct *ethernet;
//    const struct ipStruct *ip;
//    const struct tcpStruct *tcp;
//    const char *payload;

 //   u_int size_ip;
 //   u_int size_tcp;
*/
/*
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    */
   // payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);


}



int main(int argc, char* argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE];
    int errcode;

    std::vector<pcap_if_t*> devices;
    std::vector<char *> command;
    command.push_back(argv[0]);

    int i = 1;
    while (argv[i]) {
        //std::cout << argv[i]<< std::endl;
        command.push_back(argv[i]);
        //std::cout << command[i]<< std::endl;
        i++;
    }

   // if (command[1] == "list"){
   //     list_devices(devices);
   // }

   argv[1] = "wlp3s0";
   const char* device;
   const char  *errDescr;
   device = argv[1];
   p = pcap_create(device,errbuf);

    const int snaplen = 65536;
    errcode = pcap_set_snaplen(p,snaplen);
    //std::cout << "pcap_set_snaplen error code: " << errcode << std::endl;
    errcode = pcap_set_promisc(p,1);
    //std::cout << "pcap_set_promisc error code: " << errcode << std::endl;

   errcode = pcap_activate(p);
   if (errcode != 0) {
       errDescr = pcap_statustostr(errcode);
       std::cout<< "pcap_activate error! ";
       std::cout << errDescr << std::endl;
   }
   else std::cout << "capturing started..." << std::endl;

    int cnt = -1; //infinity
    char *error;

    const char *filename = "packets.pcap";
    pcap_dumper_t *fileDumper;
    fileDumper = pcap_dump_open(p,filename);
    if (fileDumper == NULL)
        error = pcap_geterr(p);


   errcode = pcap_loop(p,cnt,callback,(u_char*)fileDumper);
    if (errcode != 0) {
        errDescr = pcap_statustostr(errcode);
        std::cout<< "capturing error! ";
        std::cout << errDescr << std::endl;
    }
    else std::cout << "capturing ended" << std::endl;

    pcap_dump_close(fileDumper);
    return 0;
}