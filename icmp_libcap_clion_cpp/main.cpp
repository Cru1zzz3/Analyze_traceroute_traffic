#include <iostream>
#include <string>
#include <vector>
#include <fstream>

#include <pcap/pcap.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

};

void callback(u_char *user,const struct pcap_pkthdr *hdr,const u_char *packet){
    static int count = 1;
    std::cout << count << " packet header "<< std::endl;
    std::cout << "header captured length: "<< hdr->caplen << std::endl;
    std::cout << "header length of packet: "<< hdr->len << std::endl;
    std::cout << "timestamp: " << hdr->ts.tv_sec << std::endl; //struct timeval = usec + sec
    count++;

}

int main(int argc, char* argv[]) {
    char* namedevice;
    char errbuf[PCAP_ERRBUF_SIZE];
    int errcode;

    FILE *file;
    file = fopen("out_log.pcap","w");

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

   pcap_t* p;
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

   /* datalinks ???
   int countDatalinks;
   int **dlt_buf;
   countDatalinks = pcap_list_datalinks(p,dlt_buf);
   std::cout << countDatalinks << std::endl;
    */

    /*
    char* device = devices[0];
    p = pcap_open_live(devices[0]->name,snaplen,1,1,errbuf);
    file = pcap_file(p);
     f = fwrite(p,,count,file)
    */
    int cnt = 3 ; //infinity

    //struct pcap_pkthdr **hdr;
    //const u_char packet = pcap_next_ex(p,hdr,packet);
   errcode = pcap_loop(p,cnt,callback,NULL);
    if (errcode != 0) {
        errDescr = pcap_statustostr(errcode);
        std::cout<< "capturing error! ";
        std::cout << errDescr << std::endl;
    }
    else std::cout << "capturing ended" << std::endl;

    // file.close();
    return 0;
}