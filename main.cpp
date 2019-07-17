#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("===================================\n");
    printf("D-MAC ");
    for(int i=0; i<6; i++){
        printf("%02x ", packet[i]);
    }
    printf("\nS-MAC ");
    for(int i=6; i<12; i++){
        printf("%02x ", packet[i]);
    }
    printf("\nS-IP ");
    for(int i=26; i<30; i++){
        if (i==29){
            printf("%d", packet[i]);
            break;
        }
        printf("%d.", packet[i]);
    }
    printf("\nD-IP ");
    for(int i=30; i<34; i++){
        if (i==33){
            printf("%d", packet[i]);
            break;
        }
        printf("%d.", packet[i]);
    }
    printf("\nS-PORT ");
    int sport = packet[34]*0x100;
    sport += packet[35];
    printf("%d", sport);
    printf("\nD-PORT ");
    int dport = packet[36]*0x100;
    dport += packet[37];
    printf("%d", dport);
    printf("\nData ");
    for(int i=54; i<64; i++){
        printf("%02x ", packet[i]);
    }
    printf("\n===================================\n");
  }

  pcap_close(handle);
  return 0;
}
