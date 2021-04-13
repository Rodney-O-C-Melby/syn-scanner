/**
 * Copyright 2021 All Rights Reserved.
 **/

#include <stdio.h>  // printf
#include <string.h>  // memset, memmove
#include <sys/socket.h>	// socket, sendto, recvfrom, inet_addr, inet_aton, inet_ntoa
#include <sys/types.h>  // sendto, recvfrom, getifaddrs, freeifaddrs
#include <stdlib.h>  // exit, rand
#include <errno.h>  // errno
#include <netinet/tcp.h>  // provides declarations for tcp header
#include <netinet/ip.h>  // provides declarations for ip header
#include <arpa/inet.h>  // inet_addr, inet_aton, inet_ntoa
#include <unistd.h>  // sleep, getpid
#include <ifaddrs.h>  // getifaddrs, freeifaddrs
#include <netinet/in.h>  // IPPROTO_TCP, inet_addr, inet_aton, inet_ntoa
#include <netdb.h>  // getnameinfo, gai_strerror NI_MAXHOST, NI_MAXHOST

/**
 * 96 bit (12 bytes) pseudo header needed for tcp header checksum calculation.
 **/
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t destination_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/**
 * Generic checksum calculation function.
 **/
unsigned short get_checksum(unsigned short *ptr, int bytes) {
    register long sum = 0;
    unsigned short odd = 0;
    register short answer;
    while(bytes > 1) {
        sum += *ptr++;
        bytes -= 2;
    }
    if(bytes == 1) {
        *((u_char*)&odd) =* (u_char*)ptr;
        sum += odd;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return answer;
}

/**
 * Get Local IP of system from active network device, like 192.168.0.16 or 10.222.64.5
 **/
const char *get_local_ip(char *buffer) {
    // gets active network device name from /proc/net/route
    FILE *f;
    char line[100], *network_device, *c;
    f = fopen("/proc/net/route", "r");
    while (fgets(line, 100, f)) {
        network_device = strtok(line, " \t");
        c = strtok(NULL, " \t");
        if (network_device != NULL && c != NULL) {
            if (strcmp(c, "00000000") == 0) {
                //printf("Default interface is : %s \n" , p);
                break;
            }
        }
    }
    free(f);  // free resources

    // use active network device to get local IP address
    int fm = AF_INET;  // which family do we require , AF_INET or AF_INET6
    struct ifaddrs *ifaddr, *ifa;
    int family, s;

    if (getifaddrs(&ifaddr) == -1) {  // check for errors getting address
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // enumerate linked list, maintaining head pointer to free list
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }
        // get local ip address from linked list
        family = ifa->ifa_addr->sa_family;

        // check network device names match
        if (strcmp(ifa->ifa_name, network_device) == 0) {
            if (family == fm) {  // check is ipv4
                // use newer getnameinfo method
                s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), buffer, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                // check for errors
                if (s != 0) {
                    printf("getnameinfo() failed: %s\n", gai_strerror(s));
                    exit(EXIT_FAILURE);
                }
                return (const char *) buffer;
                //printf("address: %s", buffer);
            }
        }
    }
    freeifaddrs(ifaddr);  // free linked list
}

/**
 * Prints usage.
 **/
void print_help() {
    printf("SYN Scanner performs a SYN scan for a given IP address or IP range.\n");
    printf("Usage: \tss 192.168.1.254\n");
    printf("\tss 192.168.1.254-192.168.15.254\n");
    printf("\tss 192.168.1.254 80\n");
    printf("\tss 192.168.1.254 21-1024\n");
    printf("\tss 192.168.1.254 21 443 993\n");
}

/**
 * Check required args from user are present.
 **/
void check_args(int args_count) {
    if (geteuid() != 0) {  // check for sudo or root
        printf("Requires sudo or root permissions!\n");
        exit(EXIT_FAILURE);
    }
    if (args_count < 2) {  // check user provided args
        print_help();
        exit(EXIT_FAILURE);
    }
}

/**
 * Returns -1 on error, socket file descriptor if sending packet is ok.
 **/
int send_packet(char *source_ip, char *destination_ip, char *port, struct tcphdr* tcp) {

    // initialize required variables and pointers etc
    struct pseudo_header *ph;
    struct sockaddr_in socket_address;
    unsigned short packet[65536];  // max packet size
    memset(packet, 0, sizeof(packet));  // zero out packet
    ph = (struct pseudo_header*) packet;
	tcp = (struct tcphdr*) (ph + 1);

	// set psuedo header
    ph->source_address = inet_addr(source_ip);  // set pseudo header source address
    ph->destination_address = inet_addr(destination_ip);  // set pseudo header destination address
    ph->placeholder = 0;  // set pseudo header zero value
    ph->protocol = IPPROTO_TCP;  // set pseudo header to TCP protocol
    ph->tcp_length = htons(sizeof(*tcp));  // set pseudo header tcp length

    // set TCP Header
    tcp->th_sport = htons(3333);  // set TCP header source port
    tcp->th_dport = htons(atoi(port));  // set TCP header destination port
    tcp->th_seq = 3030; //rand();  // set sequence number
    tcp->th_off = sizeof(*tcp) / 4;  // size of header in 32-bit-chunks
    tcp->th_flags = 0x02;  // define TH_SYN 0x02
    tcp->th_win = htons (5840);  // maximum allowed window size
    tcp->th_sum = get_checksum(packet, sizeof(*ph) + sizeof(*tcp));  // create checksum

//    // for debuging
//    printf("Sent Destination Port: %u\n", tcp->th_dport);
//    printf("Sent Source Port: %u\n", tcp->th_sport);

    // set socket info
    struct in_addr dest_ip;
    inet_aton(destination_ip, &dest_ip);  // set dest ip to correct in addr format from destination ip
    socket_address.sin_addr = dest_ip;  //  set socket destination address
    socket_address.sin_port = IPPROTO_TCP; // irrelevant since Linux 2.2
    socket_address.sin_family = AF_INET;  // ipv4

    // create socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock == -1) {
        perror("Unable to create socket");
        return -1;
    }

    // socket, send to address
    int bytes = sendto(sock, tcp, sizeof(*tcp), 0, (struct sockaddr*) &socket_address, sizeof(socket_address));
    if (bytes < 0) {  // check for sendto errors
        perror("Sending packet failed");
        return -1;
    }
    return sock;
}

/**
 * Returns -1 on error, 9000 on source IP error, socket file descriptor if receiving packet is ok.
 **/
int receive_packet(char *destination_ip, int sock_fd) {

    struct ip *ip;
    struct tcphdr *tcp_header;
    unsigned char packet[65536];
    struct sockaddr_in addr;
    socklen_t addr_len;
    addr_len = sizeof(addr);

    // receive packets
    int bytes = recvfrom(sock_fd, packet, sizeof(packet), 0, (struct sockaddr *) &addr, &addr_len);
    if (bytes < 0) {
        perror("Receiving packet failed");
        return -1;
    }

    // set structs
    ip = (struct ip *) packet;
    tcp_header = (struct tcphdr *) (packet + 4 * ip->ip_hl);

    close(sock_fd);  // close socket file descriptor

    // check for RST packet (port 100% closed)
    if (tcp_header->rst == 1) {
        return 9001;  // print closed (X)
    }

    // response source ip doesnt match sent destination ip, (response maybe filtered or ARP packet)
    if (addr.sin_addr.s_addr != inet_addr(destination_ip)) {
        return 9000;  // filtered
    }

    // response destination port does not match our source port (not our response)
    if (htons(tcp_header->th_dport) != 3333) {
        return 9003;  // ignore
    }

    // no sequence number returned
    if (tcp_header->th_seq == 0) {
        return 9002;  // print closed (X)
    }

    // show responses
    if (tcp_header->th_seq != 0) {
        //printf("Open\n");  // port is open
        return 0;
    }

//    else {
//        printf("X\n");  // port def closed.
//        return 9002;
//    }

//    // set port status
//    //if (tcp_header->th_flags & TH_SYN) {
//    printf("RES RST: %d\n", tcp_header->rst);
//    printf("RES ACK: %d\n", tcp_header->th_ack);
//    printf("RES SEQ: %d\n", tcp_header->th_seq);
//    printf("flags: %d\n", tcp_header->th_flags);
//    printf("SYN: %d\n", TH_SYN);
//    printf("Binary AND: %d\n", tcp_header->th_flags & TH_SYN);

    return bytes;
}

/**
 * Scans a given IP and port, from given source IP.
 **/
int scan(char *ip, char* port, char *src_ip) {

    // initialize required variables and pointers
    //char source[32];
    struct tcphdr *tcp;
    //get_local_ip(source);  // get active local ip address
    //printf("Scanning %s:%s", ip, port);  // print scan

    // send packet to target
    int socket_fd = send_packet(src_ip, ip, port, tcp);
    if (socket_fd == -1) {
        printf("Unable to connect to ip address %s on port %d!\n", ip, atoi(port));
        exit(2);
    }

    // indicates packet sent ok
    //printf(" ... ");

    // get response, and handle errors
    int response = receive_packet(ip, socket_fd);
    if (response == -1) {
        printf("Unable to connect to ip address %s!\n", ip);
        exit(3);
    }
    if (response == 9000) {
        printf("\t%s Filtered/Timeout\n", port);
    }
    if (response == 9001) {
        printf("\t%s Closed (RST)\n", port);
    }
    if (response == 9002) {
        printf("\t%s Closed (9002)\n", port);  // print closed (X)
    }
    if (response == 0) {  // port open
        printf("\t%s:%s Open\n", ip, port);  // print scan
    }
    //printf("Response: %d.\n", response);

    return response;
}

/**
 * Returns integer index of dash character, or -1 if dash (-) not found.
 **/
int get_dash_index(char *data) {
    int index = -1;
    char *dash = strchr(data, '-');  // returns substring after and including dash (-)
    if (strstr(data, "-") != NULL) {
        index = (int)(dash - data);
    }
    return index;
}

/**
 * Returns first port in range from user args.
 **/
int get_first_port(char *args) {
    int i;
    int dash = get_dash_index(args);  // get int location of dash
    char port_number[dash];  // initialise port number char array
    for (i = 0; i < dash; i++) {  // copy all before dash to port number array
        port_number[i] = args[i];
    }
    int port = atoi(port_number);  // convert char to int
    printf("port: %d\n", port);  // for debugging
    return port;  // return port number as int
    //printf("port: %d\n", port);  // for debugging
}

/**
 * Returns last port in range from user args.
 **/
int get_last_port(char *args) {
    int i;
    int dash = get_dash_index(args);  // get int location of dash
    char *dash_string = strchr(args, '-');  // get string from dash onwards
    char port_number[strlen(dash_string) - 1];  // initialise port number char array
    for (i = 0; i < strlen(dash_string) - 1; i++) {  // assign new array minus the dash symbol
        // printf("value[%d]: %c\n", i, args[i + 1]);  // for debugging
        port_number[i] = args[(i + dash) + 1];
    }
    int port = atoi(port_number);  // convert char array to int
    return port;
}

/**
 * Returns first ip in range from user args.
 **/
char *get_first_ip(char *args, char *first) {
    int dash = get_dash_index(args);  // get int location of dash
    char *one_string = strchr(args, '1');  // get string from dash onwards
    if (one_string[0] == '1') {
        memmove(first, one_string, dash);  // move memory
    }
    return first;

}

/**
 * Returns last ip in range from user args.
 **/
char *get_last_ip(char *args) {
    char *dash_string = strchr(args, '-');  // get string from dash onwards
    if (dash_string[0] == '-') {
        memmove(dash_string, dash_string + 1, strlen(dash_string));  // move memory
    }
    return dash_string;
}

/**
 * Increments an IP Address.
 **/
int increment_ip(int *val) {
    if (*val == 255) {
        (*val) = 0;
        return 1;
    } else {
        (*val)++;
        return 0;
    }
}

/**
 * Parse user arguments, mode 1 = ip only, mode 2 = ip range only, mode 3 = ip and port only, mode 4 = ip range and port
 * only, mode  5 = ip only and port range, mode 6 = ip range and port range, mode 7 = ip and specific ports, mode 8 =
 * ip range and specific ports.
 **/
int parse_args(int count, char **args) {
    if (count == 2) {  // only ip
        // handle range
        if (get_dash_index(args[1]) != -1) {  // Dash Found
            return 2;  // mode 2 = ip range only
        } else {  // Dash NOT Found
            return 1;  // mode 1 = ip only
        }
    }
    if (count == 3) {  // ip and port
        // handle ip range
        if (get_dash_index(args[1]) != -1) {  // Dash (IP range) Found
            // handle port range
            if (get_dash_index(args[2]) != -1) {  // Dash (Port range) Found
                return 6;  // mode 6 = ip range and port range
            } else {  // Dash (Port range) NOT Found
                return 4;  // mode 4 = ip range and port only
            }
        } else {  // Dash (IP range) NOT Found
            // handle port range
            if (get_dash_index(args[2]) != -1) {  // Dash (Port range) Found
                return 5;  // mode  5 = ip only and port range
            } else {  // Dash (Port range) NOT Found
                return 3;  // mode 3 = ip and port only
            }
        }
    }
    if (count > 3) {  // ip and specific ports as args
        // handle ip range
        if (get_dash_index(args[1]) != -1) {  // Dash (IP range) Found
            return 8;  // mode 8 = ip range and specific ports.
        } else {  // Dash (IP range) NOT Found
            return 7;  // mode 7 = ip and specific ports
        }
    }
}


int main(int argc , char **argv) {
    int i;
    char source[32];
    // handle cmd line args
    check_args(argc);
    int scan_mode = parse_args(argc, argv);
    get_local_ip(source);  // get active local ip address
    printf("Syn Scanning ... max timeout 300 secs\n");

    //printf("scan_mode: %d.\n", scan_mode);

    // handle various scan modes
    if (scan_mode == 1) {  // ip only
        printf("Host: %s\n", argv[1]);  // print scan
        for (i = 1; i < 65535; i++) {  // scan all ports
            char port_number[5];  // char array for int value
            sprintf(port_number, "%d", i);  // int to string
            int ip_response = scan(argv[1], port_number, source);
            //printf("Response: %d.\n", ip_response);
        }
    }
    if (scan_mode == 2) {  // ip range

        if (get_dash_index(argv[1]) != -1) {  // get dash index

            printf("DASH FOUND\n");

            // get ip range
            char one[64];  // size of ip
            char two[64];
            char *first_ip = get_first_ip(argv[1], one);
            char *last_ip = get_last_ip(argv[1]);
            printf("first_ip: %s\n", first_ip);
            printf("last_ip: %s\n", last_ip);

            char *token = strtok(first_ip, ".");
            int x = 0;
            int ip[4] = {0};

            // break up ip into tokens
            while(token != NULL) {
                printf(" %s\n", token );
                ip[x] = atoi(token);
                x++;
                token = strtok(NULL, ".");
            }

            char *token2 = strtok(last_ip, ".");
            int y = 0;
            int ip2[4] = {0};

            // break up ip into tokens
            while(token2 != NULL) {
                printf(" %s\n", token2 );
                ip2[y] = atoi(token2);
                y++;
                token2 = strtok(NULL, ".");
            }

            // get octets
            char buf[16] = {0};
            snprintf(buf, 16, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
            printf("IP: %s\n", buf);

            char buf2[16] = {0};
            snprintf(buf2, 16, "%d.%d.%d.%d", ip2[0],ip2[1],ip2[2],ip2[3]);
            printf("IP 2: %s\n", buf2);

            char buf3[16] = {0};
            char buf4[16] = {0};
            char buf5[16] = {0};
            char buf6[16] = {0};
            while (ip[0] < ip2[0]) {
                // get all IPs in buf6
                snprintf(buf3, 16, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
                printf("%s\n", buf3);
                ip[0]++;
            }
            while (ip[1] < ip2[1]) {
                // get all IPs in buf6
                snprintf(buf4, 16, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
                printf("%s\n", buf4);
                ip[1]++;
            }
            while (ip[2] < ip2[2]) {
                // get all IPs in buf6
                snprintf(buf5, 16, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
                printf("%s\n", buf5);
                ip[2]++;
            }
            while (ip[3] <= ip2[3]) {

                // get all IPs in buf6
                snprintf(buf6, 16, "%d.%d.%d.%d", ip[0],ip[1],ip[2],ip[3]);
                printf("%s\n", buf6);

                ip[3]++;
            }

            //int ip_response = scan(buf6, 80, source);
            //ip_response = scan(buf6, argv[2], source);

//            int ip[4] = {0};
//            char buf[16] = {0};
//            while (ip[3] < 255) {
//                int place = 0;
//                while(place < 4 && increment_ip(&ip[place])) {
//                    place++;
//                }
//                snprintf(buf, 16, "%d.%d.%d.%d", ip[3],ip[2],ip[1],ip[0]);
//                printf("%s\n", buf);
//            }
            //exit(0);

        }
        //printf("DASH NOT FOUND! %d\n", get_dash_index(argv[1]));
    }
    if (scan_mode == 3) {  // one ip and one port
        /**
         * Simple Scan - One IP, One Port
         */
        printf("Host: %s\n", argv[1]);  // print scan
        int ip_response = scan(argv[1], argv[2], source);
        //printf("Response: %d.\n", ip_response);
    }
    if (scan_mode == 4) {  // ip range

    }
    if (scan_mode == 5) {  // one ip and port range
        //int port_dash = get_dash_index(argv[2]);
        if (get_dash_index(argv[2]) != -1) {  // get dash index
            int first_port = get_first_port(argv[2]);
            int last_port = get_last_port(argv[2]);
            printf("Host: %s\n", argv[1]);  // print scan
            for (i = first_port; i < last_port + 1; i++) {  // scan all given ports
                char port_number[5];  // char array for int value
                sprintf(port_number, "%d", i);  // int to string
                int ip_response = scan(argv[1], port_number, source);
                //printf("Response: %d.\n", ip_response);
            }
        }
    }
//    // scan one ip and port
//    int ip_response = scan(argv[1], argv[2]);
//    printf("Response: %d.\n", ip_response);

    return 0;
}
