#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <signal.h>

#include <pcap/pcap.h>

#define SNAPLEN 262144

struct Args
{
    const char *monitor;
    const char *fields;
};

struct ieee80211_radiotap_header {
    u_int8_t        it_version;
    u_int8_t        it_pad;
    u_int16_t       it_len;
    u_int32_t       it_present;
} __attribute__((__packed__));

struct ieee80211_frame_header_stub {
    union
    {
        struct 
        {
            u_int8_t    frame_control;
            u_int8_t    duration_id;
            u_int8_t    addr0[6];
            u_int8_t    addr1[6];
            u_int8_t    addr2[6];
        };
        u_int8_t data[20];
    };
} __attribute__((__packed__));

struct ieee80211_info
{
    char *bss;
    char *sta;
    uint16_t freq;
};

static char pcaperr[PCAP_ERRBUF_SIZE];
static struct Args args;
static pcap_if_t *iflist = NULL;
static pcap_t *live = NULL;

// static void parse_device_args(char *arg, struct DeviceArgs *devargs)
// {
//     size_t len = strlen(arg);
//     if (len == 0)
//         return;
//     for (int j = 0, h = 0; 
//         j <= len && h < len; 
//         ++j)
//     {
//         switch (arg[j])
//         {
//             case ',':
//             case '\0':
//                 assert((devargs = (struct DeviceArgs *)
//                     realloc(devargs, 
//                         sizeof(struct DeviceArgs) 
//                         * (devargs->count + 1))));
//                 devargs->names[devargs->count++] = &arg[h];
//                 arg[j] = '\0';
//                 h = j + 1;
//         }
//     }
// }

static void verify_device_name(void)
{
    assert(!pcap_findalldevs(&iflist, pcaperr));
    int has_device = 0;
    for (
        pcap_if_t *ifnode = iflist; 
        ifnode; 
        ifnode = ifnode->next)
    {
        //printf("ifn: %s\n", ifnode->name);
        if ((has_device |= !strncmp(args.monitor, ifnode->name, 32)))
        {
            break;
        }
    }
    assert(has_device);
    pcap_freealldevs(iflist);
}

static void verify_monitor_mode(void)
{
    pcap_t *pcap = pcap_create(args.monitor, pcaperr);
    pcap_activate(pcap);
    int *dlts = NULL;
    int dltcount = pcap_list_datalinks(pcap, &dlts);
    int has_monitor_mode = 0;
    for (
        int *dlt = dlts; 
        dltcount > 0; 
        --dltcount, dlt += sizeof(*dlt))
    {
        if (has_monitor_mode |= *dlt == DLT_IEEE802_11_RADIO)
        {
            break;
        }
    }
    pcap_close(pcap);
    assert(has_monitor_mode);
}

static void print_device_args(void)
{
    printf("monitor: %s\n", args.monitor);
}

static void parse_args(int argc, char **argv)
{
    assert(argc > 1);
    args.fields = "cfbs";
    for (int i = 1; i < argc; ++i)
    {
        switch (*argv[i])
        {
            case '-':
                assert(argv[i][1]);
                args.fields = argv[i] + 1;
            default:
                args.monitor = argv[i];
                // parse_device_args(argv[i], args.monitor);
                break;
        }
    }
}

void down_device(char *name)
{

}

int freqtochan(int freq)
{
    assert(freq >= 2412 && freq <= 2484);
    return freq == 2484 ? 14
        : 1 + (freq - 2412) / 5;
}

void print_bytes_line(const char *bytes, size_t n)
{
    for (int i = 0; i < n; ++i)
        printf("%02x", bytes[n]);
    putchar('\n');
}

void dump_fields(struct ieee80211_info info)
{
    for (int j = 1; j < strlen(args.fields) - 1; ++j)
    {
        switch (args.fields[j])
        {
            case 'b':
                print_bytes_line(info.bss, sizeof(info.bss));
                continue;
            case 'c':
                printf("%d\n", freqtochan(info.freq));
                continue;
            case 'f':
                printf("%d\n", info.freq);
                continue;
            case 's':
                print_bytes_line(info.sta, sizeof(info.sta));
                continue;
            default:
                assert(0);
        }
    }
}

void got_packet(
    unsigned char *args, 
    const struct pcap_pkthdr *header, 
    const unsigned char *packet)
{
    if (header->caplen < sizeof(struct ieee80211_radiotap_header))
        return;
    struct ieee80211_radiotap_header *rtap = 
        (struct ieee80211_radiotap_header *)packet;
    struct ieee80211_frame_header_stub *h80211 = 
        (struct ieee80211_frame_header_stub *)(packet + rtap->it_len);
    if ((h80211->data[0] & 0x0c) == 0x04)
    {
        // printf("control\n");
        return;
    }
    // printf("rtap len: %d\n", rtap->it_len);
    // printf("rtap present: %08x\nrtap dump: ", rtap->it_present);
    // for (int i = 0; i < rtap->it_len; ++i)
    //     printf("%02x", packet[i]);
    // printf("\n");
    char bssid[6], stmac[6];
    memset(bssid, 0, 6);
    memset(stmac, 0, 6);
    switch (h80211->data[1] & 3)
	{
		case 0:
			memcpy(bssid, h80211->data + 16, 6);
            if (!memcmp(h80211->data + 10, bssid, 6))
                break;
            memcpy(stmac, h80211->data + 10, 6);
			break; // Adhoc
		case 1:
			memcpy(bssid, h80211->data + 4, 6);
            memcpy(stmac, h80211->data + 10, 6);
			break; // ToDS
		case 2:
			memcpy(bssid, h80211->data + 10, 6);
            if (h80211->data[4] & 1)
                break;
			memcpy(stmac, h80211->data + 4, 6);
			break; // FromDS
		case 3:
			memcpy(bssid, h80211->data + 10, 6);
			break; // WDS -> Transmitter taken as BSSID
    }
    assert(rtap->it_present&8);
    uint16_t freq = *(uint16_t *)(packet + 10);
    // printf("chan: %d\n", freqtochan(freq));
    // printf("freq: %d\nbss: ", freq);
    // for (int i = 0; i < 6; ++i)
    //     printf("%02x", bssid[i]);
    // printf("\nsta: ");
    // for (int i = 0; i < 6; ++i)
    //     printf("%02x", stmac[i]);
    // printf("\n----------------\n");
    //assert(freq == 2412);
    //pcap_breakloop((pcap_t *)args);
    dump_fields((struct ieee80211_info)
        {
            .bss = bssid,
            .freq = freq,
            .sta = stmac,
        });
}

void shutdown(int code)
{
    pcap_close(live);
    exit(code);
}

void listen(void)
{
    assert(args.monitor);
    live = pcap_open_live(
        args.monitor, 
        SNAPLEN, 1, 0, pcaperr);
    assert(live);
    pcap_loop(live, -1, &got_packet, (unsigned char *)live);
}

void signal_handler(int sig)
{
    switch (sig)
    {
        case SIGINT:
        case SIGABRT:
        case SIGKILL:
            printf("caught signal.\n");
            if (live)
            {
                pcap_breakloop(live);
            }
            return;
    }
}

int main(int argc, char **argv)
{   
    memset(pcaperr, 0, sizeof(pcaperr));
    parse_args(argc, argv);
    print_device_args();
    verify_device_name();
    verify_monitor_mode();
    listen();
    shutdown(0);
    printf("\n");
    return 0;
}
