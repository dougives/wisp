#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>

#include <pcap/pcap.h>

#define SNAPLEN 262144

struct DeviceArgs
{
    size_t count;
    char *names[];
};

struct Args
{
    struct DeviceArgs *monitors;
    struct DeviceArgs *injectors;
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

static char pcaperr[PCAP_ERRBUF_SIZE];
static struct Args args;
static pcap_if_t *iflist;


static void parse_device_args(char *arg, struct DeviceArgs *devargs)
{
    size_t len = strlen(arg);
    if (len == 0)
        return;
    for (int j = 0, h = 0; 
        j <= len && h < len; 
        ++j)
    {
        switch (arg[j])
        {
            case ',':
            case '\0':
                assert((devargs = (struct DeviceArgs *)
                    realloc(devargs, 
                        sizeof(struct DeviceArgs) 
                        * (devargs->count + 1))));
                devargs->names[devargs->count++] = &arg[h];
                arg[j] = '\0';
                h = j + 1;
        }
    }
}

static void verify_device_names(void)
{
    assert(!pcap_findalldevs(&iflist, pcaperr));
    size_t devcount = 
        args.monitors->count 
        + args.injectors->count;
    char *devs[devcount];
    for (int i = 0; i < devcount; ++i)
    {
        devs[i] =
            i < args.monitors->count
                ? args.monitors->names[i]
                : args.injectors->names[i-args.monitors->count];
        //printf("dev: %s\n", devs[i]);
        int has_device = 0;
        for (
            pcap_if_t *ifnode = iflist; 
            ifnode; 
            ifnode = ifnode->next)
        {
            //printf("ifn: %s\n", ifnode->name);
            if ((has_device |= !strncmp(devs[i], ifnode->name, 32)))
            {
                break;
            }
        }
        assert(has_device);
    }
    pcap_freealldevs(iflist);
}

static void verify_monitor_mode(void)
{
    for (int i = 0; i < args.monitors->count; ++i)
    {
        pcap_t *pcap = pcap_create(args.monitors->names[i], pcaperr);
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
}

static void print_device_args(void)
{
    printf("monitors[%ld]:", args.monitors->count);
    for (int i = 0; i < args.monitors->count; ++i)
        printf(" %s", args.monitors->names[i]);
    printf("\ninjectors[%ld]:", args.injectors->count);
    for (int i = 0; i < args.injectors->count; ++i)
        printf(" %s", args.injectors->names[i]);
    printf("\n");
}

static void parse_args(int argc, char **argv)
{
    assert(argc > 1);
    assert((args.monitors = (struct DeviceArgs *)
        calloc(1, sizeof(struct DeviceArgs))));
    assert((args.injectors = (struct DeviceArgs *)
        calloc(1, sizeof(struct DeviceArgs))));
    for (int i = 1; i < argc; ++i)
    {
        switch (*argv[i])
        {
            case 'm':
                assert(argv[i][1] == '=');
                parse_device_args(&argv[i][2], args.monitors);
                break;
            case 'i':
                assert(argv[i][1] == '=');
                parse_device_args(&argv[i][2], args.injectors);
                break;
            default:
                assert(0);
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
    uint8_t bssid[6], stmac[6];
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
    printf("freq: %d\nbss: ", freq);
    for (int i = 0; i < 6; ++i)
        printf("%02x", bssid[i]);
    printf("\nsta: ");
    for (int i = 0; i < 6; ++i)
        printf("%02x", stmac[i]);
    printf("\n----------------\n");
    //assert(freq == 2412);
    //pcap_breakloop((pcap_t *)args);
}

void listen_for_associations(void)
{
    assert(args.monitors->count > 0);
    pcap_t *live[args.monitors->count];
    char errbuf[PCAP_ERRBUF_SIZE];
    for (int i = 0; i < args.monitors->count; ++i)
    {
        live[i] = pcap_open_live(
            args.monitors->names[i], 
            SNAPLEN, 1, 0, errbuf);
        assert(live[i]);
    }
    pcap_loop(live[0], -1, &got_packet, (unsigned char *)live[0]);
    for (int i = 0; i < args.monitors->count; ++i)
    {
        pcap_close(live[i]);
    }
}

int main(int argc, char **argv)
{   
    memset(pcaperr, 0, sizeof(pcaperr));
    parse_args(argc, argv);
    print_device_args();
    verify_device_names();
    verify_monitor_mode();
    listen_for_associations();
    printf("\n");
    return 0;
}
