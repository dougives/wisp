#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <signal.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include <byteswap.h>

#define SNAPLEN 262144

// cypher flags pulled from airodump-ng.h
#define STD_OPN 0x0001u
#define STD_WEP 0x0002u
#define STD_WPA 0x0004u
#define STD_WPA2 0x0008u

#define STD_FIELD (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)

#define ENC_WEP 0x0010u
#define ENC_TKIP 0x0020u
#define ENC_WRAP 0x0040u
#define ENC_CCMP 0x0080u
#define ENC_WEP40 0x1000u
#define ENC_WEP104 0x0100u
#define ENC_GCMP 0x4000u
#define ENC_GMAC 0x8000u

#define ENC_FIELD                                                              \
	(ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP40 | ENC_WEP104         \
	 | ENC_GCMP                                                                \
	 | ENC_GMAC)

#define AUTH_OPN 0x0200u
#define AUTH_PSK 0x0400u
#define AUTH_MGT 0x0800u
#define AUTH_CMAC 0x10000u
#define AUTH_SAE 0x20000u
#define AUTH_OWE 0x40000u

#define AUTH_FIELD                                                             \
	(AUTH_OPN | AUTH_PSK | AUTH_CMAC | AUTH_MGT | AUTH_SAE | AUTH_OWE)

#define STD_QOS 0x2000u

struct args
{
    const char *monitor;
    const char *fields;
    const char *dump;
    int only_assoc;
};

struct ieee80211_radiotap_header
{
    uint8_t        it_version;
    uint8_t        it_pad;
    uint16_t       it_len;
    uint32_t       it_present;
} __attribute__((__packed__));

struct ieee80211_frame_header_stub
{
    union
    {
        struct 
        {
            uint8_t    type;
            uint8_t    flags;
            uint16_t   duration_id;
            uint8_t    addr0[6];
            uint8_t    addr1[6];
            uint8_t    addr2[6];
            uint8_t    seq_frag_field[2];
        } __attribute__((__packed__));
        uint8_t data[24];
    };
} __attribute__((__packed__));

struct ieee80211_mgmt_fixed_params
{
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capabilities;
} __attribute__((__packed__));

struct ieee80211_mgmt_ssid_tag
{
    uint8_t tag_number;
    uint8_t length;
    uint8_t label[32];
} __attribute__((__packed__));

struct ieee80211_mgmt
{
    struct ieee80211_mgmt_fixed_params fixed_params;
    struct ieee80211_mgmt_ssid_tag ssid;
} __attribute__((__packed__));

struct wps_info
{
    uint8_t version;
    uint8_t state;
    uint8_t locked;
    uint8_t methods;
};

struct ieee80211_info
{
    //uint64_t ts;
    struct timeval timeval;
    uint8_t *bss;
    uint8_t *sta;
    uint16_t freq;
    int8_t power;
    uint64_t uptime;
    uint64_t interval;
    uint16_t capabilities;
    uint8_t version;
    uint8_t type;
    uint8_t subtype;
    uint8_t flags;
    size_t ssid_length;
    char ssid[33];
    uint8_t channel;
    uint32_t security;
    struct wps_info wps;
    //uint8_t max_speed;
};

static char pcaperr[PCAP_ERRBUF_SIZE];
static struct args args;
static pcap_if_t *iflist = NULL;
static pcap_t *live = NULL;
static pcap_dumper_t *dumper = NULL;

static void _shutdown(int code)
{
    if (dumper)
    {
        pcap_dump_close(dumper);
    }
    if (live)
    {
        pcap_close(live);
    }
    exit(code);
}

static uint64_t timestamp(struct timeval tv)
{
    gettimeofday(&tv, NULL);
    return (uint64_t)(
        (uint64_t)tv.tv_sec * 1000 
        + (uint64_t)tv.tv_usec / 1000);
}

static void verify_device_name(void)
{
    assert(!pcap_findalldevs(&iflist, pcaperr));
    int has_device = 0;
    for (
        pcap_if_t *ifnode = iflist; 
        ifnode; 
        ifnode = ifnode->next)
    {
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
    printf("monitor[%s]: %s\n", args.fields, args.monitor);
}

static void parse_args(int argc, char **argv)
{
    assert(argc > 1);
    memset(&args, 0, sizeof(args));
    args.fields = "tdcfbspvum";
    for (int i = 1; i < argc; ++i)
    {
        switch (*argv[i])
        {
            case '-':
                assert(argv[i][1]);
                if (argv[i][1] == '-')
                {
                    //printf("%c\n", argv[i][2]);
                    switch (argv[i][2])
                    {
                        case 'a':
                            args.only_assoc = 1;
                            continue;
                        case 'd':
                            ++i;
                            if (i >= argc)
                            {
                                goto bad_arg;
                            }
                            args.dump = argv[i];
                            continue;
                        default:
                        bad_arg:
                            assert(0);
                            _shutdown(-1);
                    }
                }
                args.fields = argv[i] + 1;
                continue;
            default:
                args.monitor = argv[i];
                continue;
        }
    }
    // printf("%s\n", args.fields);
}

int freqtochan(int freq)
{
    assert(freq >= 2412 && freq <= 2484);
    return freq == 2484 ? 14
        : 1 + (freq - 2412) / 5;
}

void print_bytes(const uint8_t *bytes, size_t n)
{
    for (int i = 0; i < n; ++i)
        printf("%02hhx", bytes[i]);
}

void print_us_time(uint64_t us)
{
    char time_string[21];
    int time_length = sprintf(time_string, "%llu", us);
    if (!time_length)
    {
        printf("0.0");
        return;
    }
    if (time_length > 6)
    {
        for (int i = 0; i < time_length - 6; ++i)
            putchar(time_string[i]);
    }
    if (time_length < 7)
    {
        putchar('0');
    }
    printf(".%s", time_string + (time_length < 7 ? 0 : time_length - 6 ));
}

void dump_fields(struct ieee80211_info info)
{
    if (args.only_assoc && !memcmp(info.sta, "\0\0\0\0\0\0", 6))
    {
        return;
    }
    for (int j = 0; j < strlen(args.fields); ++j)
    {
        switch (args.fields[j])
        {
            case 'b':
                print_bytes(info.bss, 6);
                putchar(',');
                continue;
            case 'c':
                printf("%d,", freqtochan(info.freq));
                continue;
            case 'd':
                printf("%s,", args.monitor);
                continue;
            case 'f':
                printf("%d,", info.freq);
                continue;
            case 's':
                print_bytes(info.sta, 6);
                putchar(',');
                continue;
            case 't':
                printf("%ld.%06ld,",
                    info.timeval.tv_sec,
                    info.timeval.tv_usec);
                continue;
            case 'p':
                printf("%d,", info.power);
                continue;
            case 'v':
                printf("%d,%02hhx,%02hhx,", info.version, info.type, info.subtype);
                continue;
            case 'u':
                print_us_time(info.uptime);
                putchar(',');
                print_us_time(info.interval);
                putchar(',');
                printf("%04x,", info.capabilities);
                continue;
            case 'm':
                printf("%08x,", info.security);
                printf("%02hhx,%02hhx,%02hhx,%02hhx,",
                    info.wps.version,
                    info.wps.state,
                    info.wps.locked,
                    info.wps.methods);
                printf("%zu,", info.ssid_length);
                print_bytes(info.ssid, info.ssid_length);
                putchar(',');
                //printf("%s,", info.ssid);
                continue;
            default:
                assert(0);
        }
    }
    putchar('\n');
    fflush(stdout);
}

// a good chunk of this function is modified code from airodump-ng.c
void try_parse_mgmt(
    const struct pcap_pkthdr *header,
    const unsigned char *packet,
    struct ieee80211_frame_header_stub *h80211,
    struct ieee80211_info *info)
{
    memset(info->ssid, 0, sizeof(info->ssid));
    if (h80211->type != 0x80 && h80211->type != 0x50)
        return;
    struct ieee80211_mgmt_fixed_params *fixed_params = (struct ieee80211_mgmt_fixed_params *)
        ((uint8_t *)h80211 + sizeof(struct ieee80211_frame_header_stub));
    info->uptime = fixed_params->timestamp; // bswap_64(fixed_params->timestamp);
    info->interval = fixed_params->interval * 1024; // bswap_16(fixed_params->interval) * 1024;
    info->capabilities = fixed_params->capabilities;
    uint8_t *header_start = (uint8_t *)h80211;
    uint8_t *end = header_start + header->caplen;
    uint8_t *p = (uint8_t *)(fixed_params) + sizeof(struct ieee80211_mgmt_fixed_params);

    uint32_t security = (fixed_params->capabilities & 0x10) >> 4 ? STD_WPA : STD_OPN;
    int tag_length = 0;
    while (p < end)
    {
        p += tag_length;
        tag_length = p[1];
        if (p + 2 + tag_length > end)
            break;
        int tag = p[0];
        p += 2;
        // ssid
        if (tag == 0x00)
        {
            if (tag_length > 32)
                break;
            info->ssid_length = tag_length;
            strncpy(info->ssid, p, tag_length);
            continue;
        }
        // ds
        if (tag == 0x03)
        {
            info->channel = p[0];
            continue;
        }
        // wpa/rsn
        if ((tag == 0xdd && (tag_length >= 8) 
                && !memcmp(p, "\x00\x50\xF2\x01\x01\x00", 6))
            || (tag == 0x30))
        {
            uint8_t *tag_p = p - 2;
            int offset = tag = 0xdd ? 4 : 0;
            security |= tag = 0xdd ? STD_WPA : 0;
            security |= tag = 0x30 ? STD_WPA2 : 0;

            if (tag_length < (18 + offset))
                continue;

            // Number of pairwise cipher suites
            if (tag_p + 9 + offset > end)
                break;
            int numuni = tag_p[8 + offset] + (tag_p[9 + offset] << 8);

            // Number of Authentication Key Managament suites
            if (tag_p + (11 + offset) + 4 * numuni > end)
                break;
            int numauth = tag_p[(10 + offset) + 4 * numuni]
                + (tag_p[(11 + offset) + 4 * numuni] << 8);

            tag_p += (10 + offset);

            if (tag == 0xdd && tag_p + (4 * numuni) + (2 + 4 * numauth) > end)
                break;
            if (tag == 0x30 && tag_p + (4 * numuni) + (2 + 4 * numauth) + 2 > end)
                break;

            // Get the list of cipher suites
            for (int i = 0; i < (size_t) numuni; i++)
            {
                switch (tag_p[i * 4 + 3])
                {
                    case 0x01:
                        security |= ENC_WEP;
                        break;
                    case 0x02:
                        security |= ENC_TKIP;
                        break;
                    case 0x03:
                        security |= ENC_WRAP;
                        break;
                    case 0x0A:
                    case 0x04:
                        security |= ENC_CCMP;
                        security |= STD_WPA2;
                        break;
                    case 0x05:
                        security |= ENC_WEP104;
                        break;
                    case 0x08:
                    case 0x09:
                        security |= ENC_GCMP;
                        security |= STD_WPA2;
                        break;
                    case 0x0B:
                    case 0x0C:
                        security |= ENC_GMAC;
                        security |= STD_WPA2;
                        break;
                    default:
                        break;
                }

				tag_p += 2 + 4 * numuni;

				// Get the AKM suites
				for (int i = 0; i < numauth; i++)
				{
					switch (tag_p[i * 4 + 3])
					{
						case 0x01:
							security |= AUTH_MGT;
							break;
						case 0x02:
							security |= AUTH_PSK;
							break;
						case 0x06:
						case 0x0d:
							security |= AUTH_CMAC;
							break;
						case 0x08:
							security |= AUTH_SAE;
							break;
						case 0x12:
							security |= AUTH_OWE;
							break;
						default:
							break;
					}
				}
            }
            continue;
        }

        // QoS IE
        if ((tag == 0xdd && (tag_length >= 8)
            && (memcmp(p, "\x00\x50\xF2\x02\x01\x01", 6) == 0)))
        {
            security |= STD_QOS;
            continue;
        }
        // WPS IE
        if ((tag == 0xdd && (tag_length >= 4)
            && (memcmp(p, "\x00\x50\xF2\x04", 4) == 0)))
        {
            uint8_t *tag_p = p + 4;
            int len = tag_length, subtype = 0, sublen = 0;
            while (len >= 4)
            {
                subtype = (tag_p[0] << 8) + tag_p[1];
                sublen = (tag_p[2] << 8) + tag_p[3];
                if (sublen > len) break;
                switch (subtype)
                {
                    case 0x104a: // WPS Version
                        info->wps.version = tag_p[4];
                        break;
                    case 0x1011: // Device Name
                    case 0x1012: // Device Password ID
                    case 0x1021: // Manufacturer
                    case 0x1023: // Model
                    case 0x1024: // Model Number
                    case 0x103b: // Response Type
                    case 0x103c: // RF Bands
                    case 0x1041: // Selected Registrar
                    case 0x1042: // Serial Number
                        break;
                    case 0x1044: // WPS State
                        info->wps.state = tag_p[4];
                        break;
                    case 0x1047: // UUID Enrollee
                    case 0x1049: // Vendor Extension
                        if (memcmp(&tag_p[4], "\x00\x37\x2A", 3) == 0)
                        {
                            unsigned char * pwfa = &tag_p[7];
                            int wfa_len = ntohs(*((short *) &tag_p[2]));
                            while (wfa_len > 0)
                            {
                                if (*pwfa == 0)
                                { // Version2
                                    info->wps.version = pwfa[2];
                                    break;
                                }
                                wfa_len -= pwfa[1] + 2;
                                pwfa += pwfa[1] + 2;
                            }
                        }
                        break;
                    case 0x1054: // Primary Device Type
                        break;
                    case 0x1057: // AP Setup Locked
                        info->wps.locked = tag_p[4];
                        break;
                    case 0x1008: // Config Methods
                    case 0x1053: // Selected Registrar Config Methods
                        info->wps.methods = (tag_p[4] << 8) + tag_p[5];
                        break;
                    default: // Unknown type-length-value
                        break;
                }
                tag_p += sublen + 4;
                len -= sublen + 4;
            }
            continue;
        }
    }
    info->security = security;
}

void got_packet(
    unsigned char *args, 
    const struct pcap_pkthdr *header, 
    unsigned char *packet)
{
    if (dumper)
    {
        pcap_dump((unsigned char *)dumper, header, packet);
        pcap_dump_flush(dumper);
    }
    if (header->caplen < sizeof(struct ieee80211_radiotap_header))
        return;
    struct ieee80211_radiotap_header *rtap = 
        (struct ieee80211_radiotap_header *)packet;
    unsigned char *frame_start = packet + rtap->it_len;
    struct ieee80211_frame_header_stub *h80211 = 
        (struct ieee80211_frame_header_stub *)frame_start;
    if ((h80211->data[0] & 0x0c) == 0x04)
    {
        // printf("control\n");
        return;
    }
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
    //assert(rtap->it_present&8);
    uint16_t freq = *(uint16_t *)(packet + 10);
    int8_t power = *(int8_t *)(packet + 14);
    struct ieee80211_info info;
    memset(&info, 0, sizeof(struct ieee80211_info));
    info = (struct ieee80211_info)
        {
            .bss = bssid,
            .freq = freq,
            .sta = stmac,
            //.ts = timestamp(header->ts),
            .timeval = header->ts,
            .power =  power,
            .version = h80211->type & 0x03,
            .type = (h80211->type>>2) & 0x03,
            .subtype = (h80211->type>>4) & 0x0f,
            .flags = h80211->flags,
        };
    try_parse_mgmt(header, packet, h80211, &info);
    dump_fields(info);
}

void _listen(void)
{
    assert(args.monitor);
    live = pcap_open_live(
        args.monitor, 
        SNAPLEN, 1, 0, pcaperr);
    assert(live);
    if (args.dump)
    {
        dumper = pcap_dump_open(live, args.dump);
        assert(dumper);
    }
    pcap_loop(live, -1, &got_packet, (unsigned char *)live);
}

void signal_handler(int sig)
{
    switch (sig)
    {
        case SIGINT:
        case SIGABRT:
        case SIGKILL:
            if (live)
            {
                pcap_breakloop(live);
            }
            return;
    }
}

int main(int argc, char **argv)
{   
    signal(SIGINT, signal_handler);
    signal(SIGABRT, signal_handler);
    signal(SIGKILL, signal_handler);
    memset(pcaperr, 0, sizeof(pcaperr));
    parse_args(argc, argv);
    //print_device_args();
    verify_device_name();
    verify_monitor_mode();
    _listen();
    putchar('\n');
    _shutdown(0);
    return 0;
}
