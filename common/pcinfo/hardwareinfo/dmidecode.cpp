#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <iostream>
#include "config.h"
#include "dmidecode.h"
#include "types.h"
#include "util.h"

#define SUPPORTED_SMBIOS_VER 0x0208
struct dmi_header {
    u8 type;
    u8 length;
    u16 handle;
    u8 *data;
};

/*
 * Type-independant Stuff
 */

const char *dmi_string(const struct dmi_header *dm, u8 s) {
    char *bp = (char *)dm->data;
    size_t i, len;

    if (s == 0) return "";

    bp += dm->length;
    while (s > 1 && *bp) {
        bp += strlen(bp);
        bp++;
        s--;
    }

    if (!*bp) return "";

    /* ASCII filtering */
    len = strlen(bp);
    for (i = 0; i < len; i++)
        if (bp[i] < 32 || bp[i] == 127) bp[i] = '.';

    if (strcasecmp(bp, "None") == 0) {
        return "";
    }

    return bp;
}

//static std::string dmi_memory_device_size(u16 code) {
//    std::string strSize;
//    char buf[64] = {0};
//    if (code != 0 && code != 0xFFFF) {
//        if (code & 0x8000)
//            snprintf(buf, sizeof(buf), "%u kB", code & 0x7FFF);
//        else
//            snprintf(buf, sizeof(buf), "%u %s",
//                     code >= 1024 ? code / 1024 : code,
//                     code >= 1024 ? "GB" : "MB");
//
//        strSize = buf;
//    }
//
//    return strSize;
//}

//static std::string dmi_memory_device_extended_size(u32 code) {
//    std::string strSize;
//    char buf[64] = {0};
//    code &= 0x7FFFFFFFUL;
//
//    /* Use the most suitable unit depending on size */
//    if (code & 0x3FFUL)
//        snprintf(buf, sizeof(buf), "%lu MB", (unsigned long)code);
//    else if (code & 0xFFFFFUL)
//        snprintf(buf, sizeof(buf), "%lu GB", (unsigned long)code >> 10);
//    else
//        snprintf(buf, sizeof(buf), "%lu TB", (unsigned long)code >> 20);
//
//    strSize = buf;
//
//    return strSize;
//}
//
//static const char *dmi_memory_device_type(u8 code) {
//    /* 7.18.2 */
//    static const char *type[] = {
//        "Other", /* 0x01 */
//        "Unknown",  "DRAM",     "EDRAM", "VRAM",         "SRAM",
//        "RAM",      "ROM",      "Flash", "EEPROM",       "FEPROM",
//        "EPROM",    "CDRAM",    "3DRAM", "SDRAM",        "SGRAM",
//        "RDRAM",    "DDR",      "DDR2",  "DDR2 FB-DIMM", "Reserved",
//        "Reserved", "Reserved", "DDR3",  "FBD2", /* 0x19 */
//    };
//
//    if (code >= 0x01 && code <= 0x19) return type[code - 0x01];
//    return "";
//}

//static std::string dmi_memory_device_speed(u16 code) {
//    char buf[64] = {0};
//    if (code == 0)
//        snprintf(buf, sizeof(buf), "Unknown");
//    else
//        snprintf(buf, sizeof(buf), "%u MHz", code);
//
//    return buf;
//}

static std::string dmi_processor_id(u8 type, const u8 *p) {
    char buff[64] = {0};
    snprintf(buff, sizeof(buff) - 1, "%02X %02X %02X %02X %02X %02X %02X %02X",
             p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    return std::string(buff);
}

static std::string dmi_system_uuid(const u8 *p, u16 ver) {
    int only0xFF = 1, only0x00 = 1;
    int i;

    for (i = 0; i < 16 && (only0x00 || only0xFF); i++) {
        if (p[i] != 0x00) only0x00 = 0;
        if (p[i] != 0xFF) only0xFF = 0;
    }

    if (only0xFF) {
        // printf("Not Present");
        return std::string();
    }
    if (only0x00) {
        // printf("Not Settable");
        return std::string();
    }

    /*
     * As of version 2.6 of the SMBIOS specification, the first 3
     * fields of the UUID are supposed to be encoded on little-endian.
     * The specification says that this is the defacto standard,
     * however I've seen systems following RFC 4122 instead and use
     * network byte order, so I am reluctant to apply the byte-swapping
     * for older versions.
     */
    char buff[64] = {0};
    if (ver >= 0x0206) {
        snprintf(
            buff, sizeof(buff) - 1,
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%"
            "02X",
            p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6], p[8], p[9], p[10],
            p[11], p[12], p[13], p[14], p[15]);

    } else {
        snprintf(
            buff, sizeof(buff),
            "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%"
            "02X",
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10],
            p[11], p[12], p[13], p[14], p[15]);
    }
    return std::string(buff);
}

#define out_of_spec "<OUT OF SPEC>"
static const char *dmi_processor_type(u8 code) {
    /* 7.5.1 */
    static const char *type[] = {
        "Other", /* 0x01 */
        "Unknown",       "Central Processor", "Math Processor",
        "DSP Processor", "Video Processor" /* 0x06 */
    };

    if (code >= 0x01 && code <= 0x06) return type[code - 0x01];
    return out_of_spec;
}

static const char *dmi_processor_family(const struct dmi_header *h, u16 ver) {
    const u8 *data = h->data;
    unsigned int i, low, high;
    u16 code;

    /* 7.5.2 */
    static struct {
        int value;
        const char *name;
    } family2[] = {
        {0x01, "Other"},
        {0x02, "Unknown"},
        {0x03, "8086"},
        {0x04, "80286"},
        {0x05, "80386"},
        {0x06, "80486"},
        {0x07, "8087"},
        {0x08, "80287"},
        {0x09, "80387"},
        {0x0A, "80487"},
        {0x0B, "Pentium"},
        {0x0C, "Pentium Pro"},
        {0x0D, "Pentium II"},
        {0x0E, "Pentium MMX"},
        {0x0F, "Celeron"},
        {0x10, "Pentium II Xeon"},
        {0x11, "Pentium III"},
        {0x12, "M1"},
        {0x13, "M2"},
        {0x14, "Celeron M"},
        {0x15, "Pentium 4 HT"},

        {0x18, "Duron"},
        {0x19, "K5"},
        {0x1A, "K6"},
        {0x1B, "K6-2"},
        {0x1C, "K6-3"},
        {0x1D, "Athlon"},
        {0x1E, "AMD29000"},
        {0x1F, "K6-2+"},
        {0x20, "Power PC"},
        {0x21, "Power PC 601"},
        {0x22, "Power PC 603"},
        {0x23, "Power PC 603+"},
        {0x24, "Power PC 604"},
        {0x25, "Power PC 620"},
        {0x26, "Power PC x704"},
        {0x27, "Power PC 750"},
        {0x28, "Core Duo"},
        {0x29, "Core Duo Mobile"},
        {0x2A, "Core Solo Mobile"},
        {0x2B, "Atom"},
        {0x2C, "Core M"},

        {0x30, "Alpha"},
        {0x31, "Alpha 21064"},
        {0x32, "Alpha 21066"},
        {0x33, "Alpha 21164"},
        {0x34, "Alpha 21164PC"},
        {0x35, "Alpha 21164a"},
        {0x36, "Alpha 21264"},
        {0x37, "Alpha 21364"},
        {0x38, "Turion II Ultra Dual-Core Mobile M"},
        {0x39, "Turion II Dual-Core Mobile M"},
        {0x3A, "Athlon II Dual-Core M"},
        {0x3B, "Opteron 6100"},
        {0x3C, "Opteron 4100"},
        {0x3D, "Opteron 6200"},
        {0x3E, "Opteron 4200"},
        {0x3F, "FX"},
        {0x40, "MIPS"},
        {0x41, "MIPS R4000"},
        {0x42, "MIPS R4200"},
        {0x43, "MIPS R4400"},
        {0x44, "MIPS R4600"},
        {0x45, "MIPS R10000"},
        {0x46, "C-Series"},
        {0x47, "E-Series"},
        {0x48, "A-Series"},
        {0x49, "G-Series"},
        {0x4A, "Z-Series"},
        {0x4B, "R-Series"},
        {0x4C, "Opteron 4300"},
        {0x4D, "Opteron 6300"},
        {0x4E, "Opteron 3300"},
        {0x4F, "FirePro"},
        {0x50, "SPARC"},
        {0x51, "SuperSPARC"},
        {0x52, "MicroSPARC II"},
        {0x53, "MicroSPARC IIep"},
        {0x54, "UltraSPARC"},
        {0x55, "UltraSPARC II"},
        {0x56, "UltraSPARC IIi"},
        {0x57, "UltraSPARC III"},
        {0x58, "UltraSPARC IIIi"},

        {0x60, "68040"},
        {0x61, "68xxx"},
        {0x62, "68000"},
        {0x63, "68010"},
        {0x64, "68020"},
        {0x65, "68030"},
        {0x66, "Athlon X4"},
        {0x67, "Opteron X1000"},
        {0x68, "Opteron X2000"},

        {0x70, "Hobbit"},

        {0x78, "Crusoe TM5000"},
        {0x79, "Crusoe TM3000"},
        {0x7A, "Efficeon TM8000"},

        {0x80, "Weitek"},

        {0x82, "Itanium"},
        {0x83, "Athlon 64"},
        {0x84, "Opteron"},
        {0x85, "Sempron"},
        {0x86, "Turion 64"},
        {0x87, "Dual-Core Opteron"},
        {0x88, "Athlon 64 X2"},
        {0x89, "Turion 64 X2"},
        {0x8A, "Quad-Core Opteron"},
        {0x8B, "Third-Generation Opteron"},
        {0x8C, "Phenom FX"},
        {0x8D, "Phenom X4"},
        {0x8E, "Phenom X2"},
        {0x8F, "Athlon X2"},
        {0x90, "PA-RISC"},
        {0x91, "PA-RISC 8500"},
        {0x92, "PA-RISC 8000"},
        {0x93, "PA-RISC 7300LC"},
        {0x94, "PA-RISC 7200"},
        {0x95, "PA-RISC 7100LC"},
        {0x96, "PA-RISC 7100"},

        {0xA0, "V30"},
        {0xA1, "Quad-Core Xeon 3200"},
        {0xA2, "Dual-Core Xeon 3000"},
        {0xA3, "Quad-Core Xeon 5300"},
        {0xA4, "Dual-Core Xeon 5100"},
        {0xA5, "Dual-Core Xeon 5000"},
        {0xA6, "Dual-Core Xeon LV"},
        {0xA7, "Dual-Core Xeon ULV"},
        {0xA8, "Dual-Core Xeon 7100"},
        {0xA9, "Quad-Core Xeon 5400"},
        {0xAA, "Quad-Core Xeon"},
        {0xAB, "Dual-Core Xeon 5200"},
        {0xAC, "Dual-Core Xeon 7200"},
        {0xAD, "Quad-Core Xeon 7300"},
        {0xAE, "Quad-Core Xeon 7400"},
        {0xAF, "Multi-Core Xeon 7400"},
        {0xB0, "Pentium III Xeon"},
        {0xB1, "Pentium III Speedstep"},
        {0xB2, "Pentium 4"},
        {0xB3, "Xeon"},
        {0xB4, "AS400"},
        {0xB5, "Xeon MP"},
        {0xB6, "Athlon XP"},
        {0xB7, "Athlon MP"},
        {0xB8, "Itanium 2"},
        {0xB9, "Pentium M"},
        {0xBA, "Celeron D"},
        {0xBB, "Pentium D"},
        {0xBC, "Pentium EE"},
        {0xBD, "Core Solo"},
        /* 0xBE handled as a special case */
        {0xBF, "Core 2 Duo"},
        {0xC0, "Core 2 Solo"},
        {0xC1, "Core 2 Extreme"},
        {0xC2, "Core 2 Quad"},
        {0xC3, "Core 2 Extreme Mobile"},
        {0xC4, "Core 2 Duo Mobile"},
        {0xC5, "Core 2 Solo Mobile"},
        {0xC6, "Core i7"},
        {0xC7, "Dual-Core Celeron"},
        {0xC8, "IBM390"},
        {0xC9, "G4"},
        {0xCA, "G5"},
        {0xCB, "ESA/390 G6"},
        {0xCC, "z/Architecture"},
        {0xCD, "Core i5"},
        {0xCE, "Core i3"},

        {0xD2, "C7-M"},
        {0xD3, "C7-D"},
        {0xD4, "C7"},
        {0xD5, "Eden"},
        {0xD6, "Multi-Core Xeon"},
        {0xD7, "Dual-Core Xeon 3xxx"},
        {0xD8, "Quad-Core Xeon 3xxx"},
        {0xD9, "Nano"},
        {0xDA, "Dual-Core Xeon 5xxx"},
        {0xDB, "Quad-Core Xeon 5xxx"},

        {0xDD, "Dual-Core Xeon 7xxx"},
        {0xDE, "Quad-Core Xeon 7xxx"},
        {0xDF, "Multi-Core Xeon 7xxx"},
        {0xE0, "Multi-Core Xeon 3400"},

        {0xE4, "Opteron 3000"},
        {0xE5, "Sempron II"},
        {0xE6, "Embedded Opteron Quad-Core"},
        {0xE7, "Phenom Triple-Core"},
        {0xE8, "Turion Ultra Dual-Core Mobile"},
        {0xE9, "Turion Dual-Core Mobile"},
        {0xEA, "Athlon Dual-Core"},
        {0xEB, "Sempron SI"},
        {0xEC, "Phenom II"},
        {0xED, "Athlon II"},
        {0xEE, "Six-Core Opteron"},
        {0xEF, "Sempron M"},

        {0xFA, "i860"},
        {0xFB, "i960"},

        {0x104, "SH-3"},
        {0x105, "SH-4"},
        {0x118, "ARM"},
        {0x119, "StrongARM"},
        {0x12C, "6x86"},
        {0x12D, "MediaGX"},
        {0x12E, "MII"},
        {0x140, "WinChip"},
        {0x15E, "DSP"},
        {0x1F4, "Video Processor"},
    };

    /* Special case for ambiguous value 0x30 (SMBIOS 2.0 only) */
    if (ver == 0x0200 && data[0x06] == 0x30 && h->length >= 0x08) {
        const char *manufacturer = dmi_string(h, data[0x07]);

        if (strstr(manufacturer, "Intel") != NULL ||
            strncasecmp(manufacturer, "Intel", 5) == 0)
            return "Pentium Pro";
    }

    code = (data[0x06] == 0xFE && h->length >= 0x2A) ? WORD(data + 0x28)
                                                     : data[0x06];

    /* Special case for ambiguous value 0xBE */
    if (code == 0xBE) {
        if (h->length >= 0x08) {
            const char *manufacturer = dmi_string(h, data[0x07]);

            /* Best bet based on manufacturer string */
            if (strstr(manufacturer, "Intel") != NULL ||
                strncasecmp(manufacturer, "Intel", 5) == 0)
                return "Core 2";
            if (strstr(manufacturer, "AMD") != NULL ||
                strncasecmp(manufacturer, "AMD", 3) == 0)
                return "K7";
        }

        return "Core 2 or K7";
    }

    /* Perform a binary search */
    low = 0;
    high = ARRAY_SIZE(family2) - 1;

    while (1) {
        i = (low + high) / 2;
        if (family2[i].value == code) return family2[i].name;
        if (low == high) /* Not found */
            return out_of_spec;

        if (code < family2[i].value)
            high = i;
        else
            low = i + 1;
    }
}
#undef out_of_spec

/*
 * Main
 */

static void dmi_decode(const struct dmi_header *h, u16 ver,
                       HardwareInfo &hardware_info) {
    const u8 *data = h->data;
    CpuInfo cpu_info;
    /*
     * Note: DMI types 37, 39 and 40 are untested
     */
    switch (h->type) {
        case 0: /* 7.1 BIOS Information */
            break;

        case 1: /* 7.2 System Information */
            if (h->length < 0x08) break;
            hardware_info.system_info.manufacturer = dmi_string(h, data[0x04]);
            hardware_info.system_info.product_name = dmi_string(h, data[0x05]);
            hardware_info.system_info.version = dmi_string(h, data[0x06]);
            hardware_info.system_info.serial_number = dmi_string(h, data[0x07]);
            hardware_info.system_info.uuid = dmi_system_uuid(data + 0x08, ver);
            break;

        case 2: /* 7.3 Base Board Information */
            if (h->length < 0x08) break;
            hardware_info.baseboard_info.manufacturer =
                dmi_string(h, data[0x04]);
            hardware_info.baseboard_info.product_name =
                dmi_string(h, data[0x05]);
            hardware_info.baseboard_info.version = dmi_string(h, data[0x06]);
            hardware_info.baseboard_info.serial_number =
                dmi_string(h, data[0x07]);

            break;

        case 3: /* 7.4 Chassis Information */
            break;

        case 4: /* 7.5 Processor Information */
            if (h->length < 0x1A) break;
            cpu_info.type = dmi_processor_type(data[0x05]);
            cpu_info.family = dmi_processor_family(h, ver);
            cpu_info.manufacturer = dmi_string(h, data[0x07]);
            cpu_info.cpuid = dmi_processor_id(data[0x06], data + 0x08);
            cpu_info.version = dmi_string(h, data[0x10]);
            hardware_info.cpu_infos.insert(std::make_pair(cpu_info.cpuid, cpu_info));
            break;

        case 5: /* 7.6 Memory Controller Information */
            break;

        case 6: /* 7.7 Memory Module Information */
            break;

        case 7: /* 7.8 Cache Information */
            break;

        case 8: /* 7.9 Port Connector Information */
            break;

        case 9: /* 7.10 System Slots */
            break;

        case 10: /* 7.11 On Board Devices Information */
            break;

        case 11: /* 7.12 OEM Strings */
            break;

        case 12: /* 7.13 System Configuration Options */
            break;

        case 13: /* 7.14 BIOS Language Information */
            break;

        case 14: /* 7.15 Group Associations */
            break;

        case 15: /* 7.16 System Event Log */
            break;

        case 16: /* 7.17 Physical Memory Array */
            break;

        case 17: /* 7.18 Memory Device */
            break;

        case 18: /* 7.19 32-bit Memory Error Information */
            break;

        case 19: /* 7.20 Memory Array Mapped Address */
            break;

        case 20: /* 7.21 Memory Device Mapped Address */
            break;

        case 21: /* 7.22 Built-in Pointing Device */
            break;

        case 22: /* 7.23 Portable Battery */
            break;

        case 23: /* 7.24 System Reset */
            break;

        case 24: /* 7.25 Hardware Security */
            break;

        case 25: /* 7.26 System Power Controls */
            break;

        case 26: /* 7.27 Voltage Probe */
            break;

        case 27: /* 7.28 Cooling Device */
            break;

        case 28: /* 7.29 Temperature Probe */
            break;

        case 29: /* 7.30 Electrical Current Probe */
            break;

        case 30: /* 7.31 Out-of-band Remote Access */
            break;

        case 31: /* 7.32 Boot Integrity Services Entry Point */
            break;

        case 32: /* 7.33 System Boot Information */
            break;

        case 33: /* 7.34 64-bit Memory Error Information */
            break;

        case 34: /* 7.35 Management Device */
            break;

        case 35: /* 7.36 Management Device Component */
            break;

        case 36: /* 7.37 Management Device Threshold Data */
            break;

        case 37: /* 7.38 Memory Channel */
            break;

        case 38: /* 7.39 IPMI Device Information */
                 /*
                  * We use the word "Version" instead of "Revision", conforming to
                  * the IPMI specification.
                  */
            break;

        case 39: /* 7.40 System Power Supply */
            break;

        case 40: /* 7.41 Additional Information */
            break;

        case 41: /* 7.42 Onboard Device Extended Information */
            break;

        case 42: /* 7.43 Management Controller Host Interface */
            break;

        case 126: /* 7.44 Inactive */
            break;

        case 127: /* 7.45 End Of Table */
            break;

        default:
            break;
    }
}

static void to_dmi_header(struct dmi_header *h, u8 *data) {
    h->type = data[0];
    h->length = data[1];
    h->handle = WORD(data + 2);
    h->data = data;
}

static int dmi_table(u32 base, u16 len, u16 num, u16 ver, const char *devmem,
                     HardwareInfo &hardware_info) {
    u8 *buf;
    u8 *data;
    int i = 0;
    int rc = 0;

    if ((buf = (u8 *)mem_chunk(base, len, devmem)) == NULL) {
        return -1;
    }

    data = buf;
    while (i < num &&
           data + 4 <=
               buf + len) /* 4 is the length of an SMBIOS structure header */
    {
        u8 *next;
        struct dmi_header h;
        int display = 0;

        to_dmi_header(&h, data);

        if (h.type == 127) {
            /*stop decoding at end of table marker */
            break;
        } else if (IsBaseBoardType(h.type)) {
            display = 1;
        } else if (IsSystemType(h.type)) {
            display = 1;
        } else if (IsProcessorType(h.type)) {
            display = 1;
        }

        /*
         * If a short entry is found (less than 4 bytes), not only it
         * is invalid, but we cannot reliably locate the next entry.
         * Better stop at this point, and let the user know his/her
         * table is broken.
         */
        if (h.length < 4) {
            printf(
                "Invalid entry length (%u). DMI table is "
                "broken! Stop.\n\n",
                (unsigned int)h.length);
            rc = -1;
            break;
        }

        /* look for the next handle */
        next = data + h.length;
        while (next - buf + 1 < len && (next[0] != 0 || next[1] != 0)) next++;
        next += 2;
        if (display) {
            if (next - buf <= len) {
                dmi_decode(&h, ver, hardware_info);
            }
        }

        data = next;
        i++;
    }

    free(buf);

    return rc;
}

static int smbios_decode(u8 *buf, const char *devmem,
                         HardwareInfo &hardware_info) {
    u16 ver;

    if (!checksum(buf, buf[0x05]) || memcmp(buf + 0x10, "_DMI_", 5) != 0 ||
        !checksum(buf + 0x10, 0x0F))
        return -1;

    ver = (buf[0x06] << 8) + buf[0x07];
    /* Some BIOS report weird SMBIOS version, fix that up */
    switch (ver) {
        case 0x021F:
        case 0x0221:
            ver = 0x0203;
            break;
        case 0x0233:
            ver = 0x0206;
            break;
    }

    return dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C), ver,
                     devmem, hardware_info);
}

static int legacy_decode(u8 *buf, const char *devmem,
                         HardwareInfo &hardware_info) {
    if (!checksum(buf, 0x0F)) return -1;

    return dmi_table(DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
                     ((buf[0x0E] & 0xF0) << 4) + (buf[0x0E] & 0x0F), devmem,
                     hardware_info);
}

/*
 * Probe for EFI interface
 */
#define EFI_NOT_FOUND (-1)
#define EFI_NO_SMBIOS (-2)
static int AddressFromEfi(size_t *address) {
    FILE *efi_systab;
    const char *filename;
    char linebuf[64];
    int ret;

    *address = 0; /* Prevent compiler warning */

    /*
     * Linux up to 2.6.6: /proc/efi/systab
     * Linux 2.6.7 and up: /sys/firmware/efi/systab
     */
    if ((efi_systab = fopen(filename = "/sys/firmware/efi/systab", "r")) ==
            NULL &&
        (efi_systab = fopen(filename = "/proc/efi/systab", "r")) == NULL) {
        /* No EFI interface, fallback to memory scan */
        return EFI_NOT_FOUND;
    }
    ret = EFI_NO_SMBIOS;
    while ((fgets(linebuf, sizeof(linebuf) - 1, efi_systab)) != NULL) {
        char *addrp = strchr(linebuf, '=');
        *(addrp++) = '\0';
        if (strcmp(linebuf, "SMBIOS") == 0) {
            *address = strtoul(addrp, NULL, 0);
            ret = 0;
            break;
        }
    }
    if (fclose(efi_systab) != 0) perror(filename);

    return ret;
}

static int GetHardwareInfoEFI(size_t fp, const char *devmem,
                              HardwareInfo &hardware_info) {
    u8 *buf = NULL;
    int ret = -1;

    if ((buf = (u8 *)mem_chunk(fp, 0x20, devmem)) == NULL) {
        return ret;
    }

    ret = smbios_decode(buf, devmem, hardware_info);
    free(buf);
    return ret;
}

/*
 *No EFI found
 */
static int GetHardwareInfoNoEFI(const char *devmem,
                                HardwareInfo &hardware_info) {
    u8 *buf = NULL;
    size_t fp = 0;
    int rc = 0;
    /* Fallback to memory scan (x86, x86_64) */
    if ((buf = (u8 *)mem_chunk(0xF0000, 0x10000, devmem)) == NULL) {
        return -1;
    }

    for (fp = 0; fp <= 0xFFF0; fp += 16) {
        if (memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0) {
            rc = smbios_decode(buf + fp, devmem, hardware_info);
            if (rc == 0) {
                fp += 16;
            }
        } else if (memcmp(buf + fp, "_DMI_", 5) == 0) {
            legacy_decode(buf + fp, devmem, hardware_info);
        }
    }

    free(buf);

    return 0;
}

/*
 *Get Memory and Bios,BaseBoard information
 */
int GetHardwareInfo(HardwareInfo &hardware_info) {
    size_t fp;
    int efi;
    const char *devmem = DEFAULT_MEM_DEV;

    /* First try EFI (ia64, Intel-based Mac) */
    efi = AddressFromEfi(&fp);
    if (efi == EFI_NO_SMBIOS) {
        return -1;
    } else if (efi == EFI_NOT_FOUND) {
        return GetHardwareInfoNoEFI(devmem, hardware_info);
    } else {
        return GetHardwareInfoEFI(fp, devmem, hardware_info);
    }
}
