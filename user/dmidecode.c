/*
 * DMI Decode
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "types.h"
#include "header.h"

struct dmi_header
{
        u8 type;
        u8 length;
        u16 handle;
        u8 *data;
};

static char Manufacturer[S_NAMELEN] = {0};
static char Product[S_NAMELEN] = {0};
static char Vendor[S_NAMELEN] = {0};
static char Serialnum[S_NAMELEN] = {0};
static char UUID[S_SNLEN+1] = {0};
static char SKU[S_NAMELEN] = {0};

#define DEFAULT_MEM_DEV "/dev/mem"

#define FLAG_NO_FILE_OFFSET     (1 << 0)
#define FLAG_STOP_AT_EOT        (1 << 1)

#define SYS_FIRMWARE_DIR "/sys/firmware/dmi/tables"
#define SYS_ENTRY_FILE SYS_FIRMWARE_DIR "/smbios_entry_point"
#define SYS_TABLE_FILE SYS_FIRMWARE_DIR "/DMI"

static int myread(int fd, u8 *buf, size_t count)
{
	ssize_t r = 1;
	size_t r2 = 0;

	while (r2 != count && r != 0) {
		r = read(fd, buf + r2, count - r2);
		if (r == -1)
			return -1;

		r2 += r;
	}

	if (r2 != count)
		return -1;

	return 0;
}

static int checksum(const u8 *buf, size_t len)
{
	u8 sum = 0;
	size_t a;

	for (a = 0; a < len; a++)
		sum += buf[a];
	return (sum == 0);
}

/*
 * Reads all of file from given offset, up to max_len bytes.
 * A buffer of max_len bytes is allocated by this function, and
 * needs to be freed by the caller.
 * This provides a similar usage model to mem_chunk()
 *
 * Returns pointer to buffer of max_len bytes, or NULL on error, and
 * sets max_len to the length actually read.
 *
 */
static void *read_file(off_t base, size_t *max_len, const char *filename)
{
	int fd;
	size_t r2 = 0;
	ssize_t r;
	u8 *p;

	/*
	 * Don't print error message on missing file, as we will try to read
	 * files that may or may not be present.
	 */
	if ((fd = open(filename, O_RDONLY)) == -1)
		return NULL;

	if (lseek(fd, base, SEEK_SET) == -1)
	{
		p = NULL;
		goto out;
	}

	if ((p = malloc(*max_len)) == NULL)
		goto out;

	do
	{
		r = read(fd, p + r2, *max_len - r2);
		if (r == -1)
		{
			free(p);
			p = NULL;
			goto out;
		}

		r2 += r;
	}
	while (r != 0);

	*max_len = r2;
out:
	close(fd);

	return p;
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 */
static void *mem_chunk(off_t base, size_t len, const char *devmem)
{
	void *p = NULL;
	int fd = 0;

	if ((fd = open(devmem, O_RDONLY)) == -1)
		return NULL;

	if ((p = malloc(len)) == NULL)
		goto out;

	if (lseek(fd, base, SEEK_SET) == -1)
		goto err_free;

	if (myread(fd, p, len) == 0)
		goto out;

err_free:
	free(p);
	p = NULL;

out:
	close(fd);

	return p;
}

static char *dmi_string(const struct dmi_header *dm, u8 s)
{
	char *bp = (char *)dm->data;
	size_t i, len;

	if (s == 0)
		return NULL;

	bp += dm->length;
	while (s > 1 && *bp)
	{
		bp += strlen(bp);
		bp++;
		s--;
	}

	if (!*bp)
		return NULL;

	/* ASCII filtering */
	len = strlen(bp);
	for (i = 0; i < len; i++)
		if (bp[i] < 32 || bp[i] == 127)
			bp[i] = '.';

	return bp;
}

static void dmi_system_uuid(const u8 *p, u16 ver)
{
        int only0xFF = 1, only0x00 = 1;
        int i;

        for (i = 0; i < 16 && (only0x00 || only0xFF); i++)
        {
                if (p[i] != 0x00) only0x00 = 0;
                if (p[i] != 0xFF) only0xFF = 0;
        }

        if (only0xFF)
        {
                printf("Not Present");
                return;
        }
        if (only0x00)
        {
                printf("Not Settable");
                return;
        }

        /*
         * As of version 2.6 of the SMBIOS specification, the first 3
         * fields of the UUID are supposed to be encoded on little-endian.
         * The specification says that this is the defacto standard,
         * however I've seen systems following RFC 4122 instead and use
         * network byte order, so I am reluctant to apply the byte-swapping
         * for older versions.
         */
        if (ver >= 0x0206)
                snprintf(UUID, S_SNLEN+1,
                        "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                        p[3], p[2], p[1], p[0], p[5], p[4], p[7], p[6],
                        p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
        else
                snprintf(UUID, S_SNLEN+1,
                        "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                        p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

static void dmi_decode(const struct dmi_header *h, u16 ver)
{
	const u8 *data = h->data;
	char *str = NULL;

	switch (h->type)
	{
		case 0: /* 7.1 BIOS Information */
			if (h->length < 0x12) break;
			str = dmi_string(h, data[0x04]);
			if (str)
				strncpy(Vendor, str, S_NAMELEN-1);
			break;

		case 1: /* 7.2 System Information */
			if (h->length < 0x08) break;
			str = dmi_string(h, data[0x04]);
			if (str)
				strncpy(Manufacturer, str, S_NAMELEN-1);
			str = dmi_string(h, data[0x05]);
			if (str)
				strncpy(Product, str, S_NAMELEN-1);
			str = dmi_string(h, data[0x07]);
			if (str)
				strncpy(Serialnum, str, S_NAMELEN-1);
			str = dmi_string(h, data[0x19]);
			if (str)
				strncpy(SKU, str, S_NAMELEN-1);
			dmi_system_uuid(data + 0x08, ver);
			break;

		default:
			break;
	}
}

static void to_dmi_header(struct dmi_header *h, u8 *data)
{
	h->type = data[0];
	h->length = data[1];
	h->handle = WORD(data + 2);
	h->data = data;
}

static void dmi_table_decode(u8 *buf, u32 len, u16 num, u16 ver)
{
	u8 *data;
	int i = 0;

	data = buf;
	/* 4 is the length of an SMBIOS structure header */
	while ((i < num || !num) && data + 4 <= buf + len)
	{
		u8 *next;
		struct dmi_header h;

		to_dmi_header(&h, data);

		/*
		 * If a short entry is found (less than 4 bytes), not only it
		 * is invalid, but we cannot reliably locate the next entry.
		 * Better stop at this point, and let the user know his/her
		 * table is broken.
		 */
		if (h.length < 4)
			break;

		/* look for the next handle */
		next = data + h.length;
		while ((unsigned long)(next - buf + 1) < len &&
		       (next[0] != 0 || next[1] != 0))
			next++;
		next += 2;

		if (h.type <= 1 && (unsigned long)(next - buf) <= len)
		{
			dmi_decode(&h, ver);
		}

		data = next;
		i++;
	}
}

static void dmi_table(off_t base, u32 len, u16 num, u32 ver, const char *devmem,
		      u32 flags)
{
	u8 *buf;

	if (flags & FLAG_NO_FILE_OFFSET)
	{
		/*
		 * When reading from sysfs or from a dump file, the file may be
		 * shorter than announced. For SMBIOS v3 this is expcted, as we
		 * only know the maximum table size, not the actual table size.
		 * For older implementations (and for SMBIOS v3 too), this
		 * would be the result of the kernel truncating the table on
		 * parse error.
		 */
		size_t size = len;
		buf = read_file(0, &size, devmem);
		len = size;
	} else {
		buf = mem_chunk(base, len, devmem);
	}

	if (buf == NULL)
		return;

	dmi_table_decode(buf, len, num, ver >> 8);

	free(buf);
}

static int smbios3_decode(u8 *buf, const char *devmem, u32 flags)
{
	u32 ver;
	u64 offset;

	if (!checksum(buf, buf[0x06]))
		return 0;

	ver = (buf[0x07] << 16) + (buf[0x08] << 8) + buf[0x09];
	INFO("SMBIOS %u.%u.%u present.\n",
		buf[0x07], buf[0x08], buf[0x09]);

	offset = QWORD(buf + 0x10);
	if (!(flags & FLAG_NO_FILE_OFFSET) && offset.h && sizeof(off_t) < 8)
	{
		/* 64-bit addresses not supported, sorry. */
		INFO("dmi fail, 64-bit addresses not supported\n");
		return 0;
	}

	dmi_table(((off_t)offset.h << 32) | offset.l,
		  DWORD(buf + 0x0C), 0, ver, devmem, flags | FLAG_STOP_AT_EOT);

	return 1;
}

static int smbios_decode(u8 *buf, const char *devmem, u32 flags)
{
	u32 ver;

	if (!checksum(buf, buf[0x05])
	 || memcmp(buf + 0x10, "_DMI_", 5) != 0
	 || !checksum(buf + 0x10, 0x0F))
		return 0;

	ver = (buf[0x06] << 8) + buf[0x07];
        /* Some BIOS report weird SMBIOS version, fix that up */
        switch (ver)
        {
                case 0x021F:
                case 0x0221:
                        INFO("SMBIOS version fixup (2.%d -> 2.3).\n", ver & 0xFF);
                        ver = 0x0203;
                        break;
                case 0x0233:
                        INFO("SMBIOS version fixup (2.51 -> 2.6).\n");
                        ver = 0x0206;
                        break;
        }
	INFO("SMBIOS %u.%u present.\n", ver >> 8, ver & 0xFF);
	dmi_table(DWORD(buf + 0x18), WORD(buf + 0x16), WORD(buf + 0x1C),
		ver << 8, devmem, flags);

	return 1;
}

static int legacy_decode(u8 *buf, const char *devmem, u32 flags)
{
	if (!checksum(buf, 0x0F))
		return 0;

	INFO("Legacy DMI %u.%u present.\n",
		buf[0x0E] >> 4, buf[0x0E] & 0x0F);
	dmi_table(DWORD(buf + 0x08), WORD(buf + 0x06), WORD(buf + 0x0C),
		((buf[0x0E] & 0xF0) << 12) + ((buf[0x0E] & 0x0F) << 8),
		devmem, flags);

	return 1;
}

/*
 * Probe for EFI interface
 */
#define EFI_NOT_FOUND   (-1)
#define EFI_NO_SMBIOS   (-2)
static int address_from_efi(off_t *address)
{
	FILE *efi_systab;
	const char *filename;
	char linebuf[64];
	int ret;

	*address = 0; /* Prevent compiler warning */

	/*
	 * Linux up to 2.6.6: /proc/efi/systab
	 * Linux 2.6.7 and up: /sys/firmware/efi/systab
	 */
	if ((efi_systab = fopen(filename = "/sys/firmware/efi/systab", "r")) == NULL &&
	    (efi_systab = fopen(filename = "/proc/efi/systab", "r")) == NULL) {
		/* No EFI interface, fallback to memory scan */
		return EFI_NOT_FOUND;
	}
	ret = EFI_NO_SMBIOS;
	while ((fgets(linebuf, sizeof(linebuf) - 1, efi_systab)) != NULL)
	{
		char *addrp = strchr(linebuf, '=');
		*(addrp++) = '\0';
		if (strcmp(linebuf, "SMBIOS3") == 0 ||
		    strcmp(linebuf, "SMBIOS") == 0) {
			*address = strtoull(addrp, NULL, 0);
			ret = 0;
			break;
		}
	}
	fclose(efi_systab);

	return ret;
}

static void get_dmi(void)
{
	int found = 0;
	off_t fp;
	size_t size;
	int efi;
	u8 *buf = NULL;

	/*
	 * First try reading from sysfs tables.  The entry point file could
	 * contain one of several types of entry points, so read enough for
	 * the largest one, then determine what type it contains.
	 */
	size = 0x20;
	if ((buf = read_file(0, &size, SYS_ENTRY_FILE)) != NULL)
	{
		if (size >= 24 && memcmp(buf, "_SM3_", 5) == 0)
		{
			if (smbios3_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET))
				found++;
		}
		else if (size >= 31 && memcmp(buf, "_SM_", 4) == 0)
		{
			if (smbios_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET))
				found++;
		}
		else if (size >= 15 && memcmp(buf, "_DMI_", 5) == 0)
		{
			if (legacy_decode(buf, SYS_TABLE_FILE, FLAG_NO_FILE_OFFSET))
				found++;
		}

		if (found)
			goto out;
	}

	/* Next try EFI (ia64, Intel-based Mac) */
	efi = address_from_efi(&fp);
	switch (efi)
	{
		case EFI_NOT_FOUND:
			goto memory_scan;
		case EFI_NO_SMBIOS:
			goto out;
	}

	if ((buf = mem_chunk(fp, 0x20, DEFAULT_MEM_DEV)) == NULL)
		goto out;

	if (memcmp(buf, "_SM3_", 5) == 0)
	{
		if (smbios3_decode(buf, DEFAULT_MEM_DEV, 0))
			found++;
	}
	else if (memcmp(buf, "_SM_", 4) == 0)
	{
		if (smbios_decode(buf, DEFAULT_MEM_DEV, 0))
			found++;
	}
	goto out;

memory_scan:
	/* Fallback to memory scan (x86, x86_64) */
	if ((buf = mem_chunk(0xF0000, 0x10000, DEFAULT_MEM_DEV)) == NULL)
		goto out;

	/* Look for a 64-bit entry point first */
	for (fp = 0; fp <= 0xFFE0; fp += 16)
	{
		if (memcmp(buf + fp, "_SM3_", 5) == 0)
		{
			if (smbios3_decode(buf + fp, DEFAULT_MEM_DEV, 0))
			{
				found++;
				goto out;
			}
		}
	}

	/* If none found, look for a 32-bit entry point */
	for (fp = 0; fp <= 0xFFF0; fp += 16)
	{
		if (memcmp(buf + fp, "_SM_", 4) == 0 && fp <= 0xFFE0)
		{
			if (smbios_decode(buf + fp, DEFAULT_MEM_DEV, 0))
			{
				found++;
				goto out;
			}
		}
		else if (memcmp(buf + fp, "_DMI_", 5) == 0)
		{
			if (legacy_decode(buf + fp, DEFAULT_MEM_DEV, 0))
			{
				found++;
				goto out;
			}
		}
	}

out:
	if (buf)
		free(buf);

	return;
}

static void get_kylin_info(void)
{
	int len = 0, off = 0;
	FILE *fp = NULL;
	char buf[S_LINELEN] = {0};

	fp = fopen("/etc/LICENSE", "r");
	if (!fp) {
		return;
	}

	while (fgets(buf, S_LINELEN, fp)) {
		off = 3;
		if (strncmp(buf, "TO:", off) == 0) {
			len = strlen(buf);
			if (buf[len-1] == '\n') {
				buf[len-1] = 0;
			}
			if (Manufacturer[0] == 0) {
				strncpy(Manufacturer, buf+off, S_NAMELEN-1);
			}
			if (Vendor[0] == 0) {
				strncpy(Vendor, buf+off, S_NAMELEN-1);
			}
			continue;
		}

		off = 7;
		if (strncmp(buf, "SERIAL:", off) == 0) {
			len = strlen(buf);
			if (buf[len-1] == '\n') {
				buf[len-1] = 0;
			}
			if (Serialnum[0] == 0) {
				strncpy(Serialnum, buf+off, S_NAMELEN-1);
			}
			continue;
		}

		off = 6;
		if (strncmp(buf, "CLASS:", off) == 0) {
			len = strlen(buf);
			if (buf[len-1] == '\n') {
				buf[len-1] = 0;
			}
			if (Product[0] == 0) {
				strncpy(Product, buf+off, S_NAMELEN-1);
			}
			continue;
		}
	}
	fclose(fp);
}

static void get_vmtype(char vmtype[16])
{
	if (strncmp(Manufacturer, "VMware", 6) == 0) {
		strcpy(vmtype, "vmware");
		return;
	}

	if (strncmp(Manufacturer, "Microsoft Corporation", 21) == 0) {
		strcpy(vmtype, "virtualpc");
		return;
	}

	if (strncmp(Manufacturer, "innotek GmbH", 12) == 0) {
		strcpy(vmtype, "virtualbox");
		return;
	}

	if (strncmp(Manufacturer, "oVirt", 5) == 0) {
		strcpy(vmtype, "ovirt");
		return;
	}

	if (strncmp(Manufacturer, "QEMU", 4) == 0) {
		strcpy(vmtype, "qemu");
		return;
	}

	if (strstr(Manufacturer, "HITACHI") && strstr(Product, "LPAR")) {
		strcpy(vmtype, "virtage");
		return;
	}

	if (strncmp(Vendor, "Parallels", 9) == 0) {
		strcpy(vmtype, "parallels");
		return;
	}

	if (strncmp(Vendor, "BHYVE", 5) == 0) {
		strcpy(vmtype, "bhyve");
		return;
	}

	if (strncmp(Vendor, "RHEV Hypervisor", 15) == 0) {
		strcpy(vmtype, "rhev");
		return;
	}

	if (strncmp(Product, "KVM", 3) == 0) {
		strcpy(vmtype, "kvm");
		return;
	}
}

void get_machine_model(char *model, char *vmtype, char *sn, char *uuid, int verbose)
{
	get_dmi();

	if (Vendor[0] == 0 || Manufacturer[0] == 0 ||
	    Product[0] == 0 || Serialnum[0] == 0) {
		get_kylin_info();
	}

	if (Vendor[0] == 0) {
		strncpy(Vendor, " ", S_NAMELEN-1);
	}
	if (Manufacturer[0] == 0) {
		strncpy(Manufacturer, " ", S_NAMELEN-1);
	}
	if (Product[0] == 0) {
		if (strstr(Sys_info.os_dist, "Server") ||
		    strstr(Sys_info.os_dist, "server")) {
			strncpy(Product, "Server", S_NAMELEN-1);
		} else {
			strncpy(Product, "Desktop", S_NAMELEN-1);
		}
	}
	if (Serialnum[0] == 0) {
		strncpy(Serialnum, " ", S_NAMELEN-1);
	}

	if (islower(Product[0])) {
		Product[0] += 'A' - 'a';
	}

	if (verbose) {
		printf("Vendor: %s\n", Vendor);
		printf("Manufacturer: %s\n", Manufacturer);
		printf("Product Name: %s\n", Product);
		printf("Serial Number: %s\n", Serialnum);
	}
	strncpy(model, Product, S_NAMELEN-1);
	strncpy(sn, Serialnum, S_NAMELEN-1);
	strncpy(uuid, UUID, S_SNLEN);

	get_vmtype(vmtype);

	return;
}
