#include "header.h"

typedef struct {
	unsigned char e_ident[16];	/* ELF "magic number" */
	unsigned char e_type[2];	/* Identifies object file type */
	unsigned char e_machine[2];	/* Specifies required architecture */
	unsigned char e_version[4];	/* Identifies object file version */
	unsigned char e_entry[4];	/* Entry point virtual address */
	unsigned char e_phoff[4];	/* Program header table file offset */
	unsigned char e_shoff[4];	/* Section header table file offset */
	unsigned char e_flags[4];	/* Processor-specific flags */
	unsigned char e_ehsize[2];	/* ELF header size in bytes */
	unsigned char e_phentsize[2];	/* Program header table entry size */
	unsigned char e_phnum[2];	/* Program header table entry count */
	unsigned char e_shentsize[2];	/* Section header table entry size */
	unsigned char e_shnum[2];	/* Section header table entry count */
	unsigned char e_shstrndx[2];	/* Section header string table index */
} Elf32_External_Ehdr;

typedef struct {
	unsigned char e_ident[16];	/* ELF "magic number" */
	unsigned char e_type[2];	/* Identifies object file type */
	unsigned char e_machine[2];	/* Specifies required architecture */
	unsigned char e_version[4];	/* Identifies object file version */
	unsigned char e_entry[8];	/* Entry point virtual address */
	unsigned char e_phoff[8];	/* Program header table file offset */
	unsigned char e_shoff[8];	/* Section header table file offset */
	unsigned char e_flags[4];	/* Processor-specific flags */
	unsigned char e_ehsize[2];	/* ELF header size in bytes */
	unsigned char e_phentsize[2];	/* Program header table entry size */
	unsigned char e_phnum[2];	/* Program header table entry count */
	unsigned char e_shentsize[2];	/* Section header table entry size */
	unsigned char e_shnum[2];	/* Section header table entry count */
	unsigned char e_shstrndx[2];	/* Section header string table index */
} Elf64_External_Ehdr;

#define TYPE_NUM 8
#define BYTE_GET(field) byte_get(field, sizeof (field))

#define EI_NIDENT	16	/* Size of e_ident[] */
#define SH_FTYPE_MAX	32

#define EI_MAG0		0	/* File identification byte 0 index */
#define ELFMAG0		0x7F	/* Magic number byte 0 */

#define EI_MAG1		1	/* File identification byte 1 index */
#define ELFMAG1		'E'	/* Magic number byte 1 */

#define EI_MAG2		2	/* File identification byte 2 index */
#define ELFMAG2		'L'	/* Magic number byte 2 */

#define EI_MAG3		3	/* File identification byte 3 index */
#define ELFMAG3		'F'	/* Magic number byte 3 */

#define EI_CLASS	4	/* File class */

#define ELFCLASS64	2	/* 64-bit objects */

#define EI_DATA		5	/* Data encoding */
#define ELFDATANONE	0	/* Invalid data encoding */
#define ELFDATA2LSB	1	/* 2's complement, little endian */
#define ELFDATA2MSB	2	/* 2's complement, big endian */

#define ET_NONE         0       /* No file type */
#define ET_REL          1       /* Relocatable file */
#define ET_EXEC         2       /* Executable file */
#define ET_DYN          3       /* Shared object file */
#define ET_CORE         4       /* Core file */

#define UNKNOWN		0	/* No file type */
#define DATA_FILE	1	/* Relocatable file */
#define EXEC_FILE	2	/* Executable file */
#define SCRIPT_FILE	3	/* Shared object file */
#define NORMAL_FILE	4	/* Core file */

#if defined(__GNUC__) && __GNUC__ >= 2
typedef unsigned long long dwarf_vma;
#else
typedef unsigned long dwarf_vma;
#endif

dwarf_vma (*byte_get) (unsigned char *, int);

static int is_32bit_elf;
unsigned char	e_ident[EI_NIDENT];	/* ELF "magic number" */

char script_file[TYPE_NUM][64] = {
"#!/usr/bin/perl",
"#!/usr/bin/python",
"#!/bin/sh",
"#!/bin/bash",
"#!/usr/bin/ruby",
"<script language=\"javascript\">",
"<\?php",
"<html"
};

dwarf_vma byte_get_little_endian(unsigned char *field, int size)
{
	switch (size) {
		case 1:
			return *field;
		case 2:
			return ((unsigned int) (field[0]))
				| (((unsigned int) (field[1])) << 8);
		case 3:
			return ((unsigned long) (field[0]))
				| (((unsigned long) (field[1])) << 8)
				| (((unsigned long) (field[2])) << 16);
		case 4:
			return ((unsigned long) (field[0]))
				| (((unsigned long) (field[1])) << 8)
				| (((unsigned long) (field[2])) << 16)
				| (((unsigned long) (field[3])) << 24);
		case 8:
			if (sizeof (dwarf_vma) == 8) {
				return  ((dwarf_vma) (field[0]))
					| (((dwarf_vma) (field[1])) << 8)
					| (((dwarf_vma) (field[2])) << 16)
					| (((dwarf_vma) (field[3])) << 24)
					| (((dwarf_vma) (field[4])) << 32)
					| (((dwarf_vma) (field[5])) << 40)
					| (((dwarf_vma) (field[6])) << 48)
					| (((dwarf_vma) (field[7])) << 56);
			} else if (sizeof (dwarf_vma) == 4) {
				return  ((unsigned long) (field[0]))
					| (((unsigned long) (field[1])) << 8)
					| (((unsigned long) (field[2])) << 16)
					| (((unsigned long) (field[3])) << 24);
			}
		default:
			return 0;
	}
}

dwarf_vma byte_get_big_endian(unsigned char *field, int size)
{
	switch (size) {
		case 1:
			return *field;
		case 2:
			return ((unsigned int) (field[1])) | (((int) (field[0])) << 8);
		case 3:
			return ((unsigned long) (field[2]))
				| (((unsigned long) (field[1])) << 8)
				| (((unsigned long) (field[0])) << 16);
		case 4:
			return ((unsigned long) (field[3]))
				| (((unsigned long) (field[2])) << 8)
				| (((unsigned long) (field[1])) << 16)
				| (((unsigned long) (field[0])) << 24);
		case 8:
			if (sizeof (dwarf_vma) == 8) {
				return ((dwarf_vma) (field[7]))
					| (((dwarf_vma) (field[6])) << 8)
					| (((dwarf_vma) (field[5])) << 16)
					| (((dwarf_vma) (field[4])) << 24)
					| (((dwarf_vma) (field[3])) << 32)
					| (((dwarf_vma) (field[2])) << 40)
					| (((dwarf_vma) (field[1])) << 48)
					| (((dwarf_vma) (field[0])) << 56);
			} else if (sizeof (dwarf_vma) == 4) {
				field += 4;
				return ((unsigned long) (field[3]))
					| (((unsigned long) (field[2])) << 8)
					| (((unsigned long) (field[1])) << 16)
					| (((unsigned long) (field[0])) << 24);
			}
		default:
			return 0;
	}
}

static int get_file_header(FILE * file, unsigned short *e_type)
{
	if (fread (e_ident, EI_NIDENT, 1, file) != 1) {
		return 0;
	}

	if (e_ident[EI_MAG0] != ELFMAG0
		|| e_ident[EI_MAG1] != ELFMAG1
		|| e_ident[EI_MAG2] != ELFMAG2
		|| e_ident[EI_MAG3] != ELFMAG3) {
		return 1;/*Not an ELF file*/
	}

	/* Determine how to read the rest of the header.*/
	switch (e_ident[EI_DATA]) {
		default: /* fall through */
		case ELFDATANONE: /* fall through */
		case ELFDATA2LSB:
			byte_get = byte_get_little_endian;
			break;
		case ELFDATA2MSB:
			byte_get = byte_get_big_endian;
			break;
	}

	/* For now we only support 32 bit and 64 bit ELF files.*/
	is_32bit_elf = (e_ident[EI_CLASS] != ELFCLASS64);

	/* Read in the rest of the header.*/
	if (is_32bit_elf) {
		Elf32_External_Ehdr ehdr32;
		if (fread (ehdr32.e_type, sizeof (ehdr32) - EI_NIDENT, 1, file) != 1) {
			return 0;
		}
		*e_type = BYTE_GET (ehdr32.e_type);
	} else {
		Elf64_External_Ehdr ehdr64;

		if (fread (ehdr64.e_type, sizeof (ehdr64) - EI_NIDENT, 1, file) != 1) {
			return 0;
		}

		*e_type = BYTE_GET (ehdr64.e_type);
	}

	return 1;
}

static unsigned int check_file_type(FILE *file)
{
	char buff[68] = {0};
	int ret = 0;
	unsigned short e_type = 0;  //Identifies object file type

	ret = get_file_header(file, &e_type);
	if (ret == ET_NONE) {
		return UNKNOWN;
	}

	if (e_type == ET_EXEC ||
		e_type == ET_DYN) {
		return EXEC_FILE;
	}

	/*数据文件的前64个字节有不可打印的字符*/
	fseek(file, 0, SEEK_SET);
	ret = fread(buff, 64, 1, file);
	if (ret != 1 && !feof(file)) {
		DBG("read file 64 byte error");
		return UNKNOWN;
	}

	int i = 0;
	for(i = 0; i < ret; i++) {
		if(!isprint(buff[i]) && buff[i] !='\n') {
			return DATA_FILE;
		}
	}

	for(i = 0; i < TYPE_NUM; i++) {
		if(!strncasecmp(buff, script_file[i], strlen(script_file[i]))) {
			return SCRIPT_FILE;
		}
	}

	return NORMAL_FILE;
}

int get_file_type(char *path)
{
	unsigned int type = 0;

	FILE * fp = fopen(path, "r");
	if (!fp) {
		return 0;
	}

	type = check_file_type(fp);
	fclose(fp);
	return type;
}
