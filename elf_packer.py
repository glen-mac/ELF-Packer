from enum import Enum
import sys
import logging
from pwn import *
from struct import *
from optparse import OptionParser

parser = OptionParser()
parser.add_option("-f", "--file", dest="filename",
                  help="the ELF file to pack", metavar="FILE")
parser.add_option("-b", "--bits", dest="bits",
                  help="the ELF arch to use (32/64)", metavar="BITS")
(options, args) = parser.parse_args()


ETYPE_DIC = {
    0: 'No file type',
    1: 'Relocatable file',
    2: 'Executable file',
    3: 'Shared object file',
    4: 'Core file'
}


# Enum of the section types
class SectionType(Enum):
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11
    SHT_LOPROC = 0x70000000
    SHT_HIPROC = 0x7fffffff
    SHT_LOUSER = 0x80000000
    SHT_HIUSER = 0xffffffff

class Section():
    def __init__(self, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize):
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize
    def __str__(self):
        return f"""[Start Section '{self.name}']
        sh_name      = {hex(self.sh_name)}
        sh_type      = {hex(self.sh_type)}
        sh_flags     = {hex(self.sh_flags)}
        sh_addr      = {hex(self.sh_addr)}
        sh_offset    = {hex(self.sh_offset)}
        sh_size      = {hex(self.sh_size)}
        sh_link      = {hex(self.sh_link)}
        sh_info      = {hex(self.sh_info)}
        sh_addralign = {hex(self.sh_addralign)}
        sh_entsize   = {hex(self.sh_entsize)}
        """

class Elf():
    def __init__(self, name="", data=[], bits=''):
        self.name = name
        self.data = data
        self.bits = int(bits)
        self.EI_NIDENT = 16 
        self.ELF_EHDR_SZ = 36 + self.EI_NIDENT if self.bits == 32 else 48 + self.EI_NIDENT

    """
    Parse the ELF header of the binary

    e_ident:        marks the file as an object file
    e_type:         identifies the object file type
    e_machine:      specifies the required architecture of the file
    e_version:      identifies the object file version
    e_entry:        virtual address where the system first transfers control
    e_phoff:        program header table file offset in bytes
    e_shoff:        section header table offset in bytes
    e_flags:        holds processor specific flags associated with the file
    e_ehsize:       the elf header size in bytes
    e_phentsize:    size in bytes of one entry in program header table
    e_phnum:        number of entries in program header table
    e_shentsize:    size in bytes of one section header in section header table
    e_shnum:        number of entries in section header table
    e_shstrndx:     index of the section header table for string table
    """

    def parse_header(self):
        unpack_str = f"{self.EI_NIDENT}sHHIQQQIHHHHHH" if self.bits == 64 else f"{self.EI_NIDENT}sHHIIIIIHHHHHH"
        (self.e_ident, self.e_type, self.e_machine, self.e_version,
         self.e_entry, self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = unpack(
             unpack_str, self.data[:self.ELF_EHDR_SZ])
        logging.debug(f"entry point found:\t{hex(self.e_entry)}")
        logging.debug(f"object file type:\t{ETYPE_DIC[self.e_type]}")

    """
    Parse sections of the Section Header Table

    sh_name:        index into the string table of the section name
    sh_type:        categorizes the sections contents and semantics
    sh_flags:       flags that describe miscellaneous attributes
    sh_addr:        virtual address of the first byte when in memory (if)
    sh_offset:      offset from start of file of first byte in the section
    sh_size:        the size of the section in bytes
    sh_link:        section header table index link
    sh_info:        holds extra information depending on section type
    sh_addralign:   dictates if the section has some form of size alignment
    sh_entsize:     size in bytes of each entry of section-fixed size table
    """

    def parse_sections_header(self):
        unpack_str = "IIQQQQIIQQ" if self.bits == 64 else "IIIIIIIIII"
        # dictionary of arrays indexed by section type
        self.sections = {}
        section_header_sz = self.e_shnum * self.e_shentsize
        section_table = self.data[self.e_shoff:
                                  self.e_shoff + section_header_sz]
        # skip the first section in the section header table
        # e_shstrndx:     index of the section header table for string table
        for sec_index in range(1, self.e_shnum):
            # unpack the section data
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
             sh_info, sh_addralign, sh_entsize) = unpack(
                 unpack_str,
                 section_table[sec_index * self.e_shentsize:sec_index * self.
                               e_shentsize + self.e_shentsize])
            # create the section
            sec = Section(sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                          sh_size, sh_link, sh_info, sh_addralign, sh_entsize)
            if (not self.sections.get(sh_type)):
                self.sections[sh_type] = []
            self.sections[sh_type].append(sec)
            if sec_index == self.e_shstrndx:
                self.string_table_offset = sh_offset
        
        # add the section name to each section object
        for sec_type in self.sections.keys():
            for sec in self.sections.get(sec_type):
                sec.name = self.get_string(sec.sh_name)   
                logging.debug(sec)
    
    def find_cave(self, required_size):
        # ensure that we don't look at 'SHT_NOBITS' sections
        for sec_type in self.sections.keys():
            for sec in self.sections.get(sec_type):
                if sec.sh_type == SectionType.SHT_NOBITS:
                    continue
                index = 0
                seen_nulls = 0
                checkpoint = 0
                while (index < sec.sh_size):
                    char = self.data[sec.sh_offset + index]
                    index+=1
                    if char == 0:
                        seen_nulls += 1
                    else:
                        checkpoint = index
                        seen_nulls = 0
                    if seen_nulls == required_size:
                        break
                if seen_nulls < required_size:
                    continue
                logging.debug(f"""found a code cave in section: {sec.name} with
                        required size of {required_size} bytes at address
                        {hex(sec.sh_offset + checkpoint)} in the file. The address in memory
                        would be {hex(sec.sh_addr + index)}""")
                return (sec.sh_addr + checkpoint, sec.sh_offset + checkpoint)
        logging.error("no code cave found")

    def get_string(self, index):
        elf_str = ''
        char = self.data[self.string_table_offset + index]
        while (char != 0):
            index += 1
            elf_str += chr(char)
            char = self.data[self.string_table_offset + index]
        return elf_str

    def get_section(self, name):
        for sec_type in self.sections.keys():
            for sec in self.sections.get(sec_type):
                if sec.name == name:
                    return sec


    def pack_code(self, key):
        text_sec = self.get_section('.text')
        for i in range(text_sec.sh_size):
            self.data[text_sec.sh_offset + i] ^= key

    def change_ep(self, new_ep):
        if self.bits == 32:
            self.data[24:24+4] = p32(new_ep)
        else:
            self.data[24:24+8] = p64(new_ep)
    
    def create_unpacker(self):
        text_sec = self.get_section('.text')
        text_addr = text_sec.sh_addr & 0xFFFFFFFFFFFFF000 if self.bits == 64 else text_sec.sh_addr & 0xFFFFF000
        syscall_str = 'int 0x80' if self.bits == 32 else 'syscall'
        register_prefix = 'r' if self.bits == 64 else 'e'
        syscall_num = '0x7d' if self.bits == 32 else '10'
        syscall_reg_1 = 'di' if self.bits == 64 else 'bx'
        syscall_reg_2 = 'si' if self.bits == 64 else 'cx'
        unpacker_asm = asm(f"""
        push {register_prefix}ax
        push {register_prefix}di
        push {register_prefix}si
        push {register_prefix}dx
        push {register_prefix}cx

        mov {register_prefix}ax, {syscall_num}
        mov {register_prefix}{syscall_reg_1}, {text_addr}
        mov {register_prefix}{syscall_reg_2}, {text_sec.sh_size}
        mov {register_prefix}dx, 0x7 
        {syscall_str} 

        mov {register_prefix}di, {text_sec.sh_addr}
        mov {register_prefix}si, {register_prefix}di
        mov {register_prefix}cx, {text_sec.sh_size}
        cld
        decrypt:
            lodsb
            xor al, 0xa5
            stosb
            loop decrypt

        mov {register_prefix}ax, {syscall_num}
        mov {register_prefix}{syscall_reg_1}, {text_addr}
        mov {register_prefix}{syscall_reg_2}, {text_sec.sh_size}
        mov {register_prefix}dx, 0x5
        {syscall_str}

        pop {register_prefix}cx
        pop {register_prefix}dx
        pop {register_prefix}si
        pop {register_prefix}di
        pop {register_prefix}ax
 
        push {self.e_entry}
        ret
        """)
        return unpacker_asm

    def write_unpacker(self, asm, off):
        self.data[unpacker_off:unpacker_off+len(asm)] = asm

# binary.write_unpacker(unpacker_asm, unpacker_off) 
if __name__ == '__main__':

    if options.bits == '32':
        context.arch = 'i386'
    else:
        context.arch = 'amd64'

    logging.basicConfig(
        format='%(levelname)s:\t%(message)s', level=logging.DEBUG)

    # load data into memory
    try:
        with open(options.filename, 'rb') as f:
            elf_data = bytearray(f.read())
    except:
        print(f"ERROR: Failed opening file: {options.filename}")
        sys.exit(1)

    # check header
    if elf_data[:4] != b'\x7fELF':
        print(f"ERROR: File: {options.filename} is not an ELF file")
        sys.exit(1)

    binary = Elf(name=options.filename, data=elf_data, bits=options.bits)
    binary.parse_header()
    binary.parse_sections_header()
    binary.pack_code(0xa5)
    unpacker_asm = binary.create_unpacker()
    logging.debug(f"need {len(unpacker_asm)} bytes in a cave")
    (unpacker_addr, unpacker_off) = binary.find_cave(len(unpacker_asm))
    binary.change_ep(unpacker_addr)
    binary.write_unpacker(unpacker_asm, unpacker_off) 

    # save packed binary to new file
    with open(f"{options.filename}.packed", 'wb') as f:
        f.write(binary.data)
        
