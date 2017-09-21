import sys
import logging
from struct import *

EI_NIDENT = 16
ELF32_EHDR_SZ = 36 + EI_NIDENT

ETYPE_DIC = {
    0: 'No file type',
    1: 'Relocatable file',
    2: 'Executable file',
    3: 'Shared object file',
    4: 'Core file'
}


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


class Elf():
    def __init__(self, name="", data=[]):
        self.name = name
        self.data = data

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
        (self.e_ident, self.e_type, self.e_machine, self.e_version,
         self.e_entry, self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = unpack(
             f"{EI_NIDENT}sHHIIIIIHHHHHH", self.data[:ELF32_EHDR_SZ])
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
        self.sections = []
        section_header_sz = self.e_shnum * self.e_shentsize
        section_table = self.data[self.e_shoff:
                                  self.e_shoff + section_header_sz]
        for sec_index in range(1, self.e_shnum + 1):
            # unpack the section data
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link,
             sh_info, sh_addralign, sh_entsize) = unpack(
                 'IIIIIIIIII',
                 section_table[sec_index * self.e_shentsize:sec_index * self.
                               e_shentsize + self.e_shentsize])
            # create the section
            sec = Section(sh_name, sh_type, sh_flags, sh_addr, sh_offset,
                          sh_size, sh_link, sh_info, sh_addralign, sh_entsize)
            self.sections.append(sec)

            #logging.debug(f"Section with name: {self.get_string(sh_name)}")

    def get_string(self, index):
        elf_str = ''
        char = self.data[self.e_shstrndx + index]
        logging.debug(f"string table offset is: {self.e_shstrndx}")
        while (char != b'\x00'):
            index += 1
            elf_str += chr(char)
            char = self.data[self.e_shstrndx + index]
        logging.debug(f"got string ({index}): '{elf_str}'")
        return elf_str


if __name__ == '__main__':

    logging.basicConfig(
        format='%(levelname)s:\t%(message)s', level=logging.DEBUG)

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file.elf>")
        sys.exit(1)

    # load data into memory
    try:
        with open(sys.argv[1], 'rb') as f:
            elf_data = bytearray(f.read())
    except:
        print(f"ERROR: Failed opening file: {sys.argv[1]}")
        sys.exit(1)

    # check header
    if elf_data[:4] != b'\x7fELF':
        print(f"ERROR: File: {sys.argv[1]} is not an ELF file")
        sys.exit(1)

    binary = Elf(name=sys.argv[1], data=elf_data)
    binary.parse_header()
    binary.parse_sections_header()
    binary.parse_sections()
