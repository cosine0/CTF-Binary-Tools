import hashlib
import os
import tempfile
from ROPgadget.ropgadget.core import *
from ROPgadget.ropgadget.ropchain.ropmaker import NotEnoughGadgetError
from ROPgadget.ropgadget.binary import Binary
from capstone import *

arch_code = {
    'x86': (CS_ARCH_X86, CS_MODE_32),
    'x64': (CS_ARCH_X86, CS_MODE_64),
    'arm': (CS_ARCH_ARM, CS_MODE_ARM)
}


class BinaryOption(object):
    def __init__(self, filename):
        self.binary = filename
        self.rawArch = None
        self.rawMode = None


def rop_it(code_address_pairs, rw_permission_address, architecture=None, exec_format=None, exec_files=None,
           exec_load_bases=None, verbose_gadgets=False, verbose_proceed=False):
    r"""
    Build rop chain in given binary code. If gadget is not enough, raise NotEnoughGadgetError.
    :param code_address_pairs: [('\xbinary code1...', 0xaddress1), ('\xbinary code2...', 0xaddress2), ...]
    :param rw_permission_address: memory address read, write permission. e.g. data section.
    :param architecture: One of 'x86', 'x64', or 'arm'
    :param exec_format: One of 'ELF', 'PE' or etc.
    :param exec_files: If you have executable, give the file name or list of the file names here. In this case, do not
     give args 'architecture' and 'exec_format'
    :param exec_load_bases: If your executable given in 'exec_files' is PIE, give load base address here.
     if 'exec_files' was list, use None in the place where you want to use default load address.
    :param verbose_proceed: print process
    :param verbose_gadgets: print collected gadgets
    :return: data to write in stack from RET which is filled with gadgets.
    """

    exec_sections = []
    if isinstance(exec_files, (str, unicode)):
        exec_files = [exec_files]
        exec_load_bases = [exec_load_bases]

    if exec_files is not None:
        arch_kind = None
        for exec_file, exec_load_base in zip(exec_files, exec_load_bases):
            binary = Binary(BinaryOption(exec_file))
            file_exec_sections = binary.getExecSections()
            this_arch_kind = (binary.getArch(), binary.getArchMode())
            if arch_kind != this_arch_kind and arch_kind is not None:
                raise ValueError("architecture of each executable file does not match.")
            else:
                arch_kind = this_arch_kind
            exec_format = binary.getFormat()
            if exec_load_base is not None:
                for section in file_exec_sections:
                    section["vaddr"] += exec_load_base
            exec_sections.extend(file_exec_sections)
    else:
        arch_kind = arch_code[architecture]
    data_section = {
        "vaddr": rw_permission_address
    }
    for code, address in code_address_pairs:
        exec_sections += [{
            "offset": address,
            "size": len(code),
            "vaddr": address,
            "opcodes": bytes(code)
        }]
    return Core(data_section, arch_kind[0], arch_kind[1],
                exec_format).analyze(exec_sections, verbose_gadgets, verbose_proceed)


if __name__ == '__main__':
    from pwn import *

    total_binary = ELF('/lib32/libc.so.6').get_section_by_name('.text').data()
    current_binary = ''
    for i, binary_part in enumerate(total_binary.split('\x00'), 1):
        current_binary += binary_part + '\x00'
        try:
            print rop_it([(current_binary, 0xabcdef01)], 0x12345678, exec_files='./d6e472fe7004da60e99c8bd59453df96')
        except NotEnoughGadgetError:
            print i, len(current_binary)
        else:
            break

