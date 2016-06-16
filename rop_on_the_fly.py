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


def rop_it(code_address_pairs, rw_permission_address, architecture=None, exec_format=None, exec_file=None,
           exec_load_base=None, verbose_gadgets=False, verbose_proceed=False):
    r"""
    Build rop chain in given binary code. If gadget is not enough, raise NotEnoughGadgetError.
    :param rw_permission_address: memory address read, write permission. e.g. data section.
    :param architecture: One of 'x86', 'x64', or 'arm'
    :param exec_format: One of 'ELF', 'PE' or etc.
    :param exec_file: If you have executable, give filename here. In this case, do not give args 'architecture' and
     'exec_format'
    :param exec_load_base: If your executable given in 'exec_file' is PIE, give load base address here.
    :param code_address_pairs: [('\xbinary code1...', 0xaddress1), ('\xbinary code2...', 0xaddress2), ...]
    :return: data to write in stack from RET which is filled with gadgets.
    :param verbose_proceed: print process
    :param verbose_gadgets: print collected gadgets
    """

    exec_sections = []
    if exec_file is not None:
        b = Binary(BinaryOption(exec_file))
        exec_sections += b.getExecSections()
        arch_kind = (b.getArch(), b.getArchMode())
        exec_format = b.getFormat()
        if exec_load_base is not None:
            for section in exec_sections:
                section["vaddr"] += exec_load_base
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
    for i, x in enumerate(total_binary.split('\x00'), 1):
        current_binary += x + '\x00'
        try:
            print rop_it([(current_binary, 0xabcdef01)], 0x12345678, exec_file='./d6e472fe7004da60e99c8bd59453df96')
        except NotEnoughGadgetError:
            print i, len(current_binary)
        else:
            break
