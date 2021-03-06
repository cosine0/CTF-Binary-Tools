# -*- coding: utf-8 -*-
#
#  Jonathan Salwan - 2014-05-13
#
#  http://shell-storm.org
#  http://twitter.com/JonathanSalwan
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software  Foundation, either  version 3 of  the License, or
#  (at your option) any later version.
#

import arch.ropmakerx86
import arch.ropmakerx64
from capstone import *


class ROPMaker:
    def __init__(self, arch, arch_mode, file_format, gadgets, offset, data_section):
        self.__arch = arch
        self.__arch_mode = arch_mode
        self.__data_section = data_section
        self.__format = file_format
        self.__gadgets = gadgets
        self.__offset = offset

    def generate(self, verbose=False):

        if self.__arch == CS_ARCH_X86 \
                and self.__arch_mode == CS_MODE_32 \
                and self.__format == "ELF":
            return arch.ropmakerx86.ROPMakerX86(self.__data_section, self.__gadgets, self.__offset, verbose=verbose) \
                .generate()

        elif self.__arch == CS_ARCH_X86 \
                and self.__arch_mode == CS_MODE_64 \
                and self.__format == "ELF":
            return arch.ropmakerx64.ROPMakerX64(self.__data_section, self.__gadgets, self.__offset, verbose=verbose) \
                .generate()

        else:
            raise NotImplementedError(
                "\n[Error] ROPMaker.__handlerArch - Arch not supported yet for the rop chain generation")


class NotEnoughGadgetError(Exception):
    pass


class NoDataSectionError(Exception):
    pass
