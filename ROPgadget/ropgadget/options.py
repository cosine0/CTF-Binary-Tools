# -*- coding: utf-8 -*-
#
#  Jonathan Salwan - 2014-05-17 - ROPgadget tool
#
#  http://twitter.com/JonathanSalwan
#  http://shell-storm.org/project/ROPgadget/
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software  Foundation, either  version 3 of  the License, or
#  (at your option) any later version.

from capstone import CS_MODE_32
from struct import pack


class Options:
    def __init__(self, arch_mode, gadgets, filter='', only='', range='', badbytes=''):
        self.__gadgets = gadgets
        self.__arch_mode = arch_mode
        self.__filter = filter
        self.__only = only
        self.__range = range
        self.__badbytes = badbytes

        if filter:   self.__filterOption()
        if only:     self.__onlyOption()
        if range:    self.__rangeOption()
        if badbytes: self.__deleteBadBytes()

    def __filterOption(self):
        new = []
        if not self.__filter:
            return
        filt = self.__filter.split("|")
        if not len(filt):
            return
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] in filt:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

    def __onlyOption(self):
        new = []
        if not self.__only:
            return
        only = self.__only.split("|")
        if not len(only):
            return
        for gadget in self.__gadgets:
            flag = 0
            insts = gadget["gadget"].split(" ; ")
            for ins in insts:
                if ins.split(" ")[0] not in only:
                    flag = 1
                    break
            if not flag:
                new += [gadget]
        self.__gadgets = new

    def __rangeOption(self):
        new = []
        rangeS = int(self.__range.split('-')[0], 16)
        rangeE = int(self.__range.split('-')[1], 16)
        if rangeS == 0 and rangeE == 0:
            return
        for gadget in self.__gadgets:
            vaddr = gadget["vaddr"]
            if rangeS <= vaddr <= rangeE:
                new += [gadget]
        self.__gadgets = new

    def __deleteBadBytes(self):
        if not self.__badbytes:
            return
        new = []
        # Filter out empty badbytes (i.e if badbytes was set to 00|ff| there's an empty badbyte after the last '|')
        # and convert each one to the corresponding byte
        bbytes = [bb.decode('hex') for bb in self.__badbytes.split("|") if bb]
        for gadget in self.__gadgets:
            gadAddr = pack("<L", gadget["vaddr"]) if self.__arch_mode == CS_MODE_32 else pack("<Q", gadget["vaddr"])
            try:
                for x in bbytes:
                    if x in gadAddr: raise
                new += [gadget]
            except:
                pass
        self.__gadgets = new

    def getGadgets(self):
        return self.__gadgets
