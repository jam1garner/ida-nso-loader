"""
Nintendo Switch Binary (NSO) loader for IDA

Copyright (C) 2017 jam1garner

Thanks to Reswitched and Switchbrew for info

licensed under the MIT license - see LICENSE file in project
root for more information.
"""

import os,sys,struct
from idaapi import *

#Install lz4 if they don't already have it
try:
    import lz4
except ImportError:
    import pip
    pip.main(['install','lz4'])
    import lz4

#Stolen from CTUv1
(DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ,
 DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI, DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL,
 DT_RELSZ, DT_RELENT, DT_PLTREL, DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY,
 DT_FINI_ARRAY, DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS) = xrange(31)
DT_GNU_HASH = 0x6ffffef5
DT_VERSYM = 0x6ffffff0
DT_RELACOUNT = 0x6ffffff9
DT_RELCOUNT = 0x6ffffffa
DT_FLAGS_1 = 0x6ffffffb
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd

#Also stolen from CTUv1
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3

def Int32(f):
    return struct.unpack('<L', f.read(4))[0]

def ToInt32(b):
    return struct.unpack('<L', b[:4])[0]

#Based on Mephisto
class SegInfo:
    def __init__(self, f):
        self.fileOffset = Int32(f)
        self.memoryLocation = Int32(f)
        self.decompressedSize = Int32(f)
        self.alignmentOrSize = Int32(f)

#Based on switchbrew NSO page
class MOD0:
    def __init__(self, b):
        padding = ToInt32(b[0:4])
        magicOffset = ToInt32(b[4:8])
        self.magicOffset = magicOffset
        self.magic = ToInt32(b[magicOffset:magicOffset+4])
        self.dynamicOff = ToInt32(b[magicOffset+4:magicOffset+8]) + magicOffset
        self.bssStartOff = ToInt32(b[magicOffset+0x8:magicOffset+0xC]) + magicOffset
        self.bssEndOff = ToInt32(b[magicOffset+0xC:magicOffset+0x10]) + magicOffset
        self.ehFrameHdrStart = ToInt32(b[magicOffset+0x10:magicOffset+0x14]) + magicOffset
        self.ehFrameHdrEnd = ToInt32(b[magicOffset+0x14:magicOffset+0x18]) + magicOffset
        self.moduleOff = ToInt32(b[magicOffset+0x18:magicOffset+0x1C]) + magicOffset
        self.bssSize = self.bssEndOff - self.bssStartOff
        self.ehFrameHdrSize = self.ehFrameHdrEnd - self.ehFrameHdrStart

class NSO:
    def __init__(self, f):
        self.read(f)

    def read(self, f):
        f.seek(0, 2)
        endOfFile = f.tell()
        f.seek(0x10)
        self.textSegment = SegInfo(f)
        self.rodataSegment = SegInfo(f)
        self.dataSegment = SegInfo(f)
        
        #Note: python lz4 library requires the expected decompressed size at the beginning of the compression
        #so I am nice and append it there for it :)
        f.seek(self.textSegment.fileOffset)
        data = struct.pack('<L', self.textSegment.decompressedSize) + f.read(self.rodataSegment.fileOffset - self.textSegment.fileOffset)
        self.textBytes = lz4.block.decompress(data)
        
        f.seek(self.rodataSegment.fileOffset)
        data = struct.pack('<L', self.rodataSegment.decompressedSize) + f.read(self.dataSegment.fileOffset - self.rodataSegment.fileOffset)
        self.rodataBytes = lz4.block.decompress(data)
        
        f.seek(self.dataSegment.fileOffset)
        data = struct.pack('<L', self.dataSegment.decompressedSize) + f.read(endOfFile - self.dataSegment.fileOffset)
        self.dataBytes = lz4.block.decompress(data)

        self.mod0 = MOD0(self.textBytes)


    #Not used for loader, just for looking at stuff in a better hex view than IDA's
    def dump(self):
        size = 0
        if self.textSegment.memoryLocation + len(self.textBytes) > size:
            size = self.textSegment.memoryLocation + len(self.textBytes)
        if self.rodataSegment.memoryLocation + len(self.rodataBytes) > size:
            size = self.rodataSegment.memoryLocation + len(self.rodataBytes)
        if self.dataSegment.memoryLocation + len(self.dataBytes) > size:
            size = self.dataSegment.memoryLocation + len(self.dataBytes)

        with open('nso_dump.bin', 'wb') as f:
        	f.write(size * chr(0))
        	f.seek(self.textSegment.memoryLocation)
        	f.write(self.textBytes)
        	f.seek(self.rodataSegment.memoryLocation)
        	f.write(self.rodataBytes)
        	f.seek(self.dataSegment.memoryLocation)
        	f.write(self.dataBytes)

    #kinda hacky way of reading the decompressed bytes
    def getBytes(self, pos, amt):
        if pos >= self.textSegment.memoryLocation and pos < self.textSegment.memoryLocation+len(self.textBytes):
            return self.textBytes[pos - self.textSegment.memoryLocation:(pos - self.textSegment.memoryLocation) + amt]
        if pos >= self.rodataSegment.memoryLocation and pos < self.rodataSegment.memoryLocation+len(self.rodataBytes):
            return self.rodataBytes[pos - self.rodataSegment.memoryLocation:(pos - self.rodataSegment.memoryLocation) + amt]
        if pos >= self.dataSegment.memoryLocation and pos < self.dataSegment.memoryLocation+len(self.dataBytes):
            return self.dataBytes[pos - self.dataSegment.memoryLocation:(pos - self.dataSegment.memoryLocation) + amt]

class DynTable:
    def __init__(self, nso):
        self.dynamic = []

    def append(self, tag, value):
        self.dynamic.append((tag, value))

    def __getitem__(self, tag):
        for i,j in self.dynamic:
            if i == tag:
                return j
        return None

    def getAll(self, tag):
        l = []
        for i,j in self.dynamic:
            if i == tag:
                l.append(j)
        return l

    def read(self, nso):
        i = nso.mod0.dynamicOff
        tag, value = struct.unpack('<QQ', nso.getBytes(i,0x10))
        i += 0x10
        while tag != DT_NULL:
            self.append(tag, value)
            tag, value = struct.unpack('<QQ', nso.getBytes(i,0x10))
            i += 0x10
        if self[DT_STRTAB] != None:
            strTable = self[DT_STRTAB]
            #TODO: Load imports
        if self[DT_SYMTAB] != None:
            symTable = self[DT_SYMTAB]
            


def load_file(f, neflags, format):
    set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
    SetShortPrm(idc.INF_LFLAGS, idc.GetShortPrm(idc.INF_LFLAGS) | idc.LFLG_64BIT)

    #Read in file
    nso = NSO(f)

    # add text segment
    mem2base(nso.textBytes, nso.textSegment.memoryLocation)
    add_segm(0, nso.textSegment.memoryLocation, nso.textSegment.memoryLocation+len(nso.textBytes), '.text', "CODE")
    set_segm_addressing(get_segm_by_name(".text"), 2)

    mem2base(nso.rodataBytes, nso.rodataSegment.memoryLocation)
    add_segm(0, nso.rodataSegment.memoryLocation, nso.rodataSegment.memoryLocation+len(nso.rodataBytes), '.rodata', "CONST")

    mem2base(nso.dataBytes, nso.dataSegment.memoryLocation)
    add_segm(0, nso.dataSegment.memoryLocation, nso.dataSegment.memoryLocation+len(nso.dataBytes), '.data', "DATA")

    mem2base(chr(0) * nso.mod0.bssSize, nso.mod0.bssStartOff)
    add_segm(0, nso.mod0.bssStartOff, nso.mod0.bssEndOff, '.bss', 'BSS')

    add_segm(0, nso.mod0.ehFrameHdrStart,  nso.mod0.ehFrameHdrEnd, '.eh_frame_hdr', 'CONST')

    return 1

def accept_file(f, n):
    retval = 0

    if n == 0:
        f.seek(0)
        if struct.unpack('>I', f.read(4))[0] == 0x4E534F30:
            retval = "Nintendo Switch Binary (NSO)"

    return retval

# if __name__ == "__main__":
# 	with open("G:/main", 'rb') as f:
# 		nso = NSO(f)
# 		nso.dump()