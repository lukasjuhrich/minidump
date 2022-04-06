#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from minidump.common_structs import *

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680387(v=vs.85).aspx
class MINIDUMP_MEMORY64_LIST:
    def __init__(self):
        self.NumberOfMemoryRanges = None
        self.BaseRva = None
        self.MemoryRanges = []

    def get_size(self):
        return (
            8 + 8 + len(self.MemoryRanges) * MINIDUMP_MEMORY_DESCRIPTOR64().get_size()
        )

    def to_bytes(self):
        t = len(self.MemoryRanges).to_bytes(8, byteorder="little", signed=False)
        t += self.BaseRva.to_bytes(8, byteorder="little", signed=False)
        for memrange in self.MemoryRanges:
            t += memrange.to_bytes()
        return t

    @staticmethod
    def parse(buff):
        mml = MINIDUMP_MEMORY64_LIST()
        mml.NumberOfMemoryRanges = int.from_bytes(
            buff.read(8), byteorder="little", signed=False
        )
        mml.BaseRva = int.from_bytes(buff.read(8), byteorder="little", signed=False)
        for _ in range(mml.NumberOfMemoryRanges):
            mml.MemoryRanges.append(MINIDUMP_MEMORY_DESCRIPTOR64.parse(buff))

        return mml

    def __str__(self):
        t = "== MINIDUMP_MEMORY64_LIST ==\n"
        t += "NumberOfMemoryRanges: %s\n" % self.NumberOfMemoryRanges
        t += "BaseRva: %s\n" % self.BaseRva
        for i in range(self.NumberOfMemoryRanges):
            t += str(self.MemoryRanges[i]) + "\n"
        return t


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680384(v=vs.85).aspx
class MINIDUMP_MEMORY_DESCRIPTOR64:
    def __init__(self):
        self.StartOfMemoryRange = None
        self.DataSize = None

    def get_size(self):
        return 16

    def to_bytes(self):
        t = self.StartOfMemoryRange.to_bytes(8, byteorder="little", signed=False)
        t += self.DataSize.to_bytes(8, byteorder="little", signed=False)
        return t

    @staticmethod
    def parse(buff):
        md = MINIDUMP_MEMORY_DESCRIPTOR64()
        md.StartOfMemoryRange = int.from_bytes(
            buff.read(8), byteorder="little", signed=False
        )
        md.DataSize = int.from_bytes(buff.read(8), byteorder="little", signed=False)
        return md

    def __str__(self):
        t = "Start: %s" % hex(self.StartOfMemoryRange)
        t += "Size: %s" % self.DataSize
        return t


class MinidumpMemory64List:
    def __init__(self):
        self.memory_segments = []

    @staticmethod
    def parse(dir, buff):
        buff.seek(dir.Location.Rva)
        chunk_data = buff.read(dir.Location.DataSize)
        return MinidumpMemory64List.from_chunk_data(chunk_data)

    @staticmethod
    async def aparse(dir, buff):
        await buff.seek(dir.Location.Rva)
        chunk_data = await buff.read(dir.Location.DataSize)
        return MinidumpMemory64List.from_chunk_data(chunk_data)

    @classmethod
    def from_chunk_data(cls, chunk_data):
        t = cls()
        chunk = io.BytesIO(chunk_data)
        mtl = MINIDUMP_MEMORY64_LIST.parse(chunk)
        rva = mtl.BaseRva
        for mod in mtl.MemoryRanges:
            t.memory_segments.append(MinidumpMemorySegment.parse_full(mod, rva))
            rva += mod.DataSize
        return t

    def to_table(self):
        t = []
        t.append(MinidumpMemorySegment.get_header())
        for mod in self.memory_segments:
            t.append(mod.to_row())
        return t

    def __str__(self):
        return "== MinidumpMemory64List ==\n" + construct_table(self.to_table())
