#!/usr/bin/env python3
from __future__ import annotations
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from dataclasses import dataclass, field

from minidump.common_structs import MINIDUMP_LOCATION_DESCRIPTOR, MINIDUMP_LOCATION_DESCRIPTOR64, \
    MinidumpMemorySegment


# https://docs.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_list
@dataclass
class MINIDUMP_MEMORY_LIST:
    NumberOfMemoryRanges: int
    MemoryRanges: list[MINIDUMP_MEMORY_DESCRIPTOR] = field(repr=False)

    def to_bytes(self):
        t = len(self.MemoryRanges).to_bytes(4, byteorder="little", signed=False)
        for memrange in self.MemoryRanges:
            t += memrange.to_bytes()
        return t

    @classmethod
    def parse(cls, buff):
        NumberOfMemoryRanges = int.from_bytes(buff.read(4), byteorder="little", signed=False)
        return cls(
            NumberOfMemoryRanges=NumberOfMemoryRanges,
            MemoryRanges=[MINIDUMP_MEMORY_DESCRIPTOR.parse(buff)
                          for _ in range(NumberOfMemoryRanges)]
        )

    def __str__(self):
        return "\n".join([
            "== MINIDUMP_MEMORY_LIST ==",
            f"NumberOfMemoryRanges: {self.NumberOfMemoryRanges}",
            *(str(range) for range in self.MemoryRanges),
        ])


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680384(v=vs.85).aspx
@dataclass
class MINIDUMP_MEMORY_DESCRIPTOR:
    StartOfMemoryRange: int
    MemoryLocation: MINIDUMP_LOCATION_DESCRIPTOR | MINIDUMP_LOCATION_DESCRIPTOR64
    # we do not use MemoryLocation but immediately store its fields in this object for easy access
    DataSize: int
    Rva: int

    def to_bytes(self):
        return self.StartOfMemoryRange.to_bytes(4, byteorder="little", signed=False) \
               + self.MemoryLocation.to_bytes()

    @classmethod
    def parse(cls, buff):
        # TODO: figure out what the documentation says, the person writign it was probably high...
        # The deal is: RVA sizes differ on where in the file the memory data is stored.
        # But it's not possible to know it up front if we need to read 32 or 64 bytes...
        # if md.StartOfMemoryRange < 0x100000000:
        # 	MemoryLocation = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
        # else:
        # 	MemoryLocation = MINIDUMP_LOCATION_DESCRIPTOR64.parse(buff)
        MemoryLocation = MINIDUMP_LOCATION_DESCRIPTOR.parse(buff)
        return cls(
            StartOfMemoryRange=int.from_bytes(buff.read(8), byteorder="little", signed=False),
            MemoryLocation=MemoryLocation,
            DataSize=MemoryLocation.DataSize,
            Rva=MemoryLocation.Rva,
        )

    def __str__(self):
        return "\n".join([
            f"Start: 0x{self.StartOfMemoryRange:x}",
            f"Size: {self.DataSize}",
            f"Rva: {self.Rva}",
        ])


@dataclass(repr=False)
class MinidumpMemoryList:
    memory_segments: list[MinidumpMemorySegment]

    @classmethod
    def parse(cls, dir, buff):
        buff.seek(dir.Location.Rva)
        chunk = io.BytesIO(buff.read(dir.Location.DataSize))
        mtl = MINIDUMP_MEMORY_LIST.parse(chunk)
        return cls(memory_segments=[
            MinidumpMemorySegment.parse_mini(mod, buff)
            for mod in mtl.MemoryRanges
        ])

    @classmethod
    async def aparse(cls, dir, buff):
        await buff.seek(dir.Location.Rva)
        chunk_data = await buff.read(dir.Location.DataSize)
        chunk = io.BytesIO(chunk_data)
        mtl = MINIDUMP_MEMORY_LIST.parse(chunk)
        return cls(memory_segments=[
            MinidumpMemorySegment.parse_mini(mod, buff)
            for mod in mtl.MemoryRanges
        ])

    def __str__(self):
        return "\n".join([
            "== MinidumpMemoryList ==",
            *(str(mod) for mod in self.memory_segments),
        ])

    def __repr__(self):
        return f"<{type(self).__name__} ({len(self.memory_segments)} elements)>"
