#!/usr/bin/env python3
from __future__ import annotations
#
# Author:
#  Tamas Jos (@skelsec)
#
import io
from dataclasses import dataclass
from minidump.common_structs import *

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680387(v=vs.85).aspx
@dataclass
class MINIDUMP_MEMORY64_LIST:
    NumberOfMemoryRanges: int
    BaseRva: int
    MemoryRanges: list[MINIDUMP_MEMORY_DESCRIPTOR64]

    def get_size(self):
        return (
            8 + 8 + len(self.MemoryRanges) * MINIDUMP_MEMORY_DESCRIPTOR64.get_size()
        )

    def to_bytes(self):
        return b"".join([
            len(self.MemoryRanges).to_bytes(8, byteorder="little", signed=False),
            self.BaseRva.to_bytes(8, byteorder="little", signed=False),
            *(r.to_bytes() for r in self.MemoryRanges)
        ])

    @classmethod
    def parse(cls, buff):
        NumberOfMemoryRanges = int.from_bytes(
            buff.read(8), byteorder="little", signed=False
        )

        return cls(
            NumberOfMemoryRanges=NumberOfMemoryRanges,
            BaseRva=int.from_bytes(buff.read(8), byteorder="little", signed=False),
            MemoryRanges=[
                MINIDUMP_MEMORY_DESCRIPTOR64.parse(buff)
                for _ in range(NumberOfMemoryRanges)
            ],
        )

    def __str__(self):
        return "\n".join([
            "== MINIDUMP_MEMORY64_LIST ==",
            f"NumberOfMemoryRanges: {self.NumberOfMemoryRanges}",
            f"BaseRva: {self.BaseRva}",
            *(str(r) for r in self.MemoryRanges),
        ])


# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680384(v=vs.85).aspx
@dataclass
class MINIDUMP_MEMORY_DESCRIPTOR64:
    StartOfMemoryRange: int
    DataSize: int

    @staticmethod
    def get_size():
        return 16

    def to_bytes(self):
        return b"".join([
            self.StartOfMemoryRange.to_bytes(8, byteorder="little", signed=False),
            self.DataSize.to_bytes(8, byteorder="little", signed=False),
        ])

    @classmethod
    def parse(cls, buff):
        return cls(
            StartOfMemoryRange=int.from_bytes(
                buff.read(8), byteorder="little", signed=False
            ),
            DataSize=int.from_bytes(buff.read(8), byteorder="little", signed=False),
        )

    def __str__(self):
        return f"Start: 0x{self.StartOfMemoryRange:x} Size: {self.DataSize}"


@dataclass(repr=False)
class MinidumpMemory64List:
    memory_segments: list[MinidumpMemorySegment]

    @classmethod
    def parse(cls, dir, buff):
        buff.seek(dir.Location.Rva)
        return cls.from_chunk_data(buff.read(dir.Location.DataSize))

    @classmethod
    async def aparse(cls, dir, buff):
        await buff.seek(dir.Location.Rva)
        return cls.from_chunk_data(await buff.read(dir.Location.DataSize))

    @classmethod
    def from_chunk_data(cls, chunk_data):
        mtl = MINIDUMP_MEMORY64_LIST.parse(io.BytesIO(chunk_data))
        rva = mtl.BaseRva
        memory_segments = []
        for mod in mtl.MemoryRanges:
            memory_segments.append(MinidumpMemorySegment.parse_full(mod, rva))
            rva += mod.DataSize
        return cls(memory_segments=memory_segments)

    def to_table(self):
        return [
            MinidumpMemorySegment.get_header(),
            *(mod.to_row() for mod in self.memory_segments)
        ]

    def __str__(self):
        return "== MinidumpMemory64List ==\n" + construct_table(self.to_table())

    def __repr__(self):
        return f"<{type(self).__name__} ({len(self.memory_segments)} segments)>"
