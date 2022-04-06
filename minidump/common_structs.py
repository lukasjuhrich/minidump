from __future__ import annotations

import typing
# https://msdn.microsoft.com/en-us/library/windows/desktop/ms680383(v=vs.85).aspx
from dataclasses import dataclass, field
if typing.TYPE_CHECKING:
    from minidump.streams import MINIDUMP_MEMORY_DESCRIPTOR


@dataclass
class MINIDUMP_LOCATION_DESCRIPTOR:
    DataSize: int
    Rva: int

    @staticmethod
    def get_size():
        return 8

    def to_bytes(self):
        return self.DataSize.to_bytes(4, byteorder="little", signed=False) \
            + self.Rva.to_bytes(4, byteorder="little", signed=False)

    @classmethod
    def parse(cls, buff):
        return cls(
            DataSize=int.from_bytes(buff.read(4), byteorder="little", signed=False),
            Rva=int.from_bytes(buff.read(4), byteorder="little", signed=False),
        )

    @classmethod
    async def aparse(cls, buff):
        return cls(
            DataSize=int.from_bytes(await buff.read(4), byteorder="little", signed=False),
            Rva=int.from_bytes(await buff.read(4), byteorder="little", signed=False),
        )

    def __str__(self):
        return f"Size: {self.DataSize} File offset: {self.Rva}"


@dataclass
class MINIDUMP_LOCATION_DESCRIPTOR64:
    DataSize: int
    Rva: int

    @staticmethod
    def get_size():
        return 16

    def to_bytes(self):
        return self.DataSize.to_bytes(8, byteorder="little", signed=False) \
            + self.Rva.to_bytes(8, byteorder="little", signed=False)

    @classmethod
    def parse(cls, buff):
        return cls(
            DataSize=int.from_bytes(buff.read(8), byteorder="little", signed=False),
            Rva=int.from_bytes(buff.read(8), byteorder="little", signed=False),
        )

    def __str__(self):
        return f"Size: {self.DataSize} File offset: {self.Rva}"


@dataclass
class MINIDUMP_STRING:
    Length: int
    Buffer: bytes

    @classmethod
    def parse(cls, buff):
        length = int.from_bytes(buff.read(4), byteorder="little", signed=False)
        return cls(Length=length, Buffer=buff.read(length))

    @classmethod
    async def aparse(cls, buff):
        length = int.from_bytes(await buff.read(4), byteorder="little", signed=False)
        return cls(Length=length, Buffer=await buff.read(length))

    @classmethod
    def get_from_rva(cls, rva, buff) -> str:
        pos = buff.tell()
        buff.seek(rva, 0)
        ms = cls.parse(buff)
        buff.seek(pos, 0)
        return ms.Buffer.decode("utf-16-le")

    @classmethod
    async def aget_from_rva(cls, rva, buff) -> str:
        pos = buff.tell()
        await buff.seek(rva, 0)
        ms = await cls.aparse(buff)
        await buff.seek(pos, 0)
        return ms.Buffer.decode("utf-16-le")


@dataclass
class MinidumpMemorySegment:
    size: int
    start_file_address: int
    start_virtual_address: int
    end_virtual_address: int = field(init=False)

    def __post_init__(self):
        self.end_virtual_address = self.start_virtual_address + self.size

    @classmethod
    def parse_mini(cls, memory_decriptor: MINIDUMP_MEMORY_DESCRIPTOR, buff):
        """
        memory_descriptor: MINIDUMP_MEMORY_DESCRIPTOR
        buff: file_handle
        """
        return cls(
            size=memory_decriptor.DataSize,
            start_virtual_address=memory_decriptor.StartOfMemoryRange,
            start_file_address=memory_decriptor.Rva,
        )

    @classmethod
    def parse_full(cls, memory_decriptor, rva):
        return cls(
            size=memory_decriptor.DataSize,
            start_file_address=rva,
            start_virtual_address=memory_decriptor.StartOfMemoryRange,
        )

    def inrange(self, virt_addr):
        return self.start_virtual_address <= virt_addr < self.end_virtual_address

    def validate_address(self, virtual_address, size):
        if not self.start_virtual_address <= virtual_address <= self.end_virtual_address:
            raise Exception("Reading from wrong segment!")

        if virtual_address + size > self.end_virtual_address:
            raise Exception("Read would cross boundaries!")

    def read(self, virtual_address, size, file_handler):
        self.validate_address(virtual_address, size)

        pos = file_handler.tell()
        offset = virtual_address - self.start_virtual_address
        file_handler.seek(self.start_file_address + offset, 0)
        data = file_handler.read(size)
        file_handler.seek(pos, 0)
        return data

    async def aread(self, virtual_address, size, file_handler):
        self.validate_address(virtual_address, size)

        pos = file_handler.tell()
        offset = virtual_address - self.start_virtual_address
        await file_handler.seek(self.start_file_address + offset, 0)
        data = await file_handler.read(size)
        await file_handler.seek(pos, 0)
        return data

    def search(self, pattern, file_handler, find_first=False, chunksize=50 * 1024):
        if len(pattern) > self.size:
            return []
        pos = file_handler.tell()
        file_handler.seek(self.start_file_address, 0)
        fl = []
        if find_first:
            chunksize = min(chunksize, self.size)
            data = b""
            i = 0
            while len(data) < self.size:
                i += 1
                if chunksize > (self.size - len(data)):
                    chunksize = self.size - len(data)
                data += file_handler.read(chunksize)
                marker = data.find(pattern)
                if marker != -1:
                    # print('FOUND! size: %s i: %s read: %s perc: %s' % (self.size, i, i*chunksize, 100*((i*chunksize)/self.size)))
                    file_handler.seek(pos, 0)
                    return [self.start_virtual_address + marker]

            # print('NOTFOUND! size: %s i: %s read: %s perc %s' % (self.size, i, len(data), 100*(len(data)/self.size) ))

        else:
            data = file_handler.read(self.size)
            file_handler.seek(pos, 0)

            offset = 0
            while len(data) > len(pattern):
                marker = data.find(pattern)
                if marker == -1:
                    return fl
                fl.append(marker + offset + self.start_virtual_address)
                data = data[marker + 1 :]
                offset += marker + 1
                if find_first:
                    return fl

        file_handler.seek(pos, 0)
        return fl

    async def asearch(
        self, pattern, file_handler, find_first=False, chunksize=50 * 1024
    ):
        if len(pattern) > self.size:
            return []
        pos = file_handler.tell()
        await file_handler.seek(self.start_file_address, 0)
        fl = []

        if find_first:
            chunksize = min(chunksize, self.size)
            data = b""
            i = 0
            while len(data) < self.size:
                i += 1
                if chunksize > (self.size - len(data)):
                    chunksize = self.size - len(data)
                data += await file_handler.read(chunksize)
                marker = data.find(pattern)
                if marker != -1:
                    # print('FOUND! size: %s i: %s read: %s perc: %s' % (self.size, i, i*chunksize, 100*((i*chunksize)/self.size)))
                    await file_handler.seek(pos, 0)
                    return [self.start_virtual_address + marker]

            # print('NOTFOUND! size: %s i: %s read: %s perc %s' % (self.size, i, len(data), 100*(len(data)/self.size) ))

        else:
            offset = 0
            data = await file_handler.read(self.size)
            await file_handler.seek(pos, 0)
            while len(data) > len(pattern):
                marker = data.find(pattern)
                if marker == -1:
                    return fl
                fl.append(marker + offset + self.start_virtual_address)
                data = data[marker + 1 :]
                offset += marker + 1
                if find_first:
                    return fl

        await file_handler.seek(pos, 0)
        return fl

    @staticmethod
    def get_header():
        return [
            "VA Start",
            "RVA",
            "Size",
        ]

    def to_row(self):
        return [
            hex(self.start_virtual_address),
            hex(self.start_file_address),
            hex(self.size),
        ]

    def __str__(self):
        return ", ".join([
            f"VA Start: 0x{self.start_virtual_address:x}",
            f"RVA: 0x{self.start_file_address:x}",
            f"Size: 0x{self.size:x}",
        ])


def hexdump(src, length=16, sep=".", start=0):
    """
    @brief Return {src} in hex dump.
    @param[in] length	{Int} Nb Bytes by row.
    @param[in] sep		{Char} For the text part, {sep} will be used for non ASCII char.
    @return {Str} The hexdump

    @note Full support for python2 and python3 !
    """
    result = []

    # Python3 support
    try:
        xrange(0, 1)
    except NameError:
        xrange = range

    for i in xrange(0, len(src), length):
        subSrc = src[i : i + length]
        hexa = ""
        isMiddle = False
        for h in xrange(0, len(subSrc)):
            if h == length / 2:
                hexa += " "
            h = subSrc[h]
            if not isinstance(h, int):
                h = ord(h)
            h = hex(h).replace("0x", "")
            if len(h) == 1:
                h = "0" + h
            hexa += h + " "
        hexa = hexa.strip(" ")
        text = ""
        for c in subSrc:
            if not isinstance(c, int):
                c = ord(c)
            if 0x20 <= c < 0x7F:
                text += chr(c)
            else:
                text += sep
        if start == 0:
            result.append(
                ("%08x:  %-" + str(length * (2 + 1) + 1) + "s  |%s|") % (i, hexa, text)
            )
        else:
            result.append(
                ("%08x(+%04x):  %-" + str(length * (2 + 1) + 1) + "s  |%s|")
                % (start + i, i, hexa, text)
            )
    return "\n".join(result)


def construct_table(lines, separate_head=True):
    """Prints a formatted table given a 2 dimensional array"""
    # Count the column width
    widths = []
    for line in lines:
        for i, size in enumerate([len(x) for x in line]):
            while i >= len(widths):
                widths.append(0)
            if size > widths[i]:
                widths[i] = size

    # Generate the format string to pad the columns
    print_string = ""
    for i, width in enumerate(widths):
        print_string += "{" + str(i) + ":" + str(width) + "} | "
    if len(print_string) == 0:
        return
    print_string = print_string[:-3]

    # Print the actual data
    t = ""
    for i, line in enumerate(lines):
        t += print_string.format(*line) + "\n"
        if i == 0 and separate_head:
            t += "-" * (sum(widths) + 3 * (len(widths) - 1)) + "\n"

    return t
