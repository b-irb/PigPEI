#!/usr/bin/env python3

import lzma
import os
import sys
from collections import namedtuple
from struct import calcsize, pack, unpack_from


# when we read GUIDs from the FV, we cannot correctly interpret
# endianness via struct so we modify our constants instead
def swap_guid(guid: bytes) -> bytes:
    return (
        guid[ :4][::-1] +
        guid[4:6][::-1] +
        guid[6:8][::-1] +
        guid[8: ]
    )

def str2guid(guid: str) -> bytes:
    return swap_guid(bytes.fromhex(guid))

def guid2str(guid: bytes) -> str:
    return swap_guid(guid).decode()

def align8(x: int) -> int:
    if x % 8 != 0:
        x += 8 - x % 8
    return x

EFI_FIRMWARE_FILE_SYSTEM2_GUID = \
        str2guid("8C8CE5788A3D4F1c9935896185C32DD3")
EFI_SECTION_GUID_LZMA = \
        str2guid("EE4E5898391442599D6EDC7BD79403CF")
EFI_PEI_PERMANENT_MEMORY_INSTALLED_PPI = \
        str2guid("F894643DC44942D18EA885BDD8C65BDE")

# EFI_FV_FILETYPE
EFI_FV_FILETYPE_RAW = 0x1
EFI_FV_FILETYPE_PEIM = 0x6
EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE = 0xb

# EFI_FVB_ATTRIBUTES_2
EFI_FVB2_ERASE_POLARITY = 0x800

# EFI_SECTION_TYPE
EFI_SECTION_ALL = 0x0
EFI_SECTION_COMPRESSION = 0x1
EFI_SECTION_GUID_DEFINED = 0x2
EFI_SECTION_PE32 = 0x10
EFI_SECTION_VERSION = 0x14
EFI_SECTION_USER_INTERFACE = 0x15
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_PEI_DEPEX = 0x1b

# EFI_FFS_FILE_ATTRIBUTES
FFS_ATTRIB_LARGE_FILE = 0x1
FFS_ATTRIB_DATA_ALIGNMENT = 0x38
FFS_ATTRIB_CHECKSUM = 0x40

# EFI_FFS_FILE_STATE
EFI_FILE_HEADER_CONSTRUCTION = 0x1
EFI_FILE_HEADER_VALID = 0x2
EFI_FILE_DATA_VALID = 0x4

# size field is 24-bit
FileHeaderFmt = "<16sHBB3BB"
FileHeader = namedtuple("FileHeader", [
    "name",
    "checksum",
    "type",
    "attributes",
    "size",
    "state",
])

# section size is 24-bit
FileSectionFmt = "<3BB"
FileSection = namedtuple("FileSection", [
    "size",
    "type",
])

FileSectionGuidFmt = "<16sHH"
FileSectionGuid = namedtuple("FileSectionGuid", [
    "guid",
    "data_off",
    "attributes",
])

FVHeaderFmt = "<16s16sQ4sIHHHBB"
FVHeader = namedtuple("FVHeader", [
    "zero_vec",
    "fs_guid",
    "fv_len",
    "signature",
    "attributes",
    "header_len",
    "checksum",
    "ext_header_off",
    "reserved",
    "revision",
])

FVExtHeaderFmt = "<16sI"
FVExtHeader = namedtuple("FVExtHeader", [
    "fv_name",
    "size",
])


def make_checksum(blob: bytearray) -> int:
    chk = 0
    for byte in blob:
        chk = (chk + byte) & 0xff
    return (0x100 - chk) & 0xff


def make_num(*components) -> int:
    value = 0
    for shift, component in enumerate(components):
        value |= component << (shift * 8)
    return value


def get_fvheader_sz(blob: bytes, offset: int = 0) -> int:
    header = unpack_from(FVHeaderFmt, blob, offset=offset)
    header = FVHeader._make(header)

    # incorporate extended header size if present
    if header.ext_header_off != 0:
        offset = header.ext_header_off
        ext_header = unpack_from(FVExtHeaderFmt, blob, offset=offset)
        ext_header = FVExtHeader._make(ext_header)
        offset += ext_header.size
    else:
        offset = header.header_len

    # ffs header must be 8-byte aligned
    return align8(offset)


def make_file(fname: str, erase_polarity: bool) -> bytes:
    def make_section(type, size: int) -> bytes:
        return pack(FileSectionFmt,
            (size >> 0 ) & 0xff,
            (size >> 8 ) & 0xff,
            (size >> 16) & 0xff,
            type
        )

    def make_padding(size: int) -> bytes:
        padding = align8(size) - size
        return b'\x00' * padding

    with open(fname, "rb") as f:
        module = f.read()

    DEPEX_PUSH = b'\x02'
    DEPEX_END  = b'\x08'
    payload = b""

    # load PEIM after pemanent memory is available
    depex = DEPEX_PUSH + EFI_PEI_PERMANENT_MEMORY_INSTALLED_PPI + DEPEX_END
    depex_size = calcsize(FileSectionFmt) + len(depex)
    payload += make_section(EFI_SECTION_PEI_DEPEX, depex_size)
    payload += depex
    payload += make_padding(depex_size)
    depex_size = align8(depex_size)

    # encapsulate PE32 image
    # the section size must be aligned for unknown reasons
    pe_size = calcsize(FileSectionFmt) + len(module)
    payload += make_section(EFI_SECTION_PE32, align8(pe_size))
    payload += module
    payload += make_padding(pe_size)
    pe_size = align8(pe_size)

    # UI information for easier debugging
    # this section must also be aligned for unknown reasons
    fname = "PigPei\x00".encode("utf_16_le")
    ui_size = calcsize(FileSectionFmt) + len(fname)
    payload += make_section(EFI_SECTION_USER_INTERFACE, align8(ui_size))
    payload += fname
    payload += make_padding(ui_size)
    ui_size = align8(ui_size)

    # build information for easier debugging
    ver_build = 0
    ver_str = "1.0\x00".encode("utf_16_le")
    ver_size = calcsize(FileSectionFmt) + len(ver_str) + calcsize("H")
    payload += make_section(EFI_SECTION_VERSION, ver_size)
    payload += pack("<H", ver_build) + ver_str
    payload += make_padding(ver_size)
    ver_size = align8(ver_size)

    # prepend file header
    file_size = calcsize(FileHeaderFmt) + depex_size + pe_size + ui_size + ver_size
    payload = bytearray(pack(FileHeaderFmt,
        str2guid("418b8d4eadc84298bb70ccf0a27405fe"),
        0x0,
        EFI_FV_FILETYPE_PEIM,
        0,
        # FFS_ATTRIB_CHECKSUM,
        (file_size >> 0 ) & 0xff,
        (file_size >> 8 ) & 0xff,
        (file_size >> 16) & 0xff,
        0x0
    ) + payload)

    # patch in integrity check for new file
    header_checksum = make_checksum(payload[:calcsize(FileHeaderFmt)])
    # ignore header checksum with magic value
    data_checksum = 0xaa
    checksum = pack("<BB", header_checksum, data_checksum)
    payload[16:18] = checksum

    # patch in file state (must be 0 while computing header checksum)
    # the leading reserved bits must be set to the FV erase polarity
    state = (EFI_FILE_HEADER_CONSTRUCTION
            | EFI_FILE_HEADER_VALID
            | EFI_FILE_DATA_VALID)

    # the bits are flipped depending on erase polarity
    if erase_polarity:
        state = ~state & 0xff

    payload[23] = pack("B", state & 0xff)[0]
    return payload

def main(fname: str, fv_path: str, ffs_file_path: str):
    with open(fv_path, "rb") as fv_handle:
        fv = bytearray(fv_handle.read())

    header = unpack_from(FVHeaderFmt, fv)
    header = FVHeader._make(header)
    offset = get_fvheader_sz(fv, offset=0)

    module_sz = os.stat(fname).st_size
    if module_sz > 0x1000000:
        sys.exit("unsupported for files larger than 16MB")

    if header.fs_guid != EFI_FIRMWARE_FILE_SYSTEM2_GUID:
        sys.exit("unsupported for non-FFSv2 file systems")

    offset += calcsize(FileHeaderFmt)
    compressed_section = unpack_from(FileSectionFmt, fv, offset=offset)
    compressed_section = FileSection._make((make_num(*compressed_section[:3]),
                                            compressed_section[3]))

    if compressed_section.type != EFI_SECTION_GUID_DEFINED:
        sys.exit(f"unexpected section type: {compressed_section.type} @ {offset:x}")

    offset += calcsize(FileSectionFmt)
    section_guid = unpack_from(FileSectionGuidFmt, fv, offset=offset)
    section_guid = FileSectionGuid._make(section_guid)

    if section_guid.guid != EFI_SECTION_GUID_LZMA:
        sys.exit(f"unexpected GUID: {guid2str(section_guid.guid)} @ {offset:x}")

    offset += calcsize(FileSectionGuidFmt)
    print(f"decompressing LZMA section (max {compressed_section.size} bytes)")
    try:
        decompressed = bytearray(lzma.decompress(fv[offset:]))
    except lzma.LZMAError as e:
        sys.exit(f"failed to decompress LZMA section @ {offset:x}: {e}")

    # Index into LZMA decompressed region (new offset).
    offset = calcsize(FileSectionFmt)
    inner_fv = unpack_from(FVHeaderFmt, decompressed, offset=offset)
    inner_fv = FVHeader._make(inner_fv)
    erase_polarity = b"\xff\x00"[inner_fv.attributes & EFI_FVB2_ERASE_POLARITY == 0]
    payload = make_file(fname, erase_polarity)

    print(f"writing FFS file to {ffs_file_path}")
    with open(ffs_file_path, "wb") as f:
        f.write(payload)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(f"usage: {sys.argv[0]} <module> <firmware> <ffs_file_out>")
    main(fname=sys.argv[1], fv_path=sys.argv[2], ffs_file_path=sys.argv[3])

