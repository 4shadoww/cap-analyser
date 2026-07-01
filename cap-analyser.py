#!/usr/bin/env python3
# Copyright (C) 2026 Noa-Emil Nissinen

# This is program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.    If not, see <https://www.gnu.org/licenses/>.

"""Analyse Java Card 3.1 CAP files and print method bytecode sizes."""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path

COMPONENT_METHOD = 7
COMPONENT_DESCRIPTOR = 11
COMPONENT_DEBUG = 12

ACC_ABSTRACT = 0x40
ACC_INIT = 0x80
ACC_EXTENDED = 0x08

HEADER_ACC_EXTENDED = 0x08


class Style:
    """ANSI styling when writing to a colour-capable terminal."""

    def __init__(self) -> None:
        enabled = hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.bold = "\033[1m" if enabled else ""
        self.dim = "\033[2m" if enabled else ""
        self.cyan = "\033[36m" if enabled else ""
        self.green = "\033[32m" if enabled else ""
        self.yellow = "\033[33m" if enabled else ""
        self.magenta = "\033[35m" if enabled else ""
        self.blue = "\033[34m" if enabled else ""
        self.reset = "\033[0m" if enabled else ""


def format_bytes(count: int) -> str:
    return f"{count:,} B"


def truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def visible_len(text: str) -> int:
    return len(_ANSI_RE.sub("", text))


def box_row(style: Style, content: str, inner_width: int) -> str:
    padding = inner_width - visible_len(content)
    return (
        f"{style.dim}│{style.reset}{content}{' ' * max(0, padding)}{style.dim}│{style.reset}"
    )


def box_top(style: Style, title: str, inner_width: int) -> str:
    if len(title) > inner_width:
        title = title[:inner_width]
    return (
        f"{style.yellow}{style.bold}┌{title}{'─' * (inner_width - len(title))}┐{style.reset}"
    )


def box_bottom(style: Style, inner_width: int) -> str:
    return f"{style.yellow}└{'─' * inner_width}┘{style.reset}"


def box_separator(style: Style, inner_width: int) -> str:
    return f"{style.dim}│{'─' * inner_width}│{style.reset}"


@dataclass(frozen=True)
class CapMethod:
    token: int
    access: int
    offset: int
    type_offset: int
    bytecode_size: int
    block_index: int = 0


@dataclass(frozen=True)
class DebugMethodInfo:
    name: str
    descriptor: str
    location: int
    block_index: int = 0


@dataclass(frozen=True)
class DebugClassInfo:
    name: str
    location: int
    methods: tuple[DebugMethodInfo, ...]


@dataclass(frozen=True)
class DebugInfo:
    classes: tuple[DebugClassInfo, ...]
    method_names: dict[int, tuple[str, str]]
    method_names_ext: dict[tuple[int, int], tuple[str, str]]
    methods_by_ref: dict[tuple[int, int], tuple[str, str]]
    extended_layout: bool = False
    package_extended: bool = False
    consumed: int = 0
    info_length: int = 0


@dataclass(frozen=True)
class JavaClassInfo:
    name: str
    super_name: str | None
    methods: tuple[tuple[str, str, int], ...]
    bytecode_sizes: tuple[int, ...] = ()
    source: str = ""
    access_flags: int = 0


@dataclass(frozen=True)
class ClassBinding:
    name: str
    methods: tuple[tuple[str, str, int], ...]
    best_effort: bool = False


@dataclass
class CapContext:
    extended: bool
    descriptor_classes: list[tuple[int, list[CapMethod]]]
    descriptor_blob: bytes
    types_offset: int
    java_entries: list[JavaClassInfo]
    java_classes: dict[str, JavaClassInfo]
    debug_blob: bytes | None
    debug_info: DebugInfo | None
    trusted_debug: DebugInfo | None
    class_bindings: list[ClassBinding]
    class_name_map: dict[int, str]
    debug_class_map: dict[int, DebugClassInfo]
    method_info: bytes
    block_starts: list[int]
    embedded_classes: tuple[str, ...]
    descriptor_methods: int
    implemented_methods: int
    name_source: str
    score_rows: list[list[int]] | None = None


@dataclass(frozen=True)
class MethodInfo:
    class_name: str
    name: str
    descriptor: str
    offset: int
    header_size: int
    bytecode_size: int

    @property
    def total_size(self) -> int:
        return self.header_size + self.bytecode_size


PRIMITIVE_TYPES = {
    0x1: "V",
    0x2: "Z",
    0x3: "B",
    0x4: "S",
    0x5: "I",
}

ARRAY_TYPES = {
    0xA: "[Z",
    0xB: "[B",
    0xC: "[S",
    0xD: "[I",
    0xE: "[",
}


def read_u2(data: bytes, pos: int) -> tuple[int, int]:
    return struct.unpack_from(">H", data, pos)[0], pos + 2


def read_u4(data: bytes, pos: int) -> tuple[int, int]:
    return struct.unpack_from(">I", data, pos)[0], pos + 4


def component_data(blob: bytes) -> bytes:
    return blob[3:]


def looks_like_debug_string(raw: bytes) -> bool:
    if not raw:
        return True
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if "\x00" in text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\t\n\r")
    return printable >= len(text) * 0.85


def looks_like_debug_string_table(data: bytes, pos: int) -> bool:
    """Heuristic: debug info starts with u2 string_count then utf8_info strings."""
    if pos + 4 > len(data):
        return False
    string_count, pos = read_u2(data, pos)
    if string_count < 1 or string_count > 65535:
        return False
    check_count = min(string_count, 20)
    for _ in range(check_count):
        if pos + 2 > len(data):
            return False
        length, pos = read_u2(data, pos)
        if length == 0 or length > 4096 or pos + length > len(data):
            return False
        if not looks_like_debug_string(data[pos : pos + length]):
            return False
        pos += length
    return True


def debug_info_size_from_directory(cap: zipfile.ZipFile, *, extended: bool) -> int | None:
    directory = find_component_any_suffix(cap, ("Directory.capx", "Directory.cap"))
    if directory is None or len(directory) < 27:
        return None
    if extended:
        if len(directory) >= 35:
            size = struct.unpack_from(">I", directory, 31)[0]
            if size not in {0, 0xFFFF}:
                return size
        if len(directory) >= 27:
            size = struct.unpack_from(">H", directory, 25)[0]
            if size not in {0, 0xFFFF}:
                return size
        return None
    size = struct.unpack_from(">H", directory, 25)[0]
    if size in {0, 0xFFFF}:
        return None
    return size


def component_header_info_starts(blob: bytes) -> dict[int, str]:
    """Map info-section start offsets to the header layout that implies them."""
    starts: dict[int, str] = {}
    if len(blob) < 3:
        return starts

    u2_size = struct.unpack_from(">H", blob, 1)[0]
    if u2_size + 3 == len(blob):
        starts[3] = "u2"

    if u2_size == 0xFFFF and len(blob) >= 7:
        u4_size = struct.unpack_from(">I", blob, 3)[0]
        if 0 < u4_size <= len(blob) - 7:
            starts[7] = "u2ffff-u4"

    if len(blob) >= 5:
        u4_size = struct.unpack_from(">I", blob, 1)[0]
        if 0 < u4_size <= len(blob) - 5:
            starts[5] = "u4"

    return starts


def component_info_slices(
    blob: bytes,
    *,
    info_size_hint: int | None = None,
) -> list[tuple[bytes, str, int]]:
    """Return plausible info sections from a CAP component (handles .cap and .capx headers)."""
    if len(blob) < 3:
        return []

    slices: list[tuple[bytes, str, int]] = []
    u2_size = struct.unpack_from(">H", blob, 1)[0]
    header_starts = component_header_info_starts(blob)

    if u2_size + 3 == len(blob):
        slices.append((blob[3:], "u2", 3))

    if u2_size == 0xFFFF and len(blob) >= 7:
        u4_size = struct.unpack_from(">I", blob, 3)[0]
        if u4_size + 7 == len(blob):
            slices.append((blob[7:], "u2ffff-u4", 7))
        if 0 < u4_size <= len(blob) - 7:
            slices.append((blob[7 : 7 + u4_size], "u2ffff-u4-exact", 7))
        if u4_size + 7 != len(blob) and looks_like_debug_string_table(blob, 3):
            slices.append((blob[3:], "u2ffff@3", 3))

    if len(blob) >= 5:
        u4_size = struct.unpack_from(">I", blob, 1)[0]
        if u4_size + 5 == len(blob):
            slices.append((blob[5:], "u4", 5))
        if 0 < u4_size <= len(blob) - 5:
            slices.append((blob[5 : 5 + u4_size], "u4-exact", 5))

    # Large .capx: u4 size may not exactly match file length (padding/trailing bytes).
    if len(blob) > 65535 and len(blob) >= 5:
        u4_size = struct.unpack_from(">I", blob, 1)[0]
        if 1000 <= u4_size < len(blob):
            slices.append((blob[5 : 5 + u4_size], "u4-large", 5))

    if info_size_hint is not None and info_size_hint > 0:
        hint_starts = header_starts or {3: "dir@3", 5: "dir@5", 7: "dir@7"}
        for start, label in hint_starts.items():
            end = start + info_size_hint
            if end <= len(blob):
                slices.append((blob[start:end], f"hint-{label}", start))

    # Some tools store tag + info with no size field in the on-disk .capx file.
    if looks_like_debug_string_table(blob, 1):
        slices.append((blob[1:], "tag+info", 1))

    slices.extend(
        (blob[start:], f"str@{start}", start)
        for start in range(1, min(32, len(blob)))
        if looks_like_debug_string_table(blob, start)
    )

    seen_lengths: set[int] = set()
    unique: list[tuple[bytes, str, int]] = []
    for info, label, start in slices:
        if len(info) in seen_lengths:
            continue
        seen_lengths.add(len(info))
        unique.append((info, label, start))
    return unique


def load_cap_component(cap: zipfile.ZipFile, base_name: str) -> bytes:
    """Load a CAP component by stem, accepting .cap or .capx."""
    component = find_component_any_suffix(cap, (f"{base_name}.capx", f"{base_name}.cap"))
    if component is None:
        msg = f"component {base_name}.cap[x] not found in CAP file"
        raise ValueError(msg)
    return component


def extended_method_block_starts(blob: bytes) -> list[int]:
    """Return flattened start offset of each method block in an extended Method component."""
    if len(blob) < 6:
        return [0]
    pos = 5
    block_count = blob[pos]
    pos += 1
    if block_count == 0:
        return [0]
    _, pos = read_u4(blob, pos)
    starts: list[int] = []
    cumulative = 0
    for _ in range(block_count):
        starts.append(cumulative)
        if pos + 2 > len(blob):
            break
        block_size = struct.unpack_from(">H", blob, pos)[0]
        pos += 2
        cumulative += block_size
        pos += block_size
    return starts


def method_component_data(blob: bytes, *, extended: bool) -> bytes:
    """Return the method info bytes used for header-size lookup."""
    if not extended:
        slices = component_info_slices(blob)
        return slices[0][0] if slices else component_data(blob)

    if len(blob) < 6:
        return blob[3:]
    pos = 5
    block_count = blob[pos]
    pos += 1
    if block_count == 0:
        return b""
    _, pos = read_u4(blob, pos)  # skip offset table
    blocks: list[bytes] = []
    for _ in range(block_count):
        if pos + 2 > len(blob):
            break
        block_size = struct.unpack_from(">H", blob, pos)[0]
        pos += 2
        blocks.append(blob[pos : pos + block_size])
        pos += block_size
    return b"".join(blocks)


def cap_method_absolute_offset(
    cap_method: CapMethod,
    *,
    extended: bool,
    block_starts: list[int],
) -> int:
    if not extended:
        return cap_method.offset
    if cap_method.block_index < len(block_starts):
        return block_starts[cap_method.block_index] + cap_method.offset
    return cap_method.offset


def find_component_optional(cap: zipfile.ZipFile, suffix: str) -> bytes | None:
    matches = [name for name in cap.namelist() if name.endswith(suffix)]
    if not matches:
        return None
    if len(matches) > 1:
        msg = f"multiple {suffix!r} components found in CAP file"
        raise ValueError(msg)
    return cap.read(matches[0])


def find_component_any_suffix(cap: zipfile.ZipFile, suffixes: tuple[str, ...]) -> bytes | None:
    for suffix in suffixes:
        matches = [name for name in cap.namelist() if name.lower().endswith(suffix.lower())]
        if len(matches) > 1:
            msg = f"multiple {suffix!r} components found in CAP file"
            raise ValueError(msg)
        if matches:
            return cap.read(matches[0])
    return None


def cap_uses_extended_format(cap: zipfile.ZipFile) -> bool:
    header = find_component_any_suffix(cap, ("Header.capx", "Header.cap"))
    if header is None:
        return False
    for info, _label, _start in component_info_slices(header):
        if len(info) >= 7 and struct.unpack_from(">I", info, 0)[0] == 0xDECAFFED:
            return bool(info[6] & HEADER_ACC_EXTENDED)
    return False


def descriptor_shape(descriptor: str) -> str:
    """Normalise a JVM descriptor for matching, erasing reference type names."""
    result: list[str] = []
    index = 0
    while index < len(descriptor):
        char = descriptor[index]
        if char == "L":
            result.append("L*;")
            index = descriptor.index(";", index) + 1
        elif char == "[":
            result.append("[")
            index += 1
            if index < len(descriptor) and descriptor[index] == "L":
                result.append("L*;")
                index = descriptor.index(";", index) + 1
            elif index < len(descriptor):
                result.append(descriptor[index])
                index += 1
        else:
            result.append(char)
            index += 1
    return "".join(result)


def read_descriptor_type(descriptor: str, index: int) -> tuple[str, int]:
    char = descriptor[index]
    if char == "L":
        end = descriptor.index(";", index)
        return descriptor[index : end + 1], end + 1
    if char == "[":
        element, next_index = read_descriptor_type(descriptor, index + 1)
        return f"[{element}", next_index
    return char, index + 1


def split_descriptor_params(descriptor: str) -> tuple[list[str], str]:
    if not descriptor.startswith("("):
        return [], descriptor
    index = 1
    params: list[str] = []
    while index < len(descriptor) and descriptor[index] != ")":
        param, index = read_descriptor_type(descriptor, index)
        params.append(param)
    return params, descriptor[index + 1 :]


def is_opaque_cap_reference(param: str) -> bool:
    return "imported#" in param or param.startswith("Lclass@")


def signatures_compatible_with_imported(cap_sig: str, java_sig: str) -> bool:
    """Allow CAP-only opaque/imported parameters absent from the .class file."""
    if "imported#" not in cap_sig and "class@" not in cap_sig:
        return False
    cap_params, cap_ret = split_descriptor_params(cap_sig)
    java_params, java_ret = split_descriptor_params(java_sig)
    if descriptor_shape(cap_ret) != descriptor_shape(java_ret):
        return False

    cap_index = 0
    java_index = 0
    while cap_index < len(cap_params):
        cap_param = cap_params[cap_index]
        if is_opaque_cap_reference(cap_param):
            if java_index < len(java_params):
                java_param = java_params[java_index]
                if java_param.startswith(("L", "[")):
                    cap_index += 1
                    java_index += 1
                    continue
            cap_index += 1
            continue
        if java_index >= len(java_params):
            return False
        if descriptor_shape(cap_param) != descriptor_shape(java_params[java_index]):
            return False
        cap_index += 1
        java_index += 1

    return java_index == len(java_params)


def signatures_match(cap_sig: str, java_sig: str) -> bool:
    if cap_sig == "?" or java_sig == "?":
        return cap_sig == java_sig
    if descriptor_shape(cap_sig) == descriptor_shape(java_sig):
        return True
    if signatures_compatible_with_imported(cap_sig, java_sig):
        return True
    if is_voidish_init_signature(cap_sig) and is_voidish_init_signature(java_sig):
        return True
    return cap_sig == "()V" and is_voidish_init_signature(java_sig)


def method_header_size(methods_data: bytes, offset: int) -> int:
    flags = methods_data[offset] >> 4
    if flags & ACC_EXTENDED:
        return 4
    return 2


def parse_one_class_descriptor(
    descriptor: bytes,
    pos: int,
    *,
    method_extended: bool,
) -> tuple[int, list[CapMethod], int]:
    pos += 2  # token, access_flags
    class_ref = struct.unpack_from(">H", descriptor, pos)[0]
    pos += 2
    interface_count = descriptor[pos]
    pos += 1
    field_count = struct.unpack_from(">H", descriptor, pos)[0]
    pos += 2
    method_count = struct.unpack_from(">H", descriptor, pos)[0]
    pos += 2
    pos += interface_count * 2
    pos += field_count * 7

    methods: list[CapMethod] = []
    for _ in range(method_count):
        token = descriptor[pos]
        access = descriptor[pos + 1]
        if method_extended:
            block_index = descriptor[pos + 2]
            offset, type_offset, bytecode_size = struct.unpack_from(">HHH", descriptor, pos + 3)
            pos += 13
        else:
            block_index = 0
            offset, type_offset, bytecode_size = struct.unpack_from(">HHH", descriptor, pos + 2)
            pos += 12
        methods.append(
            CapMethod(
                token=token,
                access=access,
                offset=offset,
                type_offset=type_offset,
                bytecode_size=bytecode_size,
                block_index=block_index,
            ),
        )

    return class_ref, methods, pos


def parse_descriptor(
    descriptor: bytes,
    *,
    extended: bool = False,
) -> tuple[list[tuple[int, list[CapMethod]]], bytes, int]:
    """Return descriptor classes, the full component blob, and type_descriptor_info offset."""
    if descriptor[0] != COMPONENT_DESCRIPTOR:
        msg = f"expected descriptor component tag {COMPONENT_DESCRIPTOR}, got {descriptor[0]}"
        raise ValueError(msg)

    classes: list[tuple[int, list[CapMethod]]] = []

    if extended:
        info_slices = component_info_slices(descriptor)
        if not info_slices:
            msg = "could not locate descriptor info in extended descriptor component"
            raise ValueError(msg)
        info, _label, info_start = info_slices[0]
        pos = 0
        package_count = info[pos]
        pos += 1
        for _ in range(package_count):
            class_count = info[pos]
            pos += 1
            for _ in range(class_count):
                class_ref, methods, pos = parse_one_class_descriptor(
                    info, pos, method_extended=True,
                )
                classes.append((class_ref, methods))
        return classes, descriptor, info_start + pos

    class_count = descriptor[3]
    pos = 4
    for _ in range(class_count):
        class_ref, methods, pos = parse_one_class_descriptor(descriptor, pos, method_extended=False)
        classes.append((class_ref, methods))

    return classes, descriptor, pos


def read_type_nibbles(descriptor: bytes, types_offset: int, type_offset: int) -> list[int]:
    absolute = types_offset + type_offset
    nibble_count = descriptor[absolute]
    byte_count = (nibble_count + 1) // 2
    raw = descriptor[absolute + 1 : absolute + 1 + byte_count]
    nibbles: list[int] = []
    for value in raw:
        nibbles.append(value >> 4)
        if len(nibbles) < nibble_count:
            nibbles.append(value & 0x0F)
    return nibbles[:nibble_count]


def class_ref_from_nibbles(nibbles: list[int], pos: int, class_names: dict[int, str]) -> tuple[str, int]:
    package_high, package_low, class_high, class_low = nibbles[pos : pos + 4]
    pos += 4
    class_ref = ((package_high & 0x07) << 12) | (package_low << 8) | (class_high << 4) | class_low
    if package_high & 0x08:
        name = f"imported#{class_ref:#x}"
    else:
        name = class_names.get(class_ref, f"class@{class_ref:#x}")
    return name, pos


def parse_type(nibbles: list[int], pos: int, class_names: dict[int, str]) -> tuple[str, int]:
    if pos >= len(nibbles):
        msg = "unexpected end of type descriptor"
        raise ValueError(msg)

    nibble = nibbles[pos]
    pos += 1

    if nibble in PRIMITIVE_TYPES:
        return PRIMITIVE_TYPES[nibble], pos

    if nibble in {0xA, 0xB, 0xC, 0xD}:
        return ARRAY_TYPES[nibble], pos

    if nibble == 0xE:
        name, pos = class_ref_from_nibbles(nibbles, pos, class_names)
        return f"[L{name};", pos

    if nibble == 0x6:
        name, pos = class_ref_from_nibbles(nibbles, pos, class_names)
        return f"L{name};", pos

    msg = f"unsupported type nibble {nibble:#x}"
    raise ValueError(msg)


def decode_method_signature(
    descriptor: bytes,
    types_offset: int,
    type_offset: int,
    class_names: dict[int, str],
) -> str:
    nibbles = read_type_nibbles(descriptor, types_offset, type_offset)
    if not nibbles:
        return "()V"

    types: list[str] = []
    pos = 0
    while pos < len(nibbles):
        parsed, pos = parse_type(nibbles, pos, class_names)
        types.append(parsed)

    if len(types) == 1:
        return f"(){types[0]}"

    *params, return_type = types
    return f"({''.join(params)}){return_type}"


def parse_cp(data: bytes) -> tuple[list[tuple[str, object] | None], int]:
    pos = 8
    cp_count, pos = read_u2(data, pos)
    cp: list[tuple[str, object] | None] = [None] * cp_count
    index = 1
    while index < cp_count:
        tag = data[pos]
        pos += 1
        if tag == 1:
            length, pos = read_u2(data, pos)
            cp[index] = ("utf8", data[pos : pos + length].decode())
            pos += length
        elif tag == 7:
            name_index, pos = read_u2(data, pos)
            cp[index] = ("class", name_index)
        elif tag in {3, 4}:
            pos += 4
        elif tag in {5, 6}:
            pos += 8
            index += 1
        elif tag in {8, 16, 19, 20}:
            pos += 2
        elif tag in {9, 10, 11, 12, 17, 18}:
            pos += 4
        elif tag == 15:
            pos += 3
        else:
            msg = f"unsupported constant pool tag {tag}"
            raise ValueError(msg)
        index += 1
    return cp, pos


def class_name_from_cp(cp: list[tuple[str, object] | None], index: int) -> str:
    entry = cp[index]
    if entry is None:
        msg = f"missing constant pool entry {index}"
        raise ValueError(msg)
    kind, value = entry
    if kind == "class":
        utf8_entry = cp[value]
        if utf8_entry is None or utf8_entry[0] != "utf8":
            msg = f"invalid class constant pool entry {index}"
            raise ValueError(msg)
        return utf8_entry[1].replace("/", ".")
    if kind == "utf8":
        return value.replace("/", ".")
    msg = f"constant pool entry {index} is not a class name"
    raise ValueError(msg)


def parse_class_file(data: bytes) -> JavaClassInfo:
    cp, pos = parse_cp(data)
    access_flags = struct.unpack_from(">H", data, pos)[0]
    this_class = struct.unpack_from(">H", data, pos + 2)[0]
    super_class = struct.unpack_from(">H", data, pos + 4)[0]
    pos += 6
    interface_count, pos = read_u2(data, pos)
    pos += interface_count * 2

    field_count, pos = read_u2(data, pos)
    for _ in range(field_count):
        pos += 6
        attribute_count, pos = read_u2(data, pos)
        for _ in range(attribute_count):
            pos += 2
            attribute_length, pos = read_u4(data, pos)
            pos += attribute_length

    method_count, pos = read_u2(data, pos)
    methods: list[tuple[str, str, int]] = []
    bytecode_sizes: list[int] = []
    for _ in range(method_count):
        access, pos = read_u2(data, pos)
        name_index, pos = read_u2(data, pos)
        descriptor_index, pos = read_u2(data, pos)
        attribute_count, pos = read_u2(data, pos)
        code_size = 0
        for _attr in range(attribute_count):
            attr_name_index, pos = read_u2(data, pos)
            attribute_length, pos = read_u4(data, pos)
            attr_entry = cp[attr_name_index]
            if attr_entry is not None and attr_entry[0] == "utf8" and attr_entry[1] == "Code" and attribute_length >= 4:
                code_size = struct.unpack_from(">I", data, pos + 4)[0]
            pos += attribute_length
        name_entry = cp[name_index]
        descriptor_entry = cp[descriptor_index]
        if name_entry is None or descriptor_entry is None:
            msg = "invalid method constant pool references"
            raise ValueError(msg)
        methods.append((name_entry[1], descriptor_entry[1], access))
        bytecode_sizes.append(code_size)

    super_name: str | None = None
    if super_class != 0:
        super_name = class_name_from_cp(cp, super_class)

    return JavaClassInfo(
        name=class_name_from_cp(cp, this_class),
        super_name=super_name,
        methods=tuple(methods),
        bytecode_sizes=tuple(bytecode_sizes),
        access_flags=access_flags,
    )


def load_java_class_entries(cap: zipfile.ZipFile) -> list[JavaClassInfo]:
    """Load every embedded .class file; keep duplicates (dict would drop them)."""
    entries: list[JavaClassInfo] = []
    for name in sorted(cap.namelist()):
        if name.endswith(".class"):
            source = name.replace("\\", "/")
            entries.append(replace(parse_class_file(cap.read(name)), source=source))
    return entries


def load_java_classes(cap: zipfile.ZipFile) -> dict[str, JavaClassInfo]:
    classes: dict[str, JavaClassInfo] = {}
    for info in load_java_class_entries(cap):
        classes[info.name] = info
    return classes


def cap_method_signatures(
    cap_methods: list[CapMethod],
    descriptor_blob: bytes,
    types_offset: int,
    class_names: dict[int, str] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return ordered and sorted normalised signature shapes for CAP methods."""
    names = class_names or {}
    ordered: list[str] = []
    for method in cap_methods:
        try:
            signature = decode_method_signature(
                descriptor_blob,
                types_offset,
                method.type_offset,
                names,
            )
        except ValueError:
            signature = "?"
        ordered.append(descriptor_shape(signature))
    return tuple(ordered), tuple(sorted(ordered))


def cap_class_fingerprint(
    cap_methods: list[CapMethod],
    descriptor_blob: bytes,
    types_offset: int,
) -> tuple[int, tuple[str, ...], tuple[str, ...], tuple[int, ...], tuple[int, ...]]:
    ordered_shapes, sorted_shapes = cap_method_signatures(cap_methods, descriptor_blob, types_offset)
    abstract = tuple(1 if method.bytecode_size == 0 else 0 for method in cap_methods)
    bytecode = tuple(method.bytecode_size for method in cap_methods)
    return len(cap_methods), sorted_shapes, ordered_shapes, abstract, bytecode


def implemented_bytecode_sizes(cap_methods: list[CapMethod]) -> tuple[int, ...]:
    return tuple(
        method.bytecode_size
        for method in cap_methods
        if not (method.offset == 0 and method.bytecode_size == 0)
    )


def java_implemented_bytecode_sizes(java_info: JavaClassInfo) -> tuple[int, ...]:
    sizes: list[int] = []
    for index, (_name, _descriptor, access) in enumerate(java_info.methods):
        if access & 0x0400:
            continue
        if index < len(java_info.bytecode_sizes):
            sizes.append(java_info.bytecode_sizes[index])
    return tuple(sizes)


def score_bytecode_match(cap_sizes: tuple[int, ...], java_sizes: tuple[int, ...]) -> int:
    if not cap_sizes and not java_sizes:
        return 40
    if len(cap_sizes) != len(java_sizes):
        return -1
    if cap_sizes == java_sizes:
        return 400
    score = 0
    for cap_size, java_size in zip(cap_sizes, java_sizes, strict=True):
        if cap_size == java_size:
            score += 40
        elif abs(cap_size - java_size) <= 4:
            score += 10
    return score


def java_class_fingerprint(
    java_info: JavaClassInfo,
) -> tuple[int, tuple[str, ...], tuple[str, ...], tuple[int, ...], tuple[int, ...]]:
    ordered = tuple(descriptor_shape(descriptor) for _, descriptor, _ in java_info.methods)
    abstract = tuple(1 if (access & 0x0400) else 0 for _, _, access in java_info.methods)
    bytecode = java_implemented_bytecode_sizes(java_info)
    return len(java_info.methods), tuple(sorted(ordered)), ordered, abstract, bytecode


def java_method_shapes(java_info: JavaClassInfo) -> tuple[str, ...]:
    return tuple(descriptor_shape(descriptor) for _, descriptor, _ in java_info.methods)


def java_vtable_method_shapes(java_info: JavaClassInfo) -> tuple[str, ...]:
    """Declared method shapes from .class, excluding constructors."""
    return tuple(
        descriptor_shape(descriptor)
        for name, descriptor, _access in java_info.methods
        if name not in ("<init>", "<clinit>")
    )


def cap_is_abstract_vtable(cap_methods: list[CapMethod]) -> bool:
    return bool(cap_methods) and not implemented_bytecode_sizes(cap_methods)


def multiset_subset(sub: tuple[str, ...], container: tuple[str, ...]) -> bool:
    subset = Counter(sub)
    superset = Counter(container)
    return all(superset[shape] >= count for shape, count in subset.items())


def java_impl_shape_size_pairs(java_info: JavaClassInfo) -> list[tuple[str, int]]:
    pairs: list[tuple[str, int]] = []
    for index, (_name, descriptor, access) in enumerate(java_info.methods):
        if access & 0x0400:
            continue
        bytecode_size = java_info.bytecode_sizes[index] if index < len(java_info.bytecode_sizes) else 0
        pairs.append((descriptor_shape(descriptor), bytecode_size))
    return pairs


def pair_java_impl_to_cap(
    java_impl: list[tuple[str, int]],
    cap_methods: list[CapMethod],
    cap_shapes: tuple[str, ...],
) -> bool:
    available = [
        (index, cap_shapes[index], method.bytecode_size)
        for index, method in enumerate(cap_methods)
        if not (method.offset == 0 and method.bytecode_size == 0)
    ]
    for shape, bytecode_size in java_impl:
        matched = False
        for slot, (_index, cap_shape, cap_size) in enumerate(available):
            if cap_shape != shape:
                continue
            if cap_size == bytecode_size or abs(cap_size - bytecode_size) <= 4:
                available.pop(slot)
                matched = True
                break
        if not matched:
            return False
    return True


def cap_method_signature_slots(
    cap_methods: list[CapMethod],
    descriptor_blob: bytes,
    types_offset: int,
) -> list[tuple[str, int, str]]:
    slots: list[tuple[str, int, str]] = []
    for _index, method in enumerate(cap_methods):
        if method.offset == 0 and method.bytecode_size == 0:
            continue
        try:
            signature = decode_method_signature(
                descriptor_blob,
                types_offset,
                method.type_offset,
                {},
            )
        except ValueError:
            signature = "?"
        slots.append((
            descriptor_shape(signature),
            method.bytecode_size,
            signature,
        ))
    return slots


def is_skippable_java_pairing_method(name: str, _descriptor: str, access: int) -> bool:
    if name == "<clinit>":
        return True
    if access & 0x1000:
        return True
    if access & 0x0040:
        return True
    return bool(access & 0x0400) and name != "<init>"


def java_method_pairing_slots(java_info: JavaClassInfo) -> list[tuple[str, int, str]]:
    """Java method slots for CAP matching, omitting .class-only helpers like <clinit>."""
    slots: list[tuple[str, int, str]] = []
    for index, (name, descriptor, access) in enumerate(java_info.methods):
        if is_skippable_java_pairing_method(name, descriptor, access):
            continue
        bytecode_size = java_info.bytecode_sizes[index] if index < len(java_info.bytecode_sizes) else 0
        if access & 0x0400:
            slots.append((descriptor_shape(descriptor), 0, descriptor))
        else:
            slots.append((descriptor_shape(descriptor), bytecode_size, descriptor))
    return slots


def slot_signatures_compatible(
    cap_shape: str,
    java_shape: str,
    cap_sig: str,
    java_sig: str,
) -> bool:
    if cap_shape == java_shape:
        return True
    return signatures_match(cap_sig, java_sig)


def bytecode_sizes_compatible(cap_size: int, java_size: int) -> bool:
    if cap_size == 0 and java_size == 0:
        return True
    if cap_size == java_size:
        return True
    diff = abs(cap_size - java_size)
    if diff <= 4:
        return True
    if cap_size > 0 and java_size > 0:
        return diff <= max(12, cap_size // 8, java_size // 8)
    return False


def is_voidish_init_signature(signature: str) -> bool:
    if signature == "()V":
        return True
    params, return_type = split_descriptor_params(signature)
    return (
        return_type == "V"
        and len(params) == 1
        and params[0].startswith(("L", "["))
    )


def split_voidish_init_slots(
    slots: list[tuple[str, int, str]],
) -> tuple[list[tuple[str, int, str]], list[tuple[str, int, str]]]:
    rest: list[tuple[str, int, str]] = []
    voidish: list[tuple[str, int, str]] = []
    for slot in slots:
        if is_voidish_init_signature(slot[2]):
            voidish.append(slot)
        else:
            rest.append(slot)
    return rest, voidish


def multiset_match_bytecode(cap_sizes: list[int], java_sizes: list[int]) -> bool:
    if len(cap_sizes) > len(java_sizes):
        return False
    available = list(java_sizes)
    for cap_size in sorted(cap_sizes, reverse=True):
        best_index: int | None = None
        best_diff = 10**9
        for index, java_size in enumerate(available):
            if not bytecode_sizes_compatible(cap_size, java_size):
                continue
            diff = abs(cap_size - java_size)
            if diff < best_diff:
                best_diff = diff
                best_index = index
        if best_index is None:
            return False
        available.pop(best_index)
    return True


def _cap_java_slots_compatible(
    cap_slot: tuple[str, int, str],
    java_slot: tuple[str, int, str],
    *,
    require_bytecode: bool,
    signature_only: bool,
) -> bool:
    cap_shape, bytecode_size, cap_sig = cap_slot
    java_shape, java_size, java_sig = java_slot
    if cap_sig == "?":
        return True
    if not slot_signatures_compatible(cap_shape, java_shape, cap_sig, java_sig):
        return False
    if signature_only or not require_bytecode:
        return True
    if bytecode_size > 0 and java_size == 0:
        return False
    return bytecode_sizes_compatible(bytecode_size, java_size)


def _bipartite_match_cap_to_java(
    cap_slots: list[tuple[str, int, str]],
    java_slots: list[tuple[str, int, str]],
    *,
    require_bytecode: bool = True,
    signature_only: bool = False,
) -> bool:
    """Polynomial cap-to-java assignment; java may have unmatched surplus slots."""
    java_count = len(java_slots)
    cap_count = len(cap_slots)
    if cap_count > java_count:
        return False

    compatible = [
        [
            java_index
            for java_index in range(java_count)
            if _cap_java_slots_compatible(
                cap_slots[cap_index],
                java_slots[java_index],
                require_bytecode=require_bytecode,
                signature_only=signature_only,
            )
        ]
        for cap_index in range(cap_count)
    ]
    cap_order = sorted(range(cap_count), key=lambda cap_index: len(compatible[cap_index]))
    match_java = [-1] * java_count

    def try_assign(cap_index: int, seen: list[bool]) -> bool:
        for java_index in compatible[cap_index]:
            if seen[java_index]:
                continue
            seen[java_index] = True
            matched_cap = match_java[java_index]
            if matched_cap < 0 or try_assign(matched_cap, seen):
                match_java[java_index] = cap_index
                return True
        return False

    return all(try_assign(cap_index, [False] * java_count) for cap_index in cap_order)


def pair_cap_slots_with_void_init_multiset(
    cap_slots: list[tuple[str, int, str]],
    java_slots: list[tuple[str, int, str]],
    *,
    require_bytecode: bool = True,
    signature_only: bool = False,
) -> bool:
    cap_rest, cap_void = split_voidish_init_slots(cap_slots)
    java_rest, java_voidish = split_voidish_init_slots(java_slots)

    if signature_only:
        if not pair_cap_slots_by_signature(cap_rest, java_rest):
            return False
    elif not pair_cap_slots_to_java(cap_rest, java_rest, require_bytecode=require_bytecode):
        return False

    if not cap_void:
        return True
    cap_sizes = [bytecode_size for _shape, bytecode_size, _sig in cap_void]
    java_sizes = [bytecode_size for _shape, bytecode_size, _sig in java_voidish]
    return multiset_match_bytecode(cap_sizes, java_sizes)


def pair_cap_slots_by_signature(
    cap_slots: list[tuple[str, int, str]],
    java_slots: list[tuple[str, int, str]],
) -> bool:
    return _bipartite_match_cap_to_java(
        cap_slots, java_slots, require_bytecode=False, signature_only=True,
    )


def impl_sizes_loosely_compatible(
    cap_slots: list[tuple[str, int, str]],
    java_slots: list[tuple[str, int, str]],
) -> bool:
    cap_sizes = sorted(size for _shape, size, _sig in cap_slots if size > 0)
    if not cap_sizes:
        return True
    java_available = sorted(size for _shape, size, _sig in java_slots if size > 0)
    for cap_size in reversed(cap_sizes):
        best_index: int | None = None
        best_diff = 10**9
        for index, java_size in enumerate(java_available):
            if not bytecode_sizes_compatible(cap_size, java_size):
                continue
            diff = abs(cap_size - java_size)
            if diff < best_diff:
                best_diff = diff
                best_index = index
        if best_index is None:
            return False
        java_available.pop(best_index)
    return True


def pair_cap_slots_to_java(
    cap_slots: list[tuple[str, int, str]],
    java_slots: list[tuple[str, int, str]],
    *,
    require_bytecode: bool = True,
) -> bool:
    return _bipartite_match_cap_to_java(
        cap_slots, java_slots, require_bytecode=require_bytecode, signature_only=False,
    )


def cap_method_signatures_raw(
    cap_methods: list[CapMethod],
    descriptor_blob: bytes,
    types_offset: int,
) -> list[str]:
    signatures: list[str] = []
    for method in cap_methods:
        if method.offset == 0 and method.bytecode_size == 0:
            continue
        try:
            signatures.append(decode_method_signature(
                descriptor_blob, types_offset, method.type_offset, {},
            ))
        except ValueError:
            signatures.append("?")
    return signatures


def each_java_vtable_method_in_cap(
    java_info: JavaClassInfo,
    cap_methods: list[CapMethod],
    descriptor_blob: bytes,
    types_offset: int,
) -> bool:
    cap_signatures = cap_method_signatures_raw(cap_methods, descriptor_blob, types_offset)
    for name, descriptor, _access in java_info.methods:
        if name in ("<init>", "<clinit>"):
            continue
        if not any(signatures_match(cap_sig, descriptor) for cap_sig in cap_signatures):
            return False
    return True


def score_class_pair_interface_only(
    cap_methods: list[CapMethod],
    java_info: JavaClassInfo,
    descriptor_blob: bytes,
    types_offset: int,
) -> int:
    """Match interface/shareable types: no implemented methods on either side."""
    if len(cap_methods) != len(java_info.methods):
        return -1
    if implemented_bytecode_sizes(cap_methods) or java_implemented_bytecode_sizes(java_info):
        return -1

    _count, sorted_shapes, ordered_shapes, _abstract, _bytecode = cap_class_fingerprint(
        cap_methods, descriptor_blob, types_offset,
    )
    java_ordered = tuple(descriptor_shape(descriptor) for _, descriptor, _ in java_info.methods)
    if sorted_shapes != tuple(sorted(java_ordered)):
        return -1

    return 80 + score_ordered_match(ordered_shapes, java_ordered)


def score_class_pair_abstract_vtable(
    cap_methods: list[CapMethod],
    java_info: JavaClassInfo,
    descriptor_blob: bytes,
    types_offset: int,
) -> int:
    """Match abstract CAP vtables to .class files with fewer declared methods."""
    if not cap_is_abstract_vtable(cap_methods):
        return -1

    cap_count = len(cap_methods)
    java_shapes = java_vtable_method_shapes(java_info)
    java_count = len(java_shapes)
    if java_count == 0 or java_count >= cap_count:
        return -1
    if java_count == 1 and cap_count > 3:
        return -1

    cap_ordered, _cap_sorted = cap_method_signatures(cap_methods, descriptor_blob, types_offset)
    if not multiset_subset(java_shapes, cap_ordered) and not each_java_vtable_method_in_cap(
        java_info, cap_methods, descriptor_blob, types_offset,
    ):
        return -1

    if cap_count > 12 and java_count < cap_count // 6:
        return -1

    score = 220 + 45 * java_count + 3 * (cap_count - java_count)
    if java_info.access_flags & 0x0400:
        score += 40
    declared_abstract = sum(
        1
        for name, _descriptor, access in java_info.methods
        if name not in ("<init>", "<clinit>") and (access & 0x0400)
    )
    if declared_abstract == java_count:
        score += 30
    return score


def cap_java_pairing_detail(
    cap_slots: list[tuple[str, int, str]],
    java_slots: list[tuple[str, int, str]],
) -> str:
    cap_rest, cap_void = split_voidish_init_slots(cap_slots)
    java_rest, java_voidish = split_voidish_init_slots(java_slots)

    if pair_cap_slots_with_void_init_multiset(cap_slots, java_slots, require_bytecode=True):
        return "strict match"
    if pair_cap_slots_with_void_init_multiset(cap_slots, java_slots, require_bytecode=False):
        return "relaxed bytecode"
    if pair_cap_slots_with_void_init_multiset(cap_slots, java_slots, signature_only=True):
        return "signatures only (bytecode diverges)"
    if not pair_cap_slots_by_signature(cap_rest, java_rest):
        return "non-init signature pairing failed"
    if cap_void and not multiset_match_bytecode(
        [size for _shape, size, _sig in cap_void],
        [size for _shape, size, _sig in java_voidish],
    ):
        return (
            f"voidish init bytecode mismatch "
            f"({len(cap_void)} cap vs {len(java_voidish)} java)"
        )
    return "signature pairing failed"


def pairing_detail_rank(detail: str) -> int:
    if detail == "strict match":
        return 0
    if detail.startswith("relaxed"):
        return 1
    if detail.startswith("signatures only"):
        return 2
    if detail.startswith("voidish"):
        return 3
    if detail.startswith("non-init"):
        return 4
    return 5


def pick_best_java_index(  # noqa: PLR0913
    cap_methods: list[CapMethod],
    java_entries: list[JavaClassInfo],
    score_row: list[int],
    descriptor_blob: bytes,
    types_offset: int,
    *,
    used_java: set[int] | None = None,
    allow_used: bool = False,
) -> int | None:
    """Pick the most likely embedded .class for a descriptor class."""
    if not java_entries:
        return None

    cap_count = len(cap_methods)
    cap_impl = len(implemented_bytecode_sizes(cap_methods))

    if not cap_impl:
        ordered = sorted(
            range(len(java_entries)),
            key=lambda index: (
                0 if not java_entries[index].methods else 1,
                -score_row[index],
                java_entries[index].source,
            ),
        )
        for index in ordered:
            if used_java and index in used_java and not allow_used:
                continue
            return index
        return ordered[0] if allow_used and ordered else None

    cap_slots = cap_method_signature_slots(cap_methods, descriptor_blob, types_offset)
    candidates: list[tuple[int, int, int, int]] = []
    for index, java_info in enumerate(java_entries):
        java_count = len(java_info.methods)
        if java_count < cap_count - 1:
            continue
        distance = abs(java_count - cap_count)
        if distance > 3:
            continue
        detail = cap_java_pairing_detail(
            cap_slots, java_method_pairing_slots(java_info),
        )
        candidates.append((
            pairing_detail_rank(detail),
            distance,
            -score_row[index],
            index,
        ))

    if not candidates:
        candidates = [
            (
                99,
                abs(len(java_info.methods) - cap_count),
                -score_row[index],
                index,
            )
            for index, java_info in enumerate(java_entries)
        ]

    for _rank, _distance, _neg_score, index in sorted(candidates):
        if used_java and index in used_java and not allow_used:
            continue
        return index
    if allow_used and candidates:
        return sorted(candidates)[0][3]
    return None


def score_class_pair_cap_in_java(
    cap_methods: list[CapMethod],
    java_info: JavaClassInfo,
    descriptor_blob: bytes,
    types_offset: int,
) -> int:
    """Match when CAP lists fewer or equal methods than the .class file declares."""
    java_count = len(java_info.methods)
    cap_slots = cap_method_signature_slots(cap_methods, descriptor_blob, types_offset)
    java_slots = java_method_pairing_slots(java_info)
    cap_count = len(cap_slots)
    if cap_count < 3 or cap_count > len(java_slots):
        return -1
    surplus = len(java_slots) - cap_count
    if surplus > 2 and cap_count < max(8, java_count // 4):
        return -1

    strict = pair_cap_slots_with_void_init_multiset(
        cap_slots, java_slots, require_bytecode=True,
    )
    relaxed = pair_cap_slots_with_void_init_multiset(
        cap_slots, java_slots, require_bytecode=False,
    )
    signature_only = pair_cap_slots_with_void_init_multiset(
        cap_slots, java_slots, signature_only=True,
    )

    if not strict and not relaxed and not signature_only:
        return -1
    if signature_only and not strict and not relaxed:
        cap_rest, cap_void = split_voidish_init_slots(cap_slots)
        java_rest, java_voidish = split_voidish_init_slots(java_slots)
        combined = cap_rest + cap_void
        combined_java = java_rest + java_voidish
        if not impl_sizes_loosely_compatible(combined, combined_java):
            return -1

    cap_impl_sizes = tuple(size for _shape, size, _sig in cap_slots if size > 0)
    if not cap_impl_sizes:
        return -1

    score = 240 + 50 * cap_count + 2 * max(0, java_count - cap_count)
    score += 20 * len(cap_impl_sizes)
    if cap_count == java_count:
        score += 80
    if strict:
        score += 120
    elif relaxed:
        score += 60
    else:
        score += 20
    return score


def score_class_pair_java_subset(  # noqa: PLR0911
    cap_methods: list[CapMethod],
    java_info: JavaClassInfo,
    descriptor_blob: bytes,
    types_offset: int,
) -> int:
    """Match when CAP lists more implemented methods than the .class file declares."""
    cap_impl_sizes = implemented_bytecode_sizes(cap_methods)
    if not cap_impl_sizes:
        return -1

    java_count = len(java_info.methods)
    cap_count = len(cap_methods)
    if java_count >= cap_count:
        return -1
    if java_count == 1 and cap_count > 3:
        return -1

    cap_ordered, _cap_sorted = cap_method_signatures(cap_methods, descriptor_blob, types_offset)
    java_ordered = java_method_shapes(java_info)
    if not multiset_subset(java_ordered, cap_ordered):
        return -1

    java_impl = java_impl_shape_size_pairs(java_info)
    cap_impl_count = len(cap_impl_sizes)
    java_impl_count = len(java_impl)

    if java_impl_count == 0:
        return -1
    if not pair_java_impl_to_cap(java_impl, cap_methods, cap_ordered):
        return -1
    min_impl = max(3, cap_impl_count // 4)
    if java_impl_count < min_impl:
        return -1

    score = 180 + 30 * java_count + (cap_count - java_count)
    if sorted(cap_impl_sizes) == sorted(size for _shape, size in java_impl):
        score += 80
    else:
        score += max(0, score_bytecode_match(cap_impl_sizes, tuple(size for _shape, size in java_impl)) // 4)

    return score if score >= 150 else -1


def score_class_pair(
    _class_ref: int,
    cap_methods: list[CapMethod],
    java_info: JavaClassInfo,
    descriptor_blob: bytes,
    types_offset: int,
) -> int:
    if len(cap_methods) != len(java_info.methods):
        return -1

    count, sorted_shapes, ordered_shapes, abstract, bytecode = cap_class_fingerprint(
        cap_methods, descriptor_blob, types_offset,
    )
    jcount, jsorted, jordered, jabstract, jbytecode = java_class_fingerprint(java_info)
    if count != jcount or sorted_shapes != jsorted:
        return -1
    if sum(abstract) != sum(jabstract):
        return -1

    score = 100 + score_ordered_match(ordered_shapes, jordered)
    score += score_bytecode_match(bytecode, jbytecode)
    return score


def all_bytecode_sizes(cap_methods: list[CapMethod]) -> tuple[int, ...]:
    return tuple(method.bytecode_size for method in cap_methods)


def java_all_bytecode_sizes(java_info: JavaClassInfo) -> tuple[int, ...]:
    if len(java_info.bytecode_sizes) == len(java_info.methods):
        return java_info.bytecode_sizes
    return tuple(
        java_info.bytecode_sizes[index] if index < len(java_info.bytecode_sizes) else 0
        for index in range(len(java_info.methods))
    )


def score_class_pair_bytecode_match(
    cap_methods: list[CapMethod],
    java_info: JavaClassInfo,
) -> int:
    if len(cap_methods) != len(java_info.methods):
        return -1
    cap_impl = implemented_bytecode_sizes(cap_methods)
    java_impl = java_implemented_bytecode_sizes(java_info)
    if not cap_impl and not java_impl:
        return 300
    if cap_impl == java_impl:
        return 550
    if sorted(all_bytecode_sizes(cap_methods)) == sorted(java_all_bytecode_sizes(java_info)):
        return 350
    score = score_bytecode_match(cap_impl, java_impl)
    return score if score >= 0 else -1


def score_ordered_match(
    cap_ordered: tuple[str, ...],
    java_ordered: tuple[str, ...],
) -> int:
    if cap_ordered == java_ordered:
        return 1000
    score = 0
    for cap_shape, java_shape in zip(cap_ordered, java_ordered, strict=True):
        if cap_shape == java_shape:
            score += 20
    return score


def class_pair_score(
    class_ref: int,
    cap_methods: list[CapMethod],
    java_info: JavaClassInfo,
    descriptor_blob: bytes,
    types_offset: int,
) -> int:
    score = score_class_pair(class_ref, cap_methods, java_info, descriptor_blob, types_offset)
    if score >= 0:
        return score
    score = score_class_pair_abstract_vtable(
        cap_methods, java_info, descriptor_blob, types_offset,
    )
    if score >= 0:
        return score
    score = score_class_pair_interface_only(
        cap_methods, java_info, descriptor_blob, types_offset,
    )
    if score >= 0:
        return score
    if abs(len(java_info.methods) - len(cap_methods)) <= 2:
        score = score_class_pair_cap_in_java(
            cap_methods, java_info, descriptor_blob, types_offset,
        )
        if score >= 0:
            return score
    score = score_class_pair_bytecode_match(cap_methods, java_info)
    if score >= 0:
        return score
    return score_class_pair_java_subset(
        cap_methods, java_info, descriptor_blob, types_offset,
    )


def build_class_score_matrix(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    java_entries: list[JavaClassInfo],
    descriptor_blob: bytes,
    types_offset: int,
) -> list[list[int]]:
    return [
        [
            class_pair_score(class_ref, cap_methods, java_info, descriptor_blob, types_offset)
            for java_info in java_entries
        ]
        for class_ref, cap_methods in descriptor_classes
    ]


def _hungarian_minimize(cost: list[list[int]]) -> list[int]:
    """Return column assigned to each row in a square cost matrix."""
    n = len(cost)
    u = [0] * (n + 1)
    v = [0] * (n + 1)
    p = [0] * (n + 1)
    way = [0] * (n + 1)

    for row in range(1, n + 1):
        p[0] = row
        col = 0
        minv = [10**9] * (n + 1)
        used = [False] * (n + 1)
        while True:
            used[col] = True
            row_id = p[col]
            delta = 10**9
            next_col = 0
            for j in range(1, n + 1):
                if used[j]:
                    continue
                cur = cost[row_id - 1][j - 1] - u[row_id] - v[j]
                if cur < minv[j]:
                    minv[j] = cur
                    way[j] = col
                if minv[j] < delta:
                    delta = minv[j]
                    next_col = j
            for j in range(n + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            col = next_col
            if p[col] == 0:
                break
        while col:
            prev = way[col]
            p[col] = p[prev]
            col = prev

    assignment = [-1] * n
    for col in range(1, n + 1):
        if p[col]:
            assignment[p[col] - 1] = col - 1
    return assignment


def hungarian_maximize(scores: list[list[int]], *, min_score: int) -> list[int | None]:
    """Optimal assignment of cap rows to java columns by score."""
    if not scores:
        return []
    n_rows = len(scores)
    n_cols = len(scores[0])
    size = max(n_rows, n_cols)
    max_score = max(max(row) for row in scores)
    pad = max_score + 20_000

    cost = [
        [
            pad - scores[i][j] if i < n_rows and j < n_cols else 0
            for j in range(size)
        ]
        for i in range(size)
    ]
    cols = _hungarian_minimize(cost)

    assignment: list[int | None] = []
    for row in range(n_rows):
        col = cols[row]
        if col < 0 or col >= n_cols or scores[row][col] < min_score:
            assignment.append(None)
        else:
            assignment.append(col)
    return assignment


def _apply_hungarian_assignment(  # noqa: PLR0913
    score_rows: list[list[int]],
    assignment: list[int | None],
    used_java: set[int],
    *,
    cap_count: int,
    java_count: int,
    min_score: int,
) -> None:
    rem_cap = [index for index in range(cap_count) if assignment[index] is None]
    rem_java = [index for index in range(java_count) if index not in used_java]
    if not rem_cap or not rem_java:
        return
    submatrix = [[score_rows[cap_index][java_index] for java_index in rem_java] for cap_index in rem_cap]
    sub_assign = hungarian_maximize(submatrix, min_score=min_score)
    threshold = max(min_score, 0)
    for cap_index, java_col in zip(rem_cap, sub_assign, strict=True):
        if java_col is None:
            continue
        java_index = rem_java[java_col]
        if score_rows[cap_index][java_index] < threshold:
            continue
        assignment[cap_index] = java_index
        used_java.add(java_index)


def _confident_class_edges(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    java_entries: list[JavaClassInfo],
    score_rows: list[list[int]],
    descriptor_blob: bytes,
    types_offset: int,
) -> list[tuple[int, int, int, int, int]]:
    edges: list[tuple[int, int, int, int, int]] = []
    for cap_index, (_class_ref, cap_methods) in enumerate(descriptor_classes):
        cap_impl = implemented_bytecode_sizes(cap_methods)
        cap_slots: list[tuple[str, int, str]] | None = None
        cap_len = len(cap_methods)
        for java_index, java_info in enumerate(java_entries):
            score = score_rows[cap_index][java_index]
            pair_rank = 99
            if cap_impl and abs(len(java_info.methods) - cap_len) <= 2:
                cap_slots = cap_slots or cap_method_signature_slots(
                    cap_methods, descriptor_blob, types_offset,
                )
                java_slots = java_method_pairing_slots(java_info)
                if len(cap_slots) <= len(java_slots):
                    if pair_cap_slots_with_void_init_multiset(
                        cap_slots, java_slots, require_bytecode=True,
                    ):
                        pair_rank = 0
                    elif pair_cap_slots_with_void_init_multiset(
                        cap_slots, java_slots, require_bytecode=False,
                    ):
                        pair_rank = 1
            abstract = cap_is_abstract_vtable(cap_methods) and score >= 200
            if score >= 300 or abstract or pair_rank <= 1:
                prefer_equal = 1 if len(java_info.methods) == cap_len else 0
                edges.append((
                    pair_rank,
                    -score,
                    -prefer_equal,
                    cap_index,
                    java_index,
                ))
    return edges


def assign_class_bindings(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    java_entries: list[JavaClassInfo],
    descriptor_blob: bytes,
    types_offset: int,
) -> tuple[list[ClassBinding], list[list[int]]]:
    if not java_entries:
        return [], []

    score_rows = build_class_score_matrix(
        descriptor_classes,
        java_entries,
        descriptor_blob,
        types_offset,
    )
    cap_count = len(descriptor_classes)
    java_count = len(java_entries)
    assignment: list[int | None] = [None] * cap_count
    used_java: set[int] = set()

    for _pair_rank, _neg_score, _neg_prefer, cap_index, java_index in sorted(
        _confident_class_edges(
            descriptor_classes, java_entries, score_rows, descriptor_blob, types_offset,
        ),
    ):
        if assignment[cap_index] is None and java_index not in used_java:
            assignment[cap_index] = java_index
            used_java.add(java_index)

    _apply_hungarian_assignment(
        score_rows, assignment, used_java,
        cap_count=cap_count, java_count=java_count, min_score=40,
    )
    _apply_hungarian_assignment(
        score_rows, assignment, used_java,
        cap_count=cap_count, java_count=java_count, min_score=0,
    )

    rem_cap_empty = sorted(
        index for index in range(cap_count)
        if assignment[index] is None and not descriptor_classes[index][1]
    )
    rem_java_empty = sorted(
        (index for index in range(java_count) if index not in used_java and not java_entries[index].methods),
        key=lambda index: java_entries[index].source,
    )
    for cap_index, java_index in zip(rem_cap_empty, rem_java_empty, strict=False):
        assignment[cap_index] = java_index
        used_java.add(java_index)

    best_effort_caps: set[int] = set()
    for cap_index, (_class_ref, cap_methods) in enumerate(descriptor_classes):
        if assignment[cap_index] is not None:
            continue
        cap_impl = implemented_bytecode_sizes(cap_methods)
        java_index = pick_best_java_index(
            cap_methods,
            java_entries,
            score_rows[cap_index],
            descriptor_blob,
            types_offset,
            used_java=used_java,
            allow_used=not cap_impl,
        )
        if java_index is None:
            java_index = pick_best_java_index(
                cap_methods,
                java_entries,
                score_rows[cap_index],
                descriptor_blob,
                types_offset,
                allow_used=True,
            )
        if java_index is None:
            continue
        assignment[cap_index] = java_index
        best_effort_caps.add(cap_index)
        if cap_impl:
            used_java.add(java_index)

    placeholder_methods = ("<init>", "()V", 0)
    bindings: list[ClassBinding] = []
    for cap_index, (_class_ref, cap_methods) in enumerate(descriptor_classes):
        java_index = assignment[cap_index]
        if java_index is not None and 0 <= java_index < len(java_entries):
            java_info = java_entries[java_index]
            bindings.append(ClassBinding(
                name=java_info.name,
                methods=java_info.methods,
                best_effort=cap_index in best_effort_caps,
            ))
            continue
        bindings.append(ClassBinding(
            name=f"<unknown#{cap_index}>",
            methods=tuple(placeholder_methods for _ in cap_methods),
        ))

    return bindings, score_rows


def debug_methods_as_java(debug_class: DebugClassInfo) -> tuple[tuple[str, str, int], ...]:
    return tuple((method.name, method.descriptor, 0) for method in debug_class.methods)


def resolve_class_names(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    java_entries: list[JavaClassInfo],
    debug_classes: tuple[DebugClassInfo, ...] | None = None,
    descriptor_blob: bytes | None = None,
    types_offset: int = 0,
) -> tuple[list[ClassBinding], list[list[int]] | None]:
    if descriptor_blob is None:
        bindings = [
            ClassBinding(
                name=f"<unknown#{idx}>",
                methods=tuple(("<init>", "()V", 0) for _ in cap_methods),
            )
            for idx, (_class_ref, cap_methods) in enumerate(descriptor_classes)
        ]
        return bindings, None

    if not java_entries:
        if not debug_classes:
            bindings = [
                ClassBinding(
                    name=f"<unknown#{idx}>",
                    methods=tuple(("<init>", "()V", 0) for _ in cap_methods),
                )
                for idx, (_class_ref, cap_methods) in enumerate(descriptor_classes)
            ]
            return bindings, None

        debug_info = DebugInfo(
            classes=debug_classes,
            method_names={},
            method_names_ext={},
            methods_by_ref={},
        )
        debug_class_map = bind_debug_classes(descriptor_classes, debug_info)
        bindings: list[ClassBinding] = []
        for class_idx, (class_ref, _cap_methods) in enumerate(descriptor_classes):
            debug_class = debug_class_map.get(class_ref)
            if debug_class is None and class_idx < len(debug_classes):
                debug_class = debug_classes[class_idx]
            if debug_class is not None:
                bindings.append(
                    ClassBinding(
                        name=debug_class.name.replace("/", "."),
                        methods=debug_methods_as_java(debug_class),
                    ),
                )
            else:
                bindings.append(
                    ClassBinding(
                        name=f"<unknown#{class_idx}>",
                        methods=tuple(("<init>", "()V", 0) for _ in _cap_methods),
                    ),
                )
        return bindings, None

    bindings, score_rows = assign_class_bindings(
        descriptor_classes,
        java_entries,
        descriptor_blob,
        types_offset,
    )
    if not debug_classes:
        return bindings, score_rows

    java_classes = {info.name: info for info in java_entries}
    debug_info = DebugInfo(
        classes=debug_classes,
        method_names={},
        method_names_ext={},
        methods_by_ref={},
    )
    debug_class_map = bind_debug_classes(descriptor_classes, debug_info)
    resolved: list[ClassBinding] = []
    for class_idx, (class_ref, _cap_methods) in enumerate(descriptor_classes):
        binding = bindings[class_idx]
        if not binding.name.startswith("<unknown"):
            resolved.append(binding)
            continue

        debug_class = debug_class_map.get(class_ref)
        if debug_class is None and class_idx < len(debug_classes):
            debug_class = debug_classes[class_idx]
        if debug_class is not None:
            name = debug_class.name.replace("/", ".")
            matched_java = java_classes.get(name)
            methods = matched_java.methods if matched_java else debug_methods_as_java(debug_class)
            resolved.append(ClassBinding(name=name, methods=methods))
        else:
            resolved.append(binding)

    return resolved, score_rows


def build_class_name_map(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    class_bindings: list[ClassBinding],
) -> dict[int, str]:
    names: dict[int, str] = {}
    for (class_ref, _methods), binding in zip(
        descriptor_classes, class_bindings, strict=True,
    ):
        internal_name = binding.name.replace(".", "/")
        names[class_ref] = internal_name
    return names


def unresolved_class_hints(  # noqa: PLR0913
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    java_entries: list[JavaClassInfo],
    class_bindings: list[ClassBinding],
    descriptor_blob: bytes,
    types_offset: int,
    score_rows: list[list[int]] | None = None,
) -> tuple[str, ...]:
    if score_rows is None:
        score_rows = build_class_score_matrix(
            descriptor_classes,
            java_entries,
            descriptor_blob,
            types_offset,
        )
    hints: list[str] = []

    for cap_idx, binding in enumerate(class_bindings):
        if not binding.name.startswith("<unknown"):
            continue
        cap_methods = descriptor_classes[cap_idx][1]
        row = score_rows[cap_idx]
        cap_count = len(cap_methods)
        cap_impl = len(implemented_bytecode_sizes(cap_methods))
        if not row:
            hints.append(f"{binding.name}: {cap_count} methods ({cap_impl} impl), no .class entries")
            continue

        best_idx = pick_best_java_index(
            cap_methods, java_entries, row, descriptor_blob, types_offset, allow_used=True,
        )
        if best_idx is None:
            hints.append(f"{binding.name}: {cap_count} methods ({cap_impl} impl), no .class candidate")
            continue
        java_info = java_entries[best_idx]
        cap_slots = cap_method_signature_slots(cap_methods, descriptor_blob, types_offset)
        detail = cap_java_pairing_detail(
            cap_slots, java_method_pairing_slots(java_info),
        )
        hints.append(
            f"{binding.name}: {cap_count} methods ({cap_impl} impl), "
            f"likely {java_info.name} ({len(java_info.methods)} methods): {detail}",
        )
    return tuple(hints)


def match_method_name(  # noqa: PLR0913, PLR0915
    cap_method: CapMethod,
    signature: str,
    java_methods: list[tuple[str, str, int]],
    used_indexes: set[int],
    *,
    method_index: int | None = None,
    java_bytecode_sizes: tuple[int, ...] = (),
) -> tuple[str, str]:
    def bytecode_bonus(index: int) -> int:
        if index >= len(java_bytecode_sizes):
            return 0
        java_size = java_bytecode_sizes[index]
        if java_size == 0:
            return 0
        if java_size == cap_method.bytecode_size:
            return 200
        diff = abs(java_size - cap_method.bytecode_size)
        if diff <= 4:
            return 50
        if bytecode_sizes_compatible(cap_method.bytecode_size, java_size):
            return max(10, 40 - diff)
        return 0

    def try_index(index: int) -> tuple[str, str] | None:
        if index >= len(java_methods) or index in used_indexes:
            return None
        name, descriptor, access = java_methods[index]
        if cap_method.access & ACC_INIT:
            if name == "<init>" and signatures_match(signature, descriptor):
                used_indexes.add(index)
                return "<init>", descriptor
            return None
        if descriptor != signature and not signatures_match(signature, descriptor):
            return None
        if cap_method.bytecode_size == 0 and not (access & 0x0400):
            return None
        used_indexes.add(index)
        return name, descriptor

    if method_index is not None:
        matched = try_index(method_index)
        if matched is not None:
            return matched

    if cap_method.access & ACC_INIT:
        best_init: int | None = None
        best_init_score = -1
        for index, (name, descriptor, _access) in enumerate(java_methods):
            if index in used_indexes or name != "<init>":
                continue
            if not signatures_match(signature, descriptor):
                continue
            score = bytecode_bonus(index)
            if score > best_init_score:
                best_init_score = score
                best_init = index
        if best_init is not None and best_init_score >= 0:
            used_indexes.add(best_init)
            return "<init>", java_methods[best_init][1]
        return "<init>", signature

    best_index: int | None = None
    best_score = -1
    for index, (_name, descriptor, access) in enumerate(java_methods):
        if index in used_indexes:
            continue
        if not signatures_match(signature, descriptor):
            continue
        if cap_method.bytecode_size == 0 and not (access & 0x0400):
            continue
        score = bytecode_bonus(index)
        if method_index is not None and index == method_index:
            score += 100
        if score > best_score:
            best_score = score
            best_index = index
    if best_index is not None:
        used_indexes.add(best_index)
        name, descriptor, _access = java_methods[best_index]
        return name, descriptor

    for index, (name, descriptor, _access) in enumerate(java_methods):
        if index in used_indexes:
            continue
        if signatures_match(signature, descriptor):
            used_indexes.add(index)
            return name, descriptor

    fallback = f"method#{cap_method.token}" if cap_method.token != 0xFF else f"method@{cap_method.offset}"
    return fallback, signature


def read_debug_strings(debug: bytes, pos: int) -> tuple[list[str], int]:
    string_count = struct.unpack_from(">H", debug, pos)[0]
    pos += 2
    strings: list[str] = []
    for _ in range(string_count):
        length = struct.unpack_from(">H", debug, pos)[0]
        pos += 2
        raw = debug[pos : pos + length]
        if not looks_like_debug_string(raw):
            msg = f"invalid debug string bytes at offset {pos - 2}"
            raise ValueError(msg)
        strings.append(raw.decode("utf-8"))
        pos += length
    return strings, pos


def looks_like_class_debug_name(name: str) -> bool:
    if not name or name.startswith("imported"):
        return name.startswith("imported")
    if "/" in name:
        return all(part and part[0].isalnum() for part in name.split("/") if part)
    return name[0].isalpha() and name.replace("_", "").replace("$", "").isalnum()


def is_trustworthy_debug_info(
    debug_info: DebugInfo,
    descriptor_class_count: int,
    *,
    consumed: int | None = None,
    total: int | None = None,
) -> bool:
    if not debug_info.classes:
        return False

    valid_classes = sum(1 for cls in debug_info.classes if looks_like_class_debug_name(cls.name))
    if valid_classes < len(debug_info.classes) * 0.8:
        return False

    if abs(len(debug_info.classes) - descriptor_class_count) > max(2, descriptor_class_count // 5):
        return False

    if consumed is not None and total is not None:
        slack = total - consumed
        if slack > max(32, total // 50):
            return False

    method_count = sum(len(cls.methods) for cls in debug_info.classes)
    valid_methods = sum(
        1
        for cls in debug_info.classes
        for method in cls.methods
        if method.name and method.descriptor and (method.name.startswith("<") or method.name[0].isidentifier())
    )
    return method_count == 0 or valid_methods >= method_count * 0.8


def debug_string(strings: list[str], index: int) -> str:
    if index >= len(strings):
        msg = f"debug string index {index} out of range ({len(strings)} strings)"
        raise ValueError(msg)
    return strings[index]


def parse_class_debug_info(
    debug: bytes,
    pos: int,
    strings: list[str],
    *,
    method_extended: bool,
) -> tuple[DebugClassInfo, int]:
    name_index, _access_flags, location, _superclass, _source_file = struct.unpack_from(">HHHHH", debug, pos)
    pos += 10
    interface_count = debug[pos]
    pos += 1
    field_count, method_count = struct.unpack_from(">HH", debug, pos)
    pos += 4
    pos += interface_count * 2
    pos += field_count * 10

    methods: list[DebugMethodInfo] = []
    for _ in range(method_count):
        method_name_index, descriptor_index, _method_access = struct.unpack_from(">HHH", debug, pos)
        pos += 6
        block_index = 0
        if method_extended:
            block_index = debug[pos]
            pos += 1
        method_location = struct.unpack_from(">H", debug, pos)[0]
        pos += 2
        pos += 1 + 2  # header_size, body_size
        variable_count = struct.unpack_from(">H", debug, pos)[0]
        pos += 2
        line_count = struct.unpack_from(">H", debug, pos)[0]
        pos += 2
        pos += variable_count * 9
        pos += line_count * 6
        methods.append(
            DebugMethodInfo(
                name=debug_string(strings, method_name_index),
                descriptor=debug_string(strings, descriptor_index),
                location=method_location,
                block_index=block_index,
            ),
        )

    return (
        DebugClassInfo(
            name=debug_string(strings, name_index),
            location=location,
            methods=tuple(methods),
        ),
        pos,
    )


def parse_debug_info(
    info: bytes,
    *,
    package_extended: bool,
    method_extended: bool,
) -> tuple[DebugInfo, int]:
    pos = 0
    strings, pos = read_debug_strings(info, pos)
    classes_list: list[DebugClassInfo] = []
    method_names: dict[int, tuple[str, str]] = {}
    method_names_ext: dict[tuple[int, int], tuple[str, str]] = {}
    methods_by_ref: dict[tuple[int, int], tuple[str, str]] = {}

    if package_extended:
        package_count = info[pos]
        pos += 1
        for _ in range(package_count):
            pos += 2  # package_name_index
            class_count, pos = read_u2(info, pos)
            for _ in range(class_count):
                class_info, pos = parse_class_debug_info(
                    info, pos, strings, method_extended=method_extended,
                )
                classes_list.append(class_info)
    else:
        pos += 2  # package_name_index
        class_count, pos = read_u2(info, pos)
        for _ in range(class_count):
            class_info, pos = parse_class_debug_info(
                info, pos, strings, method_extended=method_extended,
            )
            classes_list.append(class_info)

    for class_info in classes_list:
        for method_index, method in enumerate(class_info.methods):
            if not method.location:
                continue
            entry = (method.name, method.descriptor)
            methods_by_ref[(class_info.location, method_index)] = entry
            if method_extended:
                method_names_ext[(method.block_index, method.location)] = entry
            method_names[method.location] = entry

    debug_info = DebugInfo(
        classes=tuple(classes_list),
        method_names=method_names,
        method_names_ext=method_names_ext,
        methods_by_ref=methods_by_ref,
        extended_layout=method_extended,
        package_extended=package_extended,
        consumed=0,
        info_length=len(info),
    )
    return debug_info, pos


def score_debug_parse(debug_info: DebugInfo, consumed: int, total: int) -> int:
    if not debug_info.classes:
        return -1

    score = len(debug_info.classes) * 100
    slack = total - consumed
    if slack == 0:
        score += 500
    elif slack <= 8:
        score += 200
    else:
        score -= min(slack, 500)

    for class_info in debug_info.classes:
        name = class_info.name
        if looks_like_class_debug_name(name) and "/" in name:
            score += 80
        elif looks_like_class_debug_name(name):
            score += 20
        else:
            score -= 120
        score += sum(
            5
            for method in class_info.methods
            if method.name and method.descriptor and (method.name.startswith("<") or method.name[0].isidentifier())
        )

    return score


def debug_component_slices(
    debug: bytes,
    cap: zipfile.ZipFile | None,
    *,
    cap_extended: bool,
) -> list[tuple[bytes, str, int]]:
    hint = debug_info_size_from_directory(cap, extended=cap_extended) if cap else None
    return component_info_slices(debug, info_size_hint=hint)
def parse_debug_component(
    debug: bytes,
    *,
    cap_extended: bool,
    cap: zipfile.ZipFile | None = None,
) -> DebugInfo:
    if debug[0] != COMPONENT_DEBUG:
        msg = f"expected debug component tag {COMPONENT_DEBUG}, got {debug[0]}"
        raise ValueError(msg)

    best: DebugInfo | None = None
    best_score = -1
    errors: list[str] = []

    info_slices = debug_component_slices(debug, cap, cap_extended=cap_extended)
    if not info_slices:
        msg = "could not locate debug component info section"
        raise ValueError(msg)

    info_size_hint = debug_info_size_from_directory(cap, extended=cap_extended) if cap else None

    layout_orders = [
        (False, False),
        (False, True),
        (True, True),
        (True, False),
    ]
    if cap_extended:
        layout_orders = [(True, True), (True, False), (False, False), (False, True)]

    for info, hdr_label, _start in info_slices:
        for package_extended, method_extended in layout_orders:
            label = f"{hdr_label}/pkg{'ext' if package_extended else 'cmp'}/meth{'ext' if method_extended else 'cmp'}"
            try:
                debug_info, consumed = parse_debug_info(
                    info,
                    package_extended=package_extended,
                    method_extended=method_extended,
                )
            except (ValueError, IndexError, UnicodeDecodeError, struct.error) as exc:
                errors.append(f"{label}: {exc}")
                continue

            score = score_debug_parse(debug_info, consumed, len(info))
            if hdr_label in {"u2ffff@3", "hint-u2ffff-u4"}:
                score += 300
            if info_size_hint is not None and len(info) == info_size_hint:
                score += 400
            if score > best_score:
                best = replace(debug_info, consumed=consumed, info_length=len(info))
                best_score = score

    if best is not None and best_score > 0:
        return best

    msg = "failed to parse debug component"
    if errors:
        msg = f"{msg} (tried {len(errors)} layouts)"
    raise ValueError(msg)


def find_debug_component_data(cap: zipfile.ZipFile) -> bytes | None:
    matches = [
        name
        for name in cap.namelist()
        if name.lower().rsplit("/", maxsplit=1)[-1] in {"debug.cap", "debug.capx"}
    ]
    if not matches:
        return None
    if len(matches) > 1:
        capx = [name for name in matches if name.lower().endswith(".capx")]
        if len(capx) == 1:
            return cap.read(capx[0])
        msg = f"multiple debug components found: {matches}"
        raise ValueError(msg)
    return cap.read(matches[0])


def debug_parse_report(
    debug: bytes,
    *,
    cap_extended: bool,
    cap: zipfile.ZipFile | None = None,
) -> str:
    lines: list[str] = [f"debug component: {len(debug)} bytes, tag={debug[0]:#x}"]
    if len(debug) >= 7:
        u2_size = struct.unpack_from(">H", debug, 1)[0]
        u4_at1 = struct.unpack_from(">I", debug, 1)[0]
        u4_at3 = struct.unpack_from(">I", debug, 3)[0]
        lines.append(
            f"  header bytes: u2={u2_size} u4@1={u4_at1} u4@3={u4_at3} "
            f"file={len(debug)} expected@1={u4_at1 + 5} expected@3={u4_at3 + 7}",
        )
    if cap is not None:
        hint = debug_info_size_from_directory(cap, extended=cap_extended)
        if hint is not None:
            lines.append(f"  directory debug info size: {hint}")

    info_slices = debug_component_slices(debug, cap, cap_extended=cap_extended)
    if not info_slices:
        lines.append("  no valid component header found")
        return "\n".join(lines)

    layout_orders = [
        (False, False),
        (False, True),
        (True, True),
        (True, False),
    ]
    if cap_extended:
        layout_orders = [(True, True), (True, False), (False, False), (False, True)]

    for info, hdr_label, _start in info_slices:
        lines.append(f"  header {hdr_label}: info={len(info)} bytes")
        for package_extended, method_extended in layout_orders:
            label = f"pkg{'ext' if package_extended else 'cmp'}/meth{'ext' if method_extended else 'cmp'}"
            try:
                debug_info, consumed = parse_debug_info(
                    info,
                    package_extended=package_extended,
                    method_extended=method_extended,
                )
                score = score_debug_parse(debug_info, consumed, len(info))
                lines.append(
                    f"    {label}: score={score} classes={len(debug_info.classes)} "
                    f"consumed={consumed}/{len(info)}",
                )
            except (ValueError, IndexError, UnicodeDecodeError, struct.error) as exc:
                lines.append(f"    {label}: error: {exc}")
    return "\n".join(lines)


def load_debug_info(cap: zipfile.ZipFile, *, cap_extended: bool) -> DebugInfo | None:
    debug = find_debug_component_data(cap)
    if debug is None:
        return None
    try:
        return parse_debug_component(debug, cap_extended=cap_extended, cap=cap)
    except (ValueError, struct.error):
        return None


def debug_class_fingerprint(cls: DebugClassInfo) -> tuple[int, tuple[tuple[int, int], ...]]:
    impl = [(method.block_index, method.location) for method in cls.methods if method.location]
    return len(cls.methods), tuple(impl[:8])


def descriptor_class_fingerprint(cap_methods: list[CapMethod]) -> tuple[int, tuple[tuple[int, int], ...]]:
    impl = [
        (method.block_index, method.offset)
        for method in cap_methods
        if not (method.offset == 0 and method.bytecode_size == 0)
    ]
    return len(cap_methods), tuple(impl[:8])


def bind_debug_classes(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    debug_info: DebugInfo,
) -> dict[int, DebugClassInfo]:
    """Map descriptor class_ref values to parsed debug class records."""
    debug_by_location = {class_info.location: class_info for class_info in debug_info.classes}
    bound: dict[int, DebugClassInfo] = {}
    unmatched: list[tuple[int, list[CapMethod]]] = []

    for class_ref, cap_methods in descriptor_classes:
        debug_class = debug_by_location.get(class_ref)
        if debug_class is not None:
            bound[class_ref] = debug_class
        else:
            unmatched.append((class_ref, cap_methods))

    if not unmatched:
        return bound

    remaining = [class_info for class_info in debug_info.classes if class_info not in bound.values()]
    if len(unmatched) == len(remaining):
        for (class_ref, _cap_methods), debug_class in zip(unmatched, remaining, strict=True):
            bound[class_ref] = debug_class
        return bound

    debug_by_fingerprint = {}
    for class_info in remaining:
        debug_by_fingerprint.setdefault(debug_class_fingerprint(class_info), []).append(class_info)

    for class_ref, cap_methods in unmatched:
        matches = debug_by_fingerprint.get(descriptor_class_fingerprint(cap_methods), [])
        if len(matches) == 1:
            bound[class_ref] = matches[0]

    return bound


def debug_method_by_index(
    debug_class: DebugClassInfo | None,
    method_index: int,
) -> tuple[str, str] | None:
    if debug_class is None or method_index >= len(debug_class.methods):
        return None
    method = debug_class.methods[method_index]
    if not method.name:
        return None
    return method.name, method.descriptor


def lookup_debug_method(
    debug_info: DebugInfo,
    debug_class: DebugClassInfo | None,
    method_index: int,
    cap_method: CapMethod,
    *,
    absolute_offset: int,
) -> tuple[str, str] | None:
    if debug_class is not None:
        by_ref = debug_info.methods_by_ref.get((debug_class.location, method_index))
        if by_ref is not None:
            return by_ref
        for method in debug_class.methods:
            if method.location == absolute_offset:
                return method.name, method.descriptor

    if debug_info.extended_layout:
        key = (cap_method.block_index, cap_method.offset)
        if key in debug_info.method_names_ext:
            return debug_info.method_names_ext[key]

    if absolute_offset in debug_info.method_names:
        return debug_info.method_names[absolute_offset]

    return None


def resolve_method_info(  # noqa: PLR0913
    *,
    trusted_debug: DebugInfo | None,
    debug_class: DebugClassInfo | None,
    method_idx: int,
    cap_method: CapMethod,
    absolute_offset: int,
    descriptor_blob: bytes,
    types_offset: int,
    class_name_map: dict[int, str],
    java_methods: list[tuple[str, str, int]],
    java_bytecode: tuple[int, ...],
    used_indexes: set[int],
) -> tuple[str, str]:
    if trusted_debug:
        debug_match = debug_method_by_index(debug_class, method_idx)
        if debug_match is None:
            debug_match = lookup_debug_method(
                trusted_debug,
                debug_class,
                method_idx,
                cap_method,
                absolute_offset=absolute_offset,
            )
        if debug_match is not None:
            return debug_match

    descriptor = decode_method_signature(
        descriptor_blob,
        types_offset,
        cap_method.type_offset,
        class_name_map,
    )
    return match_method_name(
        cap_method,
        descriptor,
        java_methods,
        used_indexes,
        method_index=method_idx,
        java_bytecode_sizes=java_bytecode,
    )


def embedded_class_names(cap: zipfile.ZipFile) -> tuple[str, ...]:
    return tuple(
        sorted(
            name.replace("\\", "/").removeprefix("APPLET-INF/classes/").removesuffix(".class").replace("/", ".")
            for name in cap.namelist()
            if name.endswith(".class")
        ),
    )


def cap_name_source(
    java_classes: dict[str, JavaClassInfo],
    trusted_debug: DebugInfo | None,
    debug_info: DebugInfo | None,
) -> str:
    if java_classes:
        source = "embedded .class files"
        if trusted_debug:
            source += " (debug available as fallback)"
        return source
    if trusted_debug:
        return "debug (trusted)"
    if debug_info:
        return "debug (untrusted, not used)"
    return "none"


def warn_untrusted_debug(
    cap: zipfile.ZipFile,
    *,
    extended: bool,
    debug_blob: bytes | None,
    debug_info: DebugInfo | None,
    java_classes: dict[str, JavaClassInfo],
) -> None:
    if debug_blob is None:
        return
    if java_classes:
        print(
            "note: Debug.cap[x] present but unreliable; using embedded .class files",
            file=sys.stderr,
        )
        return
    if debug_info is None:
        print(
            "warning: Debug.cap[x] present but could not be parsed; falling back to heuristics",
            file=sys.stderr,
        )
        print(debug_parse_report(debug_blob, cap_extended=extended, cap=cap), file=sys.stderr)
        return
    print(
        "warning: Debug.cap[x] parsed but failed validation; falling back to heuristics",
        file=sys.stderr,
    )


def load_cap_context(cap: zipfile.ZipFile, *, warn_debug: bool = False) -> CapContext:
    extended = cap_uses_extended_format(cap)
    descriptor_component = load_cap_component(cap, "Descriptor")
    descriptor_classes, descriptor_blob, types_offset = parse_descriptor(
        descriptor_component,
        extended=extended,
    )
    descriptor_methods = sum(len(methods) for _class_ref, methods in descriptor_classes)
    implemented_methods = sum(
        1
        for _class_ref, methods in descriptor_classes
        for method in methods
        if not (method.offset == 0 and method.bytecode_size == 0)
    )

    java_entries = load_java_class_entries(cap)
    java_classes = load_java_classes(cap)
    debug_blob = find_debug_component_data(cap)
    debug_info = load_debug_info(cap, cap_extended=extended) if debug_blob else None
    trusted_debug = None
    if debug_info and is_trustworthy_debug_info(
        debug_info,
        len(descriptor_classes),
        consumed=debug_info.consumed,
        total=debug_info.info_length,
    ):
        trusted_debug = debug_info
    elif warn_debug:
        warn_untrusted_debug(
            cap,
            extended=extended,
            debug_blob=debug_blob,
            debug_info=debug_info,
            java_classes=java_classes,
        )

    class_bindings, score_rows = resolve_class_names(
        descriptor_classes,
        java_entries,
        debug_classes=trusted_debug.classes if trusted_debug else None,
        descriptor_blob=descriptor_blob,
        types_offset=types_offset,
    )
    class_name_map = build_class_name_map(descriptor_classes, class_bindings)
    debug_class_map = bind_debug_classes(descriptor_classes, trusted_debug) if trusted_debug else {}

    method_component = load_cap_component(cap, "Method")
    if method_component[0] != COMPONENT_METHOD:
        msg = f"expected method component tag {COMPONENT_METHOD}, got {method_component[0]}"
        raise ValueError(msg)
    method_info = method_component_data(method_component, extended=extended)
    block_starts = extended_method_block_starts(method_component) if extended else [0]

    return CapContext(
        extended=extended,
        descriptor_classes=descriptor_classes,
        descriptor_blob=descriptor_blob,
        types_offset=types_offset,
        java_entries=java_entries,
        java_classes=java_classes,
        debug_blob=debug_blob,
        debug_info=debug_info,
        trusted_debug=trusted_debug,
        class_bindings=class_bindings,
        class_name_map=class_name_map,
        debug_class_map=debug_class_map,
        method_info=method_info,
        block_starts=block_starts,
        embedded_classes=embedded_class_names(cap),
        descriptor_methods=descriptor_methods,
        implemented_methods=implemented_methods,
        name_source=cap_name_source(java_classes, trusted_debug, debug_info),
        score_rows=score_rows,
    )


def build_method_infos(ctx: CapContext) -> list[MethodInfo]:
    methods: list[MethodInfo] = []
    for class_idx, ((class_ref, cap_methods), binding) in enumerate(
        zip(ctx.descriptor_classes, ctx.class_bindings, strict=True),
    ):
        class_name = binding.name
        java_info = ctx.java_classes.get(class_name)
        java_bytecode = java_info.bytecode_sizes if java_info else ()
        debug_class = ctx.debug_class_map.get(class_ref)
        if debug_class is None and ctx.trusted_debug and class_idx < len(ctx.trusted_debug.classes):
            debug_class = ctx.trusted_debug.classes[class_idx]
        used_indexes: set[int] = set()
        for method_idx, cap_method in enumerate(cap_methods):
            if cap_method.offset == 0 and cap_method.bytecode_size == 0:
                continue
            absolute_offset = cap_method_absolute_offset(
                cap_method,
                extended=ctx.extended,
                block_starts=ctx.block_starts,
            )
            name, descriptor = resolve_method_info(
                trusted_debug=ctx.trusted_debug,
                debug_class=debug_class,
                method_idx=method_idx,
                cap_method=cap_method,
                absolute_offset=absolute_offset,
                descriptor_blob=ctx.descriptor_blob,
                types_offset=ctx.types_offset,
                class_name_map=ctx.class_name_map,
                java_methods=list(binding.methods),
                java_bytecode=java_bytecode,
                used_indexes=used_indexes,
            )
            header_size = (
                method_header_size(ctx.method_info, cap_method.offset)
                if cap_method.offset < len(ctx.method_info)
                else 0
            )
            methods.append(
                MethodInfo(
                    class_name=class_name,
                    name=name,
                    descriptor=descriptor,
                    offset=cap_method.offset,
                    header_size=header_size,
                    bytecode_size=cap_method.bytecode_size,
                ),
            )
    return methods


def count_method_resolution(methods: list[MethodInfo]) -> tuple[int, tuple[str, ...]]:
    resolved_methods = 0
    unresolved_method_names: list[str] = []
    for method in methods:
        if method.name.startswith(("method@", "method#")):
            unresolved_method_names.append(f"{method.class_name}.{method.name}")
        else:
            resolved_methods += 1
    return resolved_methods, tuple(unresolved_method_names)


def analyse_cap(path: Path) -> tuple[list[MethodInfo], list[ClassBinding]]:
    with zipfile.ZipFile(path) as cap:
        ctx = load_cap_context(cap, warn_debug=True)
    return build_method_infos(ctx), ctx.class_bindings


def print_methods(
    methods: list[MethodInfo],
    *,
    best_effort_classes: frozenset[str] = frozenset(),
) -> None:
    if not methods:
        print("No methods found.")
        return

    style = Style()
    by_class: dict[str, list[MethodInfo]] = {}
    for method in methods:
        by_class.setdefault(method.class_name, []).append(method)

    class_order = sorted(
        by_class,
        key=lambda class_name: sum(method.bytecode_size for method in by_class[class_name]),
        reverse=True,
    )

    total_bytecode = sum(method.bytecode_size for method in methods)
    total_header = sum(method.header_size for method in methods)
    total_size = sum(method.total_size for method in methods)

    name_width = min(48, max(len(f"{method.name}{method.descriptor}") for method in methods))
    inner_width = name_width + 29

    for class_name in class_order:
        class_methods = sorted(by_class[class_name], key=lambda method: method.bytecode_size, reverse=True)
        class_bytecode = sum(method.bytecode_size for method in class_methods)
        class_header = sum(method.header_size for method in class_methods)
        class_total = sum(method.total_size for method in class_methods)
        class_share = (class_bytecode / total_bytecode * 100) if total_bytecode else 0
        simple_name = class_name.rsplit(".", maxsplit=1)[-1]
        class_title = f" {simple_name} "

        print(box_top(style, class_title, inner_width))
        print(
            box_row(
                style,
                f" {len(class_methods)} methods · "
                f"{style.green}{format_bytes(class_bytecode)}{style.reset} bytecode · "
                f"{style.bold}{format_bytes(class_total)}{style.reset} total · "
                f"{class_share:.1f}% of package",
                inner_width,
            ),
        )
        if class_name in best_effort_classes:
            print(
                box_row(
                    style,
                    f" {style.yellow}NOTE: best-effort match{style.reset}",
                    inner_width,
                ),
            )
        print(
            box_row(
                style,
                f"  {'method':<{name_width}}  "
                f"{'offset':>6}  {'hdr':>3}  {'bc':>5}  {'total':>5}",
                inner_width,
            ),
        )
        print(box_separator(style, inner_width))

        for method in class_methods:
            display_name = truncate(
                f"{method.name}{method.descriptor}" if method.descriptor else method.name,
                name_width,
            )
            print(
                box_row(
                    style,
                    f"  {display_name:<{name_width}}  "
                    f"{method.offset:6d}  "
                    f"{method.header_size:3d}  "
                    f"{method.bytecode_size:5d}  "
                    f"{style.bold}{method.total_size:5d}{style.reset}",
                    inner_width,
                ),
            )

        print(
            box_row(
                style,
                f"  {'subtotal':<{name_width}}  "
                f"{'':>6}  "
                f"{class_header:3d}  "
                f"{style.green}{class_bytecode:5d}{style.reset}  "
                f"{style.bold}{class_total:5d}{style.reset}",
                inner_width,
            ),
        )
        print(box_bottom(style, inner_width))
        print()

    summary_title = " Summary "
    summary_inner = 44
    print(f"{style.cyan}{style.bold}╭{summary_title}{'─' * (summary_inner - len(summary_title))}╮{style.reset}")
    rows = [
        ("Methods", f"{len(methods)}"),
        ("Header", format_bytes(total_header)),
        ("Bytecode", format_bytes(total_bytecode)),
        ("Total size", f"{style.bold}{style.green}{format_bytes(total_size)}{style.reset}"),
    ]
    for label, value in rows:
        print(f"{style.dim}│{style.reset} {label:<12} {value:>{summary_inner - 15}} {style.dim}│{style.reset}")
    print(f"{style.cyan}{style.bold}╰{'─' * summary_inner}╯{style.reset}")
    print(f"{style.dim}Sizes from Method.cap (header + bytecode per method).{style.reset}")


@dataclass(frozen=True)
class CapStatus:
    extended: bool
    descriptor_classes: int
    descriptor_methods: int
    implemented_methods: int
    embedded_classes: tuple[str, ...]
    loaded_java_entries: int
    unique_java_names: int
    debug_present: bool
    debug_parsed: bool
    debug_trusted: bool
    debug_class_count: int
    debug_layout: str
    name_source: str
    resolved_classes: int
    best_effort_class_names: tuple[str, ...]
    unresolved_class_names: tuple[str, ...]
    unresolved_class_hints: tuple[str, ...]
    resolved_methods: int
    unresolved_method_names: tuple[str, ...]


def collect_cap_status(path: Path) -> CapStatus:
    with zipfile.ZipFile(path) as cap:
        ctx = load_cap_context(cap, warn_debug=False)

    methods = build_method_infos(ctx)
    resolved_methods, unresolved_method_names = count_method_resolution(methods)
    class_bindings = ctx.class_bindings

    unresolved_class_names = tuple(
        binding.name for binding in class_bindings if binding.name.startswith("<unknown")
    )
    best_effort_class_names = tuple(
        dict.fromkeys(binding.name for binding in class_bindings if binding.best_effort),
    )
    resolved_classes = len(ctx.descriptor_classes) - len(unresolved_class_names)
    class_hints = unresolved_class_hints(
        ctx.descriptor_classes,
        ctx.java_entries,
        class_bindings,
        ctx.descriptor_blob,
        ctx.types_offset,
        score_rows=ctx.score_rows,
    ) if unresolved_class_names else ()

    debug_layout = ""
    if ctx.debug_info:
        debug_layout = (
            f"pkg={'ext' if ctx.debug_info.package_extended else 'cmp'}/"
            f"meth={'ext' if ctx.debug_info.extended_layout else 'cmp'}"
        )

    return CapStatus(
        extended=ctx.extended,
        descriptor_classes=len(ctx.descriptor_classes),
        descriptor_methods=ctx.descriptor_methods,
        implemented_methods=ctx.implemented_methods,
        embedded_classes=ctx.embedded_classes,
        loaded_java_entries=len(ctx.java_entries),
        unique_java_names=len(ctx.java_classes),
        debug_present=ctx.debug_blob is not None,
        debug_parsed=ctx.debug_info is not None,
        debug_trusted=ctx.trusted_debug is not None,
        debug_class_count=len(ctx.debug_info.classes) if ctx.debug_info else 0,
        debug_layout=debug_layout,
        name_source=ctx.name_source,
        resolved_classes=resolved_classes,
        best_effort_class_names=best_effort_class_names,
        unresolved_class_names=unresolved_class_names,
        unresolved_class_hints=class_hints,
        resolved_methods=resolved_methods,
        unresolved_method_names=unresolved_method_names,
    )


def format_cap_status(status: CapStatus) -> str:  # noqa: PLR0915
    lines = [
        "CAP status",
        f"  format: {'extended' if status.extended else 'compact'}",
        (
            f"  descriptor: {status.descriptor_classes} classes, "
            f"{status.descriptor_methods} methods ({status.implemented_methods} with bytecode)"
        ),
        f"  embedded .class: {len(status.embedded_classes)} files"
        f" ({status.loaded_java_entries} loaded, {status.unique_java_names} unique names)",
    ]

    if status.loaded_java_entries != status.unique_java_names:
        lines.append(
            f"  note: {status.loaded_java_entries - status.unique_java_names} embedded .class "
            "files share a name with another file (dict lookup keeps one)",
        )
    if status.loaded_java_entries == status.descriptor_classes and status.resolved_classes < status.descriptor_classes:
        lines.append(
            f"  note: {status.descriptor_classes - status.resolved_classes} descriptor classes "
            "could not be matched to any embedded .class fingerprint",
        )

    if status.embedded_classes:
        preview = status.embedded_classes
        if len(preview) <= 8:
            lines.extend(f"    - {name}" for name in preview)
        else:
            lines.extend(f"    - {name}" for name in preview[:4])
            lines.append(f"    ... {len(preview) - 6} more ...")
            lines.extend(f"    - {name}" for name in preview[-2:])

    lines.append("")
    lines.append("Name resolution")
    lines.append(f"  source: {status.name_source}")
    lines.append(
        f"  classes: {status.resolved_classes}/{status.descriptor_classes} resolved",
    )
    if status.best_effort_class_names:
        shown = status.best_effort_class_names[:8]
        extra = len(status.best_effort_class_names) - len(shown)
        suffix = f" (+{extra} more)" if extra else ""
        lines.append(
            f"  best-effort classes ({len(status.best_effort_class_names)}): "
            f"{', '.join(shown)}{suffix}",
        )
        lines.append(
            "  note: best-effort class names are inferred from embedded .class "
            "fingerprints and may be wrong",
        )
    if status.unresolved_class_names:
        shown = status.unresolved_class_names[:12]
        extra = len(status.unresolved_class_names) - len(shown)
        suffix = f" (+{extra} more)" if extra else ""
        lines.append(f"  unresolved classes: {', '.join(shown)}{suffix}")
        if status.unresolved_class_hints:
            lines.append("  match hints (best .class candidate per unresolved class):")
            lines.extend(f"    {hint}" for hint in status.unresolved_class_hints[:8])
            if len(status.unresolved_class_hints) > 8:
                lines.append(f"    ... {len(status.unresolved_class_hints) - 8} more ...")

    unresolved_method_count = len(status.unresolved_method_names)
    lines.append(
        f"  methods: {status.resolved_methods}/{status.implemented_methods} resolved",
    )
    if unresolved_method_count:
        sample = ", ".join(status.unresolved_method_names[:6])
        suffix = f" (+{unresolved_method_count - 6} more)" if unresolved_method_count > 6 else ""
        lines.append(f"  unresolved methods: {sample}{suffix}")

    lines.append("")
    lines.append("Debug component")
    if not status.debug_present:
        lines.append("  absent")
    elif not status.debug_parsed:
        lines.append("  present but could not be parsed")
    else:
        trusted = "trusted" if status.debug_trusted else "not trusted"
        lines.append(
            f"  parsed: {status.debug_class_count} classes, {status.debug_layout}, {trusted}",
        )
        if status.debug_trusted and status.embedded_classes:
            lines.append("  note: embedded .class files take priority over debug for matched classes")

    if status.descriptor_classes > len(status.embedded_classes) and status.embedded_classes:
        gap = status.descriptor_classes - len(status.embedded_classes)
        lines.append("")
        lines.append(
            f"Hint: descriptor has {gap} more classes than embedded .class files; "
            "those need Debug.cap or matching .class entries.",
        )

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Print Java Card CAP method sizes from Method.cap")
    parser.add_argument("cap", type=Path, help="path to a Java Card CAP file (JAR)")
    parser.add_argument(
        "--debug-status",
        action="store_true",
        help="print CAP name-resolution diagnostics to stderr and exit",
    )
    parser.add_argument(
        "--debug-verbose",
        action="store_true",
        help="with --debug-status, also dump raw debug component parse attempts",
    )
    return parser


def run_debug_status(path: Path, *, verbose: bool = False) -> int:
    try:
        status = collect_cap_status(path)
        print(format_cap_status(status), file=sys.stderr)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    else:
        if verbose:
            with zipfile.ZipFile(path) as cap:
                extended = cap_uses_extended_format(cap)
                debug_blob = find_debug_component_data(cap)
                if debug_blob is not None:
                    print(file=sys.stderr)
                    print(debug_parse_report(debug_blob, cap_extended=extended, cap=cap), file=sys.stderr)
        return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.cap.is_file():
        print(f"error: {args.cap} is not a file", file=sys.stderr)
        return 1

    if args.debug_status:
        return run_debug_status(args.cap, verbose=args.debug_verbose)

    try:
        methods, class_bindings = analyse_cap(args.cap)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    best_effort = frozenset(binding.name for binding in class_bindings if binding.best_effort)
    if best_effort:
        print(
            f"note: {len(best_effort)} class name(s) are best-effort fingerprint matches "
            f"and may be wrong",
            file=sys.stderr,
        )
    print_methods(methods, best_effort_classes=best_effort)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
