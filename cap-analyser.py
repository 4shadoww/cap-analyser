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
import struct
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

COMPONENT_METHOD = 7
COMPONENT_DESCRIPTOR = 11
COMPONENT_DEBUG = 12

ACC_ABSTRACT = 0x40
ACC_INIT = 0x80
ACC_EXTENDED = 0x08


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


@dataclass(frozen=True)
class CapMethod:
    token: int
    access: int
    offset: int
    type_offset: int
    bytecode_size: int


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


def find_component(cap: zipfile.ZipFile, suffix: str) -> bytes:
    matches = [name for name in cap.namelist() if name.endswith(suffix)]
    if not matches:
        msg = f"component {suffix!r} not found in CAP file"
        raise ValueError(msg)
    if len(matches) > 1:
        msg = f"multiple {suffix!r} components found in CAP file"
        raise ValueError(msg)
    return cap.read(matches[0])


def method_header_size(methods_data: bytes, offset: int) -> int:
    flags = methods_data[offset] >> 4
    if flags & ACC_EXTENDED:
        return 4
    return 2


def parse_descriptor(
    descriptor: bytes,
) -> tuple[list[tuple[int, list[CapMethod]]], bytes, int]:
    """Return descriptor classes, the full component blob, and type_descriptor_info offset."""
    if descriptor[0] != COMPONENT_DESCRIPTOR:
        msg = f"expected descriptor component tag {COMPONENT_DESCRIPTOR}, got {descriptor[0]}"
        raise ValueError(msg)

    pos = 4
    class_count = descriptor[3]
    classes: list[tuple[int, list[CapMethod]]] = []

    for _ in range(class_count):
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
            offset, type_offset, bytecode_size = struct.unpack_from(">HHH", descriptor, pos + 2)
            methods.append(
                CapMethod(
                    token=token,
                    access=access,
                    offset=offset,
                    type_offset=type_offset,
                    bytecode_size=bytecode_size,
                ),
            )
            pos += 12

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


def parse_class_file(data: bytes) -> tuple[str, list[tuple[str, str, int]]]:
    cp, pos = parse_cp(data)
    this_class = struct.unpack_from(">H", data, pos + 2)[0]
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
    for _ in range(method_count):
        access, pos = read_u2(data, pos)
        name_index, pos = read_u2(data, pos)
        descriptor_index, pos = read_u2(data, pos)
        attribute_count, pos = read_u2(data, pos)
        for _ in range(attribute_count):
            pos += 2
            attribute_length, pos = read_u4(data, pos)
            pos += attribute_length
        name_entry = cp[name_index]
        descriptor_entry = cp[descriptor_index]
        if name_entry is None or descriptor_entry is None:
            msg = "invalid method constant pool references"
            raise ValueError(msg)
        methods.append((name_entry[1], descriptor_entry[1], access))

    return class_name_from_cp(cp, this_class), methods


def load_java_classes(cap: zipfile.ZipFile) -> dict[str, list[tuple[str, str, int]]]:
    classes: dict[str, list[tuple[str, str, int]]] = {}
    for name in cap.namelist():
        if not name.endswith(".class"):
            continue
        class_name, methods = parse_class_file(cap.read(name))
        classes[class_name] = methods
    return classes


def resolve_class_names(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    java_classes: dict[str, list[tuple[str, str, int]]],
) -> list[tuple[str, list[tuple[str, str, int]]]]:
    used: set[str] = set()
    resolved: list[tuple[str, list[tuple[str, str, int]]]] = []

    for _class_ref, cap_methods in descriptor_classes:
        method_count = len(cap_methods)
        abstract_pattern = tuple(1 if method.bytecode_size == 0 else 0 for method in cap_methods)

        candidates = [
            class_name
            for class_name, java_methods in java_classes.items()
            if class_name not in used and len(java_methods) == method_count
        ]

        match: str | None = None
        for class_name in candidates:
            java_methods = java_classes[class_name]
            java_abstract_pattern = tuple(1 if (access & 0x0400) else 0 for _, _, access in java_methods)
            if java_abstract_pattern == abstract_pattern:
                match = class_name
                break

        if match is None and len(candidates) == 1:
            match = candidates[0]

        if match is None:
            match = f"<unknown#{len(resolved)}>"

        used.add(match)
        java_methods = java_classes.get(match, [("?", "?", 0) for _ in range(method_count)])
        resolved.append((match, java_methods))

    return resolved


def build_class_name_map(
    descriptor_classes: list[tuple[int, list[CapMethod]]],
    class_bindings: list[tuple[str, list[tuple[str, str, int]]]],
) -> dict[int, str]:
    names: dict[int, str] = {}
    for (class_ref, _methods), (class_name, _java_methods) in zip(
        descriptor_classes, class_bindings, strict=True,
    ):
        internal_name = class_name.replace(".", "/")
        names[class_ref] = internal_name
    return names


def match_method_name(
    cap_method: CapMethod,
    signature: str,
    java_methods: list[tuple[str, str, int]],
    used_indexes: set[int],
) -> str:
    if cap_method.access & ACC_INIT:
        for index, (name, descriptor, _access) in enumerate(java_methods):
            if index in used_indexes:
                continue
            if name == "<init>" and descriptor == signature:
                used_indexes.add(index)
                return "<init>"
        return "<init>"

    for index, (name, descriptor, access) in enumerate(java_methods):
        if index in used_indexes:
            continue
        if descriptor != signature:
            continue
        if cap_method.bytecode_size == 0 and not (access & 0x0400):
            continue
        used_indexes.add(index)
        return name

    for index, (name, descriptor, _access) in enumerate(java_methods):
        if index in used_indexes:
            continue
        if descriptor == signature:
            used_indexes.add(index)
            return name

    if cap_method.token != 0xFF:
        return f"method#{cap_method.token}"
    return f"method@{cap_method.offset}"


def parse_debug_names(debug: bytes, _method_info: bytes) -> dict[int, tuple[str, str]]:
    if debug[0] != COMPONENT_DEBUG:
        msg = f"expected debug component tag {COMPONENT_DEBUG}, got {debug[0]}"
        raise ValueError(msg)

    pos = 3
    string_count = struct.unpack_from(">H", debug, pos)[0]
    pos += 2
    strings: list[str] = []
    for _ in range(string_count):
        length = debug[pos]
        pos += 1
        strings.append(debug[pos : pos + length].decode())
        pos += length

    pos += 2  # package_name_index
    class_count = struct.unpack_from(">H", debug, pos)[0]
    pos += 2

    names: dict[int, tuple[str, str]] = {}
    for _ in range(class_count):
        pos += 2  # name_index, access_flags
        pos += 2
        interface_count = debug[pos]
        pos += 1
        pos += interface_count * 2
        field_count = struct.unpack_from(">H", debug, pos)[0]
        pos += 2
        method_count = struct.unpack_from(">H", debug, pos)[0]
        pos += 2

        for _ in range(field_count):
            pos += 2
            attribute_count = struct.unpack_from(">H", debug, pos)[0]
            pos += 2
            for _ in range(attribute_count):
                pos += 2
                attribute_length = struct.unpack_from(">I", debug, pos)[0]
                pos += 4 + attribute_length

        for _ in range(method_count):
            name_index, descriptor_index = struct.unpack_from(">HH", debug, pos)
            pos += 2
            pos += 2  # access_flags
            location = struct.unpack_from(">H", debug, pos)[0]
            pos += 2
            pos += 1  # header_size
            pos += 2  # body_size
            variable_count = struct.unpack_from(">H", debug, pos)[0]
            pos += 2
            line_count = struct.unpack_from(">H", debug, pos)[0]
            pos += 2
            for _ in range(variable_count):
                pos += 8
            for _ in range(line_count):
                pos += 4
            if location:
                names[location] = (strings[name_index], strings[descriptor_index])

    return names


def analyse_cap(path: Path) -> list[MethodInfo]:
    with zipfile.ZipFile(path) as cap:
        method_component = find_component(cap, "Method.cap")
        descriptor_component = find_component(cap, "Descriptor.cap")

        if method_component[0] != COMPONENT_METHOD:
            msg = f"expected method component tag {COMPONENT_METHOD}, got {method_component[0]}"
            raise ValueError(msg)

        info = component_data(method_component)

        descriptor_classes, descriptor_blob, types_offset = parse_descriptor(descriptor_component)

        debug_names: dict[int, tuple[str, str]] = {}
        debug_matches = [name for name in cap.namelist() if name.endswith("Debug.cap")]
        if debug_matches:
            debug_names = parse_debug_names(cap.read(debug_matches[0]), info)

        java_classes = load_java_classes(cap)
        class_bindings = resolve_class_names(descriptor_classes, java_classes)
        class_name_map = build_class_name_map(descriptor_classes, class_bindings)

        methods: list[MethodInfo] = []
        for (_class_ref, cap_methods), (class_name, java_methods) in zip(
            descriptor_classes, class_bindings, strict=True,
        ):
            used_indexes: set[int] = set()
            for cap_method in cap_methods:
                if cap_method.offset == 0 and cap_method.bytecode_size == 0:
                    continue

                if cap_method.offset in debug_names:
                    name, descriptor = debug_names[cap_method.offset]
                else:
                    descriptor = decode_method_signature(
                        descriptor_blob,
                        types_offset,
                        cap_method.type_offset,
                        class_name_map,
                    )
                    name = match_method_name(cap_method, descriptor, java_methods, used_indexes)

                header_size = method_header_size(info, cap_method.offset) if cap_method.offset < len(info) else 0
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


def print_methods(methods: list[MethodInfo]) -> None:
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

    for class_name in class_order:
        class_methods = sorted(by_class[class_name], key=lambda method: method.bytecode_size, reverse=True)
        class_bytecode = sum(method.bytecode_size for method in class_methods)
        class_header = sum(method.header_size for method in class_methods)
        class_total = sum(method.total_size for method in class_methods)
        class_share = (class_bytecode / total_bytecode * 100) if total_bytecode else 0
        simple_name = class_name.rsplit(".", maxsplit=1)[-1]
        class_title = f" {simple_name} "

        print(f"{style.yellow}{style.bold}┌{class_title}{'─' * max(0, 58 - len(class_title))}┐{style.reset}")
        print(
            f"{style.dim}│{style.reset} "
            f"{len(class_methods)} methods · "
            f"{style.green}{format_bytes(class_bytecode)}{style.reset} bytecode · "
            f"{style.bold}{format_bytes(class_total)}{style.reset} total · "
            f"{class_share:.1f}% of package",
        )
        print(
            f"{style.dim}│{style.reset}  "
            f"{'method':<{name_width}}  "
            f"{'offset':>6}  {'hdr':>3}  {'bc':>5}  {'total':>5}",
        )
        print(f"{style.dim}│{'─' * (name_width + 28)}│{style.reset}")

        for method in class_methods:
            display_name = truncate(
                f"{method.name}{method.descriptor}" if method.descriptor else method.name,
                name_width,
            )
            print(
                f"{style.dim}│{style.reset}  "
                f"{display_name:<{name_width}}  "
                f"{method.offset:6d}  "
                f"{method.header_size:3d}  "
                f"{method.bytecode_size:5d}  "
                f"{style.bold}{method.total_size:5d}{style.reset}",
            )

        print(
            f"{style.dim}│{style.reset}  "
            f"{'subtotal':<{name_width}}  "
            f"{'':>6}  "
            f"{class_header:3d}  "
            f"{style.green}{class_bytecode:5d}{style.reset}  "
            f"{style.bold}{class_total:5d}{style.reset}",
        )
        print(f"{style.yellow}└{'─' * 58}┘{style.reset}")
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Print Java Card CAP method sizes from Method.cap")
    parser.add_argument("cap", type=Path, help="path to a Java Card 3.1 .cap file (JAR)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.cap.is_file():
        print(f"error: {args.cap} is not a file", file=sys.stderr)
        return 1

    try:
        methods = analyse_cap(args.cap)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print_methods(methods)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
