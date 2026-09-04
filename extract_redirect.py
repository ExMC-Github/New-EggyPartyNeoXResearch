#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fix_v2_opcodes.py - 修复V2 opcode还原算法，并生成还原后的 redirect.pyc。
完全参考 script_decrypter.py 的 marshal 解析/序列化框架。
"""

import struct
import json
import sys
import os

# ============================================================
# 从 script_decrypter.py 中提取的必要函数和类
# ============================================================

# Python 2.7 标准 opcode 规则
STD_OP_HAS_ARG = set(range(90, 256))
JUMP_OPCODES = {110, 111, 112, 113, 114, 115, 119, 120, 121, 122, 93, 143}
RELATIVE_JUMP_OPCODES = {110, 120, 121, 122, 93, 143}

def build_opcode_map(opcodes_full):
    """从 opcodes_full.json 构建 opcode_map，与 script_decrypter.py 一致"""
    opcode_map = {}
    for name, entry in opcodes_full.items():
        custom_op = entry["opcode"]
        is_opext = entry.get("opext", False)
        content = entry["content"]
        sub_ops = []
        for sub_name, std_code in content.items():
            has_arg = std_code in STD_OP_HAS_ARG
            if sub_name in ('EXTRA', 'ARGUMENT'):
                has_arg = False
            sub_ops.append((std_code, sub_name, has_arg))
        opcode_map[custom_op] = {
            "is_opext": is_opext,
            "sub_ops": sub_ops,
            "name": name,
        }
    return opcode_map


class _InstructionRecord:
    __slots__ = ('original_position', 'final_position', 'modified_opcode',
                 'original_size', 'expanded_bytes', 'expanded_size',
                 'is_cisc', 'jumps', 'is_extra_arg', 'extra_args', 'arg_offsets')
    def __init__(self):
        self.original_position = 0
        self.final_position = 0
        self.modified_opcode = 0
        self.original_size = 0
        self.expanded_bytes = bytearray()
        self.expanded_size = 0
        self.is_cisc = False
        self.jumps = []
        self.is_extra_arg = False
        self.extra_args = []
        self.arg_offsets = []


def restore_bytecode(code_bytes, opcode_map):
    """还原 V2 自定义字节码为标准 Python 2.7 字节码。"""
    data = bytes(code_bytes)
    instructions = []
    pos = 0
    while pos < len(data):
        b = data[pos]
        record = _InstructionRecord()
        record.original_position = pos
        record.modified_opcode = b

        if b not in opcode_map:
            # 未知 opcode → STOP_CODE (0)
            record.original_size = 1
            record.expanded_bytes = bytearray([0])
            record.expanded_size = 1
            pos += 1
            instructions.append(record)
            continue

        op_info = opcode_map[b]
        sub_ops = op_info['sub_ops']

        # 特殊处理：OPEXT_EXTRA_ARGUMENT (0x83)
        if b == 131:
            record.original_size = 3
            record.extra_args = list(data[pos+1:pos+3]) if pos+3 <= len(data) else [0,0]
            record.expanded_bytes = bytearray()
            record.expanded_size = 0
            record.is_extra_arg = True
            pos += 3
            instructions.append(record)
            continue

        # 特殊处理：OPEXT_LOAD_FAST_0_LOAD_CONST (0xAD)
        if b == 173:
            record.original_size = 3
            arg = struct.unpack_from('<H', data, pos+1)[0] if pos+3 <= len(data) else 0
            record.expanded_bytes = bytearray([124, 0, 0, 100])  # LOAD_FAST 0
            record.arg_offsets.append(len(record.expanded_bytes))  # 指向 LOAD_CONST 参数
            record.expanded_bytes.extend(struct.pack('<H', arg))
            record.expanded_size = 6
            record.is_cisc = True
            pos += 3
        else:
            record.is_cisc = len(sub_ops) > 1
            record.expanded_bytes = bytearray()
            read_pos = pos + 1
            first_arg_read = False
            record.original_size = 1

            for std_opcode, sub_name, has_arg in sub_ops:
                record.expanded_bytes.append(std_opcode)
                if has_arg:
                    if not first_arg_read:
                        arg = struct.unpack_from('<H', data, read_pos)[0] if read_pos+2 <= len(data) else 0
                        read_pos += 2
                        first_arg_read = True
                        record.original_size += 2
                    else:
                        marker = data[read_pos] if read_pos < len(data) else 0
                        read_pos += 1
                        if marker != 0x83:
                            raise ValueError(f"CISC 格式错误: 期望 0x83, 在 {read_pos-1} 得到 0x{marker:02X}")
                        arg = struct.unpack_from('<H', data, read_pos)[0] if read_pos+2 <= len(data) else 0
                        read_pos += 2
                        record.original_size += 3

                    record.arg_offsets.append(len(record.expanded_bytes))
                    record.expanded_bytes.extend(struct.pack('<H', arg))
                    if std_opcode in JUMP_OPCODES:
                        record.jumps.append({
                            'offset_in_expanded': len(record.expanded_bytes) - 2,
                            'jump_opcode': std_opcode,
                            'original_operand': arg,
                        })
            record.expanded_size = len(record.expanded_bytes)
            pos = read_pos

        instructions.append(record)

    # 计算最终位置
    final_pos = 0
    for inst in instructions:
        inst.final_position = final_pos
        final_pos += inst.expanded_size

    total_original = sum(inst.original_size for inst in instructions)
    total_expanded = final_pos

    # 修正跳转目标
    for inst in instructions:
        for jump in inst.jumps:
            original_operand = jump['original_operand']
            jump_op = jump['jump_opcode']

            if jump_op in RELATIVE_JUMP_OPCODES:
                target_orig = inst.original_position + inst.original_size + original_operand
            else:
                target_orig = original_operand

            target_final = -1
            for inst2 in instructions:
                if inst2.original_position == target_orig:
                    target_final = inst2.final_position
                    break

            if target_final == -1:
                if target_orig >= total_original:
                    target_final = total_expanded
                else:
                    for inst2 in instructions:
                        if inst2.original_position <= target_orig < inst2.original_position + inst2.original_size:
                            target_final = inst2.final_position
                            break

            if target_final == -1:
                raise ValueError(f"找不到跳转目标: 原始位置 0x{target_orig:X}")

            if jump_op in RELATIVE_JUMP_OPCODES:
                new_operand = target_final - (inst.final_position + inst.expanded_size)
                if new_operand < 0:
                    raise ValueError(f"负的相对跳转偏移: {new_operand}")
            else:
                new_operand = target_final

            offset = jump['offset_in_expanded']
            inst.expanded_bytes[offset] = new_operand & 0xFF
            inst.expanded_bytes[offset+1] = (new_operand >> 8) & 0xFF

    # 处理 OPEXT_EXTRA_ARGUMENT 覆盖
    for i, inst in enumerate(instructions):
        if inst.is_extra_arg:
            j = i - 1
            while j >= 0 and instructions[j].is_extra_arg:
                j -= 1
            if j >= 0:
                prev = instructions[j]
                extra_args = inst.extra_args
                arg_offsets = prev.arg_offsets
                for k in range(min(len(extra_args), len(arg_offsets))):
                    rev_idx = len(extra_args) - 1 - k
                    pos_in_expanded = arg_offsets[k]
                    prev.expanded_bytes[pos_in_expanded] = extra_args[rev_idx]
                    prev.expanded_bytes[pos_in_expanded+1] = 0

    # 生成结果和偏移映射
    result = bytearray()
    offset_map = {}
    for inst in instructions:
        offset_map[inst.original_position] = len(result)
        result.extend(inst.expanded_bytes)

    return bytes(result), offset_map


def fix_lnotab(lnotab, offset_map):
    """修复 lnotab 中的字节码偏移"""
    if not lnotab or len(lnotab) < 2:
        return lnotab
    old_offsets = sorted(offset_map.keys())
    result = bytearray()
    old_pos = 0
    new_pos = 0
    i = 0
    while i + 1 < len(lnotab):
        byte_inc = lnotab[i]
        line_inc = lnotab[i+1]
        old_pos += byte_inc
        new_target = 0
        for off in old_offsets:
            if off <= old_pos:
                new_target = offset_map[off]
            else:
                break
        new_inc = new_target - new_pos
        new_pos = new_target
        while new_inc > 255:
            result.append(255)
            result.append(0)
            new_inc -= 255
        result.append(new_inc & 0xFF)
        result.append(line_inc)
        i += 2
    return bytes(result)


# ---------- Marshal 解析器与序列化器 ----------
class MarshalParser:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def _u8(self):
        b = self.data[self.pos]; self.pos += 1; return b
    def _u16(self):
        v = struct.unpack_from('<H', self.data, self.pos)[0]; self.pos += 2; return v
    def _i32(self):
        v = struct.unpack_from('<i', self.data, self.pos)[0]; self.pos += 4; return v
    def _u32(self):
        v = struct.unpack_from('<I', self.data, self.pos)[0]; self.pos += 4; return v
    def _take(self, n):
        b = self.data[self.pos:self.pos+n]; self.pos += n; return b

    def parse(self):
        return self._obj()

    def _obj(self):
        t = self._u8()
        if t == 0x63:  # 'c' code
            return self._code()
        if t == 0x73:  # 's' string
            return self._take(self._u32())
        if t == 0x74:  # 't' interned
            return ('interned', self._take(self._u32()))
        if t == 0x75:  # 'u' unicode
            return ('unicode', self._take(self._u32()))
        if t == 0x28:  # '(' tuple
            n = self._u32()
            return tuple(self._obj() for _ in range(n))
        if t == 0x29:  # ')' small tuple
            n = self._u8()
            return tuple(self._obj() for _ in range(n))
        if t == 0x5B:  # '[' list
            items = []
            while True:
                o = self._obj()
                if o == '.':
                    break
                items.append(o)
            return items
        if t == 0x7B:  # '{' dict
            d = {}
            while True:
                k = self._obj()
                if k == '.':
                    break
                d[k] = self._obj()
            return d
        if t == 0x69:  # 'i' int32
            return self._i32()
        if t == 0x49:  # 'I' int64
            v = struct.unpack_from('<q', self.data, self.pos)[0]; self.pos += 8; return v
        if t == 0x66:  # 'f' float ascii
            s = bytearray()
            while self.data[self.pos] != 0:
                s.append(self.data[self.pos]); self.pos += 1
            self.pos += 1
            return float(s.decode('ascii'))
        if t == 0x67:  # 'g' binary float
            v = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8; return v
        if t == 0x54:  # 'T' True
            return True
        if t == 0x46:  # 'F' False
            return False
        if t == 0x4E:  # 'N' None
            return None
        if t == 0x53:  # 'S' StopIter
            return Ellipsis
        if t == 0x2E:  # '.' end
            return '.'
        if t == 0x52:  # 'R' stringref
            return ('ref', self._u32())
        if t == 0x72:  # 'r' back-ref (Python 2.7.4+)
            return ('ref', self._u32())
        if t == 0x6C:  # 'l' long
            n = self._i32()
            sign = 1 if n < 0 else 0
            n = abs(n)
            val = 0
            for i in range(n):
                d = self._u16() & 0x7FFF
                val += d << (i * 15)
            return ('long', val, sign) if sign else ('long', val, 0)
        if t == 0x78:  # 'x' complex ascii
            real = bytearray()
            while self.data[self.pos] != 0:
                real.append(self.data[self.pos]); self.pos += 1
            self.pos += 1
            imag = bytearray()
            while self.data[self.pos] != 0:
                imag.append(self.data[self.pos]); self.pos += 1
            self.pos += 1
            return complex(float(real.decode('ascii')), float(imag.decode('ascii')))
        if t == 0x79:  # 'y' binary complex
            r = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8
            i = struct.unpack_from('<d', self.data, self.pos)[0]; self.pos += 8
            return complex(r, i)
        if t == 0x3C:  # '<' set
            n = self._u32()
            return ('set', [self._obj() for _ in range(n)])
        if t == 0x3E:  # '>' frozenset
            n = self._u32()
            return ('frozenset', [self._obj() for _ in range(n)])
        if t == 0x30:  # '0' null
            return ('null',)
        if t == 0x3F:  # '?' unknown
            return ('unknown_marker',)
        if t == 0x61:  # 'a' ascii
            return ('ascii', self._take(self._u32()))
        if t == 0x41:  # 'A' ascii interned
            return ('ascii_interned', self._take(self._u32()))
        # Unknown type — treat as opaque single byte
        return ('unknown', t)

    def _code(self):
        return {
            'argcount':   self._i32(),
            'nlocals':    self._i32(),
            'stacksize':  self._i32(),
            'flags':      self._i32(),
            'code':       self._obj(),
            'consts':     self._obj(),
            'names':      self._obj(),
            'varnames':   self._obj(),
            'freevars':   self._obj(),
            'cellvars':   self._obj(),
            'filename':   self._obj(),
            'name':       self._obj(),
            'firstlineno': self._i32(),
            'lnotab':     self._obj(),
        }


class MarshalWriter:
    def __init__(self):
        self.buf = bytearray()

    def serialize(self, obj):
        self._obj(obj)
        return bytes(self.buf)

    def _u8(self, b):
        self.buf.append(b)
    def _i32(self, v):
        self.buf.extend(struct.pack('<i', v))
    def _u32(self, v):
        self.buf.extend(struct.pack('<I', v))
    def _raw(self, b):
        self.buf.extend(b)
    def _u16(self, v):
        self.buf.extend(struct.pack('<H', v))

    def _obj(self, obj):
        if isinstance(obj, dict) and 'argcount' in obj:
            self._code(obj); return
        if isinstance(obj, bytes):
            self._u8(0x73); self._u32(len(obj)); self._raw(obj); return
        if isinstance(obj, tuple):
            tag = obj[0] if obj else None
            if tag == 'interned':
                self._u8(0x74); self._u32(len(obj[1])); self._raw(obj[1]); return
            if tag == 'unicode':
                self._u8(0x75); self._u32(len(obj[1])); self._raw(obj[1]); return
            if tag == 'ref':
                self._u8(0x52); self._u32(obj[1]); return
            if tag == 'long':
                val, sign = obj[1], obj[2]
                digits = []
                v = val
                while v > 0:
                    digits.append(v & 0x7FFF)
                    v >>= 15
                n = len(digits)
                if sign:
                    n = -n
                self._u8(0x6C); self._i32(n)
                for d in digits:
                    self._u16(d & 0x7FFF)
                return
            if tag == 'set':
                self._u8(0x3C); self._u32(len(obj[1]))
                for item in obj[1]:
                    self._obj(item)
                return
            if tag == 'frozenset':
                self._u8(0x3E); self._u32(len(obj[1]))
                for item in obj[1]:
                    self._obj(item)
                return
            if tag == 'null':
                self._u8(0x30); return
            if tag == 'unknown_marker':
                self._u8(0x3F); return
            if tag == 'ascii':
                self._u8(0x61); self._u32(len(obj[1])); self._raw(obj[1]); return
            if tag == 'ascii_interned':
                self._u8(0x41); self._u32(len(obj[1])); self._raw(obj[1]); return
            if tag == 'unknown':
                self._u8(obj[1]); return
            # 普通元组
            self._u8(0x28); self._u32(len(obj))
            for item in obj:
                self._obj(item)
            return
        if isinstance(obj, list):
            self._u8(0x5B)
            for item in obj:
                self._obj(item)
            self._u8(0x2E); return
        if isinstance(obj, dict):
            self._u8(0x7B)
            for k, v in obj.items():
                self._obj(k); self._obj(v)
            self._u8(0x2E); return
        if isinstance(obj, bool):
            self._u8(0x54 if obj else 0x46); return
        if obj is None:
            self._u8(0x4E); return
        if obj == Ellipsis:
            self._u8(0x53); return
        if isinstance(obj, int):
            if -2**31 <= obj < 2**31:
                self._u8(0x69); self._i32(obj)
            else:
                sign = 1 if obj < 0 else 0
                val = abs(obj)
                digits = []
                v = val
                while v > 0:
                    digits.append(v & 0x7FFF)
                    v >>= 15
                n = len(digits)
                if sign:
                    n = -n
                self._u8(0x6C); self._i32(n)
                for d in digits:
                    self._u16(d & 0x7FFF)
            return
        if isinstance(obj, float):
            self._u8(0x67); self.buf.extend(struct.pack('<d', obj)); return
        if isinstance(obj, complex):
            self._u8(0x79)
            self.buf.extend(struct.pack('<d', obj.real))
            self.buf.extend(struct.pack('<d', obj.imag)); return
        raise ValueError(f"无法序列化 {type(obj)}: {obj!r}")

    def _code(self, c):
        self._u8(0x63)
        self._i32(c['argcount']); self._i32(c['nlocals'])
        self._i32(c['stacksize']); self._i32(c['flags'])
        self._obj(c['code']); self._obj(c['consts'])
        self._obj(c['names']); self._obj(c['varnames'])
        self._obj(c['freevars']); self._obj(c['cellvars'])
        self._obj(c['filename']); self._obj(c['name'])
        self._i32(c['firstlineno']); self._obj(c['lnotab'])


_MARSHAL_TAGS = frozenset(['interned', 'unicode', 'ref', 'long', 'set',
                           'frozenset', 'null', 'unknown_marker', 'ascii',
                           'ascii_interned', 'unknown'])

def find_code_objects(obj, results=None):
    if results is None:
        results = []
    if isinstance(obj, dict) and 'argcount' in obj:
        results.append(obj)
        find_code_objects(obj['consts'], results)
    elif isinstance(obj, tuple):
        if obj and isinstance(obj[0], str) and obj[0] in _MARSHAL_TAGS:
            if obj[0] in ('set', 'frozenset'):
                find_code_objects(obj[1], results)
        else:
            for item in obj:
                find_code_objects(item, results)
    elif isinstance(obj, list):
        for item in obj:
            find_code_objects(item, results)
    elif isinstance(obj, dict):
        for v in obj.values():
            find_code_objects(v, results)
    return results


def restore_marshal_opcodes(marshal_data, opcode_map):
    """解析 marshal，还原所有 code 对象的字节码，并重新序列化"""
    parser = MarshalParser(marshal_data)
    tree = parser.parse()
    for code in find_code_objects(tree):
        if isinstance(code['code'], bytes):
            restored, off_map = restore_bytecode(code['code'], opcode_map)
            code['code'] = restored
            if isinstance(code['lnotab'], bytes):
                code['lnotab'] = fix_lnotab(code['lnotab'], off_map)
    writer = MarshalWriter()
    return writer.serialize(tree)


# ============================================================
# 原来的 load_opcodes 等保持不变（但不用了，我们用 build_opcode_map）
# ============================================================

# 为了保持兼容，保留原有函数，但 main 中不再使用它们。

# ============================================================
# Main: 生成还原后的 redirect.pyc
# ============================================================

def main():
    # 路径配置（与原来相同）
    OPCODES_FULL = r"E:\reverse\opcodes_full.json"
    NPK_PATH = r"D:\FeverApps\party_pc\script.npk"

    print("Loading opcode definitions...")
    with open(OPCODES_FULL, 'r') as f:
        opcodes_full = json.load(f)
    opcode_map = build_opcode_map(opcodes_full)
    print(f"  Loaded {len(opcode_map)} modified opcodes")

    print(f"Reading NPK: {NPK_PATH}")
    with open(NPK_PATH, 'rb') as f:
        data = f.read()

    # 解析 NPK 头部（仅用于信息）
    magic = data[:4]
    entry_count = struct.unpack_from('<I', data, 4)[0]
    index_offset = struct.unpack_from('<I', data, 20)[0]
    print(f"NPK: magic={magic}, entries={entry_count}, index_offset={index_offset}")

    # 假设 redirect 模块的 marshal 数据从偏移 24 开始（与原来一致）
    raw_marshal = data[24:]

    # 解析有效长度：先创建一个解析器，解析完第一个对象后，pos 就是有效长度
    parser = MarshalParser(raw_marshal)
    _ = parser.parse()          # 解析掉 redirect 模块
    effective_length = parser.pos
    print(f"Effective marshal length: {effective_length} bytes")

    # 截取有效数据
    marshal_data = raw_marshal[:effective_length]

    # 还原并重新序列化
    print("Restoring opcodes...")
    restored_marshal = restore_marshal_opcodes(marshal_data, opcode_map)
    print(f"Restored marshal length: {len(restored_marshal)} bytes")

    # 写入 pyc 文件（Python 2.7 头部：4字节魔数 + 4字节时间戳）
    PYC_MAGIC = b'\x03\xf3\x0d\x0a'
    TIMESTAMP = b'\x00\x00\x00\x00'   # 占位
    with open('redirect.pyc', 'wb') as f:
        f.write(PYC_MAGIC)
        f.write(TIMESTAMP)
        f.write(restored_marshal)

    print("成功生成 redirect.pyc（还原后的字节码）")


if __name__ == '__main__':
    main()