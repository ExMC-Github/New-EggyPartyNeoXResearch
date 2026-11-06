#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patch_finder.py - 通过字节特征码自动定位 client.exe 中的 Python C API 函数地址

用法:
    python patch_finder.py <client.exe 路径> [-oc [输出文件]]

参数:
    exe路径      必需, client.exe 的路径
    -oc          可选, 生成基于 party_console.c 模板的 C 源文件
                  不带值时, 默认文件名 party_console_<时间>.c
                  带值时, 使用指定路径

示例:
    python patch_finder.py D:\\FeverApps\\party_pc\\bin\\client.exe
    python patch_finder.py client.exe -oc
    python patch_finder.py client.exe -oc my_console.c

原理:
    client.exe 静态链接了 Python 2.7.3, 导出表里没有 Python 函数符号。
    本脚本从已知版本中提取各函数入口处的前若干字节作为特征码,
    其中 RIP 相对寻址的 disp32 和 call/jmp 的 rel32 替换为通配符 ??,
    然后在目标 exe 中搜索这些特征码来自动定位函数地址。

输出:
    1. 结果表格 (函数名 / 状态 / RVA / VA / 已知RVA / 匹配数)
    2. C 宏定义, 可直接粘贴到 DLL 源码
    3. 如指定 -oc, 生成可直接编译的 C 源文件
    4. 汇总信息
"""

import sys
import re
import struct
import argparse
from datetime import datetime

# ======================================================================
# 特征码表
#   (函数名, 特征码字符串, 已知RVA)
#
#   特征码格式: 空格分隔的十六进制字节, ?? 为通配符
#   通配符覆盖:
#     - RIP 相对寻址的 4 字节 disp32  (mov rax,[rip+??] / lea rcx,[rip+??])
#     - call / jmp 的 4 字节 rel32
#   函数序言 (push / sub rsp / mov [rsp+xx]) 保留为固定字节
#
#   如需添加新函数, 往此列表追加一行即可。
# ======================================================================

SIGNATURES = [
    (
        "PyImport_AddModule",
        # 48 89 5C 24 08          mov [rsp+8], rbx
        # 48 89 74 24 10          mov [rsp+10], rsi
        # 57                      push rdi
        # 48 83 EC 20             sub rsp, 20
        # 48 8B 05 ?? ?? ?? ??    mov rax, [rip+disp32]
        # 48 8B F9                mov rdi, rcx
        # 48 8B 58 08             mov rbx, [rax+8]
        # 48 83 7B 10 00          cmp qword [rbx+10], 0
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 "
        "48 8B 05 ?? ?? ?? ?? 48 8B F9 48 8B 58 08 48 83 7B 10 00",
        0x034D0FD0,
    ),
    (
        "PyModule_GetDict",
        # 40 53                   push rbx
        # 48 83 EC 20             sub rsp, 20
        # 48 8B D9                mov rbx, rcx
        # 48 8D 15 ?? ?? ?? ??    lea rdx, [rip+disp32]
        # 48 8B 49 08             mov rcx, [rcx+8]
        # 48 3B CA                cmp rcx, rdx
        # 74 22                   je +22
        "40 53 48 83 EC 20 48 8B D9 "
        "48 8D 15 ?? ?? ?? ?? 48 8B 49 08 48 3B CA 74 22",
        0x035009A0,
    ),
    (
        "Py_CompileStringFlags",
        # 48 89 5C 24 08          mov [rsp+8], rbx
        # 48 89 6C 24 10          mov [rsp+10], rbp
        # 48 89 74 24 18          mov [rsp+18], rsi
        # 48 89 7C 24 20          mov [rsp+20], rdi
        # 41 56                   push r14
        # 48 83 EC 30             sub rsp, 30
        # 49 8B D9                mov rbx, r9
        # 41 8B E8                mov ebp, r8d
        # 48 8B F2                mov rsi, rdx
        # 4C 8B F1                mov r14, rcx
        "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 "
        "41 56 48 83 EC 30 49 8B D9 41 8B E8 48 8B F2 4C 8B F1",
        0x034CEFC0,
    ),
    (
        "PyEval_EvalCode",
        # 48 83 EC 58             sub rsp, 58
        # 33 C0                   xor eax, eax
        # 45 33 C9                xor r9d, r9d
        # 48 89 44 24 48          mov [rsp+48], rax
        # 89 44 24 40             mov [rsp+40], eax
        # 48 89 44 24 38          mov [rsp+38], rax
        # 89 44 24 30             mov [rsp+30], eax
        # 48 89 44 24 28          mov [rsp+28], rax
        # 89 44 24 20             mov [rsp+20], eax
        "48 83 EC 58 33 C0 45 33 C9 "
        "48 89 44 24 48 89 44 24 40 48 89 44 24 38 "
        "89 44 24 30 48 89 44 24 28 89 44 24 20",
        0x0350EAC0,
    ),
    (
        "PyErr_PrintEx",
        # 40 55                   push rbp
        # 53                      push rbx
        # 48 8B EC                mov rbp, rsp
        # 48 83 EC 48             sub rsp, 48
        # 8B D9                   mov ebx, ecx
        # 48 8B 0D ?? ?? ?? ??    mov rcx, [rip+disp32]
        # E8 ?? ?? ?? ??          call rel32
        # 85 C0                   test eax, eax
        # 74 05                   je +5
        "40 55 53 48 8B EC 48 83 EC 48 8B D9 "
        "48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 85 C0 74 05",
        0x034CE7C0,
    ),
    (
        "PyGILState_Ensure",
        # 48 89 5C 24 08          mov [rsp+8], rbx
        # 57                      push rdi
        # 48 83 EC 20             sub rsp, 20
        # 8B 0D ?? ?? ?? ??       mov ecx, [rip+disp32]
        # E8 ?? ?? ?? ??          call rel32
        # 48 8B D8                mov rbx, rax
        # 48 85 C0                test rax, rax
        # 75 31                   jne +31
        "48 89 5C 24 08 57 48 83 EC 20 "
        "8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 31",
        0x034DC0D0,
    ),
    (
        "PyGILState_Release",
        # 48 89 5C 24 08          mov [rsp+8], rbx
        # 57                      push rdi
        # 48 83 EC 20             sub rsp, 20
        # 8B F9                   mov edi, ecx
        # 8B 0D ?? ?? ?? ??       mov ecx, [rip+disp32]
        # E8 ?? ?? ?? ??          call rel32
        # 48 8B D8                mov rbx, rax
        # 48 85 C0                test rax, rax
        # 75 0C                   jne +0C
        "48 89 5C 24 08 57 48 83 EC 20 8B F9 "
        "8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 75 0C",
        0x034DC170,
    ),
]


# ======================================================================
# party_console.c 模板
#   @@IMAGE_BASE@@   -> 实际镜像基址
#   @@TIMESTAMP@@    -> 生成时间
#   @@RVA_DEFINES@@  -> 扫描得到的 RVA 宏定义
# ======================================================================

C_TEMPLATE = r"""/*
 * party_console.c - Python 2.7 交互式控制台注入 DLL
 *
 * 功能: AllocConsole -> 重定向 stdio -> code.interact()
 *
 * 目标: client.exe (静态链接 Python 2.7.3, imagebase @@IMAGE_BASE@@)
 * 生成: @@TIMESTAMP@@ (由 patch_finder.py 自动生成)
 */

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ===== Python C API 函数指针类型 ===== */
typedef void* (*FnPyImport_AddModule)(const char*);
typedef void* (*FnPyModule_GetDict)(void*);
typedef void* (*FnPy_CompileStringFlags)(const char*, const char*, int, void*);
typedef void* (*FnPyEval_EvalCode)(void*, void*, void*);
typedef void  (*FnPyErr_PrintEx)(int);
typedef int   (*FnPyGILState_Ensure)(void);
typedef void  (*FnPyGILState_Release)(int);

/* ===== RVA 偏移 (imagebase = @@IMAGE_BASE@@) ===== */
@@RVA_DEFINES@@

/* Py_file_input = 257 */
#define Py_file_input 257

/* ===== 注入后执行的 Python 代码 ===== */
static const char* PYTHON_CODE =
    "import sys, code\n"
    "sys.stdin = open('CONIN$', 'r')\n"
    "sys.stdout = open('CONOUT$', 'w')\n"
    "sys.stderr = open('CONOUT$', 'w')\n"
    "print 'Python 2.7 Interactive Console'\n"
    "print 'Type exit() to quit'\n"
    "code.interact()\n";

/* ===== 日志输出 ===== */
static void WriteLog(const char* msg)
{
    FILE* f;
    char  logPath[MAX_PATH];

    GetTempPathA(MAX_PATH, logPath);
    strcat_s(logPath, MAX_PATH, "party_console.log");

    if (fopen_s(&f, logPath, "a") == 0 && f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, msg);
        fclose(f);
    }
}

/* ===== 控制台线程 ===== */
static DWORD WINAPI ConsoleThread(LPVOID lpParam)
{
    /* 获取 client.exe 基址 */
    uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
    if (!base) {
        WriteLog("ERROR: GetModuleHandleA(NULL) failed");
        return 1;
    }

    /* 解析函数地址 */
    FnPyImport_AddModule    PyImport_AddModule    = (FnPyImport_AddModule)   (base + RVA_PyImport_AddModule);
    FnPyModule_GetDict      PyModule_GetDict      = (FnPyModule_GetDict)     (base + RVA_PyModule_GetDict);
    FnPy_CompileStringFlags Py_CompileStringFlags = (FnPy_CompileStringFlags)(base + RVA_Py_CompileStringFlags);
    FnPyEval_EvalCode       PyEval_EvalCode       = (FnPyEval_EvalCode)      (base + RVA_PyEval_EvalCode);
    FnPyErr_PrintEx         PyErr_PrintEx         = (FnPyErr_PrintEx)        (base + RVA_PyErr_PrintEx);
    FnPyGILState_Ensure     PyGILState_Ensure     = (FnPyGILState_Ensure)    (base + RVA_PyGILState_Ensure);
    FnPyGILState_Release    PyGILState_Release    = (FnPyGILState_Release)   (base + RVA_PyGILState_Release);

    /* 1. 分配控制台 */
    if (!AllocConsole()) {
        WriteLog("AllocConsole failed (may already have a console)");
    }

    /* 2. 重定向 C 标准流到控制台 */
    freopen("CONIN$", "r", stdin);
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);

    WriteLog("Console allocated, C stdio redirected");

    /* 3. 获取 GIL */
    WriteLog("Acquiring GIL...");
    int gstate = PyGILState_Ensure();
    WriteLog("GIL acquired");

    /*
     * ===== 手动拼接 PyRun_SimpleStringFlags =====
     *   m = PyImport_AddModule("__main__")
     *   d = PyModule_GetDict(m)
     *   co = Py_CompileStringFlags(code, "<console>", Py_file_input, NULL)
     *   v = PyEval_EvalCode(co, d, d)
     */

    /* Step 1: 获取 __main__ 模块 */
    void* mainModule = PyImport_AddModule("__main__");
    if (!mainModule) {
        WriteLog("ERROR: PyImport_AddModule failed");
        PyGILState_Release(gstate);
        return 1;
    }

    /* Step 2: 获取 __main__ 字典 */
    void* mainDict = PyModule_GetDict(mainModule);
    if (!mainDict) {
        WriteLog("ERROR: PyModule_GetDict failed");
        PyGILState_Release(gstate);
        return 1;
    }

    /* Step 3: 编译 Python 代码 */
    void* codeObj = Py_CompileStringFlags(PYTHON_CODE, "<console>", Py_file_input, NULL);
    if (!codeObj) {
        WriteLog("ERROR: Py_CompileStringFlags failed");
        PyErr_PrintEx(0);
        PyGILState_Release(gstate);
        return 1;
    }
    WriteLog("Console code compiled");

    /* Step 4: 执行 - code.interact() 会阻塞直到用户输入 exit() */
    void* result = PyEval_EvalCode(codeObj, mainDict, mainDict);
    if (!result) {
        WriteLog("ERROR: PyEval_EvalCode failed");
        PyErr_PrintEx(0);
    } else {
        WriteLog("Console session ended normally");
    }

    /* 4. 释放 GIL */
    PyGILState_Release(gstate);
    WriteLog("GIL released, console thread exiting");

    return 0;
}

/* ===== DLL 入口 ===== */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, ConsoleThread, hModule, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
"""


# ======================================================================
# PE 文件解析
# ======================================================================

def parse_pe(data):
    """解析 PE 头, 返回 (image_base, sections list)

    sections list 中每个元素:
        name, va, vsize, raw_ptr, raw_size, flags
    """
    if len(data) < 64 or data[:2] != b'MZ':
        raise ValueError("不是有效的 PE 文件 (缺少 MZ 标头)")

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
        raise ValueError("PE 签名无效")

    coff = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    size_opt_hdr = struct.unpack_from('<H', data, coff + 16)[0]

    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic == 0x20B:          # PE32+ (64-bit)
        image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    else:                       # PE32 (32-bit)
        image_base = struct.unpack_from('<I', data, opt + 28)[0]

    sections = []
    sec_base = opt + size_opt_hdr
    for i in range(num_sections):
        off = sec_base + i * 40
        raw = data[off:off + 40]
        sections.append({
            'name':     raw[0:8].rstrip(b'\x00').decode('ascii', errors='replace'),
            'va':       struct.unpack_from('<I', raw, 12)[0],
            'vsize':    struct.unpack_from('<I', raw, 8)[0],
            'raw_ptr':  struct.unpack_from('<I', raw, 20)[0],
            'raw_size': struct.unpack_from('<I', raw, 16)[0],
            'flags':    struct.unpack_from('<I', raw, 36)[0],
        })
    return image_base, sections


def file_offset_to_rva(sections, offset):
    """文件偏移 → RVA, 找不到返回 None"""
    for s in sections:
        start = s['raw_ptr']
        end = start + max(s['raw_size'], s['vsize'])
        if start <= offset < end:
            return offset - s['raw_ptr'] + s['va']
    return None


# ======================================================================
# 特征码编译与搜索
# ======================================================================

def compile_sig(sig_str):
    """将 '48 89 5C ?? ??' 编译为正则对象

    固定字节 -> re.escape(bytes([byte]))
    通配符 ?? -> b'.' (配合 re.DOTALL 匹配任意字节)
    """
    parts = sig_str.split()
    chunks = []
    for p in parts:
        if p == '??':
            chunks.append(b'.')
        else:
            chunks.append(re.escape(bytes([int(p, 16)])))
    return re.compile(b''.join(chunks), re.DOTALL)


def search_pattern(data, regex):
    """返回所有匹配的文件偏移列表"""
    return [m.start() for m in regex.finditer(data)]


def sig_byte_count(sig_str):
    """特征码总字节数 (含通配符)"""
    return len(sig_str.split())


def sig_fixed_count(sig_str):
    """特征码中固定字节数 (不含通配符)"""
    return sum(1 for p in sig_str.split() if p != '??')


# ======================================================================
# C 文件生成
# ======================================================================

def generate_c_file(found, image_base, output_path):
    """根据模板生成 C 源文件, RVA 值来自扫描结果

    found:       dict {函数名: RVA}
    image_base:  PE 镜像基址
    output_path: 输出文件路径
    """
    # 生成 RVA 宏定义块
    rva_lines = []
    for name, _, known_rva in SIGNATURES:
        rva = found.get(name)
        if rva:
            rva_lines.append("#define RVA_%-25s 0x%08X" % (name, rva))
        else:
            rva_lines.append("#define RVA_%-25s 0x%08X  /* 未找到, 使用已知值 */"
                             % (name, known_rva))
    rva_block = "\n".join(rva_lines)

    # 填充模板
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = C_TEMPLATE
    content = content.replace("@@IMAGE_BASE@@", "0x%016X" % image_base)
    content = content.replace("@@TIMESTAMP@@", ts)
    content = content.replace("@@RVA_DEFINES@@", rva_block)

    # 写入文件
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(content)

    return output_path


# ======================================================================
# 主函数
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        description="通过字节特征码自动定位 client.exe 中的 Python C API 函数地址",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('exe', help='client.exe 路径')
    parser.add_argument(
        '-oc', nargs='?', const='', default=None,
        help='生成基于 party_console.c 模板的 C 源文件; '
             '不带值时默认文件名 party_console_<时间>.c',
    )
    args = parser.parse_args()

    exe_path = args.exe

    try:
        with open(exe_path, 'rb') as f:
            data = f.read()
    except IOError as e:
        print("[!] 无法读取文件: %s" % e)
        sys.exit(1)

    print("=" * 76)
    print("  patch_finder - Python C API 函数地址自动定位")
    print("=" * 76)
    print("文件:       %s" % exe_path)
    print("大小:       %d 字节 (%.1f MB)" % (len(data), len(data) / 1048576.0))

    try:
        image_base, sections = parse_pe(data)
    except ValueError as e:
        print("[!] PE 解析失败: %s" % e)
        sys.exit(1)

    print("镜像基址:   0x%016X" % image_base)
    print("节区:       %d 个" % len(sections))
    for s in sections:
        exec_flag = "X" if s['flags'] & 0x20000000 else "-"
        print("  [%s] %-8s  VA=0x%08X  VSize=0x%08X  Raw=0x%08X  RSize=0x%08X"
              % (exec_flag, s['name'], s['va'], s['vsize'],
                 s['raw_ptr'], s['raw_size']))

    # ---- 逐个搜索 ----
    print("\n" + "=" * 76)
    print("%-25s  %-6s  %-12s  %-18s  %-12s  %-4s  %s"
          % ("函数", "状态", "RVA", "VA", "已知RVA", "匹配", "备注"))
    print("-" * 76)

    found = {}
    for name, sig_str, known_rva in SIGNATURES:
        regex = compile_sig(sig_str)
        matches = search_pattern(data, regex)
        n = len(matches)
        total_bytes = sig_byte_count(sig_str)
        fixed_bytes = sig_fixed_count(sig_str)

        if n == 0:
            print("%-25s  %-6s  %-12s  %-18s  %-12s  %-4d  %d字节(%d固定+%d通配)"
                  % (name, "失败", "N/A", "N/A",
                     "0x%08X" % known_rva, 0,
                     total_bytes, fixed_bytes, total_bytes - fixed_bytes))
            continue

        # 优先取在可执行节中的匹配
        rva = None
        for off in matches:
            r = file_offset_to_rva(sections, off)
            if r is not None:
                rva = r
                break

        if rva is None:
            print("%-25s  %-6s  %-12s  %-18s  %-12s  %-4d  (节区外)"
                  % (name, "异常", "N/A", "N/A",
                     "0x%08X" % known_rva, n))
            continue

        va = image_base + rva
        if n == 1:
            status = "OK"
        else:
            status = "多匹配"

        if rva == known_rva:
            note = "= 已知RVA"
        else:
            note = "!= 已知 (差 %+d)" % (rva - known_rva)

        print("%-25s  %-6s  0x%08X  0x%016X  0x%08X  %-4d  %s"
              % (name, status, rva, va, known_rva, n, note))
        found[name] = rva

    # ---- C 宏定义 ----
    print("\n" + "=" * 76)
    print("C 宏定义 (粘贴到 DLL 源码):")
    print("-" * 76)
    for name, sig_str, known_rva in SIGNATURES:
        rva = found.get(name)
        if rva:
            print("#define RVA_%-25s 0x%08X" % (name, rva))
        else:
            print("#define RVA_%-25s 0x%08X  /* 未找到, 使用已知值 */"
                  % (name, known_rva))

    # ---- 生成 C 文件 ----
    if args.oc is not None:
        if args.oc == '':
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = "party_console_%s.c" % ts
        else:
            out_path = args.oc

        generate_c_file(found, image_base, out_path)
        print("\n" + "=" * 76)
        print("[+] C 文件已生成: %s" % out_path)
        print("    模板: party_console.c (AllocConsole + code.interact)")
        print("    RVA:  %d/%d 已填充" % (len(found), len(SIGNATURES)))

    # ---- 汇总 ----
    total = len(SIGNATURES)
    ok = len(found)
    print("\n" + "=" * 76)
    print("汇总: %d/%d 函数已定位" % (ok, total))
    if ok == total:
        print("[+] 全部函数定位成功!")
    else:
        missing = [n for n, _, _ in SIGNATURES if n not in found]
        print("[!] 未找到: %s" % ", ".join(missing))
        print("    可能原因: client.exe 版本不同 / 代码已修改 / 文件被加壳")


if __name__ == '__main__':
    main()
