# New-EggyPartyNeoXResearch
针对蛋仔派对的网易NeoX引擎的研究 但是第二次

## 为什么做这个
之前的已经失效了，因为他们换了sth
而且之前做的那个我都没分析完成，就做了

## 逆向思路
依旧从Eggitor先入手，需要使用老版本的Eggitor，这先贴上下载地址

[u5 editor](https://u5.gdl.netease.com/Eggitor_Installer_1.0.11.exe)

这个版本的client.exe拥有导出函数，好分析

首先，写一个注入用的DLL：

就比如说这个 [nxconsole](https://github.com/ExMC-Github/New-EggyPartyNeoXResearch/blob/main/nxconsole.cpp)

可以优先使用bin文件夹的cmdtxt1.py，然后打开code.interact直接拿到真实python环境

先通过python命令将opcode.opmap导出为txt

```python
import opcode; a = open('opmap.txt','r'); a.write(str(opcode.opmap)); a.close()
```

然后就可以拿到opcode map来进行下一步分析

### redirect

从python中有个叫C_file的模块，可以直接访问NeoX的VFS，通过`C_file.get_file('redirect.nxs','')`就可以获得redirect的marshal string

然后从之前提取的opmap.txt可以发现，有一堆OPEXT_开头的字节码，这一看就不是python的

那么，就需要分析PyEval_EvalCodeEx了，再次之前，先用某些方法得到NeoX opcode -> standard opcode的映射表（OPEXT的话，这是类似CISC指令集的命令，就是一个命令里面就是两个命令的结合体，到时候解析的时候拆开就好了）

#### 关于为什么不用自带的dis

dz官方那个神秘，把dis的所有print都直接pass，用毛啊

代码先说到这，来说点其他的

## 资源获取

研究过NPK基本上都知道，NPK里面的都是hash，文件名都是hash，这该怎么办呢

官方在服务器上刚好放了map和file_list文件，直接拿来用

需要先拼接URL来GET正确资源

首先贴上json链接：

[u5.update.netease.com/pl/npk_version_android.txt](https://u5.update.netease.com/pl/npk_version_android.txt)

将version字段(如patch_android_202609021825_4250747)提取出来，进行URL拼接

`http://u5.gph.netease.com/{version}/assets.ppk.map`

如`http://u5.gph.netease.com/patch_android_202609021825_4250747/assets.ppk.map`

即可获取到map文件，map文件是一种pbin格式，或者说file_list文件都是这种

dz的ptutils.py里面有这些:

```
E:\reverse\script_v2_decrypter\script\patch>uncompyle6 ptutils.pyc
# uncompyle6 version 3.9.3
# Python bytecode version base 2.7 (62211)
# Decompiled from: Python 3.14.6 (heads/main:343dbf9, Sep  3 2026, 19:38:38) [MSC v.1951 64 bit (AMD64)]
# Embedded file name: patch\ptutils.py


def legacy_load_bin_file(file_path):
    output = None
    with open(file_path, 'rb') as f:
        output = legacy_load_bin(f.read())
    return output


def legacy_load_bin(data):
    import base64, cPickle
    return cPickle.loads(base64.b64decode(data))


PBIN_SIGNATURE = 'PZ$C'
PBIN_ENCRYPT_SIGNATURE = 'PZ$E'

def load_compressed_bin_file(file_path):
    import zstd
    out = None
    with open(file_path, 'rb') as fp:
        data = fp.read(4)
        if data == PBIN_SIGNATURE:
            zdata = fp.read()
            if len(zdata) == 0:
                return ''
            out = zstd.decompress(zdata)
        elif data == PBIN_ENCRYPT_SIGNATURE:
            zdata = fp.read()
            if len(zdata) == 0:
                return ''
            import package
            zdata = package.pkg_decrypt(3, zdata, 'ppk')
            out = zstd.decompress(zdata)
        else:
            out = legacy_load_bin(data + fp.read())
    return out


def load_compressed_json_file(file_path):
    import json
    data = load_compressed_bin_file(file_path)
    return json.loads(data)


NETWORK_4G_NO_TIP_SIZE = 157286400
return

# okay decompiling ptutils.pyc

E:\reverse\script_v2_decrypter\script\patch>
```

可以看到，这里面有加载pbin文件的函数

那么就可以在运行时直接
```python
from patch import ptutils
bin_file = '此处应替换成bin文件地址'
data = ptutils.load_compressed_bin_file(bin_file)
a = open(bin_file + ".txt",'wb')
a.write(data)
a.close()
```

就可以直接获得原始的文件了

具体怎么获取资源就不细说了，这边说一下怎么获取资源数据

用C_file模块的get_res_file函数，这是调用方式:

`C_file.get_res_file('gui2/background/bg_login.png')`

类似这种的获取方式，如果说failed的话，那么把png换成kta再试试就好了
