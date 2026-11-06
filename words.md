需要逆向的游戏为u5（蛋仔派对）

该游戏opcodes含有非标准opcode，且magic number是标准的magic + 1（数字，如62212）

非标准opcode指游戏内含有OPEXT_开头的CISC opcodes

游戏的脚本包是script.npk，在官方电脑版本（发烧）版本采用了AES-256-ECB（v2）+rotor加密，但是是魔改的AES

发烧版本的script.npk需要先提取redirect.nxs并还原字节码（记得拆解CISC字节码成标准）然后uncompyle6

然后，可以在NpkImporter这个class中看到有关C_file的引用，在发烧版本，是直接将文件名的哈希作为salt

salt可以通过获取file_list并且解密file_list拿到路径哈希，就是path_id，那个就是salt

发烧版本的script是不完全v2的，部分是rotor（如json模块啥的）

rotor的话随便解了，Github上其他的大佬是做了有关阴阳师的研究啥的，详情需看[NeoxResearch](https://github.com/ZhangFengze/NeoxResearch)这个项目，这里面有解密rotor相关逻辑

解密file_list的话，就需要反汇编python层的那个package模块中的pkg_decrypt函数，查找是3且参数为'ppk'的（是魔改AES-128-ECB）

然后拿到了之后，跳过4字节文件头然后读取就好了，虽然说如果可以动态调试（如注入获取游戏客户端python执行权限，但是发烧版给python的PyRun_SimpleString整个搞成空气了，反正我看IDA的时候没看到，需要自己那5个函数的RVA手动拼一个，或者看看`patch_finder.py`），则可以通过项目`README.md`中提到的方法

(Not complete)
