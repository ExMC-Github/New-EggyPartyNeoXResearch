## 其他的什么东西

### 资源获取（在线）

在u5(u5na)的更新系统中，就是VersionState阶段，会从在线自动获取资源

而资源表就有这些:

u5:

  - [Android](https://u5.update.netease.com/pl/npk_version_android.txt)
  
  - [iOS](https://u5.update.netease.com/pl/npk_version_ios.txt)

  - [PC](https://u5.update.netease.com/pl/npk_version_pc.txt)

  - [Eggitor](https://u5.update.netease.com/pl/npk_version_ed.txt) (*End of Line on 2026/06/03*)
  
  - [Linux](https://u5.update.netease.com/pl/npk_version_linux.txt) 

u5na(需要使用境外网络才能访问):

  - [Android(OLD)](https://u5na.update.easebar.com/pl/npk_version_android.txt) (Season 8)
  
  - [Android(NEW)](https://u5na.update.easebar.com/pl/npk_version_android_new.txt)
  
  - [iOS(OLD)](https://u5na.update.easebar.com/pl/npk_version_ios.txt)

  - [iOS(NEW)](https://u5na.update.easebar.com/pl/npk_version_ios_new.txt)

这些url的特征就是，**都是json文件**，游戏就是解析这个文件实现更新检查的（如中间人替换掉这个文件的网络通讯然后把不必要内容删掉可以强行进入内测版）

首先，我要告诉npk文件的获取方式：

npk获取文件，需要gph链接，通常是

`u5.gph.netease.com`等，若是u5na则把u5改成u5na然后把netease替换成easebar（其实不换也行）

然后，通过gph链接，进行文件拼接，需要先看这个json里面有哪些文件

<img width="1365" height="767" alt="None" src="https://github.com/user-attachments/assets/c470156f-578e-4a3c-b829-fe3d97cde1f7" />

就比如说这些，都是npk文件，这边以ext_packer_sound_1.npk为例（若是ext开头的npk则需要改成npkext开头的）

<img width="920" height="347" alt="图片" src="https://github.com/user-attachments/assets/45e862a5-b4ab-4b5e-a913-b96fcc26e0d1" />

http://u5.gph.netease.com/npkext_android_202611041827_4430397/ext_packer_sound_1.npk

然后呢，也key下载file_list，如

http://u5.gph.netease.com/npkext_android_202611041827_4430397/ext_packer_sound_1_file_list

多端的话，得看npkext和version字段，直接替换就行了

linux端的话，比较特殊，一般是这样的

https://u5.gph.netease.com/linux/24/assets/script.npk

**`https://u5.gph.netease.com/linux/` + 版本 + 路径** 的样子

linux端没有npkext_version字段，因为根本不需要，直接加就行了，linux版本也可以直接下client

https://u5.gph.netease.com/linux/24/bin/client

### 神秘

扎啤的wy**拿AI开发Linux版本**，依赖都不装全，还得自己apt装，麻烦

而且，好像还是用arch + WSL开发的，因为启动脚本里面写的是d3d和WSL，我主机的Debian 13根本跑不起来

给我提示GLIBC版本过久，这可不是换依赖就能解决的东西

另外，这是他们的eggitor文档

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/c8d4cc0e-f658-4860-a791-d5f278d65b5e" />

还有扫符号环节

这一堆DLL我有类似的，我记得还有pyworld.dll什么的，从wy的其他游戏拿到了（也是真粗心啊测试的东西放着不删）

（不知道写什么了）
