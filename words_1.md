## 资源获取（在线）

在u5或者说u5na更新系统中，就是VersionState阶段，会从在线自动获取资源

而资源表就有这些:

u5:

  - [Android](https://u5.update.netease.com/pl/npk_version_android.txt)
  
  - [IOS](https://u5.update.netease.com/pl/npk_version_ios.txt)

  - [PC](https://u5.update.netease.com/pl/npk_version_pc.txt)
  
  - [Linux](https://u5.update.netease.com/pl/npk_version_linux.txt) 

u5na(在神秘中需要使用神秘七个木棍才能访问):

  - [Android(Season 8)](https://u5na.update.easebar.com/pl/npk_version_android.txt)
  
  - [Android](https://u5na.update.easebar.com/pl/npk_version_android_new.txt)
  
  - [IOS](https://u5na.update.easebar.com/pl/npk_version_ios.txt)

这些url的特征就是，**都是json文件**，这意味着游戏就是解析这个文件实现更新检查的，如你hook掉这个文件的网络通讯然后把不必要内容删掉可以强行进入内测版

首先，我要告诉npk文件的获取方式：

npk获取文件，需要gph链接，通常是

`u5.gph.netease.com`等，若是u5na则把u5改成u5na然后把netease替换成easebar（其实不换也行）

然后，通过gph链接，进行文件拼接，需要先看这个json里面有哪些文件

<img width="1365" height="767" alt="None" src="https://github.com/user-attachments/assets/c470156f-578e-4a3c-b829-fe3d97cde1f7" />

就比如说这些，都是npk文件，这边以ext_packer_sound_1.npk为例（若是ext开头的npk则需要改成npkext开头的）

<img width="920" height="347" alt="图片" src="https://github.com/user-attachments/assets/45e862a5-b4ab-4b5e-a913-b96fcc26e0d1" />

http://u5.gph.netease.com/npkext_android_202611041827_4430397/ext_packer_sound_1.npk

（剩下的我真不知道该写点什么了，写到一半忘记了）
