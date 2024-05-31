# PE virus

一个简单的 32 位 Windows 病毒，被感染的 PE 文件在执行时会生成一个空文件，并感染同目录下的所有 PE 文件。

## 使用方法

`/bin` 目录下包含病毒程序 `pe-virus.exe`、自制的目标程序 `msgboxA.exe` 和 `msgboxB.exe` 以及非自制的目标程序 `PEview.exe`。

```powershell
.\pe-virus.exe <目标程序>
```

建议新建目录后在隔离环境下测试。

* `pe-virus.exe` 会在指定的目标程序末尾插入病毒节 .shcode，并修改其头部的相应字段使其仍为合法的 PE 文件
* .shcode 节是通过 `shellcode.c` 中的 `#pragma code_seg(".shcode")` 预编译指令将整个文件编译为一个单独的节得到的
* 目标程序被感染后，在运行时会先执行一段恶意函数，然后遍历同目录下的 exe 文件，感染其中的符合条件者（即未被感染过的合法 PE 文件），使其拥有与自身相同的行为，最后执行目标程序原本的正常功能

## VS 项目属性

* 配置平台：Release x86
* C/C++ 设置：
  * 优化：禁用**优化** (/Od)
  * 代码生成：禁用**安全检查** (/GS-)
  * 语言：关闭**移除未引用的代码和数据**、关闭**符合模式** (/permissive)
* 链接器设置：
  * 系统：**子系统**为控制台 (/SUBSYSTEM:CONSOLE)
  * 优化：关闭**引用** (/OPT:NOREF)、**启用 COMDAT 折叠** (/OPT:ICF)、使用**链接时间代码生成** (/LTCG)

## 实现思路

整理了一下原本的实验代码，源文件为 `infect.c` 和 `shellcode.c`。前者能将自身的一个节插入到目标 PE 文件末尾，同时修改其头部信息确保依然合法；后者的功能与之类似，添加了一个恶意功能，且目标变为了同目录的所有 exe 文件。两个源文件之间没有任何关联，尤其是对于病毒程序 `pe-virus.exe` 来说，实际上只执行了 `infect.c`，而 `shellcode.c` 仅仅被编译为节，作为载荷被注入到目标程序里。

下面以 `shellcode.c` 为例，分析具体实现中的一些要点：

1. 感染的过程是将内存中程序自身的 .shcode 节写入到目标磁盘文件里，这里注意到内存数据为节对齐，磁盘数据为文件对齐，故需要有由自身的节对齐到目标的文件对齐的转换。
2. 因为 shellcode 是直接写入到目标文件里的，并未参与其编译链接过程，所以在 shellcode 中无法直接通过库函数的名称来调用库函数（因为目标程序里的函数名称-地址映射信息对 shellcode 而言是错误的）。但是，库函数也是通过各种动态链接库 DLL 来导入到程序里的，并且几乎所有的 32 位 Windows 程序都会链接 `kernel32.dll`，而其中有两个函数 `LoadLibraryA()` 和 `GetProcAddress()`，可以导入任何一个 DLL 并获取其中指定函数的基址，有了库函数的基址后就能够通过函数指针的方式来调用库函数。
3. 查找程序自身和 kernel32 的基址是通过 TEB -> PEB -> Ldr -> InMemoryModuleList 做到的。TEB在 `fs:[0]`，PEB 在 `fs:[0x30]`，Ldr 在 `[fs:[0x30]]+0x0c`，InMemoryModuleList在 `[[fs:[0x30]]+0x0c]+0x14`，可以通过内联汇编得到 InMemoryModuleList 的指针。该结构体构造比较奇特，建议查阅下具体结构。系统中有三种保存了模块信息的 List，但 InMemoryModuleList 是按载入内存的顺序排列的，故第一个节点一定是当前程序本身，所以这里使用 InMemoryOrderLinks 来移动查找节点，该 Links 包含前向 Flink 和后向 Blink 指针，在查找时，应当注意这个 Links 本身就对应了一定的偏移 0x008，它指向的下一个节点也同样是这个位置，所以要得到 0x018 的 DllBase，只需要加上 0x010 的偏移即可。对于查找指定模块（如 kernel32）的基址也是一样，通过指定名称为 `KERNEL32.DLL` 的 BaseDllName 来遍历链表，同时也要注意指针自身的 0x008 偏移，且 _UNICODE_STRING 结构体的后四个字节才是真正指向其名字的指针，所以应使用的查找偏移为 0x028。
4. 得到 kernel32 的基址后就可以在其中找到 `LoadLibraryA()` 和 `GetProcAddress()`，方法是通过 DLL 的导出目录找到函数导出表，即名字表、序号表、地址表，根据库函数名称在名字表中的位置来得到在序号表中的序号，再根据序号在地址表里找到其地址。在有了库函数的地址后，可以声明名为 pLoadLibraryA 和 pGetProcAddress 的函数指针，并按照 Windows 文档使用完全相同的参数、返回值和调用方式（WINAPI 对应 stdcall，WINAPIV 对应 cdecl），然后再用 pLoadLibraryA 和 pGetProcAddress 类型定义名为 LoadLibraryA 和 GetProcAddress 的变量。这样一来，虽然该函数是自定义的，但却和真正的没有区别。需要注意的是要使用字符数组，字符串在 shellcode 中是无法找到的。
5. 为了让被感染的程序不丢失原有的功能，还需要在执行完恶意函数和感染功能后跳转回原本的程序入口点。因此这里先将原本的 EntryPoint 写到了 DOS stub 的最后四个字节（也就是 NT Header 的前面四个字节），然后再填充新的入口点。
