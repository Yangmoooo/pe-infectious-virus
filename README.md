# 计算机病毒 PE病毒

## 实验环境：

* Windows 11 64位
* Visual Studio 2022
* *编译配置：Release x86*
* *编译器设置（C/C++）：禁用优化/Od（优化），禁用安全检查/GS-（代码生成），关闭移除未引用的代码和数据（语言），关闭符合模式/permissive（语言）*
* *链接器设置：子系统控制台 /SUBSYSTEM:CONSOLE（系统），关闭引用/OPT:NOREF（优化），启用COMDAT折叠/OPT:ICF（优化）*

## 目录结构：

*本实验测试程序均为32位，建议将目标程序复制到testing目录后运行病毒程序*

* /src目录：源码目录，包含病毒源码infect.cpp、shellcode.cpp、自制的目标程序target1&2源码
* /testing目录：测试目录，包含病毒程序infect.exe
* /testing/OriginalPE目录：自制的目标程序target1&2、非自制的目标程序PEview

## 程序功能：

*将infect.cpp和shellcode.cpp添加到VS项目infect中，生成infect.exe（使用/testing中已有的infect.exe亦可）*

* 运行infect.exe后，会向在infect.cpp中指定的exe文件（这里指定为PEview.exe）末尾插入病毒节.shcode并修改对应字段，该节通过shellcode.cpp中的 `#pragma code_seg(".shcode")` 预编译指令将整个shellcode.cpp作为单独的节.shcode得到
* 目标程序被感染后，运行时会先执行一段恶意函数（这里的功能为生成学号文件），然后遍历当前目录下的exe文件，感染其中的符合条件者（即未被感染过的合法PE文件），使其拥有与自身相同的行为，最后执行原本的正常功能
* 自制的目标程序target1.exe和target2.exe的功能分别是弹窗显示表情^_~和;-)

## 设计思路：

~~屁话部分~~

我已经有相当长的时间没有写过C程序了，很多原本就掌握得不好的知识更是一塌糊涂，这次的实验于我是有一定难度的，但我也想借这个机会好好复习下相关的内容。为了循序渐进，我将整个功能分成两块：infect.cpp和shellcode.cpp。前者的功能很简单，就是把自身的一个节插入到指定的exe文件末尾，同时修改目标文件的头部信息，使其仍为一个合法的正常exe文件；后者的功能是类似的，只是加了一个恶意功能，且目标变为了同目录的所有exe文件，但由于shellcode特殊的执行环境，难度更大。因此我先编写了infect.cpp，一方面熟悉C的语法，另一方面熟悉病毒主要功能（感染插入）的流程，然后再编写shellcode.cpp，在infect.cpp的基础上进行优化。作为记录，我保留了原本的~~稀烂~~infect.cpp，并没有再对它进行优化。

两份代码没有任何关联，shellcode.cpp仅仅在链接时作为.shcode节和infect.cpp一起生成infect.exe。这样的好处是实现infect.cpp时只需要实现插入和修改功能即可，不用考虑多余的事情，shellcode的功能就完全在shellcode.cpp里实现；不好之处在于它们的功能之间缺少逻辑联系，代码风格也不尽相同（这是我前后水平上的差异），产生了不恰当的分裂感。

下面提几个具体实现的重难点（infect.cpp和shellcode.cpp思路是差不多的，就以shellcode为例）：

1. 想要完成这个实验（如果按我的思路），首先得清楚认识到我们要做什么。我们实际上是想“把自身的一个节插入到另一个exe里”，根据我们对内存、磁盘的了解，更准确的说法应该是“把一段内存中的数据写入到磁盘文件里”。为什么不是文件->文件？因为当前程序占用了文件本身，无法从文件读入自身数据；为什么不是内存-> 内存？这个其实是可以的，而且效率可能更高，就是把目标文件通过map类函数映射到内存中再处理，但是步骤也更多，我就没有采用。
2. 对于“把一段内存中的数据写入到磁盘文件里”这句话，“内存中的数据”对应我们的.shcode节，“磁盘文件”就是我们的目标文件。原本infect.exe和目标exe都是磁盘文件，运行infect.exe的过程就是把infect.exe从磁盘里载入到内存中。我们就是要把内存里的.shcode节写入到磁盘里的目标exe里。并且，内存数据均为节对齐，磁盘数据均为文件对齐，所以过程中还要注意自身节对齐到目标文件对齐的转换。
3. 因为shellcode是直接插入到目标exe里的，并未参与目标exe的编译链接过程，所以在shellcode里无法直接通过库函数的名称来调用库函数（因为目标程序里的函数名称-地址映射信息对shellcode而言是错误的）。但我们知道，库函数是通过各种动态链接库dll来导入到程序里的，而且在kernel32.dll里有两个函数LoadLibraryA()和GetProcAddress()，可以将任何一个dll导入并获取dll中指定函数的基址，有了库函数的基址我们就可以通过函数指针的方式来调用库函数。
4. 查找程序自身和kernel32的基址是通过TEB->PEB->Ldr->InMemoryModuleList，TEB在fs:[0]，PEB在fs:[0x30]，Ldr在[fs:[0x30]]+0x0c，InMemoryModuleList在[[fs:[0x30]]+0x0c]+0x14，我通过汇编得到了InMemoryModuleList的指针。这个结构体构造比较奇特，建议搜索下具体结构看看。其实有三种List，它们都保存模块的信息，但InMemoryModuleList是按载入内存的顺序排列的，故第一个节点一定是当前程序本身，所以这里使用InMemoryOrderLinks来移动查找节点，该Links包含前向Flink和后向Blink指针，在查找时，应当注意这个Links本身就对应了一定的偏移0x008，它指向的下一个节点也同样是这个位置，所以要得到0x018的DllBase，就只需要加上0x010的偏移即可。对于查找指定模块（如kernel32）的基址，也是一样，通过指定名称为KERNEL32.DLL的BaseDllName，来遍历链表，不仅也要注意指针本身的0x008偏移，而且_UNICODE_STRING结构体的后四个字节才是真正指向其名字的指针，所以我使用的查找偏移为0x028。
5. 得到kernel32的基址后就可以在其中找到LoadLibraryA()和GetProcAddress()，方法是通过dll的导出目录找到函数导出表，即名字表、序号表、地址表，根据库函数名称在名字表中的位置来得到在序号表中的序号，再根据序号在地址表里找到其地址。我们已经有了库函数的地址，应该怎么样来使用它呢？这里我定义了名为pLoadLibraryA和pGetProcAddress的函数指针，并按照Windows文档里的内容声明了一模一样的参数、返回值和调用方式（WINAPI对应__stdcall，WINAPIV对应__cdecl），然后再以pLoadLibraryA和pGetProcAddress类型定义两个名为LoadLibraryA和GetProcAddress的变量，这样一来，这个变量虽然是我们自定义的，但却和真正的这个函数是一模一样的了。需要注意的是要使用字符数组，字符串会无法找到。
6. 为了不丢失被感染exe原有的功能，我们需要在执行完恶意和感染部分后跳转回原本的程序入口点。因此我先将原本的EntryPoint写到了DOS stub的最后四个字节（也就是NT Header的前四个字节），然后再填充新的入口点。
