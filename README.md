# 计算机病毒 PE病毒

make即可

helloworld0.exe和helloworld1.exe源程序是helloworld0.asm和helloworld1.asm，使用masm32v11编译链接得到，命令为：

ml /c /coff helloworld0.asm

link /subsystem:windows helloworld0.obj

ml /c /coff helloworld1.asm

link /subsystem:windows helloworld1.obj
