# Bomb Lab

## 介绍

“二进制炸弹”是作为目标代码文件提供给学生的程序。 运行时，它提示用户输入6个不同的字符串。 如果其中任何一个不正确，炸弹就会“爆炸”，学生必须通过拆卸和逆向工程程序来“消散”自己独特的炸弹，以确定6个字符串应该是什么。该实验室教会学生理解汇编语言，并强迫他们学习如何使用调试器。

[实验地址](http://csapp.cs.cmu.edu/3e/labs.html)

[README文档](http://csapp.cs.cmu.edu/3e/README-bomblab)

[实验指导](http://csapp.cs.cmu.edu/3e/bomblab.pdf)

## 实验步骤

使用GDB逆向工程推断6个字符串。设置断点，一步一步调试，找到`explode_bomb`的跳转命令，结合逻辑和寄存器的值进行判断字符串的值。



<p align="center">
<img src="https://s3.ax1x.com/2020/12/29/rqFoFg.png" width="400">
</p>



每一个炸弹都是从`read_line()`函数从输入流stdin中读取的，存放于input变量中，对应`%rax`寄存器中，将`%rax`的值赋给`%rdi`作为参数传递给`phase_x`函数，**`%rdi`中存放的是字符串的首地址**。

[gdb帮助文档](http://csapp.cs.cmu.edu/3e/docs/gdbnotes-x86-64.pdf)

## phase_1

在命令行中使用以下命令：
```bash
调试bomb可执行程序
unix> gdb bomb 

反汇编phase_1函数
gdb> disas phase_1
```
得到：
```bash
gdb) disas phase_1
Dump of assembler code for function phase_1:
   0x0000000000400ee0 <+0>:	sub    $0x8,%rsp
   0x0000000000400ee4 <+4>:	mov    $0x402400,%esi
   0x0000000000400ee9 <+9>:	callq  0x401338 <strings_not_equal>
   0x0000000000400eee <+14>:	test   %eax,%eax
   0x0000000000400ef0 <+16>:	je     0x400ef7 <phase_1+23>
   0x0000000000400ef2 <+18>:	callq  0x40143a <explode_bomb>
   0x0000000000400ef7 <+23>:	add    $0x8,%rsp
   0x0000000000400efb <+27>:	retq
End of assembler dump.
```

1. 字符串首地址在`%rdi`寄存器中。
2. 申请8个字节的栈空间。
3. 将立即数`0x402400`存放到`%esi`寄存器中（第二个参数寄存器）。
4. 调用字符串比较函数，比较是否相同，结果返回于`%eax`中。
5. 检查`%eax`中的值是否为0，为0跳转到<phase_1+23>，跳过引爆炸弹的函数。
6. 否则执行explod_bomb函数，回收栈空间。

故`%esi`寄存器存放的指向字符串的地址便是第一个字符串。

在phase_1和explode_bomb处设置断点并运行，检查`%rsi`寄存器指向字符串的值。

<p align="center">
<img src="https://s3.ax1x.com/2020/12/29/rqFMLV.png" width="400">
</p>

第一个字符串便是`Border relations with Canada have never been better.`。

第一个💣解除。

## phase_2

同样的步骤查看`phase_2`函数的反汇编代码：
```bash
(gdb) disas phase_2
Dump of assembler code for function phase_2:
   0x0000000000400efc <+0>:	push   %rbp
   0x0000000000400efd <+1>:	push   %rbx
   0x0000000000400efe <+2>:	sub    $0x28,%rsp
   0x0000000000400f02 <+6>:	mov    %rsp,%rsi
   0x0000000000400f05 <+9>:	callq  0x40145c <read_six_numbers>
   0x0000000000400f0a <+14>:	cmpl   $0x1,(%rsp)
   0x0000000000400f0e <+18>:	je     0x400f30 <phase_2+52>
   0x0000000000400f10 <+20>:	callq  0x40143a <explode_bomb>
   0x0000000000400f15 <+25>:	jmp    0x400f30 <phase_2+52>
   0x0000000000400f17 <+27>:	mov    -0x4(%rbx),%eax
   0x0000000000400f1a <+30>:	add    %eax,%eax
   0x0000000000400f1c <+32>:	cmp    %eax,(%rbx)
   0x0000000000400f1e <+34>:	je     0x400f25 <phase_2+41>
   0x0000000000400f20 <+36>:	callq  0x40143a <explode_bomb>
   0x0000000000400f25 <+41>:	add    $0x4,%rbx
   0x0000000000400f29 <+45>:	cmp    %rbp,%rbx
   0x0000000000400f2c <+48>:	jne    0x400f17 <phase_2+27>
   0x0000000000400f2e <+50>:	jmp    0x400f3c <phase_2+64>
   0x0000000000400f30 <+52>:	lea    0x4(%rsp),%rbx
   0x0000000000400f35 <+57>:	lea    0x18(%rsp),%rbp
   0x0000000000400f3a <+62>:	jmp    0x400f17 <phase_2+27>
   0x0000000000400f3c <+64>:	add    $0x28,%rsp
   0x0000000000400f40 <+68>:	pop    %rbx
   0x0000000000400f41 <+69>:	pop    %rbp
   0x0000000000400f42 <+70>:	retq
End of assembler dump.
```
我们可以看到将`%rbp`和`%rbx`压入栈后，请求了0x28大小的栈空间，将`%rsp`赋给`%rsi`第二个寄存器，第一个参数寄存器是`%rdi`，然后进去了`read_six_numbers`函数，根据名字是估计读入6个数字的函数。

我们进入`read_six_numbers`函数一探究竟。

```bash
(gdb) disas read_six_numbers
Dump of assembler code for function read_six_numbers:
   0x000000000040145c <+0>:	sub    $0x18,%rsp
   0x0000000000401460 <+4>:	mov    %rsi,%rdx
   0x0000000000401463 <+7>:	lea    0x4(%rsi),%rcx
   0x0000000000401467 <+11>:	lea    0x14(%rsi),%rax
   0x000000000040146b <+15>:	mov    %rax,0x8(%rsp)
   0x0000000000401470 <+20>:	lea    0x10(%rsi),%rax
   0x0000000000401474 <+24>:	mov    %rax,(%rsp)
   0x0000000000401478 <+28>:	lea    0xc(%rsi),%r9
   0x000000000040147c <+32>:	lea    0x8(%rsi),%r8
   0x0000000000401480 <+36>:	mov    $0x4025c3,%esi
   0x0000000000401485 <+41>:	mov    $0x0,%eax
   0x000000000040148a <+46>:	callq  0x400bf0 <__isoc99_sscanf@plt>
   0x000000000040148f <+51>:	cmp    $0x5,%eax
   0x0000000000401492 <+54>:	jg     0x401499 <read_six_numbers+61>
   0x0000000000401494 <+56>:	callq  0x40143a <explode_bomb>
   0x0000000000401499 <+61>:	add    $0x18,%rsp
   0x000000000040149d <+65>:	retq
End of assembler dump.
```
逐指令分析：
1. 申请0x18大小的栈空间，24个字节。
2. 将`%rsi`赋给`%rdx`寄存器，`%rsi`是`phase_2`传入进来的参数，内容是调用函数之前的`%rsp`。
3. 将`%rsi`加上0x4赋给`rcx`寄存器。
4. 将`%rsi`加上0x14赋给`rax`寄存器。
5. 将`%rax`赋给`%rsp`+0x8偏移量指向的内存中。
6. 将`%rsi`加上0x10赋给`rax`寄存器。
7. 将`%rax`赋给`%rsp`指向的内存中。
8. 将`%rsi`加上0xc赋给`%r9`寄存器。
9. 将`%rsi`加上0x8赋给`%r8`寄存器。
10. 将立即数0x4025c3赋给`%esi`寄存器。
11. 将`eax`置为0。
12. 调用`sscanf`函数。

`sscanf`函数的语法是：
```c
int sscanf(const char *buffer, const char *format, [argument]...); 
```
第一个参数是起始地址，第二个参数是格式字符串，第三个是参数变量。
我们观察一下此时各个寄存器的内容。
| %rax | %rdi | %rsi | %rdx | %rcx | %r8 | %r9 | 
| ---  | ---  | ---  | ---  | ---  | --- | --- | 
|  0x0 | 第二个字符串地址 | 0x4025c3 | 调用函数之前的%rsp | 调用函数之前的%rsp + 0x4 | 调用函数之前的%rsp + 0x8 | 调用函数之前的%rsp + 0xc | 调用函数之前的%rsp + 0x1c | 
| 返回值 | 第一个参数寄存器 | 第二个参数寄存器 | 第三个参数寄存器 | 第四个参数寄存器 | 第五个参数寄存器 | 第六个参数寄存器 | 

可以想到`%rdi`对应第一个参数起始地址;

`%rsi`对应第二个参数对应格式字符串;

`%rdx`对应`&buffer[0]`;

`%rcx`对应`&buffer[1]`;

`r8`对应`&buffer[2]`;

`r9`对应`&buffer[3]`;

`调用函数前的%rsp + 0x10`，也就是`函数内的%rsp`对应`&buffer[4]`;

`调用函数前的%rsp + 0x14`，也就是`函数内的%rsp+0x8`对应`&buffer[5]`。

我们将进入`read_six_number`函数内执行到调用`sscanf`函数之前，查看`%rsi`的内容
```bash
(gdb) x/s $esi
0x4025c3:	"%d %d %d %d %d %d"
```
验证成功是，六个数字的输入格式控制符。
我们回到`phase_2`函数：
```bash
(gdb) disas phase_2
Dump of assembler code for function phase_2:
   0x0000000000400efc <+0>:	push   %rbp
   0x0000000000400efd <+1>:	push   %rbx
   0x0000000000400efe <+2>:	sub    $0x28,%rsp
   0x0000000000400f02 <+6>:	mov    %rsp,%rsi
   0x0000000000400f05 <+9>:	callq  0x40145c <read_six_numbers>
=> 0x0000000000400f0a <+14>:	cmpl   $0x1,(%rsp)
   0x0000000000400f0e <+18>:	je     0x400f30 <phase_2+52>
   0x0000000000400f10 <+20>:	callq  0x40143a <explode_bomb>
   0x0000000000400f15 <+25>:	jmp    0x400f30 <phase_2+52>
   0x0000000000400f17 <+27>:	mov    -0x4(%rbx),%eax
   0x0000000000400f1a <+30>:	add    %eax,%eax
   0x0000000000400f1c <+32>:	cmp    %eax,(%rbx)
   0x0000000000400f1e <+34>:	je     0x400f25 <phase_2+41>
   0x0000000000400f20 <+36>:	callq  0x40143a <explode_bomb>
   0x0000000000400f25 <+41>:	add    $0x4,%rbx
   0x0000000000400f29 <+45>:	cmp    %rbp,%rbx
   0x0000000000400f2c <+48>:	jne    0x400f17 <phase_2+27>
   0x0000000000400f2e <+50>:	jmp    0x400f3c <phase_2+64>
   0x0000000000400f30 <+52>:	lea    0x4(%rsp),%rbx
   0x0000000000400f35 <+57>:	lea    0x18(%rsp),%rbp
   0x0000000000400f3a <+62>:	jmp    0x400f17 <phase_2+27>
   0x0000000000400f3c <+64>:	add    $0x28,%rsp
   0x0000000000400f40 <+68>:	pop    %rbx
   0x0000000000400f41 <+69>:	pop    %rbp
   0x0000000000400f42 <+70>:	retq
End of assembler dump.
```

发现将`%rsp`起始地址指向的内容和0x1比较。也就是`buffer[0]`，如果相等就跳转到`<phase_2+52>`否则就引爆炸弹，所以可以判定`buffer[0] = 1`；

将`%rsp`加上0x4赋给`%rbx`，也就是将`&buffer[1]`的值赋给了`rbx`寄存器；

将`%rsp`加上0x18赋给`%rbp`，将`&buffer[6]`的值赋给了`rbp`寄存器也就是数组的临界地址；

接着跳转到`<phase_2+27>`，将`%rbx`减0x4后的地址指向的内容赋给`%eax`，也就是`%eax = buffer[0]`，将`%eax`扩大1倍，然后与`%rbx`地址指向的内容进行比较，如果不相等引爆炸弹，相等接着跳转。
...
可以发现就是在比较
```c
buffer[5] = 2 * buffer[4];
buffer[4] = 2 * buffer[3];
...
buffer[1] = 2 * buffer[0];
buffer[0] = 1;
```
所以字符串的内容便是`1 2 4 8 16 32`。

第二个💣解除。

## phase_3

```bash
(gdb) disas phase_3
Dump of assembler code for function phase_3:
   0x0000000000400f43 <+0>:	sub    $0x18,%rsp
   0x0000000000400f47 <+4>:	lea    0xc(%rsp),%rcx
   0x0000000000400f4c <+9>:	lea    0x8(%rsp),%rdx
   0x0000000000400f51 <+14>:	mov    $0x4025cf,%esi
   0x0000000000400f56 <+19>:	mov    $0x0,%eax
   0x0000000000400f5b <+24>:	callq  0x400bf0 <__isoc99_sscanf@plt>
   0x0000000000400f60 <+29>:	cmp    $0x1,%eax
   0x0000000000400f63 <+32>:	jg     0x400f6a <phase_3+39>
   0x0000000000400f65 <+34>:	callq  0x40143a <explode_bomb>
   0x0000000000400f6a <+39>:	cmpl   $0x7,0x8(%rsp)
   0x0000000000400f6f <+44>:	ja     0x400fad <phase_3+106>
   0x0000000000400f71 <+46>:	mov    0x8(%rsp),%eax
   0x0000000000400f75 <+50>:	jmpq   *0x402470(,%rax,8)
   0x0000000000400f7c <+57>:	mov    $0xcf,%eax
   0x0000000000400f81 <+62>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f83 <+64>:	mov    $0x2c3,%eax
   0x0000000000400f88 <+69>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f8a <+71>:	mov    $0x100,%eax
   0x0000000000400f8f <+76>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f91 <+78>:	mov    $0x185,%eax
   0x0000000000400f96 <+83>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f98 <+85>:	mov    $0xce,%eax
   0x0000000000400f9d <+90>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400f9f <+92>:	mov    $0x2aa,%eax
   0x0000000000400fa4 <+97>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400fa6 <+99>:	mov    $0x147,%eax
   0x0000000000400fab <+104>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400fad <+106>:	callq  0x40143a <explode_bomb>
   0x0000000000400fb2 <+111>:	mov    $0x0,%eax
   0x0000000000400fb7 <+116>:	jmp    0x400fbe <phase_3+123>
   0x0000000000400fb9 <+118>:	mov    $0x137,%eax
   0x0000000000400fbe <+123>:	cmp    0xc(%rsp),%eax
   0x0000000000400fc2 <+127>:	je     0x400fc9 <phase_3+134>
   0x0000000000400fc4 <+129>:	callq  0x40143a <explode_bomb>
   0x0000000000400fc9 <+134>:	add    $0x18,%rsp
   0x0000000000400fcd <+138>:	retq
End of assembler dump.
```
有了上一个phase的经验，我们之间查看`%esi`的内容：
```bash
(gdb) x/s $esi
0x4025cf:	"%d %d"
```
我们可以推断输入的字符串包含2个整数。一个存放在`%rsp+0x8`，一个存放在`%rsp+0xc`中。

`cmpl $0x7,0x8(%rsp)`，比较第一个数与0x7的大小关系，如果大于7跳到<+106>引爆炸弹。
由于是`ja`命令所以，第一个数的范围是`0-6`的整数。

将`mov 0x8(%rsp),%eax`将第一个数赋给`%eax`，`jmpq   *0x402470(,%rax,8)`，根据第一个数的值进行一次间接跳转。我们分别测试第一个数`0-6`，可以得到不同的间接跳转，发现每个跳转都是第二个数与某个立即数进行比较。我们可以得到下表。

| 第一个参数 | 第二个参数 |
| --- | --- |
| 0 | 207 |
| 1 | 311 |
| 2 | 707 |
| 3 | 256 |
| 4 | 389 |
| 5 | 206 |
| 6 | 682 |

所以字符串的内容是上表中的任意一对数，例如`0 207`。

第三个💣解除。


## phase_4

```bash
(gdb) disas phase_4
Dump of assembler code for function phase_4:
   0x000000000040100c <+0>:	sub    $0x18,%rsp
   0x0000000000401010 <+4>:	lea    0xc(%rsp),%rcx
   0x0000000000401015 <+9>:	lea    0x8(%rsp),%rdx
   0x000000000040101a <+14>:	mov    $0x4025cf,%esi
   0x000000000040101f <+19>:	mov    $0x0,%eax
   0x0000000000401024 <+24>:	callq  0x400bf0 <__isoc99_sscanf@plt>
   0x0000000000401029 <+29>:	cmp    $0x2,%eax
   0x000000000040102c <+32>:	jne    0x401035 <phase_4+41>
   0x000000000040102e <+34>:	cmpl   $0xe,0x8(%rsp)
   0x0000000000401033 <+39>:	jbe    0x40103a <phase_4+46>
   0x0000000000401035 <+41>:	callq  0x40143a <explode_bomb>
   0x000000000040103a <+46>:	mov    $0xe,%edx
   0x000000000040103f <+51>:	mov    $0x0,%esi
   0x0000000000401044 <+56>:	mov    0x8(%rsp),%edi
   0x0000000000401048 <+60>:	callq  0x400fce <func4>
   0x000000000040104d <+65>:	test   %eax,%eax
   0x000000000040104f <+67>:	jne    0x401058 <phase_4+76>
   0x0000000000401051 <+69>:	cmpl   $0x0,0xc(%rsp)
   0x0000000000401056 <+74>:	je     0x40105d <phase_4+81>
   0x0000000000401058 <+76>:	callq  0x40143a <explode_bomb>
   0x000000000040105d <+81>:	add    $0x18,%rsp
   0x0000000000401061 <+85>:	retq
End of assembler dump.
```
查看`%esi`寄存器指向的内容。
```bash
(gdb) x/s $esi
0x4025cf:	"%d %d"
```
我们能够得知字符串包含两个整数。使用`sscanf`函数读入，这部分代码我们之前已经熟悉过不再讲解。
我们从`<+46>`行开始看，将`%edx`赋值为0xe，将`%esi`赋值为0x0，将`%edi`赋值为第一个输入整数，传入`func4`函数中。

我们反汇编查看`func4`函数的代码：

```c
(gdb) disas func4
Dump of assembler code for function func4:
   0x0000000000400fce <+0>:	sub    $0x8,%rsp
   0x0000000000400fd2 <+4>:	mov    %edx,%eax 
   0x0000000000400fd4 <+6>:	sub    %esi,%eax
   0x0000000000400fd6 <+8>:	mov    %eax,%ecx
   0x0000000000400fd8 <+10>:	shr    $0x1f,%ecx
   0x0000000000400fdb <+13>:	add    %ecx,%eax
   0x0000000000400fdd <+15>:	sar    %eax
   0x0000000000400fdf <+17>:	lea    (%rax,%rsi,1),%ecx
   0x0000000000400fe2 <+20>:	cmp    %edi,%ecx
   0x0000000000400fe4 <+22>:	jle    0x400ff2 <func4+36>
   0x0000000000400fe6 <+24>:	lea    -0x1(%rcx),%edx
   0x0000000000400fe9 <+27>:	callq  0x400fce <func4>
   0x0000000000400fee <+32>:	add    %eax,%eax
   0x0000000000400ff0 <+34>:	jmp    0x401007 <func4+57>
   0x0000000000400ff2 <+36>:	mov    $0x0,%eax
   0x0000000000400ff7 <+41>:	cmp    %edi,%ecx
   0x0000000000400ff9 <+43>:	jge    0x401007 <func4+57>
   0x0000000000400ffb <+45>:	lea    0x1(%rcx),%esi
   0x0000000000400ffe <+48>:	callq  0x400fce <func4>
   0x0000000000401003 <+53>:	lea    0x1(%rax,%rax,1),%eax
   0x0000000000401007 <+57>:	add    $0x8,%rsp
   0x000000000040100b <+61>:	retq
End of assembler dump.
```

由于`%ecx`的值被覆盖而未先使用，所以我们判定`func4`使用3个参数寄存器，分别是`%edi`，`esi`，`edx`寄存器。

```c
void func4(int x, int y, int z)
x in %rdi, y in %rsi, z in %rdx, k in %rax, t in %rcx

第一次进入时 y = 0x0, z = 0xe;

mov %edx,%eax  
sub %esi,%eax              k = z - y; k = 0xe;
mov %eax,%ecx  
shr $0x1f,%ecx             t = k >> 31; t = 0x0;
add %ecx,%eax  
sar %eax                   k = (k + t) >> 1; k = 0x7;
lea (%rax,%rsi,1),%ecx     t = (k + y);  t = 0x7;
cmp %edi, %ecx             
jle <func4+36>             x < 0x7时，会继续执行，否则跳转<func4+36>
lea -0x1(%rcx),%edx        z = t - 1; z = 0x6;
callq <func4>              x < 0x7时会递归调用<func4>

<func4+36>
mov $0x0,%eax              k = 0x0;
cmp %edi,%ecx              
jge <func4+57>             x 0x7 >= x时，跳转<func4+57> 由于之前的判定x < 0x7 执行到这里是 x >=0x7 所以x == 0x7时跳转<func4+57>，发现跳转<57>后就就跳出函数了 
```

后面的一段代码就不分析了。从前面的代码我们可以得出结论：要想函数执行完毕，`%rdi`寄存器的内容必须是0x7，也就是第一个参数的值。

执行完`func4`函数后返回`phase_4`，`cmpl $0x0,0xc(%rsp)`，检查第二个参数与0是否相等，如果不相等就会引爆炸弹，说明第二个参数是0x0。

所以字符串的内容是`7 0`。

第四个💣拆除。

## phase_5

```bash
(gdb) disas phase_5
Dump of assembler code for function phase_5:
   0x0000000000401062 <+0>:	push   %rbx
   0x0000000000401063 <+1>:	sub    $0x20,%rsp
   0x0000000000401067 <+5>:	mov    %rdi,%rbx
   0x000000000040106a <+8>:	mov    %fs:0x28,%rax
   0x0000000000401073 <+17>:	mov    %rax,0x18(%rsp)
   0x0000000000401078 <+22>:	xor    %eax,%eax
   0x000000000040107a <+24>:	callq  0x40131b <string_length>
   0x000000000040107f <+29>:	cmp    $0x6,%eax
   0x0000000000401082 <+32>:	je     0x4010d2 <phase_5+112>
   0x0000000000401084 <+34>:	callq  0x40143a <explode_bomb>
   0x0000000000401089 <+39>:	jmp    0x4010d2 <phase_5+112>
   0x000000000040108b <+41>:	movzbl (%rbx,%rax,1),%ecx
   0x000000000040108f <+45>:	mov    %cl,(%rsp)
   0x0000000000401092 <+48>:	mov    (%rsp),%rdx
   0x0000000000401096 <+52>:	and    $0xf,%edx
   0x0000000000401099 <+55>:	movzbl 0x4024b0(%rdx),%edx
   0x00000000004010a0 <+62>:	mov    %dl,0x10(%rsp,%rax,1)
   0x00000000004010a4 <+66>:	add    $0x1,%rax
   0x00000000004010a8 <+70>:	cmp    $0x6,%rax
   0x00000000004010ac <+74>:	jne    0x40108b <phase_5+41>
   0x00000000004010ae <+76>:	movb   $0x0,0x16(%rsp)
   0x00000000004010b3 <+81>:	mov    $0x40245e,%esi
   0x00000000004010b8 <+86>:	lea    0x10(%rsp),%rdi
   0x00000000004010bd <+91>:	callq  0x401338 <strings_not_equal>
   0x00000000004010c2 <+96>:	test   %eax,%eax
   0x00000000004010c4 <+98>:	je     0x4010d9 <phase_5+119>
   0x00000000004010c6 <+100>:	callq  0x40143a <explode_bomb>
   0x00000000004010cb <+105>:	nopl   0x0(%rax,%rax,1)
   0x00000000004010d0 <+110>:	jmp    0x4010d9 <phase_5+119>
   0x00000000004010d2 <+112>:	mov    $0x0,%eax
   0x00000000004010d7 <+117>:	jmp    0x40108b <phase_5+41>
   0x00000000004010d9 <+119>:	mov    0x18(%rsp),%rax
   0x00000000004010de <+124>:	xor    %fs:0x28,%rax
   0x00000000004010e7 <+133>:	je     0x4010ee <phase_5+140>
   0x00000000004010e9 <+135>:	callq  0x400b30 <__stack_chk_fail@plt>
   0x00000000004010ee <+140>:	add    $0x20,%rsp
   0x00000000004010f2 <+144>:	pop    %rbx
   0x00000000004010f3 <+145>:	retq
End of assembler dump.
```
先检查字符串长度是否为6，如果长度不为6直接引爆炸弹。取出字符串的第一个字符与0xf相与，取出字符的第四位作为偏移量。取出`0x4024b0+偏移量`地址指向的字节内容赋给栈空间。循环从第一个字符到第6个字符，最后将字符串与`0x40245e`地址指向的字符串比较，如果相等成功解除炸弹否则引爆。

我们查看两个地址指向的内容。
```bash
(gdb) x/s 0x4024b0
0x4024b0 <array.3449>:	"maduiersnfotvbylSo you think you can stop the bomb with ctrl-c, do you?"
(gdb) x/s 0x40245e
0x40245e:	"flyers"
```
我们从长字符串选出组成`"flyers"`，可以使用程序代码帮助我们写出偏移值。
```cpp
#include <iostream>
#include <string>
using namespace std;
int main() {
  string a = "maduiersnfotvbylSo you think you can stop the bomb with ctrl-c, do you?";
  string b = "flyers";
  for (int i = 0; i < b.size(); ++i) {
    for (int j = 0; j < a.size(); ++j) {
      if (b[i] == a[j]) {
        cout << j << endl;
        break;
      }
    }
  }
  return 0;
}

9 15 14 5 6 7
```
我们再把偏移值作为ASCII字符的低四位，构造成可输入的字符。我这里是分别加上80(01010000)，构成第五个字符串`Y_^UVW`。

第五个💣拆除。

## phase_6

```bash
(gdb) disas phase_6
Dump of assembler code for function phase_6:
   0x00000000004010f4 <+0>:	push   %r14
   0x00000000004010f6 <+2>:	push   %r13
   0x00000000004010f8 <+4>:	push   %r12
   0x00000000004010fa <+6>:	push   %rbp
   0x00000000004010fb <+7>:	push   %rbx
   0x00000000004010fc <+8>:	sub    $0x50,%rsp
   0x0000000000401100 <+12>:	mov    %rsp,%r13
   0x0000000000401103 <+15>:	mov    %rsp,%rsi
   0x0000000000401106 <+18>:	callq  0x40145c <read_six_numbers>
   0x000000000040110b <+23>:	mov    %rsp,%r14
   0x000000000040110e <+26>:	mov    $0x0,%r12d
   0x0000000000401114 <+32>:	mov    %r13,%rbp
   0x0000000000401117 <+35>:	mov    0x0(%r13),%eax
   0x000000000040111b <+39>:	sub    $0x1,%eax
   0x000000000040111e <+42>:	cmp    $0x5,%eax
   0x0000000000401121 <+45>:	jbe    0x401128 <phase_6+52>
   0x0000000000401123 <+47>:	callq  0x40143a <explode_bomb>
   0x0000000000401128 <+52>:	add    $0x1,%r12d
   0x000000000040112c <+56>:	cmp    $0x6,%r12d
   0x0000000000401130 <+60>:	je     0x401153 <phase_6+95>
   0x0000000000401132 <+62>:	mov    %r12d,%ebx
   0x0000000000401135 <+65>:	movslq %ebx,%rax
   0x0000000000401138 <+68>:	mov    (%rsp,%rax,4),%eax
   0x000000000040113b <+71>:	cmp    %eax,0x0(%rbp)
   0x000000000040113e <+74>:	jne    0x401145 <phase_6+81>
   0x0000000000401140 <+76>:	callq  0x40143a <explode_bomb>
   0x0000000000401145 <+81>:	add    $0x1,%ebx
   0x0000000000401148 <+84>:	cmp    $0x5,%ebx
   0x000000000040114b <+87>:	jle    0x401135 <phase_6+65>
   0x000000000040114d <+89>:	add    $0x4,%r13
   0x0000000000401151 <+93>:	jmp    0x401114 <phase_6+32>
   0x0000000000401153 <+95>:	lea    0x18(%rsp),%rsi
   0x0000000000401158 <+100>:	mov    %r14,%rax
   0x000000000040115b <+103>:	mov    $0x7,%ecx
   0x0000000000401160 <+108>:	mov    %ecx,%edx
   0x0000000000401162 <+110>:	sub    (%rax),%edx
   0x0000000000401164 <+112>:	mov    %edx,(%rax)
   0x0000000000401166 <+114>:	add    $0x4,%rax
   0x000000000040116a <+118>:	cmp    %rsi,%rax
   0x000000000040116d <+121>:	jne    0x401160 <phase_6+108>
   0x000000000040116f <+123>:	mov    $0x0,%esi
   0x0000000000401174 <+128>:	jmp    0x401197 <phase_6+163>
   0x0000000000401176 <+130>:	mov    0x8(%rdx),%rdx
   0x000000000040117a <+134>:	add    $0x1,%eax
   0x000000000040117d <+137>:	cmp    %ecx,%eax
   0x000000000040117f <+139>:	jne    0x401176 <phase_6+130>
   0x0000000000401181 <+141>:	jmp    0x401188 <phase_6+148>
   0x0000000000401183 <+143>:	mov    $0x6032d0,%edx
   0x0000000000401188 <+148>:	mov    %rdx,0x20(%rsp,%rsi,2)
   0x000000000040118d <+153>:	add    $0x4,%rsi
   0x0000000000401191 <+157>:	cmp    $0x18,%rsi
   0x0000000000401195 <+161>:	je     0x4011ab <phase_6+183>
   0x0000000000401197 <+163>:	mov    (%rsp,%rsi,1),%ecx
   0x000000000040119a <+166>:	cmp    $0x1,%ecx
   0x000000000040119d <+169>:	jle    0x401183 <phase_6+143>
   0x000000000040119f <+171>:	mov    $0x1,%eax
   0x00000000004011a4 <+176>:	mov    $0x6032d0,%edx
   0x00000000004011a9 <+181>:	jmp    0x401176 <phase_6+130>
   0x00000000004011ab <+183>:	mov    0x20(%rsp),%rbx
   0x00000000004011b0 <+188>:	lea    0x28(%rsp),%rax
   0x00000000004011b5 <+193>:	lea    0x50(%rsp),%rsi
   0x00000000004011ba <+198>:	mov    %rbx,%rcx
   0x00000000004011bd <+201>:	mov    (%rax),%rdx
   0x00000000004011c0 <+204>:	mov    %rdx,0x8(%rcx)
   0x00000000004011c4 <+208>:	add    $0x8,%rax
   0x00000000004011c8 <+212>:	cmp    %rsi,%rax
   0x00000000004011cb <+215>:	je     0x4011d2 <phase_6+222>
   0x00000000004011cd <+217>:	mov    %rdx,%rcx
   0x00000000004011d0 <+220>:	jmp    0x4011bd <phase_6+201>
   0x00000000004011d2 <+222>:	movq   $0x0,0x8(%rdx)
   0x00000000004011da <+230>:	mov    $0x5,%ebp
   0x00000000004011df <+235>:	mov    0x8(%rbx),%rax
   0x00000000004011e3 <+239>:	mov    (%rax),%eax
   0x00000000004011e5 <+241>:	cmp    %eax,(%rbx)
   0x00000000004011e7 <+243>:	jge    0x4011ee <phase_6+250>
   0x00000000004011e9 <+245>:	callq  0x40143a <explode_bomb>
   0x00000000004011ee <+250>:	mov    0x8(%rbx),%rbx
   0x00000000004011f2 <+254>:	sub    $0x1,%ebp
   0x00000000004011f5 <+257>:	jne    0x4011df <phase_6+235>
   0x00000000004011f7 <+259>:	add    $0x50,%rsp
   0x00000000004011fb <+263>:	pop    %rbx
   0x00000000004011fc <+264>:	pop    %rbp
   0x00000000004011fd <+265>:	pop    %r12
   0x00000000004011ff <+267>:	pop    %r13
   0x0000000000401201 <+269>:	pop    %r14
   0x0000000000401203 <+271>:	retq
End of assembler dump.
```

第6个`phase_6`函数比较长但逻辑并不复杂。指令执行的逻辑是：

1. 输入包含6个整数的字符串。
2. 使用嵌套的循环，验证每个数都小于等于6，大于等于0，且每个数互不相等。
3. 对每个整数进行一次处理`x = 7 - x`。
3. 使用额外的栈空间，存储每个数i指向一个链表的结点地址。
4. 更改链表的指向。
5. 链表按照值递减的顺序。

```bash
   # 设每个数的值是i，链表是node。指令的操作是将每个数映射栈空间的内存单元存放的是链表第i个结点的地址。如果第1个整数的值是6，对应内存单元存放的是链表第6个结点的地址。
   0x000000000040116f <+123>:	mov    $0x0,%esi
   0x0000000000401174 <+128>:	jmp    0x401197 <phase_6+163>
   0x0000000000401176 <+130>:	mov    0x8(%rdx),%rdx # cur = cur -> next 下一个地址。
   0x000000000040117a <+134>:	add    $0x1,%eax 
   0x000000000040117d <+137>:	cmp    %ecx,%eax # 比较
   0x000000000040117f <+139>:	jne    0x401176 <phase_6+130>
   0x0000000000401181 <+141>:	jmp    0x401188 <phase_6+148>
   0x0000000000401183 <+143>:	mov    $0x6032d0,%edx # 将链表首地址赋给元素对应的栈空间。
   0x0000000000401188 <+148>:	mov    %rdx,0x20(%rsp,%rsi,2)
   0x000000000040118d <+153>:	add    $0x4,%rsi
   0x0000000000401191 <+157>:	cmp    $0x18,%rsi
   0x0000000000401195 <+161>:	je     0x4011ab <phase_6+183>
   0x0000000000401197 <+163>:	mov    (%rsp,%rsi,1),%ecx # 取出第esi+1个数。
   0x000000000040119a <+166>:	cmp    $0x1,%ecx 
   0x000000000040119d <+169>:	jle    0x401183 <phase_6+143> # 由于每个数大于等于1，此处检查是不是1，如果是1跳转<phase_6+143>。
   0x000000000040119f <+171>:	mov    $0x1,%eax # 比较flag
   0x00000000004011a4 <+176>:	mov    $0x6032d0,%edx
   0x00000000004011a9 <+181>:	jmp    0x401176 <phase_6+130>

(gdb) x 0x6032d0
0x6032d0 <node1>:	0x0000014c
(gdb) x/36 0x6032d0
0x6032d0 <node1>:	0x0000014c	0x00000001	0x006032e0	0x00000000
0x6032e0 <node2>:	0x000000a8	0x00000002	0x006032f0	0x00000000
0x6032f0 <node3>:	0x0000039c	0x00000003	0x00603300	0x00000000
0x603300 <node4>:	0x000002b3	0x00000004	0x00603310	0x00000000
0x603310 <node5>:	0x000001dd	0x00000005	0x00603320	0x00000000
0x603320 <node6>:	0x000001bb	0x00000006	0x00000000	0x00000000

(gdb) x/24d 0x6032d0
0x6032d0 <node1>:	332	1	6304480	0
0x6032e0 <node2>:	168	2	6304496	0
0x6032f0 <node3>:	924	3	6304512	0
0x603300 <node4>:	691	4	6304528	0
0x603310 <node5>:	477	5	6304544	0
0x603320 <node6>:	443	6	0	0
```
查看`0x6032d0`地址指向的空间，发现是一个结构体链表，每个结点存储一个值和链表结点序号和next指针。

根据每个整数的值取得相应的链接结点地址，然后修改链表结点的next指针，使得链表构成值降序。所以修改后的链表应该是(924) -> (691) -> (477) -> (443) -> (332) -> (168)，相应的结点序号序列应该是(3) -> (4) -> (5) -> (6) -> (1) -> (2)。

由于值是被7处理过的，原整数序列应该为`4 3 2 1 6 5 `，第6个字符串应该是`4 3 2 1 6 5`。

第六个💣拆除。

## 总结
跟着网友的答案参考学习完著名的**Bomb Lab**，感觉收获满满。对汇编语言有了一定的了解，对`%rsp`和其他参数寄存器有了更深刻的认识，对指针和地址的使用也更加清晰。