/*
 * Electric Fence - Red-Zone memory allocator.
 * Bruce Perens, 1988, 1993
 *
 * This is a special version of malloc() and company for debugging software
 * that is suspected of overrunning or underrunning the boundaries of a
 * malloc buffer, or touching free memory.
 *
 * It arranges for each malloc buffer to be followed (or preceded)
 * in the address space by an inaccessable virtual memory page,
 * and for free memory to be inaccessable. If software touches the
 * inaccessable page, it will get an immediate segmentation
 * fault. It is then trivial to uncover the offending code using a debugger.
 *
 * An advantage of this product over most malloc debuggers is that this one
 * detects reading out of bounds as well as writing, and this one stops on
 * the exact instruction that causes the error, rather than waiting until the
 * next boundary check.
 *
 * There is one product that debugs malloc buffer overruns
 * better than Electric Fence: "Purify" from Purify Systems, and that's only
 * a small part of what Purify does. I'm not affiliated with Purify, I just
 * respect a job well done.
 *
 * This version of malloc() should not be linked into production software,
 * since it tremendously increases the time and memory overhead of malloc().
 * Each malloc buffer will consume a minimum of two virtual memory pages,
 * this is 16 kilobytes on many systems. On some systems it will be necessary
 * to increase the amount of swap space in order to debug large programs that
 * perform lots of allocation, because of the per-buffer overhead.
 */
#include "efence.h"
#include <stdlib.h>
#include <unistd.h>
#include <memory.h>
#include <string.h>
#include <pthread.h>

#ifdef malloc
#undef malloc
#endif

#ifdef calloc
#undef calloc
#endif

static const char version[] = "\n"
							  "==================================================\n"
							  "  Electric Fence 3.0\n"
							  "    Copyright (C) 1987-1998 Bruce Perens.\n"
							  "    Copyright (C) 2012-2013 Alexander von Gluck IV\n"
							  "==================================================\n";

static const char enabled[] = "\n  Memory fencing has been enabled\n\n";

/*
 * MEMORY_CREATION_SIZE is the amount of memory to get from the operating
 * system at one time. We'll break that memory down into smaller pieces for
 * malloc buffers. One megabyte is probably a good value.
 */

/*
 * 一次从内核申请的内存大小，定义为 1 M
 */
#define MEMORY_CREATION_SIZE 1024 * 1024

/*
 * Enum Mode indicates the status of a malloc buffer.
 */

enum _Mode
{
	NOT_IN_USE = 0, /* Available to represent a malloc buffer. */
	FREE,			/* A free buffer. */
	ALLOCATED,		/* A buffer that is in use. */
	PROTECTED,		/* A freed buffer that can not be allocated again. */
	INTERNAL_USE	/* A buffer used internally by malloc(). */
};
/*
 * 设置 malloc buffer 的状态
 */
typedef enum _Mode Mode;

/*
 * Struct Slot contains all of the information about a malloc buffer except
 * for the contents of its memory.
 */

struct _Slot
{
	void *userAddress;
	void *internalAddress;
	size_t userSize;
	size_t internalSize;
	Mode mode;
};
/*
 * 一个 malloc buffer 包含的所有信息
 */
typedef struct _Slot Slot;

/*
 * EF_DISABLE_BANNER is a global variable used to control whether
 * Electric Fence prints its usual startup message.  If the value is
 * -1, it will be set from the environment default to 0 at run time.
 */

/*
 * 是否在启动时打印 Electric Fence 信息，为 0 时打印
 */
int EF_DISABLE_BANNER = -1;

/*
 * EF_ALIGNMENT is a global variable used to control the default alignment
 * of buffers returned by malloc(), calloc(), and realloc(). It is all-caps
 * so that its name matches the name of the environment variable that is used
 * to set it. This gives the programmer one less name to remember.
 * If the value is -1, it will be set from the environment or sizeof(int)
 * at run time.
 */

/*
 * malloc 等接口返回地址的对齐，可以通过环境变量设置，默认 sizeof(int)
 */
int EF_ALIGNMENT = -1;

/*
 * EF_PROTECT_FREE is a global variable used to control the disposition of
 * memory that is released using free(). It is all-caps so that its name
 * matches the name of the environment variable that is used to set it.
 * If its value is greater non-zero, memory released by free is made
 * inaccessable and never allocated again. Any software that touches free
 * memory will then get a segmentation fault. If its value is zero, freed
 * memory will be available for reallocation, but will still be inaccessable
 * until it is reallocated.
 * If the value is -1, it will be set from the environment or to 0 at run-time.
 */

/*
 * 是否将 free 后的内存保护起来，非 0 时会设置成无法访问并且不再分配出去，为 0 时会被分配出去，但是直到被分配出去前，都无法访问
 */
int EF_PROTECT_FREE = -1;

/*
 * EF_PROTECT_BELOW is used to modify the behavior of the allocator. When
 * its value is non-zero, the allocator will place an inaccessable page
 * immediately _before_ the malloc buffer in the address space, instead
 * of _after_ it. Use this to detect malloc buffer under-runs, rather than
 * over-runs. It won't detect both at the same time, so you should test your
 * software twice, once with this value clear, and once with it set.
 * If the value is -1, it will be set from the environment or to zero at
 * run-time
 */

/*
 * 非0时在 buffer 前面放不可访问的page，0 时在后面放
 */
int EF_PROTECT_BELOW = -1;

/*
 * EF_ALLOW_MALLOC_0 is set if Electric Fence is to allow malloc(0). I
 * trap malloc(0) by default because it is a common source of bugs.
 */

/*
 * 为 0 时 trap malloc(0)，否则不 trap
 */
int EF_ALLOW_MALLOC_0 = -1;

/*
 * EF_FREE_WIPES is set if Electric Fence is to wipe the memory content
 * of freed blocks.  This makes it easier to check if memory is freed or
 * not
 */

/*
 * 非 0 时清空 free 内存中的内容，否则不清空
 */
int EF_FREE_WIPES = -1;

/*
 * allocationList points to the array of slot structures used to manage the
 * malloc arena.
 */

/*
 * 指向用于管理 malloc arena 中内存的 slot 链
 */
static Slot *allocationList = 0;

/*
 * allocationListSize is the size of the allocation list. This will always
 * be a multiple of the page size.
 */

/*
 * 表示 allocationList 链的大小
 */
static size_t allocationListSize = 0;

/*
 * slotCount is the number of Slot structures in allocationList.
 */

/*
 * 表示 allocationList 中 slot 的个数
 */
static size_t slotCount = 0;

/*
 * unUsedSlots is the number of Slot structures that are currently available
 * to represent new malloc buffers. When this number gets too low, we will
 * create new slots.
 */

/*
 * 表示当前还可以使用的 slot 的数量
 */
static size_t unUsedSlots = 0;

/*
 * slotsPerPage is the number of slot structures that fit in a virtual
 * memory page.
 */

/*
 * 表示一个 page 所能包含的 slot 数量
 */
static size_t slotsPerPage = 0;

/*
 * internalUse is set when allocating and freeing the allocatior-internal
 * data structures.
 */

/*
 * 在当前分配器malloc和free自身需要使用的内存时进行设置
 */
static int internalUse = 0;

/*
 * noAllocationListProtection is set to tell malloc() and free() not to
 * manipulate the protection of the allocation list. This is only set in
 * realloc(), which does it to save on slow system calls, and in
 * allocateMoreSlots(), which does it because it changes the allocation list.
 */

/*
 * 表示内存分配时能否访问 allocation list，为 0 时不可访问，分配时设置为可以访问，且分配结束会再次设置不可访问
 * 用于防止用户程序乱搞
 */
static int noAllocationListProtection = 0;

/*
 * bytesPerPage is set at run-time to the number of bytes per virtual-memory
 * page, as returned by Page_Size().
 */

/*
 * 表示一个 page 的大小，字节数
 */
static size_t bytesPerPage = 0;

/*
 * mutex to enable multithreaded operation
 */
static pthread_mutex_t mutex;
static pid_t mutexpid = 0;
static int locknr = 0;

/* 
 * 用于多线程分配时加锁
 */
static void lock()
{
	if (pthread_mutex_trylock(&mutex))
	{
		if (mutexpid == getpid())
		{
			locknr++;
			return;
		}
		else
		{
			pthread_mutex_lock(&mutex);
		}
	}
	mutexpid = getpid();
	locknr = 1;
}

/* 
 * 用于多线程分配时解锁
 */
static void unlock()
{
	locknr--;
	if (!locknr)
	{
		mutexpid = 0;
		pthread_mutex_unlock(&mutex);
	}
}

/*
 * internalError is called for those "shouldn't happen" errors in the
 * allocator.
 */
static void
internalError(void)
{
	EF_Abort("Internal error in allocator.");
}

/*
 * initialize sets up the memory allocation arena and the run-time
 * configuration information.
 */

/*
 * 初始化函数
 * 设置 allocation arena 并且设置相关的参数
 */
static void
initialize(void)
{
	// 一次从内核申请的内存大小
	size_t size = MEMORY_CREATION_SIZE;
	size_t slack;
	char *string;
	Slot *slot;

	/*
	 * 设置是否需要打印启动信息
	 */
	if (EF_DISABLE_BANNER == -1)
	{
		if ((string = getenv("EF_DISABLE_BANNER")) != 0)
			EF_DISABLE_BANNER = atoi(string);
		else
			EF_DISABLE_BANNER = 0;
	}

	if (EF_DISABLE_BANNER == 0)
		EF_Print(version);

	/*
	 * Import the user's environment specification of the default
	 * alignment for malloc(). We want that alignment to be under
	 * user control, since smaller alignment lets us catch more bugs,
	 * however some software will break if malloc() returns a buffer
	 * that is not word-aligned.
	 *
	 * I would like
	 * alignment to be zero so that we could catch all one-byte
	 * overruns, however if malloc() is asked to allocate an odd-size
	 * buffer and returns an address that is not word-aligned, or whose
	 * size is not a multiple of the word size, software breaks.
	 * This was the case with the Sun string-handling routines,
	 * which can do word fetches up to three bytes beyond the end of a
	 * string. I handle this problem in part by providing
	 * byte-reference-only versions of the string library functions, but
	 * there are other functions that break, too. Some in X Windows, one
	 * in Sam Leffler's TIFF library, and doubtless many others.
	 */

	/*
	 * 设置 malloc 等分配内存的对齐大小，默认为 sizeof(int)
	 */
	if (EF_ALIGNMENT == -1)
	{
		if ((string = getenv("EF_ALIGNMENT")) != 0)
			EF_ALIGNMENT = (size_t)atoi(string);
		else
			EF_ALIGNMENT = sizeof(int);
	}

	/*
	 * See if the user wants to protect the address space below a buffer,
	 * rather than that above a buffer.
	 */

	/*
	 * 设置是否需要在分配的 buffer 前面设置 fence，默认在后面设置
	 */
	if (EF_PROTECT_BELOW == -1)
	{
		if ((string = getenv("EF_PROTECT_BELOW")) != 0)
			EF_PROTECT_BELOW = (atoi(string) != 0);
		else
			EF_PROTECT_BELOW = 0;
	}

	/*
	 * See if the user wants to protect memory that has been freed until
	 * the program exits, rather than until it is re-allocated.
	 */

	/*
	 * 设置是否需要保护 free 后的内存，非 0 时保护
	 */
	if (EF_PROTECT_FREE == -1)
	{
		if ((string = getenv("EF_PROTECT_FREE")) != 0)
			EF_PROTECT_FREE = (atoi(string) != 0);
		else
			EF_PROTECT_FREE = 0;
	}

	/*
	 * See if the user wants to allow malloc(0).
	 */

	/*
	 * 设置是否允许 malloc(0)
	 */
	if (EF_ALLOW_MALLOC_0 == -1)
	{
		if ((string = getenv("EF_ALLOW_MALLOC_0")) != 0)
			EF_ALLOW_MALLOC_0 = (atoi(string) != 0);
		else
			EF_ALLOW_MALLOC_0 = 0;
	}

	/*
	 * See if the user wants us to wipe out freed memory.
	 */

	/*
	 * 设置是否需要在 free 后清空内存，否则等到再分配时才进行
	 */
	if (EF_FREE_WIPES == -1)
	{
		if ((string = getenv("EF_FREE_WIPES")) != 0)
			EF_FREE_WIPES = (atoi(string) != 0);
		else
			EF_FREE_WIPES = 0;
	}

	/*
	 * Get the run-time configuration of the virtual memory page size.
	 */

	/* 
	 * 获得一个 page 的大小，字节数
	 */
	bytesPerPage = Page_Size();

	/*
	 * Figure out how many Slot structures to allocate at one time.
	 */

	/* 
	 * 获得一次能分配 slot 的个数
	 */
	slotCount = slotsPerPage = bytesPerPage / sizeof(Slot);

	/* 
	 * 获得 allocationList 的大小
	 */
	allocationListSize = bytesPerPage;

	/* 
	 * 如果 size 比 page 小，更新 size 为 page 大小
	 */
	if (allocationListSize > size)
		size = allocationListSize;

	/*
	 * size 的大小不是 page 的整数倍，将 size 按 page 向上对齐
	*/
	if ((slack = size % bytesPerPage) != 0)
		size += bytesPerPage - slack;

	/*
	 * Allocate memory, and break it up into two malloc buffers. The
	 * first buffer will be used for Slot structures, the second will
	 * be marked free.
	 */

	/*
	 * 通过 mmap 分配 内存，并清 0，转换成 slot 数组
	*/
	slot = allocationList = (Slot *)Page_Create(size);
	memset((char *)allocationList, 0, allocationListSize);

	/*
	* slot[0] 用于描述 allocationList 这整块内存
	* 设置 slot[0] 的相关属性，大小为allocationList整个的大小
	*/
	slot[0].internalSize = slot[0].userSize = allocationListSize;
	slot[0].internalAddress = slot[0].userAddress = allocationList;
	slot[0].mode = INTERNAL_USE;

	/*
	 * allocationListSize 为 allocationList 的大小，上面初始化成了一个 page 的大小
	 * size 为一次通过 mmap 分配的大小，上面初始化成了 1M
	 * 也即分配给了 slot 数组后，需要看看还有没有剩余的部分，剩余部分用于对外分配
	*/
	if (size > allocationListSize)
	{
		/*
		 * 用 slot[1] 来保存剩下这部分的内存信息
		 * 起始地址为 allocationList 结束的地址，即起始地址加上allocationList的大小
		 * 大小即为 size 减去 allocationList 的大小
		*/
		slot[1].internalAddress = slot[1].userAddress = ((char *)slot[0].internalAddress) + slot[0].internalSize;
		slot[1].internalSize = slot[1].userSize = size - slot[0].internalSize;
		slot[1].mode = FREE;
	}

	/*
	 * Deny access to the free page, so that we will detect any software
	 * that treads upon free memory.
	 */

	/* 
	 * 将剩余的这部分，也即slot[1]描述的这部分通过 mprotect 设置成不可访问
	 * 由于 allocationList 大小为 1 page，那么剩余部分也是 page 的整数，将这些 page 通过 mprotect 设置成不可访问
	 */
	Page_DenyAccess(slot[1].internalAddress, slot[1].internalSize);

	/*
	 * Account for the two slot structures that we've used.
	 */

	/*
	 * 已经使用了两个 slot，更新 unUsedSlots
	*/
	unUsedSlots = slotCount - 2;

	/* 
	 * 打印 enabled
	 */
	if (EF_DISABLE_BANNER == 0)
		EF_Print(enabled);
}

/*
 * allocateMoreSlots is called when there are only enough slot structures
 * left to support the allocation of a single malloc buffer.
 */

/* 
 * 用于分配新的 slot 
 * 当剩余 slot 数量不够时会被调用
 * 新分配 1 个 page
 */
static void
allocateMoreSlots(void)
{
	/* 
	 * 新大小等于之前的大小加上新分配个一个 page 的大小
	 */
	size_t newSize = allocationListSize + bytesPerPage;
	void *newAllocation;
	void *oldAllocation = allocationList;

	/* 
	 * 将 allocationList 部分的内存设置为可以访问
	 */
	Page_AllowAccess(allocationList, allocationListSize);

	/* 
	 * 接下来需要访问 allocationList，所以设置 noAllocationListProtection 为 1，
	 * 让其他线程不用设置 allocationList 为不可访问
	 */
	noAllocationListProtection = 1;

	/* 
	 * 设置 internalUse 为 1，避免其他线程也重复走这个流程
	 */
	internalUse = 1;

#ifdef __GNUC__
	asm volatile("" ::: "memory");
#endif

	/* 
	 * 分配新的 allocationList 
	 */
	newAllocation = malloc(newSize);

#ifdef __GNUC__
	asm volatile("" ::: "memory");
#endif

	/* 
	 * 将之前的 allocationList 数组里的内容复制到 newAllocation
	 * 并将新分配的 1 个 page 设置为 0
	 */
	memcpy(newAllocation, allocationList, allocationListSize);
	memset(&(((char *)newAllocation)[allocationListSize]), 0, bytesPerPage);

	/* 
	 * 更新 allocationList ，并更新大小和 slot 数量
	 */
	allocationList = (Slot *)newAllocation;
	allocationListSize = newSize;
	slotCount += slotsPerPage;
	unUsedSlots += slotsPerPage;

#ifdef __GNUC__
	asm volatile("" ::: "memory");
#endif

	/* 
	 * 释放旧的 allocationList
	 */
	free(oldAllocation);

#ifdef __GNUC__
	asm volatile("" ::: "memory");
#endif

	/*
	 * Keep access to the allocation list open at this point, because
	 * I am returning to memalign(), which needs that access.
	 */

	/* 
	 * 已经分配完了，重置这俩变量
	 */
	noAllocationListProtection = 0;
	internalUse = 0;
}

/*
 * This is the memory allocator. When asked to allocate a buffer, allocate
 * it in such a way that the end of the buffer is followed by an inaccessable
 * memory page. If software overruns that buffer, it will touch the bad page
 * and get an immediate segmentation fault. It's then easy to zero in on the
 * offending code with a debugger.
 *
 * There are a few complications. If the user asks for an odd-sized buffer,
 * we would have to have that buffer start on an odd address if the byte after
 * the end of the buffer was to be on the inaccessable page. Unfortunately,
 * there is lots of software that asks for odd-sized buffers and then
 * requires that the returned address be word-aligned, or the size of the
 * buffer be a multiple of the word size. An example are the string-processing
 * functions on Sun systems, which do word references to the string memory
 * and may refer to memory up to three bytes beyond the end of the string.
 * For this reason, I take the alignment requests to memalign() and valloc()
 * seriously, and
 *
 * Electric Fence wastes lots of memory. I do a best-fit allocator here
 * so that it won't waste even more. It's slow, but thrashing because your
 * working set is too big for a system's RAM is even slower.
 */
extern C_LINKAGE void *
memalign(size_t alignment, size_t userSize)
{
	register Slot *slot;
	register size_t count;
	Slot *fullSlot = 0;
	Slot *emptySlots[2];
	/* 
	 * 为 userSize + 1 个 page 大小后 按 page 向上对齐后的大小
	 */
	size_t internalSize;
	size_t slack;
	char *address;

	/* 
	 * 如果 allocationList 还没初始化过，初始化
	 */
	if (allocationList == 0)
		initialize();

	/*
	 * 申请大小为 0，EF_ALLOW_MALLOC_0 为 0 时不允许分配 0 字节
	*/
	if (userSize == 0 && !EF_ALLOW_MALLOC_0)
		EF_Abort("Allocating 0 bytes, probably a bug.");

	/*
	 * If EF_PROTECT_BELOW is set, all addresses returned by malloc()
	 * and company will be page-aligned.
	 */

	/* 
	 * 如果设置了 EF_PROTECT_BELOW 为 0，则返回的地址需要按 page 对齐，这样他前面的 page 可以设置为无法访问
	 * 此处判断没有设置，userSize 按 alignment 向上对齐
	 */
	if (!EF_PROTECT_BELOW && alignment > 1)
	{
		if ((slack = userSize % alignment) != 0)
			userSize += alignment - slack;
	}

	/*
	 * The internal size of the buffer is rounded up to the next page-size
	 * boudary, and then we add another page's worth of memory for the
	 * dead page.
	 */

	/* 
	 * internalSize 为 userSize 的内部大小，为了能让当前分配的内存后面是下一个page
	 * 所以需要将 userSize 的大小转换成 page 的大小，返回的时候从挨着下一个 page 的地方往前找 userSize 返回
	 */
	internalSize = userSize + bytesPerPage;
	if ((slack = internalSize % bytesPerPage) != 0)
		internalSize += bytesPerPage - slack;

	/*
	 * These will hold the addresses of two empty Slot structures, that
	 * can be used to hold information for any memory I create, and any
	 * memory that I mark free.
	 */

	/* 
	 * 创建两个空的 emptySlots，可以用来保存 slot 指针
	 * 这俩是用于从 slot 中找到俩没有被用过的 slot，然后在从 allocationList 找不到合适大小的内存时
	 * emptySlots[0] 用于保存当 slot 中找不到合适大小的内存时，重新从内核申请的内存的信息
	 * emptySlots[1] 赋值给emptySlots[0] 后面还会用于保存分割剩下的内存的信息
	 */
	emptySlots[0] = 0;
	emptySlots[1] = 0;

	/*
	 * The internal memory used by the allocator is currently
	 * inaccessable, so that errant programs won't scrawl on the
	 * allocator's arena. I'll un-protect it here so that I can make
	 * a new allocation. I'll re-protect it before I return.
	 */

	/* 
	 * 将 allocationList 设置为可以访问，这个跟我们剩下用于分配的内存不在一个 page 上
	 * 所以不会影响那部分内存的属性
	 */
	if (!noAllocationListProtection)
		Page_AllowAccess(allocationList, allocationListSize);

	/*
	 * If I'm running out of empty slots, create some more before
	 * I don't have enough slots left to make an allocation.
	 */
	/* 
	 * 当前可使用的 slot 少于 7 个，进行分配
	 */
	if (!internalUse && unUsedSlots < 7)
	{
		allocateMoreSlots();
	}

	/*
	 * Iterate through all of the slot structures. Attempt to find a slot
	 * containing free memory of the exact right size. Accept a slot with
	 * more memory than we want, if the exact right size is not available.
	 * Find two slot structures that are not in use. We will need one if
	 * we split a buffer into free and allocated parts, and the second if
	 * we have to create new memory and mark it as free.
	 *
	 */

	/* 
	 * 遍历所有的 slot，尝试找到一个我们能分配的大小
	 */
	for (slot = allocationList, count = slotCount; count > 0; count--)
	{
		/* 
		 * 找到类型为 FREE 并且 internalSize 大于我们这次要分配的 internalSize 的 slot
		 * 对于没有用于描述内存的 slot，mode 为 0 NOT_IN_USE
		 */
		if (slot->mode == FREE && slot->internalSize >= internalSize)
		{
			/* 
			 * 没有保存过 fullSlot 或者 fullSlot 的大小比当前 slot 的要大，更新 fullSlot
			 * 实际上就是从所有大于当前要分配的 internalSize 的 slot 中找到一个最小的，即最合适的
			 */
			if (!fullSlot || slot->internalSize < fullSlot->internalSize)
			{
				fullSlot = slot;
				/* 
				 * 当前 slot 的大小刚好合适并且 emptySlots[0] 非空，即我们也找到了一个空的 slot 用于保存分割后的信息，直接退出
				 */
				if (slot->internalSize == internalSize && emptySlots[0])
					break; /* All done, */
			}
		}
		/* 
		 * 当前遍历的 slot 为 NOT_IN_USE，还没被使用
		 * 我们需要从里面找到俩 slot 保存到 emptySlots 中
		 */
		else if (slot->mode == NOT_IN_USE)
		{
			if (!emptySlots[0])
				emptySlots[0] = slot;
			else if (!emptySlots[1])
				emptySlots[1] = slot;
			else if (fullSlot && fullSlot->internalSize == internalSize)
				break; /* All done. */
		}
		slot++;
	}

	/* 
	 * 没有找到一个空闲的 slot，那么我们无法描述当前用于分配的这块内存，异常
	 */
	if (!emptySlots[0])
		internalError();

	/* 
	 * fullSlot 为空，即我们没有从所有的 FREE slot 中找到大小比 internalSize 大的
	 * 我们需要申请更多内存来满足这次分配
	 */
	if (!fullSlot)
	{
		/*
		 * I get here if I haven't been able to find a free buffer
		 * with all of the memory I need. I'll have to create more
		 * memory. I'll mark it all as free, and then split it into
		 * free and allocated portions later.
		 */

		/* 
		 * 继续向内核申请 MEMORY_CREATION_SIZE 大小的内存
		 */
		size_t chunkSize = MEMORY_CREATION_SIZE;
		
		/* 
		 * 没找到另一个空闲的 slot， 异常
		 */
		if (!emptySlots[1])
			internalError();

		/* 
		 * 向内核一次申请的内存大小比 internalSize 小
		 * 则将申请大小修改为 internalSize
		 */
		if (chunkSize < internalSize)
			chunkSize = internalSize;

		/* 
		 * 将 chunkSize 按 page 向上对齐
		 */
		if ((slack = chunkSize % bytesPerPage) != 0)
			chunkSize += bytesPerPage - slack;

		/* Use up one of the empty slots to make the full slot. */
		/* 
		 * 用 emptySlots[0] 来保存当前分配的内存的信息
		 */
		fullSlot = emptySlots[0];
		emptySlots[0] = emptySlots[1];
		fullSlot->internalAddress = Page_Create(chunkSize);
		fullSlot->internalSize = chunkSize;
		fullSlot->mode = FREE;
		unUsedSlots--;
	}


	/* 
	 * 到此为止，我们已经获得了俩 fullSlot 和 emptySlots[1]
	 * fullSlot 为大小比我们要分配的 internalSize 大的 slot
	 * emptySlots[1] 用于保存分割剩下那部分内存的信息
	 */
	/*
	 * If I'm allocating memory for the allocator's own data structures,
	 * mark it INTERNAL_USE so that no errant software will be able to
	 * free it.
	 */

	/* 
	 * 判断当前是不是我们自己在申请内存，
	 * 我们自己申请，设置 slot 为 INTERNAL_USE，避免被用户程序错误释放
	 * 程序申请，设置 slot 为 ALLOCATED，表示该内存已分配
	 */
	if (internalUse)
		fullSlot->mode = INTERNAL_USE;
	else
		fullSlot->mode = ALLOCATED;

	/*
	 * If the buffer I've found is larger than I need, split it into
	 * an allocated buffer with the exact amount of memory I need, and
	 * a free buffer containing the surplus memory.
	 */

	/* 
	 * 如果我们找到的 fullSlot 大小比我们需要的大小要大，进行分割
	 */
	if (fullSlot->internalSize > internalSize)
	{
		/* 
		 * 用 emptySlots[0] 来保存我们分割剩余部分内存的信息，并设置为 free
		 * 更新 fullSlot 的大小
		 */
		emptySlots[0]->internalSize = fullSlot->internalSize - internalSize;
		emptySlots[0]->internalAddress = ((char *)fullSlot->internalAddress) + internalSize;
		emptySlots[0]->mode = FREE;
		fullSlot->internalSize = internalSize;
		unUsedSlots--;
	}

	/* 
	 * 判断是在 buffer 的前面还是后面设置 inaccessable page
	 */
	if (!EF_PROTECT_BELOW)
	{
		/*
		 * Arrange the buffer so that it is followed by an inaccessable
		 * memory page. A buffer overrun that touches that page will
		 * cause a segmentation fault.
		 */

		/* 
		 * 在 buffer 的后面加上 inaccessable page
		 */

		address = (char *)fullSlot->internalAddress;

		/* Set up the "live" page. */

		/* 
		 * 设置能被访问的 page，因为申请的大小为 page 的倍数，所以按 page 设置
		 * 将从 fullSlot->internalAddress 开始的，除了最后一个 page 都设置为可以访问
		 */
		if (internalSize - bytesPerPage > 0)
			Page_AllowAccess(
				fullSlot->internalAddress, internalSize - bytesPerPage);

		/* 
		 * 获得最后一个 page 的起始地址
		*/
		address += internalSize - bytesPerPage;

		/* Set up the "dead" page. */
		/* 
		 * 将最后一个 page 设置为不可访问
		 */
		Page_DenyAccess(address, bytesPerPage);

		/* Figure out what address to give the user. */
		/* 
		 * 从最后一个 page 开始，向前减去实际要分配的大小 userSize，即为需要返回给用户的地址
		 */
		address -= userSize;
	}
	else
	{ /* EF_PROTECT_BELOW != 0 */
		/*
		 * Arrange the buffer so that it is preceded by an inaccessable
		 * memory page. A buffer underrun that touches that page will
		 * cause a segmentation fault.
		 */

		/* 
		 * 在 buffer 的前面加上 inaccessable page
		 */

		address = (char *)fullSlot->internalAddress;

		/* Set up the "dead" page. */
		/* 
		 * 将第一个 page 设置为不可访问
		 */
		Page_DenyAccess(address, bytesPerPage);

		/* 
		 * 实际要分配的地址即为第一个 page 的结束地址
		 */
		address += bytesPerPage;

		/* Set up the "live" page. */
		/* 
		 * 将除了第一个 page 以外的部分设置为可以访问
		 */
		if (internalSize - bytesPerPage > 0)
			Page_AllowAccess(address, internalSize - bytesPerPage);
	}

	/*
	 * 将我们分配出去的这个 slot 的用户信息进行更新
	 * userAddress 为我们实际分配给用户的地址
	 * userSize 为我们实际分配给用户的大小
	*/
	fullSlot->userAddress = address;
	fullSlot->userSize = userSize;

	/*
	 * Make the pool's internal memory inaccessable, so that the program
	 * being debugged can't stomp on it.
	 */

	/*
	 * 非我们自己分配内存，分配完了以后将 allocationList 设置为不可访问
	*/
	if (!internalUse)
		Page_DenyAccess(allocationList, allocationListSize);

	return address;
}

/*
 * Find the slot structure for a user address.
 */
static Slot *
slotForUserAddress(void *address)
{
	register Slot *slot = allocationList;
	register size_t count = slotCount;

	for (; count > 0; count--)
	{
		if (slot->userAddress == address)
			return slot;
		slot++;
	}

	return 0;
}

/*
 * Find the slot structure for an internal address.
 */
static Slot *
slotForInternalAddress(void *address)
{
	register Slot *slot = allocationList;
	register size_t count = slotCount;

	for (; count > 0; count--)
	{
		if (slot->internalAddress == address)
			return slot;
		slot++;
	}
	return 0;
}

/*
 * Given the internal address of a buffer, find the buffer immediately
 * before that buffer in the address space. This is used by free() to
 * coalesce two free buffers into one.
 */
static Slot *
slotForInternalAddressPreviousTo(void *address)
{
	register Slot *slot = allocationList;
	register size_t count = slotCount;

	for (; count > 0; count--)
	{
		if (((char *)slot->internalAddress) + slot->internalSize == address)
			return slot;
		slot++;
	}
	return 0;
}

extern C_LINKAGE void
free(void *address)
{
	Slot *slot;
	Slot *previousSlot = 0;
	Slot *nextSlot = 0;

	lock();

	if (address == 0)
	{
		unlock();
		return;
	}

	if (allocationList == 0)
		EF_Abort("free() called before first malloc().");

	if (!noAllocationListProtection)
		Page_AllowAccess(allocationList, allocationListSize);

	slot = slotForUserAddress(address);

	if (!slot)
		EF_Abort("free(%a): address not from malloc().", address);

	if (slot->mode != ALLOCATED)
	{
		if (internalUse && slot->mode == INTERNAL_USE)
			/* Do nothing. */;
		else
		{
			EF_Abort(
				"free(%a): freeing free memory.", address);
		}
	}

	if (EF_PROTECT_FREE)
		slot->mode = PROTECTED;
	else
		slot->mode = FREE;

	if (EF_FREE_WIPES)
		memset(slot->userAddress, 0xbd, slot->userSize);

	previousSlot = slotForInternalAddressPreviousTo(slot->internalAddress);
	nextSlot = slotForInternalAddress(
		((char *)slot->internalAddress) + slot->internalSize);

	if (previousSlot && (previousSlot->mode == FREE || previousSlot->mode == PROTECTED))
	{
		/* Coalesce previous slot with this one. */
		previousSlot->internalSize += slot->internalSize;
		if (EF_PROTECT_FREE)
			previousSlot->mode = PROTECTED;

		slot->internalAddress = slot->userAddress = 0;
		slot->internalSize = slot->userSize = 0;
		slot->mode = NOT_IN_USE;
		slot = previousSlot;
		unUsedSlots++;
	}
	if (nextSlot && (nextSlot->mode == FREE || nextSlot->mode == PROTECTED))
	{
		/* Coalesce next slot with this one. */
		slot->internalSize += nextSlot->internalSize;
		nextSlot->internalAddress = nextSlot->userAddress = 0;
		nextSlot->internalSize = nextSlot->userSize = 0;
		nextSlot->mode = NOT_IN_USE;
		unUsedSlots++;
	}

	slot->userAddress = slot->internalAddress;
	slot->userSize = slot->internalSize;

	/*
	 * Free memory is _always_ set to deny access. When EF_PROTECT_FREE
	 * is true, free memory is never reallocated, so it remains access
	 * denied for the life of the process. When EF_PROTECT_FREE is false,
	 * the memory may be re-allocated, at which time access to it will be
	 * allowed again.
	 */
	Page_DenyAccess(slot->internalAddress, slot->internalSize);

	if (!noAllocationListProtection)
		Page_DenyAccess(allocationList, allocationListSize);

	unlock();
}

extern C_LINKAGE void *
realloc(void *oldBuffer, size_t newSize)
{
	void *newBuffer = malloc(newSize);

	lock();

	if (oldBuffer)
	{
		size_t size;
		Slot *slot;

		Page_AllowAccess(allocationList, allocationListSize);
		noAllocationListProtection = 1;

		slot = slotForUserAddress(oldBuffer);

		if (slot == 0)
			EF_Abort(
				"realloc(%a, %d): address not from malloc().", oldBuffer, newSize);

		if (newSize < (size = slot->userSize))
			size = newSize;

		if (size > 0)
			memcpy(newBuffer, oldBuffer, size);

		free(oldBuffer);
		noAllocationListProtection = 0;
		Page_DenyAccess(allocationList, allocationListSize);

		if (size < newSize)
			memset(&(((char *)newBuffer)[size]), 0, newSize - size);

		/* Internal memory was re-protected in free() */
	}
	unlock();

	return newBuffer;
}

/*
 * 重写 malloc 接口
*/
extern C_LINKAGE void *
malloc(size_t size)
{
	void *allocation;

	if (allocationList == 0)
	{
		pthread_mutex_init(&mutex, NULL);
		initialize(); /* This sets EF_ALIGNMENT */
	}
	lock();
	allocation = memalign(EF_ALIGNMENT, size);

	unlock();

	return allocation;
}

extern C_LINKAGE void *
calloc(size_t nelem, size_t elsize)
{
	size_t size = nelem * elsize;
	void *allocation;

	lock();

	allocation = malloc(size);
	memset(allocation, 0, size);
	unlock();

	return allocation;
}

/*
 * This will catch more bugs if you remove the page alignment, but it
 * will break some software.
 */
extern C_LINKAGE void *
valloc(size_t size)
{
	void *allocation;

	lock();
	allocation = memalign(bytesPerPage, size);
	unlock();

	return allocation;
}
