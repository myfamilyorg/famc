/* Ensure compiler compat */
#ifndef __famc__

#define STATIC_ASSERT(condition, message) \
	typedef unsigned char static_assert_##message[(condition) ? 1 : -1]

STATIC_ASSERT(sizeof(char) == 1, char_size);
STATIC_ASSERT(sizeof(unsigned char) == 1, uchar_size);
STATIC_ASSERT(sizeof(short) == 2, short_size);
STATIC_ASSERT(sizeof(unsigned short) == 2, ushort_size);
STATIC_ASSERT(sizeof(int) == 4, int_size);
STATIC_ASSERT(sizeof(unsigned int) == 4, uint_size);
STATIC_ASSERT(sizeof(unsigned) == 4, u2int_size);
STATIC_ASSERT(sizeof(long) == 8, long_size);
STATIC_ASSERT(sizeof(unsigned long) == 8, ulong_size);
STATIC_ASSERT(sizeof(void *) == 8, os_64_bit);
STATIC_ASSERT(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, little_endian);

#endif /* __famc__ */

struct open_how {
	unsigned long flags;
	unsigned long mode;
	unsigned long resolve;
};

struct io_cqring_offsets {
	unsigned head;
	unsigned tail;
	unsigned ring_mask;
	unsigned ring_entries;
	unsigned overflow;
	unsigned cqes;
	unsigned flags;
	unsigned resv1;
	unsigned long user_addr;
};

struct io_sqring_offsets {
	unsigned head;
	unsigned tail;
	unsigned ring_mask;
	unsigned ring_entries;
	unsigned flags;
	unsigned dropped;
	unsigned array;
	unsigned resv1;
	unsigned long user_addr;
};

struct io_uring_params {
	unsigned sq_entries;
	unsigned cq_entries;
	unsigned flags;
	unsigned sq_thread_cpu;
	unsigned sq_thread_idle;
	unsigned features;
	unsigned wq_fd;
	unsigned resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

struct io_uring_rsrc_update2 {
	unsigned offset;
	unsigned resv;
	unsigned long data;
	unsigned long tags;
	unsigned nr;
	unsigned resv2;
};

struct io_uring_cqe {
	unsigned long user_data;
	int res;
	unsigned flags;
};

struct io_uring_sqe {
	unsigned char opcode;
	unsigned char flags;
	unsigned short ioprio;
	int fd;
	unsigned long off;
	unsigned long addr;
	unsigned len;
	unsigned other_flags;
	unsigned long user_data;
	unsigned short buf_index;
	unsigned short personality;
	int splice_fd_in;
	struct {
		unsigned long addr3;
		unsigned long __pad2[1];
	} addr3;
};

struct Sync {
	struct io_uring_params params;
	int ring_fd;
	unsigned char *sq_ring;
	unsigned char *cq_ring;
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	unsigned long sq_ring_size;
	unsigned long cq_ring_size;
	unsigned long sqes_size;
	unsigned *sq_tail;
	unsigned *sq_array;
	unsigned *cq_head;
	unsigned *cq_tail;
	unsigned *sq_mask;
	unsigned *cq_mask;
};

/*
int IORING_OP_NOP = 0;
int IORING_OP_READV = 1;
int IORING_OP_WRITEV = 2;
int IORING_OP_FSYNC = 3;
int IORING_OP_READ_FIXED = 4;
int IORING_OP_WRITE_FIXED = 5;
int IORING_OP_POLL_ADD = 6;
int IORING_OP_POLL_REMOVE = 7;
int IORING_OP_SYNC_FILE_RANGE = 8;
int IORING_OP_SENDMSG = 9;
int IORING_OP_RECVMSG = 10;
int IORING_OP_TIMEOUT = 11;
int IORING_OP_TIMEOUT_REMOVE = 12;
int IORING_OP_ACCEPT = 13;
int IORING_OP_ASYNC_CANCEL = 14;
int IORING_OP_LINK_TIMEOUT = 15;
int IORING_OP_CONNECT = 16;
int IORING_OP_FALLOCATE = 17;
int IORING_OP_OPENAT = 18;
int IORING_OP_CLOSE = 19;
int IORING_OP_FILES_UPDATE = 20;
int IORING_OP_STATX = 21;
int IORING_OP_READ = 22;
int IORING_OP_WRITE = 23;
int IORING_OP_FADVISE = 24;
int IORING_OP_MADVISE = 25;
int IORING_OP_SEND = 26;
int IORING_OP_RECV = 27;
int IORING_OP_OPENAT2 = 28;
int IORING_OP_EPOLL_CTL = 29;
int IORING_OP_SPLICE = 30;
int IORING_OP_PROVIDE_BUFFERS = 31;
int IORING_OP_REMOVE_BUFFERS = 32;
int IORING_OP_TEE = 33;
int IORING_OP_SHUTDOWN = 34;
int IORING_OP_RENAMEAT = 35;
int IORING_OP_UNLINKAT = 36;
int IORING_OP_MKDIRAT = 37;
int IORING_OP_SYMLINKAT = 38;
int IORING_OP_LINKAT = 39;
int IORING_OP_MSG_RING = 40;
int IORING_OP_FSETXATTR = 41;
int IORING_OP_SETXATTR = 42;
int IORING_OP_FGETXATTR = 43;
int IORING_OP_GETXATTR = 44;
int IORING_OP_SOCKET = 45;
int IORING_OP_URING_CMD = 46;
int IORING_OP_SEND_ZC = 47;
int IORING_OP_SENDMSG_ZC = 48;
int IORING_OP_READ_MULTISHOT = 49;
int IORING_OP_WAITID = 50;
int IORING_OP_FUTEX_WAIT = 51;
int IORING_OP_FUTEX_WAKE = 52;
int IORING_OP_FUTEX_WAITV = 53;
int IORING_OP_FIXED_FD_INSTALL = 54;
int IORING_OP_FTRUNCATE = 55;
int IORING_OP_BIND = 56;
int IORING_OP_LISTEN = 57;
int IORING_OP_RECV_ZC = 58;
int IORING_OP_EPOLL_WAIT = 59;
int IORING_OP_READV_FIXED = 60;
int IORING_OP_WRITEV_FIXED = 61;
int IORING_OP_PIPE = 62;
int IORING_OP_NOP128 = 63;
int IORING_OP_URING_CMD128 = 64;
int IORING_OP_LAST = 65;

int PROT_READ = 1;
int PROT_WRITE = 2;
int MAP_SHARED = 1;
int MAP_PRIVATE = 2;
int MAP_ANONYMOUS = 32;
void *MAP_FAILED = (void *)-1;

unsigned long IORING_OFF_SQ_RING = 0;
unsigned long IORING_OFF_CQ_RING = 134217728;
unsigned long IORING_OFF_SQES = 268435456;

unsigned IORING_ENTER_GETEVENTS = 1;
*/

int errno;
struct Sync *global_sync;

void *memset(void *ptr, int value, unsigned long len) {
	unsigned long i;
	i = 0;
loop:
	if (i >= len) return ptr;
	((char *)ptr)[i++] = (unsigned char)value;
	goto loop;
}

void *memcpy(void *dest, const void *src, unsigned long n) {
	char *d = (char *)dest;
	const char *s = (void *)src;
	while (n--) *d++ = *s++;
	return dest;
}

long raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4,
		 long a5);
__asm(
    ".section .text\n"
    ".local raw_syscall\n"
    "raw_syscall:\n"
    "endbr64\n"
    "mov    %rdi,%rax\n"
    "mov    %r8,%r10\n"
    "mov    %rsi,%rdi\n"
    "mov    %r9,%r8\n"
    "mov    %rdx,%rsi\n"
    "mov    0x8(%rsp),%r9\n"
    "mov    %rcx,%rdx\n"
    "syscall\n"
    "ret\n"
    "xchg   %ax,%ax\n");

int close(int fd) {
	int ret;
	ret = raw_syscall(3, fd, 0, 0, 0, 0, 0);
	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}
	return ret;
}

void *mmap(void *addr, unsigned long length, int prot, int flags, int fd,
	   long offset) {
	void *ret;
	ret =
	    (void *)raw_syscall(9, (long)addr, length, prot, flags, fd, offset);
	if ((long)ret < 0) {
		errno = -(long)ret;
		return (void *)-1;
	}
	return ret;
}
int munmap(void *addr, unsigned long length) {
	int ret;
	ret = raw_syscall(11, (long)addr, length, 0, 0, 0, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	return 0;
}

void exit_group(int status) {
	raw_syscall(231, status, 0, 0, 0, 0, 0);
s:
	goto s;
}

int io_uring_setup(unsigned entries, struct io_uring_params *params) {
	int ret;
	ret = raw_syscall(425, entries, (long)params, 0, 0, 0, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	return ret;
}
int io_uring_enter2(unsigned fd, unsigned to_submit, unsigned min_complete,
		    unsigned flags, void *arg, unsigned long sz) {
	int ret;
	ret =
	    raw_syscall(426, fd, to_submit, min_complete, flags, (long)arg, sz);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	return 0;
}

void sync_destroy(struct Sync *sync) {
	if (sync) {
		if (sync->sq_ring) munmap(sync->sq_ring, sync->sq_ring_size);
		sync->sq_ring = 0;
		if (sync->cq_ring) munmap(sync->cq_ring, sync->cq_ring_size);
		sync->cq_ring = 0;
		if (sync->sqes) munmap(sync->sqes, sync->sqes_size);
		sync->sqes = 0;

		if (sync->ring_fd > 0) close(sync->ring_fd);
		sync->ring_fd = -1;

		munmap(sync, sizeof(struct Sync));
	}
}

int sync_init(struct Sync **s) {
	struct Sync *sync;

	sync = mmap(0, sizeof(struct Sync), 3, 33, -1, 0);
	if (sync == (void *)-1) {
		return -1;
	}

	sync->sq_ring = 0;
	sync->cq_ring = 0;
	sync->sqes = 0;
	sync->ring_fd = io_uring_setup(1, &sync->params);
	if (sync->ring_fd < 0) {
		sync_destroy(sync);
		return -1;
	}

	sync->sq_ring_size = sync->params.sq_off.array +
			     sync->params.sq_entries * sizeof(unsigned);
	sync->cq_ring_size =
	    sync->params.cq_off.cqes +
	    sync->params.cq_entries * sizeof(struct io_uring_cqe);
	sync->sqes_size = sync->params.sq_entries * sizeof(struct io_uring_sqe);

	sync->sq_ring = mmap(0, sync->sq_ring_size, 3, 1, sync->ring_fd, 0);
	if (sync->sq_ring == (void *)-1) {
		sync->sq_ring = 0;
		sync_destroy(sync);
		return -1;
	}

	sync->cq_ring =
	    mmap(0, sync->cq_ring_size, 3, 1, sync->ring_fd, 134217728);

	if (sync->cq_ring == (void *)-1) {
		sync->cq_ring = 0;
		sync_destroy(sync);
		return -1;
	}
	sync->sqes = mmap(0, sync->sqes_size, 3, 1, sync->ring_fd, 268435456);
	if (sync->sqes == (void *)-1) {
		sync->sqes = 0;
		sync_destroy(sync);
		return -1;
	}

	sync->sq_tail = (unsigned *)(sync->sq_ring + sync->params.sq_off.tail);
	sync->sq_array =
	    (unsigned *)(sync->sq_ring + sync->params.sq_off.array);
	sync->cq_head = (unsigned *)(sync->cq_ring + sync->params.cq_off.head);
	sync->cq_tail = (unsigned *)(sync->cq_ring + sync->params.cq_off.tail);
	sync->sq_mask =
	    (unsigned *)(sync->sq_ring + sync->params.sq_off.ring_mask);

	sync->cq_mask =
	    (unsigned *)(sync->cq_ring + sync->params.cq_off.ring_mask);
	sync->cqes =
	    (struct io_uring_cqe *)(sync->cq_ring + sync->params.cq_off.cqes);

	*s = sync;
	return 0;
}

void atomic_add_u32(unsigned *ptr, unsigned value);
__asm(
    ".section .text\n"
    ".local atomic_add_u32\n"
    "atomic_add_u32 :\n"
    "endbr64\n"
    "lock add %esi,(%rdi)\n"
    "ret\n");

void atomic_sub_u32(unsigned *ptr, unsigned value);
__asm(
    ".section .text\n"
    ".local atomic_sub_u32\n"
    "atomic_sub_u32 :\n"
    "endbr64\n"
    "lock sub %esi,(%rdi)\n"
    "ret\n");

long sync_execute(struct Sync *sync, struct io_uring_sqe sqe) {
	int ret, result;
	unsigned cq_mask, sq_mask, sq_tail, index, cq_head, idx;

	cq_mask = *sync->cq_mask;
	sq_mask = *sync->sq_mask;
	sq_tail = *sync->sq_tail;
	index = sq_tail & sq_mask;
	cq_head = *sync->cq_head;
	sync->sq_array[index] = index;
	sync->sqes[index] = sqe;
	atomic_add_u32(sync->sq_tail, 1);
	ret = io_uring_enter2(sync->ring_fd, 1, 1, 1, 0, 0);

	if (ret < 0)
		atomic_sub_u32(sync->sq_tail, 1);
	else {
		idx = cq_head & cq_mask;
		result = sync->cqes[idx].res;
		if (sync->cqes[idx].res < 0) {
			ret = -1;
			errno = -result;
		} else
			ret = result;

		atomic_add_u32(sync->cq_head, 1);
	}

	if (ret < 0) return -1;
	return ret;
}

int pwrite(int fd, void *buf, unsigned long len, unsigned long offset) {
	struct io_uring_sqe sqe;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = 23;
	sqe.addr = (unsigned long)buf;
	sqe.fd = fd;
	sqe.len = len;
	sqe.off = offset;
	sqe.user_data = 1;

	if (!global_sync)
		if (sync_init(&global_sync) < 0) return -1;

	return sync_execute(global_sync, sqe);
}

int open(const char *path, int flags, unsigned mode) {
	struct open_how how;
	struct io_uring_sqe sqe;

	memset(&sqe, 0, sizeof(sqe));
	how.flags = flags;
	how.mode = mode;
	how.resolve = 0;
	sqe.opcode = 28;
	sqe.addr = (unsigned long)path;
	sqe.fd = -100;
	sqe.len = sizeof(struct open_how);
	sqe.off = (unsigned long)&how;
	sqe.user_data = 1;

	if (!global_sync)
		if (sync_init(&global_sync) < 0) return -1;
	return sync_execute(global_sync, sqe);
}

int main(int argc, char **argv, char **envp) {
	global_sync = 0;
	errno = 0;
	if (!argv || !envp || !argc) {
		pwrite(2, "err!\n", 5, 0);
		exit_group(-1);
	}
	pwrite(2, "hello world!\n", 13, 0);
	return argc;
}

__asm(
    ".section .text\n"
    ".global _start\n"
    "_start:\n"
    "    movq (%rsp), %rdi\n"
    "    lea 8(%rsp), %rsi\n"
    "    mov %rdi, %rcx\n"
    "    add $1, %rcx\n"
    "    shl $3, %rcx\n"
    "    lea (%rsi, %rcx), %rdx\n"
    "    mov %rsp, %rcx\n"
    "    and $-16, %rsp\n"
    "    call main\n"
    "    mov %rax, %rdi\n"
    "    jmp exit_group\n");

