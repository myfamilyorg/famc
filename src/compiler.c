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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-const-variable"

static const int IORING_OP_NOP = 0;
static const int IORING_OP_READV = 1;
static const int IORING_OP_WRITEV = 2;
static const int IORING_OP_FSYNC = 3;
static const int IORING_OP_READ_FIXED = 4;
static const int IORING_OP_WRITE_FIXED = 5;
static const int IORING_OP_POLL_ADD = 6;
static const int IORING_OP_POLL_REMOVE = 7;
static const int IORING_OP_SYNC_FILE_RANGE = 8;
static const int IORING_OP_SENDMSG = 9;
static const int IORING_OP_RECVMSG = 10;
static const int IORING_OP_TIMEOUT = 11;
static const int IORING_OP_TIMEOUT_REMOVE = 12;
static const int IORING_OP_ACCEPT = 13;
static const int IORING_OP_ASYNC_CANCEL = 14;
static const int IORING_OP_LINK_TIMEOUT = 15;
static const int IORING_OP_CONNECT = 16;
static const int IORING_OP_FALLOCATE = 17;
static const int IORING_OP_OPENAT = 18;
static const int IORING_OP_CLOSE = 19;
static const int IORING_OP_FILES_UPDATE = 20;
static const int IORING_OP_STATX = 21;
static const int IORING_OP_READ = 22;
static const int IORING_OP_WRITE = 23;
static const int IORING_OP_FADVISE = 24;
static const int IORING_OP_MADVISE = 25;
static const int IORING_OP_SEND = 26;
static const int IORING_OP_RECV = 27;
static const int IORING_OP_OPENAT2 = 28;
static const int IORING_OP_EPOLL_CTL = 29;
static const int IORING_OP_SPLICE = 30;
static const int IORING_OP_PROVIDE_BUFFERS = 31;
static const int IORING_OP_REMOVE_BUFFERS = 32;
static const int IORING_OP_TEE = 33;
static const int IORING_OP_SHUTDOWN = 34;
static const int IORING_OP_RENAMEAT = 35;
static const int IORING_OP_UNLINKAT = 36;
static const int IORING_OP_MKDIRAT = 37;
static const int IORING_OP_SYMLINKAT = 38;
static const int IORING_OP_LINKAT = 39;
static const int IORING_OP_MSG_RING = 40;
static const int IORING_OP_FSETXATTR = 41;
static const int IORING_OP_SETXATTR = 42;
static const int IORING_OP_FGETXATTR = 43;
static const int IORING_OP_GETXATTR = 44;
static const int IORING_OP_SOCKET = 45;
static const int IORING_OP_URING_CMD = 46;
static const int IORING_OP_SEND_ZC = 47;
static const int IORING_OP_SENDMSG_ZC = 48;
static const int IORING_OP_READ_MULTISHOT = 49;
static const int IORING_OP_WAITID = 50;
static const int IORING_OP_FUTEX_WAIT = 51;
static const int IORING_OP_FUTEX_WAKE = 52;
static const int IORING_OP_FUTEX_WAITV = 53;
static const int IORING_OP_FIXED_FD_INSTALL = 54;
static const int IORING_OP_FTRUNCATE = 55;
static const int IORING_OP_BIND = 56;
static const int IORING_OP_LISTEN = 57;
static const int IORING_OP_RECV_ZC = 58;
static const int IORING_OP_EPOLL_WAIT = 59;
static const int IORING_OP_READV_FIXED = 60;
static const int IORING_OP_WRITEV_FIXED = 61;
static const int IORING_OP_PIPE = 62;
static const int IORING_OP_NOP128 = 63;
static const int IORING_OP_URING_CMD128 = 64;
static const int IORING_OP_LAST = 65;

static const int PROT_READ = 1;
static const int PROT_WRITE = 2;
static const int MAP_SHARED = 1;
static const int MAP_PRIVATE = 2;
static const int MAP_ANONYMOUS = 32;
static const void *MAP_FAILED = (void *)-1;

static const unsigned long IORING_OFF_SQ_RING = 0;
static const unsigned long IORING_OFF_CQ_RING = 134217728;
static const unsigned long IORING_OFF_SQES = 268435456;

static const unsigned IORING_ENTER_GETEVENTS = 1;

#pragma GCC diagnostic pop

static int errno = 0;
static struct Sync *global_sync = 0;

static long raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4,
			long a5) {
	long result;
	register long _a3 __asm__("r10") = a3;
	register long _a4 __asm__("r8") = a4;
	register long _a5 __asm__("r9") = a5;
	__asm__ volatile("syscall"
			 : "=a"(result)
			 : "a"(sysno), "D"(a0), "S"(a1), "d"(a2), "r"(_a3),
			   "r"(_a4), "r"(_a5)
			 : "rcx", "r11", "memory");
	return result;
}

static int close(int fd) {
	int ret = raw_syscall(3, fd, 0, 0, 0, 0, 0);
	if (ret < 0) {
		errno = -ret;
		ret = -1;
	}
	return ret;
}

static void *mmap(void *addr, unsigned long length, int prot, int flags, int fd,
		  long offset) {
	void *ret =
	    (void *)raw_syscall(9, (long)addr, length, prot, flags, fd, offset);
	if ((long)ret < 0) {
		errno = -(long)ret;
		return (void *)-1;
	}
	return ret;
}
static int munmap(void *addr, unsigned long length) {
	int ret = raw_syscall(11, (long)addr, length, 0, 0, 0, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	return 0;
}

void exit_group(int status) {
	raw_syscall(231, status, 0, 0, 0, 0, 0);
	while (1);
}

static int io_uring_setup(unsigned entries, struct io_uring_params *params) {
	int ret = raw_syscall(425, entries, (long)params, 0, 0, 0, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	return ret;
}
static int io_uring_enter2(unsigned fd, unsigned to_submit,
			   unsigned min_complete, unsigned flags, void *arg,
			   unsigned long sz) {
	int ret =
	    raw_syscall(426, fd, to_submit, min_complete, flags, (long)arg, sz);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	return 0;
}

static void sync_destroy(struct Sync *sync) {
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

static int sync_init(struct Sync **s) {
	struct Sync *sync = 0;

	sync = mmap(0, sizeof(struct Sync), PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	if (sync == MAP_FAILED) {
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

	sync->sq_ring = mmap(0, sync->sq_ring_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, sync->ring_fd, IORING_OFF_SQ_RING);
	if (sync->sq_ring == MAP_FAILED) {
		sync->sq_ring = 0;
		sync_destroy(sync);
		return -1;
	}

	sync->cq_ring = mmap(0, sync->cq_ring_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, sync->ring_fd, IORING_OFF_CQ_RING);

	if (sync->cq_ring == MAP_FAILED) {
		sync->cq_ring = 0;
		sync_destroy(sync);
		return -1;
	}
	sync->sqes = mmap(0, sync->sqes_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, sync->ring_fd, IORING_OFF_SQES);
	if (sync->sqes == MAP_FAILED) {
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
__asm__(
    ".section .text\n"
    ".global atomic_add_u32\n"
    "atomic_add_u32 :\n"
    "endbr64\n"
    "lock add %esi,(%rdi)\n"
    "ret\n");

void atomic_sub_u32(unsigned *ptr, unsigned value);
__asm__(
    ".section .text\n"
    ".global atomic_sub_u32\n"
    "atomic_sub_u32 :\n"
    "endbr64\n"
    "lock sub %esi,(%rdi)\n"
    "ret\n");

static long sync_execute(struct Sync *sync, const struct io_uring_sqe sqe) {
	int ret, result;
	unsigned cq_mask = *sync->cq_mask;
	unsigned sq_mask = *sync->sq_mask;
	unsigned sq_tail = *sync->sq_tail;
	unsigned index = sq_tail & sq_mask;
	unsigned cq_head = *sync->cq_head;
	unsigned idx, flag = IORING_ENTER_GETEVENTS;
	sync->sq_array[index] = index;
	sync->sqes[index] = sqe;
	atomic_add_u32(sync->sq_tail, 1);
	ret = io_uring_enter2(sync->ring_fd, 1, 1, flag, 0, 0);

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

	return ret < 0 ? -1 : ret;
}

static int pwrite(int fd, const void *buf, unsigned long len,
		  unsigned long offset) {
	struct io_uring_sqe sqe = {0};
	sqe.opcode = IORING_OP_WRITE;
	sqe.addr = (unsigned long)buf;
	sqe.fd = fd;
	sqe.len = len;
	sqe.off = offset;
	sqe.user_data = 1;

	if (!global_sync)
		if (sync_init(&global_sync) < 0) return -1;

	return sync_execute(global_sync, sqe);
}

int main(int argc, char **argv, char **envp) {
	if (!argv || !envp) {
		pwrite(2, "err!\n", 5, 0);
		exit_group(-1);
	}
	pwrite(2, "hello world!\n", 13, 0);
	return argc;
}

__asm__(
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

