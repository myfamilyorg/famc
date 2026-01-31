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

enum io_uring_op {
	IORING_OP_NOP,
	IORING_OP_READV,
	IORING_OP_WRITEV,
	IORING_OP_FSYNC,
	IORING_OP_READ_FIXED,
	IORING_OP_WRITE_FIXED,
	IORING_OP_POLL_ADD,
	IORING_OP_POLL_REMOVE,
	IORING_OP_SYNC_FILE_RANGE,
	IORING_OP_SENDMSG,
	IORING_OP_RECVMSG,
	IORING_OP_TIMEOUT,
	IORING_OP_TIMEOUT_REMOVE,
	IORING_OP_ACCEPT,
	IORING_OP_ASYNC_CANCEL,
	IORING_OP_LINK_TIMEOUT,
	IORING_OP_CONNECT,
	IORING_OP_FALLOCATE,
	IORING_OP_OPENAT,
	IORING_OP_CLOSE,
	IORING_OP_FILES_UPDATE,
	IORING_OP_STATX,
	IORING_OP_READ,
	IORING_OP_WRITE,
	IORING_OP_FADVISE,
	IORING_OP_MADVISE,
	IORING_OP_SEND,
	IORING_OP_RECV,
	IORING_OP_OPENAT2,
	IORING_OP_EPOLL_CTL,
	IORING_OP_SPLICE,
	IORING_OP_PROVIDE_BUFFERS,
	IORING_OP_REMOVE_BUFFERS,
	IORING_OP_TEE,
	IORING_OP_SHUTDOWN,
	IORING_OP_RENAMEAT,
	IORING_OP_UNLINKAT,
	IORING_OP_MKDIRAT,
	IORING_OP_SYMLINKAT,
	IORING_OP_LINKAT,
	IORING_OP_MSG_RING,
	IORING_OP_FSETXATTR,
	IORING_OP_SETXATTR,
	IORING_OP_FGETXATTR,
	IORING_OP_GETXATTR,
	IORING_OP_SOCKET,
	IORING_OP_URING_CMD,
	IORING_OP_SEND_ZC,
	IORING_OP_SENDMSG_ZC,
	IORING_OP_READ_MULTISHOT,
	IORING_OP_WAITID,
	IORING_OP_FUTEX_WAIT,
	IORING_OP_FUTEX_WAKE,
	IORING_OP_FUTEX_WAITV,
	IORING_OP_FIXED_FD_INSTALL,
	IORING_OP_FTRUNCATE,
	IORING_OP_BIND,
	IORING_OP_LISTEN,
	IORING_OP_RECV_ZC,
	IORING_OP_EPOLL_WAIT,
	IORING_OP_READV_FIXED,
	IORING_OP_WRITEV_FIXED,
	IORING_OP_PIPE,
	IORING_OP_NOP128,
	IORING_OP_URING_CMD128,
	IORING_OP_LAST
};

static const int PROT_READ = 0x01;
static const int PROT_WRITE = 0x02;
static const int MAP_SHARED = 0x01;
/* static const int MAP_PRIVATE = 0x02; */
static const int MAP_ANONYMOUS = 0x20;
static const void *MAP_FAILED = (void *)-1;

static const unsigned long IORING_OFF_SQ_RING = 0UL;
static const unsigned long IORING_OFF_CQ_RING = 0x8000000UL;
static const unsigned long IORING_OFF_SQES = 0x10000000UL;

static const unsigned IORING_ENTER_GETEVENTS = (1U << 0);

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

static int errno = 0;
static struct Sync *global_sync = 0;

long raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4,
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

int sync_init(struct Sync **s) {
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

long sync_execute(struct Sync *sync, const struct io_uring_sqe sqe) {
	int ret, result;
	unsigned cq_mask = *sync->cq_mask;
	unsigned sq_mask = *sync->sq_mask;
	unsigned sq_tail = *sync->sq_tail;
	unsigned index = sq_tail & sq_mask;
	unsigned cq_head = *sync->cq_head;
	unsigned idx, flag = IORING_ENTER_GETEVENTS;
	sync->sq_array[index] = index;
	sync->sqes[index] = sqe;
	__atomic_fetch_add(sync->sq_tail, 1, __ATOMIC_SEQ_CST);
	ret = io_uring_enter2(sync->ring_fd, 1, 1, flag, 0, 0);

	if (ret < 0)
		__atomic_fetch_add(sync->sq_tail, 1, __ATOMIC_SEQ_CST);
	else {
		idx = cq_head & cq_mask;
		result = sync->cqes[idx].res;
		if (sync->cqes[idx].res < 0) {
			ret = -1;
			errno = -result;
		} else
			ret = result;

		__atomic_fetch_add(sync->cq_head, 1, __ATOMIC_RELEASE);
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

