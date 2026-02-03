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

enum TokenType {
	Term,
	StringLit,
	CharLit,
	NumberLit,
	SemiPunct,
	AsteriskPunct,
	AmpersandPunct,
	PipePunct,
	RightBracketPunct,
	LeftBracketPunct,
	RightBracePunct,
	LeftBracePunct,
	RightParenPunct,
	LeftParenPunct,
	DotPunct,
	PercentPunct,
	DivPunct,
	CommaPunct,
	ColonPunct,
	BangPunct,
	NotEqualPunct,
	EqualIncrPunct,
	EqualDecrPunct,
	IncrPunct,
	DecrPunct,
	EqualPunct,
	DoubleEqualPunct,
	GreaterThanEqualPunct,
	LessThanEqualPunct,
	GreaterThanPunct,
	LessThanPunct,
	LogicalAndPunct,
	LogicalOrPunct,
	MinusPunct,
	PlusPunct,
	ArrowPunct,
	SizeOfReserved,
	GotoReserved,
	IfReserved,
	ElseReserved,
	EnumReserved,
	StructReserved,
	IntReserved,
	LongReserved,
	UnsignedReserved,
	AsmReserved,
	CharReserved,
	ShortReserved,
	ReturnReserved,
	VoidReserved,
	Ident,
	TokenError,
	TokenTypeLast
};

struct lexer {
	char *in;
	unsigned long off;
	unsigned long line_num;
	unsigned long col_start;
	unsigned long len;
};

enum node_kind {
	NodeIntLiteral,
	NodeStringLiteral,
	NodeIdent,
	NodeBinaryExpr,
	NodeIf,
	NodeBlock,
	NodeGoto,
	NodeDeref,
	NodePostIncr,
	NodeLabel,
	NodeCast,
	NodeReturn,
	NodeVarDecl,
	NodeFuncDecl,
	NodeFuncProto,
	NodeCall,
	NodeStructDecl,
	NodeMemberAccess,
	NodeArraySubscript,
	NodeEnumDecl,
	NodeEnumeratorDecl,
	NodePointerType,
	NodeArrayType,
	NodeStructType,
	NodeEnumType,
	NodeAsm,
	NodeAssign
};

enum binary_kind_op {
	BinOpAdd,
	BinOpSub,
	BinOpMul,
	BinOpDiv,
	BinOpMod,
	BinOpGE,
	BinOpEQ,
	BinOpNE,
	BinOpLT,
	BinOpLE,
	BinOpGT
};

enum assign_op_kind { AssignSimple, AssignAdd, AssignSub };

struct asm_data {
	char **lines;
	unsigned long count;
};

struct assign_data {
	struct node *lhs;
	struct node *rhs;
	enum assign_op_kind op;
};

struct source_location {
	unsigned long off;
	unsigned long line_num;
	unsigned long column_num;
};

struct node {
	enum node_kind kind;
	struct source_location src_loc;
	void *data;
};

struct int_literal_data {
	unsigned long value;
};

struct string_literal {
	char *value;
	unsigned long len;
};

struct cast_data {
	struct node *type;
	struct node *expr;
};

struct dereference_data {
	struct node *expr;
};

struct post_increment_data {
	struct node *expr;
};

struct post_decrement_data {
	struct node *expr;
};

struct goto_data {
	struct node *label;
};

struct label_data {
	struct node *name;
};

struct binary_expr {
	struct node *left;
	struct node *right;
	enum binary_kind_op op;
};

struct struct_type_data {
	struct node *name;
};

struct enum_type_data {
	struct node *name;
};

struct block_data {
	struct node **stmts;
	unsigned long count;
};

struct return_data {
	struct node *expr;
};

struct var_decl_data {
	struct node *type;
	struct node *name;
	struct node *init;
};

struct func_decl_data {
	struct node *return_type;
	struct node *name;
	struct node **params;
	unsigned long param_count;
	struct node *body;
};

struct call_data {
	struct node *callee;
	struct node **args;
	unsigned long arg_count;
};

struct struct_decl_data {
	struct node *name;
	struct node **fields;
	unsigned long field_count;
};

struct member_access_data {
	struct node *base;
	struct node *field;
	int is_arrow;
};

struct array_subscript_data {
	struct node *base;
	struct node *index;
};

struct enum_decl_data {
	struct node *name;
	struct node **enumerators;
	unsigned long count;
};

struct enumerator_data {
	struct node *name;
	struct node *value;
};

struct pointer_type_data {
	struct node *pointee;
};

struct array_type_data {
	struct node *element_type;
	unsigned long size;
};

struct statx_timestamp {
	long tv_sec;
	unsigned tv_nsec;
	int __reserved;
};

struct statx {
	unsigned stx_mask;
	unsigned stx_blksize;
	unsigned long stx_attributes;
	unsigned stx_nlink;
	unsigned stx_uid;
	unsigned stx_gid;
	unsigned short stx_mode;
	unsigned short __spare0[1];
	unsigned long stx_ino;
	unsigned long stx_size;
	unsigned long stx_blocks;
	unsigned long stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	unsigned stx_rdev_major;
	unsigned stx_rdev_minor;
	unsigned stx_dev_major;
	unsigned stx_dev_minor;
	unsigned long stx_mnt_id;
	unsigned stx_dio_mem_align;
	unsigned stx_dio_offset_align;
	unsigned long __spare3[12];
};

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

int errno;
struct Sync *global_sync;

void *memset(void *ptr, int value, unsigned long len) {
	unsigned long i;
	i = 0;
begin:
	if (i >= len) return ptr;
	((char *)ptr)[i++] = (unsigned char)value;
	goto begin;
}

void *memcpy(void *dest, void *src, unsigned long n) {
	char *d = (char *)dest;
	char *s = (void *)src;
begin:
	if (n--) goto end;
	*d++ = *s++;
	goto begin;
end:
	return dest;
}

void *memmove(void *dest, const void *src, unsigned long n) {
	char *d = (void *)((char *)dest + n);
	char *s = (void *)((char *)src + n);
begin:
	if (n-- == 0) goto end;
	d--;
	s--;
	*d = *s;
	goto begin;
end:
	return dest;
}

unsigned long strlen(char *x) {
	char *y = x;
begin:
	if (!*x) goto end;
	x++;
	goto begin;
end:
	return x - y;
}

long raw_syscall(long sysno, long a0, long a1, long a2, long a3, long a4,
		 long a5);
__asm(
    ".section .text\n"
    "raw_syscall:\n"
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

void atomic_add_unsigned(unsigned *ptr, unsigned value);
__asm(
    ".section .text\n"
    "atomic_add_unsigned :\n"
    "lock add %esi,(%rdi)\n"
    "ret\n");

void atomic_sub_unsigned(unsigned *ptr, unsigned value);
__asm(
    ".section .text\n"
    "atomic_sub_unsigned :\n"
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
	atomic_add_unsigned(sync->sq_tail, 1);
	ret = io_uring_enter2(sync->ring_fd, 1, 1, 1, 0, 0);

	if (ret < 0)
		atomic_sub_unsigned(sync->sq_tail, 1);
	else {
		idx = cq_head & cq_mask;
		result = sync->cqes[idx].res;
		if (sync->cqes[idx].res < 0) {
			ret = -1;
			errno = -result;
		} else
			ret = result;

		atomic_add_unsigned(sync->cq_head, 1);
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

int open(char *path, int flags, unsigned mode) {
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

int ftruncate(int fd, unsigned long len) {
	struct io_uring_sqe sqe;

	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = 55;
	sqe.fd = fd;
	sqe.off = len;
	sqe.user_data = 1;

	if (!global_sync)
		if (sync_init(&global_sync) < 0) return -1;

	return sync_execute(global_sync, sqe);
}

int statx(char *pathname, struct statx *st) {
	struct io_uring_sqe sqe;
	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = 21;
	sqe.fd = -100;
	sqe.addr = (unsigned long)pathname;
	sqe.len = 2047;
	sqe.off = (unsigned long)st;
	sqe.user_data = 1;
	if (!global_sync)
		if (sync_init(&global_sync) < 0) return -1;
	return sync_execute(global_sync, sqe);
}

int unlink(char *pathname) {
	struct io_uring_sqe sqe;
	memset(&sqe, 0, sizeof(sqe));
	sqe.opcode = 36;
	sqe.fd = -100;
	sqe.addr = (unsigned long)pathname;
	sqe.user_data = 1;
	if (!global_sync)
		if (sync_init(&global_sync) < 0) return -1;
	return sync_execute(global_sync, sqe);
}

void panic(char *msg) {
	pwrite(2, msg, strlen(msg), 0);
	pwrite(2, "\n", 1, 0);
	exit_group(-1);
}

int fdputs(int fd, char *msg) { return pwrite(fd, msg, strlen(msg), 0); }

int write_num(int fd, unsigned long num) {
	char buf[21];
	char *p;
	unsigned long len;
	long written;
	if (fd < 0) return -1;
	p = buf + sizeof(buf) - 1;
	*p = '\0';

	if (num == 0)
		*--p = '0';
	else {
	begin:
		if (num <= 0) goto end;
		*--p = '0' + (num % 10);
		num = num / 10;
		goto begin;
	}
end:

	len = buf + sizeof(buf) - 1 - p;
	written = pwrite(fd, p, len, 0);
	if (written < 0) return -1;
	if ((unsigned long)written != len) return -1;
	return 0;
}

void *map(unsigned long length) {
	void *v = mmap(0, length, 3, 34, -1, 0);
	if (v == (void *)-1) return 0;
	return v;
}

void *fmap(int fd, unsigned long size, unsigned long offset) {
	void *v = mmap(0, size, 3, 1, fd, offset);
	if (v == (void *)-1) return 0;
	return v;
}

void *fmap_ro(int fd, unsigned long size, unsigned long offset) {
	void *v = mmap(0, size, 1, 1, fd, offset);
	if (v == (void *)-1) return 0;
	return v;
}

int lexer_skip_whitespace(struct lexer *l) {
	char c;
begin:
	if (l->off >= l->len) return 0;
	c = l->in[l->off];
	if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' ||
	    c == '\f') {
		if (l->in[l->off] == '\n') {
			l->col_start = l->off + 1;
			l->line_num++;
		}
		l->off++;
		goto begin;
	}

	if (c == '/' && l->off + 1 < l->len && l->in[l->off + 1] == '*') {
		l->off += 2;

	comment_body:
		if (l->off + 1 >= l->len) return -1;

		if (l->in[l->off] == '*' && l->off + 1 < l->len &&
		    l->in[l->off + 1] == '/') {
			l->off += 2;
			goto begin;
		}
		if (l->in[l->off] == '\n') {
			l->col_start = l->off + 1;
			l->line_num++;
		}
		l->off++;
		goto comment_body;
	}

	if (c == '#') {
		l->off++;
	preproc_body:
		if (l->off >= l->len) return -1;
		if (l->in[l->off] == '#' && l->in[l->off + 1] == 'e' &&
		    l->in[l->off + 2] == 'n' && l->in[l->off + 3] == 'd' &&
		    l->in[l->off + 4] == 'i' && l->in[l->off + 5] == 'f') {
			l->off += 6;
			goto begin;
		}
		if (l->in[l->off] == '\n') {
			l->col_start = l->off + 1;
			l->line_num++;
		}

		l->off++;
		goto preproc_body;
	}

	return 0;
}

enum TokenType lexer_read_ident(struct lexer *l) {
begin:
	if (!(l->off < l->len &&
	      ((l->in[l->off] >= 'a' && l->in[l->off] <= 'z') ||
	       (l->in[l->off] >= 'A' && l->in[l->off] <= 'Z') ||
	       l->in[l->off] == '_' ||
	       (l->in[l->off] >= '0' && l->in[l->off] <= '9'))))
		goto end;
	l->off++;
	goto begin;
end:
	return Ident;
}

enum TokenType lexer_next_token(struct lexer *l, unsigned long *start) {
	if (l->off >= l->len) return Term;
	if (lexer_skip_whitespace(l) < 0) {
		*start = l->off;
		return TokenError;
	}
	*start = l->off;
	if (l->in[l->off] == '\"') {
		l->off++;
	begin_strlit:
		if (l->off >= l->len ||
		    (l->in[l->off] == '\n' && l->in[l->off - 1] != '\\'))
			return TokenError;
		if (l->in[l->off] == '\"') goto end_strlit;
		if (l->in[l->off] == '\n') {
			l->col_start = l->off + 1;
			l->line_num++;
		}

		l->off++;
		goto begin_strlit;
	end_strlit:
		l->off++;
		return StringLit;
	} else if (l->in[l->off] == '\'') {
		if (l->off + 2 < l->len) {
			l->off++;
			return TokenError;
		}
		if (l->in[l->off + 1] == '\\' && l->off + 3 < l->len)
			return TokenError;
		if (l->in[l->off + 1] == '\n') {
			l->col_start = l->off + 1;
			l->line_num++;
			l->off++;
			return TokenError;
		}

		if (l->in[l->off + 1] == '\\')
			l->off += 4;
		else
			l->off += 3;
		if (l->in[l->off - 1] != '\'' || l->in[l->off - 2] == '\n')
			return TokenError;
		return CharLit;
	} else if (l->in[l->off] == '(') {
		l->off++;
		return LeftParenPunct;
	} else if (l->in[l->off] == ')') {
		l->off++;
		return RightParenPunct;
	} else if (l->in[l->off] == '+') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '+') {
			l->off += 2;
			return IncrPunct;
		} else if (l->off + 1 < l->len && l->in[l->off + 1] == '=') {
			l->off += 2;
			return EqualIncrPunct;
		} else {
			l->off++;
			return PlusPunct;
		}
	} else if (l->in[l->off] == '.') {
		l->off++;
		return DotPunct;
	} else if (l->in[l->off] == '{') {
		l->off++;
		return LeftBracePunct;
	} else if (l->in[l->off] == '}') {
		l->off++;
		return RightBracePunct;
	} else if (l->in[l->off] == '[') {
		l->off++;
		return LeftBracketPunct;
	} else if (l->in[l->off] == ']') {
		l->off++;
		return RightBracketPunct;
	} else if (l->in[l->off] == ';') {
		l->off++;
		return SemiPunct;
	} else if (l->in[l->off] == '=') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '=') {
			l->off += 2;
			return DoubleEqualPunct;
		} else {
			l->off++;
			return EqualPunct;
		}
	} else if (l->in[l->off] == '>') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '=') {
			l->off += 2;
			return GreaterThanEqualPunct;
		} else {
			l->off++;
			return GreaterThanPunct;
		}
	} else if (l->in[l->off] == '<') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '=') {
			l->off += 2;
			return LessThanEqualPunct;
		} else {
			l->off++;
			return LessThanPunct;
		}
	} else if (l->in[l->off] == '*') {
		l->off++;
		return AsteriskPunct;
	} else if (l->in[l->off] == '&') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '&') {
			l->off += 2;
			return LogicalAndPunct;
		} else {
			l->off++;
			return AmpersandPunct;
		}
	} else if (l->in[l->off] == '|') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '|') {
			l->off += 2;
			return LogicalOrPunct;
		} else {
			l->off++;
			return PipePunct;
		}
	} else if (l->in[l->off] == ',') {
		l->off++;
		return CommaPunct;
	} else if (l->in[l->off] == ':') {
		l->off++;
		return ColonPunct;
	} else if (l->in[l->off] == '/') {
		l->off++;
		return DivPunct;
	} else if (l->in[l->off] == '%') {
		l->off++;
		return PercentPunct;
	} else if (l->in[l->off] == '!') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '=') {
			l->off += 2;
			return NotEqualPunct;
		} else {
			l->off++;
			return BangPunct;
		}
	} else if (l->in[l->off] == '-') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == '+') {
			l->off += 2;
			return DecrPunct;
		} else if (l->off + 1 < l->len && l->in[l->off + 1] == '=') {
			l->off += 2;
			return EqualDecrPunct;
		} else if (l->off + 1 < l->len && l->in[l->off + 1] == '>') {
			l->off += 2;
			return ArrowPunct;
		} else {
			l->off++;
			return MinusPunct;
		}
	} else if (l->in[l->off] == '_') {
		if (l->off + 4 < l->len && l->in[l->off + 1] == '_' &&
		    l->in[l->off + 2] == 'a' && l->in[l->off + 3] == 's' &&
		    l->in[l->off + 4] == 'm') {
			if (l->off + 5 < l->len) {
				char ch = l->in[l->off + 5];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}
			l->off += 5;
			return AsmReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'c') {
		if (l->off + 3 < l->len && l->in[l->off + 1] == 'h' &&
		    l->in[l->off + 2] == 'a' && l->in[l->off + 3] == 'r') {
			if (l->off + 4 < l->len) {
				char ch = l->in[l->off + 4];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 4;
			return CharReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'v') {
		if (l->off + 3 < l->len && l->in[l->off + 1] == 'o' &&
		    l->in[l->off + 2] == 'i' && l->in[l->off + 3] == 'd') {
			if (l->off + 4 < l->len) {
				char ch = l->in[l->off + 4];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 4;
			return VoidReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'l') {
		if (l->off + 3 < l->len && l->in[l->off + 1] == 'o' &&
		    l->in[l->off + 2] == 'n' && l->in[l->off + 3] == 'g') {
			if (l->off + 4 < l->len) {
				char ch = l->in[l->off + 4];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 4;
			return LongReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'u') {
		if (l->off + 7 < l->len && l->in[l->off + 1] == 'n' &&
		    l->in[l->off + 2] == 's' && l->in[l->off + 3] == 'i' &&
		    l->in[l->off + 4] == 'g' && l->in[l->off + 5] == 'n' &&
		    l->in[l->off + 6] == 'e' && l->in[l->off + 7] == 'd') {
			if (l->off + 8 < l->len) {
				char ch = l->in[l->off + 8];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 8;
			return UnsignedReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'e') {
		if (l->off + 3 < l->len && l->in[l->off + 1] == 'l' &&
		    l->in[l->off + 2] == 's' && l->in[l->off + 3] == 'e') {
			if (l->off + 4 < l->len) {
				char ch = l->in[l->off + 4];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 4;
			return ElseReserved;
		} else if (l->off + 3 < l->len && l->in[l->off + 1] == 'n' &&
			   l->in[l->off + 2] == 'u' &&
			   l->in[l->off + 3] == 'm') {
			if (l->off + 4 < l->len) {
				char ch = l->in[l->off + 4];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 4;
			return EnumReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'g') {
		if (l->off + 3 < l->len && l->in[l->off + 1] == 'o' &&
		    l->in[l->off + 2] == 't' && l->in[l->off + 3] == 'o') {
			if (l->off + 4 < l->len) {
				char ch = l->in[l->off + 4];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 4;
			return GotoReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 's') {
		if (l->off + 4 < l->len && l->in[l->off + 1] == 'h' &&
		    l->in[l->off + 2] == 'o' && l->in[l->off + 3] == 'r' &&
		    l->in[l->off + 4] == 't') {
			if (l->off + 5 < l->len) {
				char ch = l->in[l->off + 5];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 5;
			return ShortReserved;
		} else if (l->off + 5 < l->len && l->in[l->off + 1] == 't' &&
			   l->in[l->off + 2] == 'r' &&
			   l->in[l->off + 3] == 'u' &&
			   l->in[l->off + 4] == 'c' &&
			   l->in[l->off + 5] == 't') {
			if (l->off + 6 < l->len) {
				char ch = l->in[l->off + 6];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 6;
			return StructReserved;
		} else if (l->off + 5 < l->len && l->in[l->off + 1] == 'i' &&
			   l->in[l->off + 2] == 'z' &&
			   l->in[l->off + 3] == 'e' &&
			   l->in[l->off + 4] == 'o' &&
			   l->in[l->off + 5] == 'f') {
			if (l->off + 6 < l->len) {
				char ch = l->in[l->off + 6];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 6;
			return SizeOfReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'i') {
		if (l->off + 1 < l->len && l->in[l->off + 1] == 'f') {
			if (l->off + 2 < l->len) {
				char ch = l->in[l->off + 2];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 2;
			return IfReserved;
		} else if (l->off + 2 < l->len && l->in[l->off + 1] == 'n' &&
			   l->in[l->off + 2] == 't') {
			if (l->off + 3 < l->len) {
				char ch = l->in[l->off + 3];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 3;
			return IntReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] == 'r') {
		if (l->off + 5 < l->len && l->in[l->off + 1] == 'e' &&
		    l->in[l->off + 2] == 't' && l->in[l->off + 3] == 'u' &&
		    l->in[l->off + 4] == 'r' && l->in[l->off + 5] == 'n') {
			if (l->off + 6 < l->len) {
				char ch = l->in[l->off + 6];
				if ((ch >= 'A' && ch <= 'Z') ||
				    (ch >= 'a' && ch <= 'z') ||
				    (ch >= '0' && ch <= '9') || ch == '_')
					return lexer_read_ident(l);
			}

			l->off += 6;
			return ReturnReserved;
		} else
			return lexer_read_ident(l);
	} else if (l->in[l->off] >= '0' && l->in[l->off] <= '9') {
	number_begin:
		l->off++;
		if (l->off >= l->len || l->in[l->off] < '0' ||
		    l->in[l->off] > '9') {
			char ch = l->in[l->off];
			if ((ch >= 'A' && ch <= 'Z') ||
			    (ch >= 'a' && ch <= 'z') || ch == '_')
				return TokenError;
			goto number_end;
		}
		goto number_begin;
	number_end:
		return NumberLit;
	} else if ((l->in[l->off] >= 'a' && l->in[l->off] <= 'z') ||
		   (l->in[l->off] >= 'A' && l->in[l->off] <= 'Z') ||
		   l->in[l->off] == '_') {
		return lexer_read_ident(l);
	}

	if (l->off < l->len) {
		l->off++;
		return TokenError;
	}

	return Term;
}

int main(int argc, char **argv, char **envp) {
	unsigned long start;
	int fd;
	struct statx st;
	struct lexer l;
	enum TokenType t;
	global_sync = 0;
	errno = 0;
	if (!argv || !envp || argc != 2) panic("Usage: famc <input_file>");

	if ((fd = open(argv[1], 0, 0)) < 0) panic("No such file!");
	if (statx(argv[1], &st) < 0) panic("Could not stat input file!");

	l.in = fmap_ro(fd, st.stx_size, 0);
	if (!l.in) panic("mmap fail!");

	l.len = st.stx_size;
	l.line_num = l.col_start = l.off = 0;

	fdputs(2, "output file: ");
	pwrite(2, l.in, st.stx_size, 0);

begin:
	t = lexer_next_token(&l, &start);
	if (t == Term) goto end;
	fdputs(2, "start=");
	write_num(2, start);
	fdputs(2, ",type=");
	write_num(2, t);
	fdputs(2, ",lineno=");
	write_num(2, l.line_num + 1);
	fdputs(2, ",col=");
	write_num(2, start - l.col_start);
	fdputs(2, "\n");
	goto begin;
end:

	close(fd);
	munmap(l.in, st.stx_size);
	return 0;
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

