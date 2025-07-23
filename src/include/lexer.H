#include <libfam/types.H>

typedef struct {
	const u8* text;
	u64 len;
	u64 offset;
} Lexer;

typedef struct {
	i32 ttype;
	u8* value;
	u64 len;
} Token;

#define TOKEN_COMPLETE 0
#define TOKEN_OK 1
#define TOKEN_ERR 2

i32 lexer_init(Lexer* lex, const u8* text, u64 len);
i32 lexer_next_token(Lexer* lex, Token* next);
