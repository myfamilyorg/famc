#include <lexer.H>
#include <libfam/error.H>

STATIC i32 lexer_skip_white_space(Lexer* lex) {
	while (lex->offset < lex->len) {
		if (lex->text[lex->offset] != ' ' &&
		    lex->text[lex->offset] != '\t' &&
		    lex->text[lex->offset] != '\f' &&
		    lex->text[lex->offset] != '\v' &&
		    lex->text[lex->offset] != '\r' &&
		    lex->text[lex->offset] != '\n')
			break;

		lex->offset++;
	}
	return 0;
}

i32 lexer_init(Lexer* lex, const u8* text, u64 len) {
	if (!lex || !text) {
		err = EINVAL;
		return -1;
	}

	lex->text = text;
	lex->len = len;
	lex->offset = 0;

	return 0;
}

i32 lexer_next_token(Lexer* lex, Token* next) {
	u64 start;
	if (!lex || !next) {
		err = EINVAL;
		return -1;
	}

	if (lex->offset >= lex->len) return TOKEN_COMPLETE;
	start = lex->offset;
	lexer_skip_white_space(lex);
	if (lex->offset >= lex->len) return TOKEN_COMPLETE;

	if (start) {
	}

	return TOKEN_COMPLETE;
}
