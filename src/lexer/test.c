#include <famc/lexer.H>
#include <libfam/misc.H>
#include <libfam/test.H>

Test(lexer1) {
	Lexer l;
	Token t;
	const u8 *text = "\r  \n int  \tx(Data *v) { return v->x; } ";
	lexer_init(&l, text, strlen(text));

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 3, "t.len=3");
	ASSERT(!strcmpn(t.value, "int", 3), "t.value=int");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "x", 1), "t.value=x");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "(", 1), "t.value=(");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 4, "t.len=4");
	ASSERT(!strcmpn(t.value, "Data", 4), "t.value=Data");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "*", 1), "t.value=*");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "v", 1), "t.value=v");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, ")", 1), "t.value=)");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "{", 1), "t.value={");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, strlen("return"), "t.len=strlen(return)");
	ASSERT(!strcmpn(t.value, "return", strlen("return")), "t.value=return");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "v", 1), "t.value=v");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "->", 2), "t.value=->");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "x", 1), "t.value=x");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, ";", 1), "t.value=;");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "}", 1), "t.value=}");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_COMPLETE, "complete");
}
