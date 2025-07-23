#include <famc/lexer.H>
#include <libfam/error.H>
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

Test(lexer2) {
	Lexer l;
	Token t;
	const u8 *text = "\"abc\" 123.789 'v'";

	lexer_init(&l, text, strlen(text));

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "abc literal");
	ASSERT_EQ(t.len, 5, "t.len=5");
	ASSERT(!strcmpn(t.value, "\"abc\"", 5), "t.value=\"abc\"");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "123.789 literal");
	ASSERT_EQ(t.len, 7, "t.len=7");
	ASSERT(!strcmpn(t.value, "123.789", 7), "t.value=123.789");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "'v' literal");
	ASSERT_EQ(t.len, 3, "t.len=3");
	ASSERT(!strcmpn(t.value, "'v'", 3), "'v' lit");
}

Test(lexer3_comments) {
	Lexer l;
	Token t;
	const u8 *text = "/* multi\nline comment */ // line comment\n int x;";

	lexer_init(&l, text, strlen(text));

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "int after comments");
	ASSERT_EQ(t.len, 3, "t.len=3");
	ASSERT(!strcmpn(t.value, "int", 3), "t.value=int");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "x", 1), "t.value=x");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "ok");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, ";", 1), "t.value=;");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_COMPLETE, "complete");
}

Test(lexer4_unterminated) {
	Lexer l;
	Token t;

	const u8 *text = "\"unterminated /* unterminated comment";

	lexer_init(&l, text, strlen(text));

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_ERR, "unterminated * string");
	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_COMPLETE, "complete");
}

Test(lexer5_numbers) {
	Lexer l;
	Token t;
	const u8 *text = "0xFF 077 123u 1.2f 1e-10 0x1.4p10";

	lexer_init(&l, text, strlen(text));

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "hex");
	ASSERT_EQ(t.len, 4, "t.len=4");
	ASSERT(!strcmpn(t.value, "0xFF", 4), "0xFF");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "octal");
	ASSERT_EQ(t.len, 3, "t.len=3");
	ASSERT(!strcmpn(t.value, "077", 3), "077");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "unsigned int");
	ASSERT_EQ(t.len, 4, "t.len=4");
	ASSERT(!strcmpn(t.value, "123u", 4), "123u");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "float suffix");
	ASSERT_EQ(t.len, 4, "t.len=4");
	ASSERT(!strcmpn(t.value, "1.2f", 4), "1.2f");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "exponent");
	ASSERT_EQ(t.len, 5, "t.len=5");
	ASSERT(!strcmpn(t.value, "1e-10", 5), "1e-10");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_ERR, "hex float");
}

Test(lexer6_punct) {
	Lexer l;
	Token t;
	const u8 *text =
	    ">>= <<= ... == >= <= -> ++ -- += -= *= /= %= &= |= ^= << >> && || "
	    "!= # @ ~ ? : ,";

	lexer_init(&l, text, strlen(text));

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, ">>=");
	ASSERT_EQ(t.len, 3, "t.len=3");
	ASSERT(!strcmpn(t.value, ">>=", 3), "t.value=>>=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "<<=");
	ASSERT_EQ(t.len, 3, "t.len=3");
	ASSERT(!strcmpn(t.value, "<<=", 3), "t.value=<<=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "...");
	ASSERT_EQ(t.len, 3, "t.len=3");
	ASSERT(!strcmpn(t.value, "...", 3), "t.value=...");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "==");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "==", 2), "t.value==");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, ">=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, ">=", 2), "t.value>=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "<=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "<=", 2), "t.value<=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "->");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "->", 2), "t.value->");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "++");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "++", 2), "t.value++");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "--");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "--", 2), "t.value--");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "+=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "+=", 2), "t.value+=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "-=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "-=", 2), "t.value-=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "*=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "*=", 2), "t.value*=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "/=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "/=", 2), "t.value/=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "%=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "%=", 2), "t.value%=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "&=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "&=", 2), "t.value&=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "|=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "|=", 2), "t.value|=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "^=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "^=", 2), "t.value^=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "<<");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "<<", 2), "t.value<<");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, ">>");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, ">>", 2), "t.value>>");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "&&");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "&&", 2), "t.value&&");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "||");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "||", 2), "t.value||");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "!=");
	ASSERT_EQ(t.len, 2, "t.len=2");
	ASSERT(!strcmpn(t.value, "!=", 2), "t.value!=");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "#");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "#", 1), "t.value=#");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "@");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "@", 1), "t.value=@");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "~");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "~", 1), "t.value=~");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "?");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, "?", 1), "t.value=?");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, ":");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, ":", 1), "t.value=:");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, ",");
	ASSERT_EQ(t.len, 1, "t.len=1");
	ASSERT(!strcmpn(t.value, ",", 1), "t.value=,");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_COMPLETE, "complete");
}

Test(lexer7_invalid_punct) {
	Lexer l;
	Token t;
	const u8 *text = "0xFD $";

	lexer_init(&l, text, strlen(text));

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_OK, "0xFD number");
	ASSERT_EQ(t.len, 4, "t.len=4");
	ASSERT(!strcmpn(t.value, "0xFD", 4), "t.value=0xFD");

	ASSERT_EQ(lexer_next_token(&l, &t), TOKEN_ERR, "invalid $");
	ASSERT_EQ(l.err, EINVAL, "err=EINVAL");
}

