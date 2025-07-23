#include <famc/lexer.H>
#include <libfam/error.H>
#include <libfam/misc.H>

STATIC void lexer_incr_offset(Lexer* lex) {
	if (lex->text[lex->offset] == '\n') {
		lex->line_num++;
		lex->col_num = 0;
	} else
		lex->col_num++;
	lex->offset++;
}

STATIC i32 lexer_skip_white_space(Lexer* lex) {
	i32 ret;
	u8 c;
	u8 next_c;
	ret = 0;
	if (!lex) {
		err = EINVAL;
		return -1;
	}
	while (lex->offset < lex->len) {
		c = lex->text[lex->offset];
		if (c != ' ' && c != '\t' && c != '\f' && c != '\v' &&
		    c != '\r' && c != '\n') {
			if (c == '/' && lex->offset + 1 < lex->len) {
				next_c = lex->text[lex->offset + 1];
				if (next_c == '/') {
					lex->offset += 2;
					lex->col_num += 2;
					while (lex->offset < lex->len &&
					       lex->text[lex->offset] != '\n') {
						lex->offset++;
						lex->col_num++;
					}
					continue;
				} else if (next_c == '*') {
					lex->offset += 2;
					lex->col_num += 2;
					while (lex->offset + 1 < lex->len) {
						if (lex->text[lex->offset] ==
							'*' &&
						    lex->text[lex->offset +
							      1] == '/') {
							lex->offset += 2;
							lex->col_num += 2;
							break;
						}
						if (lex->text[lex->offset] ==
						    '\n') {
							lex->line_num++;
							lex->col_num = 1;
						} else {
							lex->col_num++;
						}
						lex->offset++;
					}
					if (lex->offset + 1 >= lex->len) {
						err = EINVAL;
						return -1;
					}
					continue;
				}
			}
			break;
		}
		lexer_incr_offset(lex);
	}
	return ret;
}

STATIC i32 lexer_proc_string_lit(Lexer* lex) {
	u8 c;
	lexer_incr_offset(lex); /* Skip opening " */
	while (lex->offset < lex->len) {
		c = lex->text[lex->offset];
		if (c == '"') {
			lexer_incr_offset(lex); /* Skip closing " */
			return TOKEN_OK;
		}
		if (c == '\\') {
			lexer_incr_offset(lex); /* Skip \ */
			if (lex->offset >= lex->len) {
				err = EINVAL;
				return TOKEN_ERR;
			}
			/* Skip escaped char (e.g., \n, \") */
			lexer_incr_offset(lex);
			continue;
		}
		lexer_incr_offset(lex);
	}
	err = EINVAL;
	return TOKEN_ERR;
}

STATIC i32 lexer_proc_char_lit(Lexer* lex) {
	u8 c;
	lexer_incr_offset(lex); /* Skip opening ' */
	if (lex->offset >= lex->len) {
		err = EINVAL;
		return TOKEN_ERR;
	}
	c = lex->text[lex->offset];
	if (c == '\\') {
		lexer_incr_offset(lex); /* Skip \ */
		if (lex->offset >= lex->len) {
			err = EINVAL;
			return TOKEN_ERR;
		}
		/* Skip escaped char (e.g., \n, \xFF) */
		lexer_incr_offset(lex);
	} else {
		lexer_incr_offset(lex); /* Skip regular char */
	}
	if (lex->offset >= lex->len || lex->text[lex->offset] != '\'') {
		err = EINVAL;
		return TOKEN_ERR;
	}
	lexer_incr_offset(lex); /* Skip closing ' */
	return TOKEN_OK;
}

STATIC i32 lexer_proc_number_lit(Lexer* lex) {
	u8 first;
	u8 next_c;
	first = lex->text[lex->offset];
	if (first == '0') {
		lexer_incr_offset(lex);
		if (lex->offset < lex->len) {
			next_c = lex->text[lex->offset];
			if (next_c == 'x' || next_c == 'X') {
				lexer_incr_offset(lex); /* Skip x/X for hex */
				while (lex->offset < lex->len) {
					next_c = lex->text[lex->offset];
					if (!((next_c >= '0' &&
					       next_c <= '9') ||
					      (next_c >= 'a' &&
					       next_c <= 'f') ||
					      (next_c >= 'A' &&
					       next_c <= 'F'))) {
						break;
					}
					lexer_incr_offset(lex);
				}
			} else if (next_c >= '0' && next_c <= '7') {
				/* Octal */
				while (lex->offset < lex->len) {
					next_c = lex->text[lex->offset];
					if (!(next_c >= '0' && next_c <= '7')) {
						break;
					}
					lexer_incr_offset(lex);
				}
			} else {
				/* Decimal zero */
			}
		}
	} else {
		/* Decimal */
		while (lex->offset < lex->len) {
			next_c = lex->text[lex->offset];
			if (!(next_c >= '0' && next_c <= '9')) {
				break;
			}
			lexer_incr_offset(lex);
		}
	}
	/* Handle float part (. or e/E) */
	if (lex->offset < lex->len && lex->text[lex->offset] == '.') {
		lexer_incr_offset(lex);
		while (lex->offset < lex->len) {
			next_c = lex->text[lex->offset];
			if (!(next_c >= '0' && next_c <= '9')) {
				break;
			}
			lexer_incr_offset(lex);
		}
	}
	if (lex->offset < lex->len) {
		next_c = lex->text[lex->offset];
		if (next_c == 'e' || next_c == 'E') {
			lexer_incr_offset(lex);
			if (lex->offset < lex->len) {
				next_c = lex->text[lex->offset];
				if (next_c == '+' || next_c == '-') {
					lexer_incr_offset(lex);
				}
			}
			while (lex->offset < lex->len) {
				next_c = lex->text[lex->offset];
				if (!(next_c >= '0' && next_c <= '9')) {
					break;
				}
				lexer_incr_offset(lex);
			}
		}
	}
	/* Handle suffixes (u, l, f, etc.) */
	while (lex->offset < lex->len) {
		next_c = lex->text[lex->offset];
		if (!(next_c == 'u' || next_c == 'U' || next_c == 'l' ||
		      next_c == 'L' || next_c == 'f' || next_c == 'F')) {
			break;
		}
		lexer_incr_offset(lex);
	}
	return TOKEN_OK;
}

STATIC i32 lexer_proc_ident(Lexer* lex) {
	u8 c;
	while (lex->offset < lex->len) {
		c = lex->text[lex->offset];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_')) {
			break;
		}
		lexer_incr_offset(lex);
	}
	return TOKEN_OK;
}

STATIC i32 lexer_proc_punct(Lexer* lex) {
	u8 c;
	u8 next_c;
	u8 next_next_c;
	c = lex->text[lex->offset];
	if (lex->offset + 1 < lex->len) {
		next_c = lex->text[lex->offset + 1];
		if (lex->offset + 2 < lex->len) {
			next_next_c = lex->text[lex->offset + 2];
			if ((c == '>' && next_c == '>' && next_next_c == '=') ||
			    (c == '<' && next_c == '<' && next_next_c == '=') ||
			    (c == '.' && next_c == '.' && next_next_c == '.')) {
				lexer_incr_offset(lex);
				lexer_incr_offset(lex);
				lexer_incr_offset(lex);
				return TOKEN_OK;
			}
		}
		if ((c == '=' && next_c == '=') ||
		    (c == '>' && next_c == '=') ||
		    (c == '<' && next_c == '=') ||
		    (c == '!' && next_c == '=') ||
		    (c == '+' && next_c == '=') ||
		    (c == '-' && next_c == '=') ||
		    (c == '*' && next_c == '=') ||
		    (c == '/' && next_c == '=') ||
		    (c == '%' && next_c == '=') ||
		    (c == '&' && next_c == '=') ||
		    (c == '^' && next_c == '=') ||
		    (c == '|' && next_c == '=') ||
		    (c == '<' && next_c == '<') ||
		    (c == '>' && next_c == '>') ||
		    (c == '&' && next_c == '&') ||
		    (c == '|' && next_c == '|') ||
		    (c == '+' && next_c == '+') ||
		    (c == '-' && next_c == '-') ||
		    (c == '-' && next_c == '>')) {
			lexer_incr_offset(lex);
			lexer_incr_offset(lex);
			return TOKEN_OK;
		}
	}
	/* Single-char punctuation */
	if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%' ||
	    c == '&' || c == '|' || c == '^' || c == '~' || c == '!' ||
	    c == '<' || c == '>' || c == '=' || c == '?' || c == ':' ||
	    c == ';' || c == ',' || c == '.' || c == '(' || c == ')' ||
	    c == '[' || c == ']' || c == '{' || c == '}' || c == '#' ||
	    c == '@') {
		lexer_incr_offset(lex);
		return TOKEN_OK;
	}
	/* Invalid punctuation/char */
	err = EINVAL;
	return TOKEN_ERR;
}

i32 lexer_init(Lexer* lex, const u8* text, u64 len) {
	if (!lex || !text) {
		err = EINVAL;
		return -1;
	}

	lex->text = text;
	lex->len = len;
	lex->offset = 0;
	lex->line_num = 1;
	lex->col_num = 0;

	return 0;
}

i32 lexer_next_token(Lexer* lex, Token* next) {
	u64 start, line_num, col_num;
	i32 ret;
	u8 next_char;
	if (!lex || !next) {
		err = EINVAL;
		return TOKEN_ERR;
	}

	if (lex->offset >= lex->len) return TOKEN_COMPLETE;
	lexer_skip_white_space(lex);
	start = lex->offset;
	line_num = lex->line_num;
	col_num = lex->col_num;

	if (lex->offset >= lex->len) return TOKEN_COMPLETE;

	next_char = lex->text[lex->offset];

	if (next_char == '"')
		ret = lexer_proc_string_lit(lex);
	else if (next_char == '\'')
		ret = lexer_proc_char_lit(lex);
	else if (next_char <= '9' && next_char >= '0')
		ret = lexer_proc_number_lit(lex);
	else if ((next_char <= 'z' && next_char >= 'a') ||
		 (next_char <= 'Z' && next_char >= 'A') || next_char == '_')
		ret = lexer_proc_ident(lex);
	else
		ret = lexer_proc_punct(lex);

	if (ret == TOKEN_OK) {
		next->value = lex->text + start;
		next->len = lex->offset - start;
		next->line_num = line_num;
		next->col_num = col_num;
	}

	return ret;
}
