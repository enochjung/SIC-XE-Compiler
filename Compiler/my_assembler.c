/*
 * 화일명 : my_assembler.c 
 * 설  명 : 이 프로그램은 SIC/XE 머신을 위한 간단한 Assembler 프로그램의 메인루틴으로,
 * 입력된 파일의 코드 중, 명령어에 해당하는 OPCODE를 찾아 출력한다.
 */

/*
 *
 * 프로그램의 헤더를 정의한다. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#include "my_assembler.h"

static void print_compile_error(int error_code, const uchar* str);
static void print_compile_error_token(int error_code, const token* tok);
static int add_inst(const uchar* str);
static int add_label(token* tok, const uchar* ptr, int length);
static int add_operator(token* tok, const uchar* ptr, int length);
static int add_operand(token* tok, const uchar* ptr, int length);
static void add_comment(token* tok, const uchar* ptr, int length);
static void add_nixbpe(token* tok);
static int find_token(const uchar* str, int is_comment, const char** ptr);
static int search_opcode_with_length(uchar *str, int length);
static int compare(const void* first, const void* second);
static symbol* create_base_symbol(const uchar* name, int address, int cs_num, int is_external);
static symbol* create_symbol(const uchar* name, int address, int cs_num);
static symbol* create_start_symbol(const uchar* name, int address, int cs_num);
static symbol* create_temporary_symbol(int locctr, int cs_num, const uchar* operand);
static symbol* create_external_symbol(const uchar* name, int cs_num);
static void parse_statement(symbol* sym, int locctr, int cs_num, const uchar* str);
static symbol* create_equation(const uchar* name, int address, int cs_num, const uchar* operand);
static int create_literal(const uchar(*operand)[MAX_OPERAND_LENGTH], int cs_num);
static int is_hex(uchar c);
static int parse_hex_from_literal(const uchar* str);
static int parse_string_from_literal(const uchar* str);
static int parse_decimal_from_operand(const uchar(*operand)[MAX_OPERAND_LENGTH]);
static symbol* get_symbol(const uchar* name, int cs_num);
static symbol* get_start_symbol(int cs_num);
static int search_literal(const uchar* name, int cs_num);
static int update_literal_pool(int locctr);
static uchar* get_string(const uchar* str, int length);
static void symbol_clean(symbol* sym);
static void symbol_push(symbol* dest, symbol* data, int flag);
static int h2i(const uchar* hex);
static int hl2i(const uchar* hex, int length);
static int a2i(const uchar* str);
static int al2i(const uchar* str, int length);
static int reg2i(const uchar* reg);
static void add_length_to_text_record(uchar* str, int value);
static void write_header_record(const uchar* name, int start_addr, int length);
static void write_define_record(const uchar operand[][MAX_OPERAND_LENGTH], int cs_num);
static void write_refer_record(const uchar operand[][MAX_OPERAND_LENGTH]);
static void write_modification_record(modification* mod);
static void write_all_modification_record();
static void clear_modification_record();
static void write_text_record(int locctr, int byte, int data);
static int write_literal(int locctr, const uchar* literal);
static void write_end_record(int execute_addr);
static void create_simple_modification(int addr, int half_byte);
static void create_external_modification(const uchar* name, int addr, int half_byte, int flag);
static void create_every_external_modification(const symbol* sym, int addr, int half_byte);

enum Code
{
	CODE_BYTE = 0x0B,
	CODE_CSECT = 0x0A,
	CODE_END = 0x0E,
	CODE_EQU = 0x09,
	CODE_EXTDEF = 0x02,
	CODE_EXTREF = 0x03,
	CODE_LTORG = 0x07,
	CODE_RESB = 0x06,
	CODE_RESW = 0x05,
	CODE_START = 0x01,
	CODE_WORD = 0x0D
};

enum Error
{
	ERROR_MEMORY_ASSIGNMENT_FAIL = -1,
	ERROR_UNRECOGNIZABLE_TEXT = -2,
	ERROR_UNCLOSED_QUOTE = -3,
	ERROR_WRONG_LABEL = -4,
	ERROR_WRONG_OPERATOR = -5,
	ERROR_WRONG_OPERAND = -6,
	ERROR_WRONG_EXPRESSION = -7,
	ERROR_NO_START = -8,
	ERROR_NO_LABEL = -9,
	ERROR_DECLARE_SAME_LABEL = -10,
	ERROR_DECLARE_REFER_AGAIN = -11
};

/* ----------------------------------------------------------------------------------
 * 설명 : 컴파일 오류를 출력한다. 
 * 매계 : 오류 번호 및 오류가 난 코드 줄 
 * 반환 : 없음 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */

static void print_compile_error(int error_code, const uchar* str)
{
	if (error_code == ERROR_MEMORY_ASSIGNMENT_FAIL)
		fprintf(stderr, "컴파일 실패 : 메모리 할당 실패\n");
	else if (error_code == ERROR_UNRECOGNIZABLE_TEXT)
		fprintf(stderr, "컴파일 실패 : 잘못된 문자\n");
	else if (error_code == ERROR_UNCLOSED_QUOTE)
		fprintf(stderr, "컴파일 실패 : 닫히지 않은 따옴표\n");
	else if (error_code == ERROR_WRONG_LABEL)
		fprintf(stderr, "컴파일 실패 : 잘못된 label\n");
	else if (error_code == ERROR_WRONG_OPERATOR)
		fprintf(stderr, "컴파일 실패 : 잘못된 operator\n");
	else if (error_code == ERROR_WRONG_OPERAND)
		fprintf(stderr, "컴파일 실패 : 잘못된 operand\n");
	else if (error_code == ERROR_WRONG_EXPRESSION)
		fprintf(stderr, "컴파일 실패 : 잘못된 표현식\n");
	else if (error_code == ERROR_NO_START)
		fprintf(stderr, "컴파일 실패 : START로 시작하지 않음\n");
	else if (error_code == ERROR_NO_LABEL)
		fprintf(stderr, "컴파일 실패 : 레이블이 명시되지 않음\n");
	else if (error_code == ERROR_DECLARE_SAME_LABEL)
		fprintf(stderr, "컴파일 실패 : 중복된 이름으로 선언\n");
	else if (error_code == ERROR_DECLARE_REFER_AGAIN)
		fprintf(stderr, "컴파일 실패 : 외부 심볼 재정의\n");
	else
		fprintf(stderr, "컴파일 실패 : 알 수 없는 오류. 오류 코드 : %d\n", error_code);

	fprintf(stderr, "%s\n", str);
}

static void print_compile_error_token(int error_code, const token* tok)
{
	int i;

	if (error_code == ERROR_MEMORY_ASSIGNMENT_FAIL)
		fprintf(stderr, "컴파일 실패 : 메모리 할당 실패\n");
	else if (error_code == ERROR_UNRECOGNIZABLE_TEXT)
		fprintf(stderr, "컴파일 실패 : 잘못된 문자\n");
	else if (error_code == ERROR_UNCLOSED_QUOTE)
		fprintf(stderr, "컴파일 실패 : 닫히지 않은 따옴표\n");
	else if (error_code == ERROR_WRONG_LABEL)
		fprintf(stderr, "컴파일 실패 : 잘못된 label\n");
	else if (error_code == ERROR_WRONG_OPERATOR)
		fprintf(stderr, "컴파일 실패 : 잘못된 operator\n");
	else if (error_code == ERROR_WRONG_OPERAND)
		fprintf(stderr, "컴파일 실패 : 잘못된 operand\n");
	else if (error_code == ERROR_WRONG_EXPRESSION)
		fprintf(stderr, "컴파일 실패 : 잘못된 표현식\n");
	else if (error_code == ERROR_NO_START)
		fprintf(stderr, "컴파일 실패 : START로 시작하지 않음\n");
	else if (error_code == ERROR_NO_LABEL)
		fprintf(stderr, "컴파일 실패 : 레이블이 명시되지 않음\n");
	else if (error_code == ERROR_DECLARE_SAME_LABEL)
		fprintf(stderr, "컴파일 실패 : 중복된 이름으로 선언\n");
	else if (error_code == ERROR_DECLARE_REFER_AGAIN)
		fprintf(stderr, "컴파일 실패 : 외부 심볼 재정의\n");
	else
		fprintf(stderr, "컴파일 실패 : 알 수 없는 오류. 오류 코드 : %d\n", error_code);

	fprintf(stderr, "%s\t%s\t", tok->label == NULL ? "" : tok->label, tok->operator);
	for (i = 0; i < 3 && tok->operand[i][0]; ++i)
	{
		fprintf(stderr, "%s", tok->operand[i]);
		if (i + 1 < 3 && tok->operand[i + 1][0])
			fprintf(stderr, ",");
	}
	fprintf(stderr, "\n");
}

/* ----------------------------------------------------------------------------------
 * 설명 : 사용자로 부터 어셈블리 파일을 받아서 명령어의 OPCODE를 찾아 출력한다.
 * 매계 : 실행 파일, 어셈블리 파일 
 * 반환 : 성공 = 0, 실패 = < 0 
 * 주의 : 현재 어셈블리 프로그램의 리스트 파일을 생성하는 루틴은 만들지 않았다. 
 *		   또한 중간파일을 생성하지 않는다. 
 * ----------------------------------------------------------------------------------
 */
int main(int argc, uchar *argv[])
{
	if (init_my_assembler() < 0)
	{
		printf("init_my_assembler: 프로그램 초기화에 실패 했습니다.\n");
		return -1;
	}

	if (assem_pass1() < 0)
	{
		printf("assem_pass1: 패스1 과정에서 실패하였습니다.  \n");
		return -1;
	}

	//make_opcode_output("output");
	//make_opcode_output(NULL);

	make_symtab_output("symtab.txt");
	//make_symtab_output(NULL);
	make_literaltab_output("literaltab.txt");
	//make_literaltab_output(NULL);

	if (assem_pass2() < 0)
	{
		printf(" assem_pass2: 패스2 과정에서 실패하였습니다.  \n");
		return -1;
	}

	make_objectcode_output("output.txt");
	//make_objectcode_output(NULL);

	return 0;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 프로그램 초기화를 위한 자료구조 생성 및 파일을 읽는 함수이다. 
 * 매계 : 없음
 * 반환 : 정상종료 = 0 , 에러 발생 = -1
 * 주의 : 각각의 명령어 테이블을 내부에 선언하지 않고 관리를 용이하게 하기 
 *		   위해서 파일 단위로 관리하여 프로그램 초기화를 통해 정보를 읽어 올 수 있도록
 *		   구현하였다. 
 * ----------------------------------------------------------------------------------
 */
int init_my_assembler(void)
{
	int result = 0;

	if ((result = init_inst_file("inst.data")) < 0)
		return -1;
	if ((result = init_input_file("input.txt")) < 0)
		return -1;
	return result;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 머신을 위한 기계 코드목록 파일을 읽어 기계어 목록 테이블(inst_table)을 
 *        생성하는 함수이다. 
 * 매계 : 기계어 목록 파일
 * 반환 : 정상종료 = 0 , 에러 < 0 
 * 주의 : 기계어 목록파일 형식은 자유롭게 구현한다. 예시는 다음과 같다.
 *	
 *	===============================================================================
 *		   | 이름 | 형식 | 기계어 코드 | 오퍼랜드의 갯수 | NULL|
 *	===============================================================================	   
 *		
 * ----------------------------------------------------------------------------------
 */
int init_inst_file(uchar *inst_file)
{
	FILE *file;
	int errno;
	uchar buffer[20];

	if ((file = fopen(inst_file, "r")) == NULL)
		return -1;

	while (!feof(file))
	{
		fgets(buffer, 20, file);
		if (add_inst(buffer) != 0)
			return -1;
	}

	if (fclose(file) != 0)
		return -1;

	return errno;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 기계코드 목록 한 줄을 받아, 목록 테이블을 저장한다.
 * 매계 : 기계코드 목록 문자열
 * 반환 : 정상종료 = 0 , 에러 < 0  
 * 주의 : 메모리 할당 사용
 *		
 * ----------------------------------------------------------------------------------
 */
static int add_inst(const uchar* str)
{
	uchar name[10];
	uchar ops[10];
	int format;
	uchar op[10];

	if (inst_index == MAX_INST)
		return -1;

	sscanf(str, "%s\t%s\t%d\t%s\n", name, ops, &format, op);

	if ((inst_table[inst_index] = (inst*)malloc(sizeof(inst))) == NULL)
		return -1;

	strcpy(inst_table[inst_index]->str, name);
	
	if (ops[0] == '-')
		inst_table[inst_index]->ops = 0;
	else if (ops[0] == 'M')
		inst_table[inst_index]->ops = 1;
	else if (ops[0] == 'N')
		inst_table[inst_index]->ops = 3;
	else if (ops[1] == 'R')
		inst_table[inst_index]->ops = 4;
	else if (ops[1] == 'N')
		inst_table[inst_index]->ops = 5;
	else
		inst_table[inst_index]->ops = 2;

	inst_table[inst_index]->format = format;

	inst_table[inst_index]->op = (uchar)strtol(op, NULL, 16);

	++inst_index;

	return 0;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 어셈블리 할 소스코드를 읽어 소스코드 테이블(input_data)를 생성하는 함수이다. 
 * 매계 : 어셈블리할 소스파일명
 * 반환 : 정상종료 = 0 , 에러 < 0  
 * 주의 : 라인단위로 저장한다.
 *		
 * ----------------------------------------------------------------------------------
 */
int init_input_file(uchar *input_file)
{
	FILE *file;
	int errno;
	uchar buffer[250];
	int length;

	if (fopen_s(&file, input_file, "r") != 0)
		return -1;

	while (!feof(file))
	{
		if (fgets(buffer, 250, file) == NULL)
			break;

		length = (int)strlen(buffer);
		if ((input_data[line_num] = (uchar*)malloc(length + 1)) == NULL)
			return ERROR_MEMORY_ASSIGNMENT_FAIL;
		strcpy(input_data[line_num], buffer);

		++line_num;
	}

	if (fclose(file) != 0)
		return -1;

	return errno;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 소스 코드를 읽어와 토큰단위로 분석하고 토큰 테이블을 작성하는 함수이다. 
 *        패스 1로 부터 호출된다. 
 * 매계 : 파싱을 원하는 문자열  
 * 반환 : 정상종료 = 0, 코멘트 = 1, 에러 < 0
 * 주의 : my_assembler 프로그램에서는 라인단위로 토큰 및 오브젝트 관리를 하고 있다. 
 * ----------------------------------------------------------------------------------
 */
int token_parsing(uchar *str)
{
	uchar* ptr;
	token* tok;
	int length, is_label, is_operand, ret;
	int i;

	length = find_token(str, 0, &ptr);
	if (length <= 0)
		return length;

	if (*ptr == '.') // dot comment
		return 1;

	if ((token_table[token_line] = (token*)malloc(sizeof(token))) == NULL)
		return ERROR_MEMORY_ASSIGNMENT_FAIL;
	tok = token_table[token_line];
	tok->label = NULL;
	tok->operator = NULL;
	for (i = 0; i < MAX_OPERAND; ++i)
		tok->operand[i][0] = 0;
	tok->comment[0] = 0;

	is_label = *ptr != '+' && search_opcode_with_length(ptr, length) < 0;

	if (is_label) // label
	{
		if ((ret = add_label(tok, ptr, length)) < 0)
			return ret;
		length = find_token(ptr + length, 0, &ptr);
	}
	{ // operator
		if (length < 0)
			return length;
		if (length == 0)
			return ERROR_WRONG_OPERATOR;
		if ((ret = add_operator(tok, ptr, length)) < 0)
			return ret;
		is_operand = ret == 1;
	}
	if (is_operand) // operand
	{
		length = find_token(ptr + length, 0, &ptr);
		if (length < 0)
			return length;
		if (length == 0)
			return ERROR_WRONG_OPERAND;

		if ((ret = add_operand(tok, ptr, length)) < 0)
			return ret;
	}
	{ // comment
		length = find_token(ptr + length, 1, &ptr);
		if (length < 0)
			return length;

		add_comment(tok, ptr, length);
	}
	add_nixbpe(tok);

	++token_line;

	return 0;
}

/* ----------------------------------------------------------------------------------
 * 설명 : token_table에 label값을 넣는다. 
 * 매계 : token 주소, 문자열 시작 주소, 문자열 길이
 * 반환 : 성공 = 0, 실패 < 0 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int add_label(token* tok, const uchar* ptr, int length)
{
	if ((tok->label = (uchar*)malloc(length + 1)) == NULL)
		return ERROR_MEMORY_ASSIGNMENT_FAIL;
	strncpy(tok->label, ptr, length);
	tok->label[length] = 0;

	return 0;
}

/* ----------------------------------------------------------------------------------
 * 설명 : token_table에 operator를 넣는다. 
 * 매계 : token 주소, 문자열 시작 주소, 문자열 길이
 * 반환 : 성공 = 해당 operator의 operand 여부, 실패 < 0 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int add_operator(token* tok, const uchar* ptr, int length)
{
	int idx;
	int format4 = ptr[0] == '+';

	if ((tok->operator = (uchar*)malloc(length + 1)) == NULL)
		return ERROR_MEMORY_ASSIGNMENT_FAIL;
	strncpy(tok->operator, ptr, length);
	tok->operator[length] = 0;

	idx = search_opcode(tok->operator + format4);
	if (idx < 0)
		return ERROR_WRONG_OPERATOR;

	return inst_table[idx]->ops > 0;
}

/* ----------------------------------------------------------------------------------
 * 설명 : token_table에 operand를 넣는다. 
 * 매계 : token 주소, 문자열 시작 주소, 문자열 길이
 * 반환 : 성공 = 0, 실패 < 0 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int add_operand(token* tok, const uchar* ptr, int length)
{
	int i;
	uchar buffer[100];
	uchar* p;

	strncpy(buffer, ptr, length);
	buffer[length] = 0;
	p = strtok(buffer, ",");

	for (i = 0; i < MAX_OPERAND; ++i)
	{
		if (*p == 0)
			return ERROR_WRONG_OPERAND;
		strcpy(tok->operand[i], p);
		p = strtok(NULL, ",");
		if (p == NULL)
			return 0;
	}

	return ERROR_WRONG_OPERAND;
}

/* ----------------------------------------------------------------------------------
 * 설명 : token_table에 comment값을 넣는다. 
 * 매계 : token 주소, 문자열 시작 주소
 * 반환 : 없음 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void add_comment(token* tok, const uchar* ptr, int length)
{
	strncpy(tok->comment, ptr, length);
	tok->comment[length] = 0;
}

/* ----------------------------------------------------------------------------------
 * 설명 : token의 nixbpe 값을 결정한다.
 * 매계 : token 주소
 * 반환 : 없음 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void add_nixbpe(token* tok)
{
	uchar nixbpe;
	inst* operator;
	
	nixbpe = 0;
	operator = inst_table[search_opcode(tok->operator)];
	if (operator->format < 3)
		return;

	// ni
	if (tok->operand[0][0] == '@')
		nixbpe |= 0b100000;
	else if (tok->operand[0][0] == '#')
		nixbpe |= 0b010000;
	else
		nixbpe |= 0b110000;

	// x
	if (tok->operand[1][0] == 'X')
		nixbpe |= 0b001000;

	// p
	if (tok->operand[0][0] != '#' && tok->operator[0] != '+' && operator->ops == 1)
		nixbpe |= 0b000010;

	// e
	if (tok->operator[0] == '+')
		nixbpe |= 0b000001;

	tok->nixbpe = nixbpe;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 소스 코드 제일 앞에 있는 토큰을 찾는다. 
 * 매계 : 소스코드, 코멘트 여부, 시작 위치를 받을 포인터
 * 반환 : 토큰 길이. 오류 < 0 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int find_token(const uchar* str, int is_comment, const char** ptr)
{
	int i;
	int quote = 0;

	for (*ptr = str; !isgraph((*ptr)[0]); ++(*ptr))
	{
		if ((*ptr)[0] == 0)
			return 0;
		else if (!isspace((*ptr)[0]))
			return ERROR_UNRECOGNIZABLE_TEXT;
	}

	if (is_comment)
	{
		for (i = 1; (*ptr)[i]; ++i);
		for (; !isgraph((*ptr)[i - 1]); --i);

		return i;
	}

	for (i = 0; (*ptr)[i]; ++i)
	{
		if (!isgraph((*ptr)[i]))
		{
			if (!quote)
				break;
		}
		else if ((*ptr)[i] == '\'')
			quote = 1 - quote;
	}

	return quote? ERROR_UNCLOSED_QUOTE : i;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 입력 문자열이 기계어 코드인지를 검사하는 함수이다. 
 * 매계 : 토큰 단위로 구분된 문자열 
 * 반환 : 정상종료 = 기계어 테이블 인덱스, 에러 < 0 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
int search_opcode(uchar *str)
{
	if (str[0] == '+')
		return search_opcode(str + 1);

	inst** ptr = bsearch(str, inst_table, inst_index, sizeof(inst*), compare);
	
	if (ptr != NULL)
		return ptr - inst_table;
	return -1;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 입력 문자열이 기계어 코드인지를 검사하는 함수이다. 
 * 매계 : 토큰 단위로 구분된 문자열, 문자열 길이
 * 반환 : 정상종료 = 기계어 테이블 인덱스, 에러 < 0 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int search_opcode_with_length(uchar *str, int length)
{
	uchar buffer[100];

	strncpy(buffer, str, length);
	buffer[length] = 0;

	return search_opcode(buffer);
}

/* ----------------------------------------------------------------------------------
 * 설명 : bsearch를 위한 uchar* & inst->str 비교 함수 
 * 매계 : uchar*, inst* 
 * 반환 : 비교값 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int compare(const void* first, const void* second)
{
	return strcmp(first, (*((inst**)second))->str);
}

/* ----------------------------------------------------------------------------------
 * 설명 : 심볼을 테이블에 추가해주는 함수
 * 매계 : 심볼 이름, 심볼 주소, 수식, CS 넘버
 * 반환 : 심볼 주소
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static symbol* create_base_symbol(const uchar* name, int address, int cs_num, int is_external)
{
	int length = strlen(name);

	symbol* sym = sym_table + sym_num++;

	sym->symbol = (uchar*)malloc(length);
	strcpy(sym->symbol, name);
	sym->addr = address;
	sym->cs_num = cs_num;
	sym->is_external = is_external;
	sym->op_len[0] = 0;
	sym->op_len[1] = 0;

	return sym;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 심볼을 테이블에 추가해주는 함수
 * 매계 : 심볼 이름, 심볼 주소, 수식, CS 넘버
 * 반환 : 심볼 주소
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static symbol* create_symbol(const uchar* name, int address, int cs_num)
{
	symbol* sym = create_base_symbol(name, address, cs_num, 0);
	symbol_push(sym, get_start_symbol(cs_num), 1);

	return sym;
}

static symbol* create_start_symbol(const uchar* name, int address, int cs_num)
{
	return create_base_symbol(name, address, cs_num, 1);
}

static symbol* create_temporary_symbol(int locctr, int cs_num, const uchar* operand)
{
	symbol* sym = malloc(sizeof(symbol));

	sym->symbol = NULL;
	sym->addr = 0;
	sym->cs_num = cs_num;
	sym->is_external = 0;
	sym->op_len[0] = 0;
	sym->op_len[1] = 0;

	parse_statement(sym, locctr, cs_num, operand);

	return sym;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 외부 심볼을 테이블에 추가해주는 함수
 * 매계 : 심볼 이름, CS 넘버
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static symbol* create_external_symbol(const uchar* name, int cs_num)
{
	return create_base_symbol(name, 0, cs_num, 1);
}

static void parse_statement(symbol* sym, int locctr, int cs_num, const uchar* str)
{
	int constant_time;
	int sign;
	int parenthesis_stack[100]; // 괄호 부호 저장
	int parenthesis_size;
	int parenthesis_sign;
	int i, j;
	uchar* ptr;

	constant_time = 1;
	sign = 1;
	parenthesis_size = 0;
	parenthesis_sign = 1;

	for (i = 0; str[i]; ++i)
	{
		if (constant_time)
		{
			if (isupper(str[i]))
			{
				for (j = 0; isupper(str[i + j]); ++j);

				ptr = get_string(str + i, j);
				symbol_push(sym, get_symbol(ptr, cs_num), sign * parenthesis_sign);
				free(ptr);
				i += j - 1;
				constant_time = 0;
			}
			else if (isdigit(str[i]))
			{
				for (j = 0; isdigit(str[i + j]); ++j);
				sym->addr += al2i(str + i, j) * sign * parenthesis_sign;
				i += j - 1;
				constant_time = 0;
			}
			else if (str[i] == '*')
			{
				sym->addr += locctr * sign * parenthesis_sign;
				symbol_push(sym, get_start_symbol(cs_num), sign * parenthesis_sign);
			}
			else if (str[i] == '(')
			{
				parenthesis_stack[parenthesis_size++] = sign;
				parenthesis_sign *= sign;
				sign = 1;
			}
		}
		else
		{
			if (str[i] == ')')
			{
				parenthesis_sign *= parenthesis_stack[--parenthesis_size];
			}
			else
			{
				sign = str[i] == '+' ? 1 : -1;
				constant_time = 1;
			}
		}
	}
}

/* ----------------------------------------------------------------------------------
 * 설명 : EQU를 테이블에 추가해주는 함수
 * 매계 : 심볼 이름, 심볼 주소, 수식, CS 넘버
 * 반환 :  
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static symbol* create_equation(const uchar* name, int address, int cs_num, const uchar* operand)
{
	symbol* sym;

	sym = create_base_symbol(name, 0, cs_num, 0);
	parse_statement(sym, address, cs_num, operand);

	return sym;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 리터럴을 테이블에 추가해주는 함수
 * 매계 : 리터럴 이름, CS 넘버
 * 반환 : 정상 종료 = size of literal>=0, 에러 = <0
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int create_literal(const uchar(*operand)[MAX_OPERAND_LENGTH], int cs_num)
{
	int value;
	int size;

	if (operand[0][0] != '=' || operand[1][0] != 0)
		return ERROR_WRONG_OPERAND;

	const char* name = operand[0];
	if (name[1] == 'X')
	{
		value = parse_hex_from_literal(name + 2);
		if (value < 0)
			return ERROR_WRONG_OPERAND;
		size = 1;
	}
	else if (name[1] == 'C')
	{
		value = parse_string_from_literal(name + 2);
		if (value < 0)
			return ERROR_WRONG_OPERAND;
		size = value;
	}
	else
	{
		value = atoi(name + 1);
		size = 3;
	}

	if ((literal_table[literal_num].literal = (uchar*)malloc(strlen(name))) == NULL)
		return ERROR_MEMORY_ASSIGNMENT_FAIL;
	strcpy(literal_table[literal_num].literal, name);
	literal_table[literal_num].addr = -1;
	literal_table[literal_num].cs_num = cs_num;

	++literal_num;
	return size;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 문자가 hex인지 여부 확인
 * 매계 : 확인할 문자
 * 반환 : hex면 1, 아니면 0
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int is_hex(uchar c)
{
	return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F');
}

/* ----------------------------------------------------------------------------------
 * 설명 : 문자열에서 hex 리터럴 파싱
 * 매계 : 따옴표로 쌓여 있는 파싱할 문자열
 * 반환 : 정상 종료 = hex 값>=0, 에러 = <0
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int parse_hex_from_literal(const uchar* str)
{
	if (!(str[0] == '\'' && is_hex(str[1]) && is_hex(str[2]) && str[3] == '\'' && str[4] == 0))
		return -1;

	return (int)strtol(str + 1, NULL, 16);
}

/* ----------------------------------------------------------------------------------
 * 설명 : 문자열에서 문자열 리터럴 파싱
 * 매계 : 따옴표로 쌓여 있는 파싱할 문자열
 * 반환 : 정상 종료 = 파싱한 문자열 크기>=0, 에러 = <0
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int parse_string_from_literal(const uchar* str)
{
	int length = strlen(str);
	if (!(str[0] == '\'' && str[length - 1] == '\''))
		return -1;

	return length - 2;
}

/* ----------------------------------------------------------------------------------
 * 설명 : operand에서 숫자 파싱
 * 매계 : operand 배열
 * 반환 : 정상 종료 = 파싱한 숫자>=0, 에러 = <0
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int parse_decimal_from_operand(const uchar (*operand)[MAX_OPERAND_LENGTH])
{
	int length = strlen(operand[0]);
	int i;
	for (i = 0; i < length; ++i)
		if (!isdigit(operand[0][i]))
			return -1;

	return atoi(operand[0]);
}

/* ----------------------------------------------------------------------------------
 * 설명 : 마지막 cs 내부 symtab에서 symbol 찾기
 * 매계 : symbol 이름, CS 넘버
 * 반환 : symbol index>=0, 찾기 실패 = -1
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static symbol* get_symbol(const uchar* name, int cs_num)
{
	int i;

	for (i = 0; i < sym_num; ++i)
		if (sym_table[i].cs_num == cs_num && strcmp(sym_table[i].symbol, name) == 0)
			return sym_table + i;

	return NULL;
}

static symbol* get_start_symbol(int cs_num)
{
	int i;

	for (i = 0; i < sym_num; ++i)
		if (sym_table[i].cs_num == cs_num)
			return sym_table + i;

	return NULL;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 마지막 cs 내부 littab에서 literal 찾기
 * 매계 : literal 이름, CS 넘버
 * 반환 : literal index>=0, 찾기 실패 = -1
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int search_literal(const uchar* name, int cs_num)
{
	int i;

	for (i = 0; i < literal_num; ++i)
		if (literal_table[i].cs_num == cs_num && strcmp(literal_table[i].literal, name) == 0)
			return i;

	return -1;
}

/* ----------------------------------------------------------------------------------
 * 설명 : 메모리 위치가 정해지지 않은 리터럴 위치 결정
 * 매계 : locctr
 * 반환 : 정상종료 = >=0(최종 locctr 위치), 실패 = -1
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int update_literal_pool(int locctr)
{
	int i;

	for (i = 0; i < literal_num; ++i)
		if (literal_table[i].addr == -1)
		{
			literal_table[i].addr = locctr;
			if (literal_table[i].literal[1] == 'X')
				locctr += 1;
			else if (literal_table[i].literal[1] == 'C')
				locctr += parse_string_from_literal(literal_table[i].literal + 2);
			else
				locctr += 3;
		}

	return locctr;
}

/* ----------------------------------------------------------------------------------
 * 설명 : str에서 특정 글자수 추출
 * 매계 : 동적할당으로 저장된 추출한 문자열
 * 반환 : 문자열 포인터
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static uchar* get_string(const uchar* str, int length)
{
	uchar* ptr = (uchar*)malloc(length + 1);
	strncpy(ptr, str, length);
	ptr[length] = 0;
	return ptr;
}

static void symbol_clean(symbol* sym)
{
	int i, j;
	int flag;

	for (i = 0; i < sym->op_len[0]; ++i)
	{
		flag = 0;
		for (j = 0; j < sym->op_len[1]; ++j)
			if (sym->op[0][i] == sym->op[1][j])
			{
				flag = 1;
				sym->op[0][i] = sym->op[0][--(sym->op_len[0])];
				sym->op[1][j] = sym->op[1][--(sym->op_len[1])];
				break;
			}
		if (flag)
			--i;
	}
}

static void symbol_push(symbol* dest, symbol* data, int flag) // flag = 1 or -1
{
	int i;
	int idx;

	for (i = 0; i < data->op_len[0]; ++i)
		symbol_push(dest, data->op[0][i], flag);
	for (i = 0; i < data->op_len[1]; ++i)
		symbol_push(dest, data->op[1][i], -flag);

	if (data->is_external)
	{
		idx = flag == -1;
		dest->op[idx][dest->op_len[idx]++] = data;
	}
	else
		dest->addr += data->addr * flag;

	symbol_clean(dest);
}

/* ----------------------------------------------------------------------------------
* 설명 : 어셈블리 코드를 위한 패스1과정을 수행하는 함수이다.
*		   패스1에서는..
*		   1. 프로그램 소스를 스캔하여 해당하는 토큰단위로 분리하여 프로그램 라인별 토큰
*		   테이블을 생성한다.
*
* 매계 : 없음
* 반환 : 정상 종료 = 0 , 에러 = < 0
* 주의 : 현재 초기 버전에서는 에러에 대한 검사를 하지 않고 넘어간 상태이다.
*	  따라서 에러에 대한 검사 루틴을 추가해야 한다.
*
* -----------------------------------------------------------------------------------
*/
static int assem_pass1(void)
{
	int error_code;

	int cs_num;
	int i, j;
	int val;
	symbol* sym;

	locctr = 0;
	cs_num = 0;

	for (i = 0; i < line_num; ++i)
	{
		// parse token
		if ((error_code = token_parsing(input_data[i])) == 1)
			continue;
		else if (error_code < 0)
		{
			print_compile_error(error_code, input_data[i]);
			return -1;
		}

		// get opcode
		const token* tok = token_table[token_line - 1];
		int op_idx = search_opcode(tok->operator);
		if (op_idx == -1)
		{
			print_compile_error(ERROR_WRONG_OPERATOR, input_data[i]);
			return -1;
		}
		int opcode = inst_table[op_idx]->op;

		// process assembler code
		if (i == 0 && opcode != CODE_START)
		{
			print_compile_error(ERROR_NO_START, input_data[i]);
			return -1;
		}

		switch (opcode)
		{
		case CODE_BYTE:
			if (tok->label == NULL)
			{
				print_compile_error(ERROR_WRONG_LABEL, input_data[i]);
				return -1;
			}
			create_symbol(tok->label, locctr, cs_num);

			if (tok->operand[0][0] == 0 || tok->operand[1][0] != 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			else if (tok->operand[0][0] == 'X')
			{
				if (parse_hex_from_literal(tok->operand[0] + 1) < 0)
				{
					print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
					return -1;
				}
				locctr += 1;
			}
			else if (tok->operand[0][0] == 'C')
			{
				if ((val = parse_string_from_literal(tok->operand[0] + 1)) < 0)
				{
					print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
					return -1;
				}
				locctr += val;
			}
			else
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			break;

		case CODE_CSECT:
			if (tok->label == NULL)
			{
				print_compile_error(ERROR_WRONG_LABEL, input_data[i]);
				return -1;
			}
			if (tok->operand[0][0] != 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			if ((locctr = update_literal_pool(locctr)) < 0)
			{
				print_compile_error(-1, "잘못된 리터럴 인식자");
				return -1;
			}
			cs_length[cs_num] = locctr;
			locctr = 0;
			++cs_num;
			create_start_symbol(tok->label, locctr, cs_num);

			break;

		case CODE_END:
			if (tok->label != NULL)
			{
				print_compile_error(ERROR_WRONG_LABEL, input_data[i]);
				return -1;
			}
			if (tok->operand[0][0] == 0 || tok->operand[1][0] != 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			if ((locctr = update_literal_pool(locctr)) < 0)
			{
				print_compile_error(-1, "잘못된 리터럴 인식자");
				return -1;
			}
			cs_length[cs_num] = locctr;
			sym = create_temporary_symbol(cs_length[0], 0, tok->operand[0]);
			symbol_push(sym, get_start_symbol(0), -1);
			start_address = sym->addr;

			return 0;

		case CODE_EQU:
			if (tok->label == NULL)
			{
				print_compile_error(ERROR_WRONG_LABEL, input_data[i]);
				return -1;
			}
			if (tok->operand[0][0] == 0 || tok->operand[1][0] != 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			create_equation(tok->label, locctr, cs_num, tok->operand[0]);
			break;

		case CODE_EXTDEF:
			// nop
			break;

		case CODE_EXTREF:
			for (j = 0; j < MAX_OPERAND && tok->operand[j][0]; ++j)
				create_external_symbol(tok->operand[j], cs_num);
			break;

		case CODE_LTORG:
			if ((locctr = update_literal_pool(locctr)) < 0)
			{
				print_compile_error(-1, "잘못된 리터럴 인식자");
				return -1;
			}
			break;

		case CODE_RESB:
			if (tok->label == NULL)
			{
				print_compile_error(ERROR_NO_LABEL, input_data[i]);
				return -1;
			}
			create_symbol(tok->label, locctr, cs_num);
			if ((val = parse_decimal_from_operand(tok->operand)) < 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			locctr += val;
			break;

		case CODE_RESW:
			if (tok->label == NULL)
			{
				print_compile_error(ERROR_NO_LABEL, input_data[i]);
				return -1;
			}
			create_symbol(tok->label, locctr, cs_num);
			if ((val = parse_decimal_from_operand(tok->operand)) < 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			locctr += val * 3;
			break;

		case CODE_START:
			if ((locctr = parse_decimal_from_operand(tok->operand)) < 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			if (tok->label == NULL)
			{
				print_compile_error(ERROR_NO_LABEL, input_data[i]);
				return -1;
			}
			create_start_symbol(tok->label, locctr, cs_num);
			break;

		case CODE_WORD:
			if (tok->label == NULL)
			{
				print_compile_error(ERROR_WRONG_LABEL, input_data[i]);
				return -1;
			}
			create_symbol(tok->label, locctr, cs_num);

			if (tok->operand[0][0] == 0 || tok->operand[1][0] != 0)
			{
				print_compile_error(ERROR_WRONG_OPERAND, input_data[i]);
				return -1;
			}
			locctr += 3;

			break;

		default:
			// update symbol
			if (tok->label != NULL)
				create_symbol(tok->label, locctr, cs_num);

			// update literal
			if (tok->operand[0][0] == '=')
				if (search_literal(tok->operand[0], cs_num) == -1)
					if (error_code = create_literal(tok->operand, cs_num) < 0)
					{
						print_compile_error(error_code, input_data[i]);
						return -1;
					}

			// format 3 / format 4 / add locctr
			if (tok->operator[0] == '+')
				locctr += 4;
			else
				locctr += inst_table[op_idx]->format;
			break;
		}
	}

	return 0;
}

/* ----------------------------------------------------------------------------------
* 설명 : 입력된 문자열의 이름을 가진 파일에 프로그램의 결과를 저장하는 함수이다.
*        여기서 출력되는 내용은 명령어 옆에 OPCODE가 기록된 표(과제 3번) 이다.
* 매계 : 생성할 오브젝트 파일명
* 반환 : 없음
* 주의 : 만약 인자로 NULL값이 들어온다면 프로그램의 결과를 표준출력으로 보내어
*        화면에 출력해준다.
*        또한 과제 3번에서만 쓰이는 함수이므로 이후의 프로젝트에서는 사용되지 않는다.
* -----------------------------------------------------------------------------------
*/
void make_opcode_output(uchar *file_name)
{
	FILE* file;
	int i, j, format4;

	file = file_name == NULL ? stdout : fopen(file_name, "w");

	for (i = 0; i < token_line; ++i)
	{
		fprintf(file, "%s\t%s\t", token_table[i]->label == NULL ? "" : token_table[i]->label, token_table[i]->operator);
		
		for (j = 0; j < 3 && token_table[i]->operand[j][0]; ++j)
		{
			fprintf(file, "%s", token_table[i]->operand[j]);
			if (j + 1 < 3 && token_table[i]->operand[j + 1][0])
				fprintf(file, ",");
		}

		format4 = token_table[i]->operator[0] == '+';
		j = search_opcode(token_table[i]->operator + format4);
		if (inst_table[j]->format)
			fprintf(file, "\t%02X", inst_table[j]->op);
		fprintf(file, "\n");
	}

	if (file_name != NULL)
		fclose(file);
}

/* ----------------------------------------------------------------------------------
* 설명 : 입력된 문자열의 이름을 가진 파일에 프로그램의 결과를 저장하는 함수이다.
*        여기서 출력되는 내용은 SYMBOL별 주소값이 저장된 TABLE이다.
* 매계 : 생성할 오브젝트 파일명
* 반환 : 없음
* 주의 : 만약 인자로 NULL값이 들어온다면 프로그램의 결과를 표준출력으로 보내어
*        화면에 출력해준다.
*
* -----------------------------------------------------------------------------------
*/
void make_symtab_output(uchar *file_name)
{
	FILE* file;
	int i;
	symbol* sym;

	file = file_name == NULL ? stdout : fopen(file_name, "w");

	for (i = 0; i < sym_num; ++i)
	{
		sym = sym_table + i;

		if (i > 0 && sym->cs_num != (sym - 1)->cs_num)
			fprintf(file, "\n");
		if (!sym->is_external || (i == 0 || sym->cs_num != (sym - 1)->cs_num))
			fprintf(file, "%s\t%X\n", sym->symbol, sym->addr);
	}
	fprintf(file, "\n");

	if (file_name != NULL)
		fclose(file);
}

/* ----------------------------------------------------------------------------------
* 설명 : 입력된 문자열의 이름을 가진 파일에 프로그램의 결과를 저장하는 함수이다.
*        여기서 출력되는 내용은 LITERAL별 주소값이 저장된 TABLE이다.
* 매계 : 생성할 오브젝트 파일명
* 반환 : 없음
* 주의 : 만약 인자로 NULL값이 들어온다면 프로그램의 결과를 표준출력으로 보내어
*        화면에 출력해준다.
*
* -----------------------------------------------------------------------------------
*/
void make_literaltab_output(uchar *file_name)
{
	FILE* file;
	int i;

	file = file_name == NULL ? stdout : fopen(file_name, "w");

	for (i = 0; i < literal_num; ++i)
	{
		if (i > 0 && literal_table[i].cs_num != literal_table[i - 1].cs_num)
			fprintf(file, "\n");
		fprintf(file, "%s", literal_table[i].literal);
		//for (j = 3; literal_table[i].literal[j] != '\''; ++j)
		//	fprintf(file, "%c", literal_table[i].literal[j]);

		fprintf(file, "\t%X\n", literal_table[i].addr);
	}

	if (file_name != NULL)
		fclose(file);
}

/* ----------------------------------------------------------------------------------
 * 설명 : hex string 값을 int로 반환
 * 매계 : NULL문자로 끝나는 hex string
 * 반환 : int 값
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int h2i(const uchar* hex)
{
	return strtol(hex, NULL, 16);
}

/* ----------------------------------------------------------------------------------
 * 설명 : hex string 값을 int로 변환
 * 매계 : hex string, string 길이
 * 반환 : int 값
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int hl2i(const uchar* hex, int length)
{
	uchar buffer[20] = { 0 };
	strncpy(buffer, hex, length);
	return h2i(buffer);
}

/* ----------------------------------------------------------------------------------
 * 설명 : int string 값을 int로 변환
 * 매계 : NULL문자로 끝나는 int string
 * 반환 : int 값
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int a2i(const uchar* str)
{
	return atoi(str);
}

/* ----------------------------------------------------------------------------------
 * 설명 : int string 값을 int로 변환
 * 매계 : int string, string 길이
 * 반환 : int 값
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int al2i(const uchar* str, int length)
{
	uchar buffer[20] = { 0 };
	strncpy(buffer, str, length);
	return a2i(buffer);
}

/* ----------------------------------------------------------------------------------
 * 설명 : Register string을 해당 register value로 변환
 * 매계 : register string
 * 반환 : register value
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int reg2i(const uchar* reg)
{
	if (reg[0] == 'A')
		return 0;
	else if (reg[0] == 'X')
		return 1;
	else if (reg[0] == 'L')
		return 2;
	else if (reg[0] == 'P')
		return 8;
	else if (reg[0] == 'B')
		return 3;
	else if (reg[0] == 'T')
		return 5;
	else if (reg[0] == 'F')
		return 6;
	else if (reg[1] == 'W')
		return 9;
	else
		return 4;
}

/* ----------------------------------------------------------------------------------
 * 설명 : obejct program의 T record 중 length 부분의 값을 원하는 만큼 증가시킴
 * 매계 : record string, 증가시킬 값
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void add_length_to_text_record(uchar* str, int value)
{
	uchar tmp;

	tmp = str[9];
	value += hl2i(str + 7, 2);
	sprintf(str + 7, "%02X", value);
	str[9] = tmp;
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 H record 작성
 * 매계 : 프로그램 이름, 시작 주소, 길이
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void write_header_record(const uchar* name, int start_addr, int length)
{
	uchar* str;
	
	str = object_code[object_code_num++];
	sprintf(str, "H%-6s%06X%06X", name, start_addr, length);
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 D record 작성
 * 매계 : EXTDEF 명령어의 operand, 해당 명령어가 사용된 CS 넘버
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void write_define_record(const uchar operand[][MAX_OPERAND_LENGTH], int cs_num)
{
	uchar* str;
	int length, i;
	
	str = object_code[object_code_num - 1];
	if (str[0] == 'D')
		length = strlen(str);

	for (i = 0; operand[i][0]; ++i)
	{
		if (str[0] != 'D' || length + 12 > MAX_OBJECT_CODE_DEFINE_REFER_WIDTH)
		{
			str = object_code[object_code_num++];
			sprintf(str, "D");
			length = 1;
		}

		sprintf(str + length, "%-6s%06X", operand[i], get_symbol(operand[i], cs_num)->addr);
		length += 12;
	}
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 R record 작성
 * 매계 : EXTREF 명령어의 oeprand
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void write_refer_record(const uchar operand[][MAX_OPERAND_LENGTH])
{
	uchar* str;
	int length, i;
	
	str = object_code[object_code_num - 1];
	if (str[0] == 'R')
		length = strlen(str);

	for (i = 0; operand[i][0]; ++i)
	{
		if (str[0] != 'R' || length + 6 > MAX_OBJECT_CODE_DEFINE_REFER_WIDTH)
		{
			str = object_code[object_code_num++];
			sprintf(str, "R");
			length = 1;
		}

		sprintf(str + length, "%-6s", operand[i]);
		length += 6;
	}
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 M record 작성
 * 매계 : modification 주소
 * 반환 : 
 * 주의 : write_all_modification_record 함수 외에서는 사용하면 안됨
 *		
 * ----------------------------------------------------------------------------------
 */
static void write_modification_record(modification* mod)
{
	uchar* str;
	
	str = object_code[object_code_num++];

	if (mod->flag == 0)
		sprintf(str, "M%06X%02X", mod->addr, mod->length);
	else
		sprintf(str, "M%06X%02X%c%-6s", mod->addr, mod->length, mod->flag == 1 ? '+' : '-', mod->name);
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 M record 작성
 * 매계 : 
 * 반환 : 
 * 주의 : 해당 함수 실행 후 clear_modification_record() 함수를 실행하여야 함
 *		
 * ----------------------------------------------------------------------------------
 */
static void write_all_modification_record()
{
	int i;

	for (i = 0; i < mod_num; ++i)
		write_modification_record(mod_table + i);
}

/* ----------------------------------------------------------------------------------
 * 설명 : mod_table 초기화
 * 매계 : 
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void clear_modification_record()
{
	mod_num = 0;
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 T record 작성
 * 매계 : locctr, 작성할 data의 크기, data
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void write_text_record(int locctr, int byte, int data)
{
	uchar* str;
	int start, length;
	
	str = object_code[object_code_num - 1];
	if (str[0] == 'T')
	{
		start = hl2i(str + 1, 6);
		length = hl2i(str + 7, 2);
	}

	if (byte < 4)
		data &= (1 << (byte * 8)) - 1;
	if (str[0] == 'T' && locctr == start + length && (length + byte) * 2 + 9 <= MAX_OBJECT_CODE_TEXT_WIDTH)
	{
		sprintf(str + (length * 2 + 9), "%0*X", byte * 2, data);
		add_length_to_text_record(str, byte);
	}
	else
	{
		str = object_code[object_code_num++];
		sprintf(str, "T%06X%02X%0*X", locctr, byte, byte * 2, data);
	}
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 T record 중 literal 작성
 * 매계 : locctr, literal string 주소
 * 반환 : 작성된 literal 크기
 * 주의 : literal string은 literal 구분자인 'C' 또는 'X'에서 시작하여야 함
 *		
 * ----------------------------------------------------------------------------------
 */
static int write_literal(int locctr, const uchar* literal)
{
	int i;

	if (literal[0] == 'C')
	{
		for (i = 2; literal[i] != '\''; ++i)
			write_text_record(locctr++, 1, literal[i]);
	}
	else if (literal[0] == 'X')
		write_text_record(locctr++, 1, hl2i(literal + 2, 2));
	else
	{
		int value = atoi(literal);
		write_text_record(locctr, 3, value);
		locctr += 3;
	}

	return locctr;
}

/* ----------------------------------------------------------------------------------
 * 설명 : object program의 E record 작성
 * 매계 : 실행 주소 (없을 경우 -1)
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void write_end_record(int execute_addr)
{
	uchar* str;
	
	str = object_code[object_code_num++];
	if (execute_addr >= 0)
		sprintf(str, "E%06X", execute_addr);
	else
		sprintf(str, "E");
}

/* ----------------------------------------------------------------------------------
 * 설명 : 단순 modification 생성
 * 매계 : 값을 변경할 주소, 변경할 크기(half byte)
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void create_simple_modification(int addr, int half_byte)
{
	create_external_modification("", addr, half_byte, 0);
}

/* ----------------------------------------------------------------------------------
 * 설명 : 외부 modification 생성
 * 매계 : 값을 변경할 주소, 변경할 크기(half byte), flag('+' or '-'), 심볼 이름 string
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void create_external_modification(const uchar* name, int addr, int half_byte, int flag)
{
	modification* mod;

	mod = mod_table + mod_num;
	strcpy(mod->name, name);
	mod->addr = addr;
	mod->length = half_byte;
	mod->flag = flag;
	++mod_num;
}

/* ----------------------------------------------------------------------------------
 * 설명 : operand에 적혀 있는 외부 변수를 모두 찾아 modification에 작성
 * 매계 : operand string, 해당 operand의 CS 넘버, 값을 변경할 주소, 변경할 크기(half byte)
 * 반환 : 
 * 주의 : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void create_every_external_modification(const symbol* sym, int addr, int half_byte)
{
	int i;

	for (i = 0; i < sym->op_len[0]; ++i)
		create_external_modification(sym->op[0][i]->symbol, addr, half_byte, 1);
	for (i = 0; i < sym->op_len[1]; ++i)
		create_external_modification(sym->op[1][i]->symbol, addr, half_byte, -1);
}

/* ----------------------------------------------------------------------------------
* 설명 : 어셈블리 코드를 기계어 코드로 바꾸기 위한 패스2 과정을 수행하는 함수이다.
*		   패스 2에서는 프로그램을 기계어로 바꾸는 작업은 라인 단위로 수행된다.
*		   다음과 같은 작업이 수행되어 진다.
*		   1. 실제로 해당 어셈블리 명령어를 기계어로 바꾸는 작업을 수행한다.
* 매계 : 없음
* 반환 : 정상종료 = 0, 에러발생 = < 0
* 주의 :
* -----------------------------------------------------------------------------------
*/
static int assem_pass2(void)
{
	int cs_num;
	int before_locctr;
	int ni_operand;
	int literal_idx;
	int op_idx;
	int opcode;
	inst* operator;
	symbol* sym;
	int format4;
	int i, j;
	int val;
	token* tok;

	locctr = 0;
	cs_num = 0;
	literal_idx = 0;

	for (i = 0; i < token_line; ++i)
	{
		// get opcode
		tok = token_table[i];
		op_idx = search_opcode(tok->operator);
		operator = inst_table[op_idx];
		opcode = operator->op;
		format4 = tok->operator[0] == '+';

		// process assembler code
		switch (opcode)
		{
		case CODE_BYTE:
			locctr = write_literal(locctr, tok->operand[0]);
			break;

		case CODE_CSECT:
			for (; literal_idx < literal_num && literal_table[literal_idx].cs_num == cs_num; ++literal_idx)
				locctr = write_literal(locctr, literal_table[literal_idx].literal + 1);
			write_all_modification_record();
			clear_modification_record();
			write_end_record(cs_num == 0 ? start_address : -1);
			locctr = 0;
			++cs_num;
			write_header_record(tok->label, locctr, cs_length[cs_num]);

			break;

		case CODE_END:
			for (; literal_idx < literal_num && literal_table[literal_idx].cs_num == cs_num; ++literal_idx)
				locctr = write_literal(locctr, literal_table[literal_idx].literal + 1);
			write_all_modification_record();
			clear_modification_record();
			write_end_record(cs_num == 0 ? start_address : -1);
			return 0;

		case CODE_EQU:
			// nop
			break;

		case CODE_EXTDEF:
			for (j = 0; tok->operand[j][0]; ++j)
			{
				sym = get_symbol(tok->operand[j], cs_num);
				if (sym->is_external || sym->op_len[0] != 1 || sym->op_len[1] != 0)
				{
					print_compile_error_token(ERROR_DECLARE_REFER_AGAIN, tok);
					return -1;
				}
			}
			write_define_record(tok->operand, cs_num);
			break;

		case CODE_EXTREF:
			write_refer_record(tok->operand);
			break;

		case CODE_LTORG:
			for (; literal_table[literal_idx].cs_num == cs_num; ++literal_idx)
				locctr = write_literal(locctr, literal_table[literal_idx].literal + 1);
			break;

		case CODE_RESB:
			val = parse_decimal_from_operand(tok->operand);
			locctr += val;
			break;

		case CODE_RESW:
			val = parse_decimal_from_operand(tok->operand);
			locctr += val * 3;
			break;

		case CODE_START:
			sym = get_start_symbol(cs_num);
			write_header_record(tok->label, sym->addr, cs_length[cs_num]);
			break;

		case CODE_WORD:
			sym = create_temporary_symbol(locctr, cs_num, tok->operand[0]);
			create_every_external_modification(sym, locctr, 6);
			write_text_record(locctr, 3, sym->addr);
			free(sym);
			locctr += 3;

			break;

		default:
			before_locctr = locctr;
			ni_operand = tok->operand[0][0] == '#' || tok->operand[0][0] == '@';

			if (format4)
				locctr += 4;
			else
				locctr += inst_table[op_idx]->format;

			if (format4)
			{
				sym = create_temporary_symbol(before_locctr, cs_num, tok->operand[0] + ni_operand);
				create_every_external_modification(sym, before_locctr + 1, 5);

				val = sym->addr & 0xFFFFF;
				val |= opcode << 24;
				val |= tok->nixbpe << 20;
				write_text_record(before_locctr, 4, val);

				free(sym);
			}
			else if (operator->format == 3)
			{
				val = 0;
				if (tok->operand[0][0] == '=')
				{
					val = literal_table[search_literal(tok->operand[0], cs_num)].addr;
					val = (val - locctr) & 0xFFF;
				}
				else if (operator->ops == 1)
				{
					if (tok->operand[0][0] != '#')
					{
						sym = create_temporary_symbol(before_locctr, cs_num, tok->operand[0] + ni_operand);
						sym->addr -= locctr;
						symbol_push(sym, get_start_symbol(cs_num), -1);
					}
					else
						sym = create_temporary_symbol(before_locctr, cs_num, tok->operand[0] + ni_operand);
					create_every_external_modification(sym, before_locctr + 1, 3);

					val = sym->addr & 0xFFF;
					free(sym);
				}
				else
				{
					// all is zero
				}

				val |= opcode << 16;
				val |= tok->nixbpe << 12;
				write_text_record(before_locctr, 3, val);
			}
			else if (operator->format == 2)
			{
				switch (operator->ops)
				{
				case 2: // R
					val = reg2i(tok->operand[0]) << 4;
					break;

				case 3: // N
					val = a2i(tok->operand[0]) << 4;
					break;

				case 4: // RR
					val = reg2i(tok->operand[0]) << 4;
					val |= reg2i(tok->operand[1]);
					break;

				default: // RN
					val = reg2i(tok->operand[0]) << 4;
					val |= a2i(tok->operand[1]);
					break;
				}
				val |= opcode << 8;
				write_text_record(before_locctr, 2, val);
			}
			else
			{
				write_text_record(before_locctr, 1, opcode);
			}
			break;
		}
	}

	return 0;
}

/* ----------------------------------------------------------------------------------
* 설명 : 입력된 문자열의 이름을 가진 파일에 프로그램의 결과를 저장하는 함수이다.
*        여기서 출력되는 내용은 object code (프로젝트 1번) 이다.
* 매계 : 생성할 오브젝트 파일명
* 반환 : 없음
* 주의 : 만약 인자로 NULL값이 들어온다면 프로그램의 결과를 표준출력으로 보내어
*        화면에 출력해준다.
*
* -----------------------------------------------------------------------------------
*/
void make_objectcode_output(uchar *file_name)
{
	FILE* file;
	int i;

	file = file_name == NULL ? stdout : fopen(file_name, "w");

	for (i = 0; i < object_code_num; ++i)
	{
		fprintf(file, "%s\n", object_code[i]);
		if (object_code[i][0] == 'E')
			fprintf(file, "\n");
	}

	if (file_name != NULL)
		fclose(file);
}