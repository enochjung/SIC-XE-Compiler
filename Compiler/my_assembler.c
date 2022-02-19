/*
 * ȭ�ϸ� : my_assembler.c 
 * ��  �� : �� ���α׷��� SIC/XE �ӽ��� ���� ������ Assembler ���α׷��� ���η�ƾ����,
 * �Էµ� ������ �ڵ� ��, ��ɾ �ش��ϴ� OPCODE�� ã�� ����Ѵ�.
 */

/*
 *
 * ���α׷��� ����� �����Ѵ�. 
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
 * ���� : ������ ������ ����Ѵ�. 
 * �Ű� : ���� ��ȣ �� ������ �� �ڵ� �� 
 * ��ȯ : ���� 
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */

static void print_compile_error(int error_code, const uchar* str)
{
	if (error_code == ERROR_MEMORY_ASSIGNMENT_FAIL)
		fprintf(stderr, "������ ���� : �޸� �Ҵ� ����\n");
	else if (error_code == ERROR_UNRECOGNIZABLE_TEXT)
		fprintf(stderr, "������ ���� : �߸��� ����\n");
	else if (error_code == ERROR_UNCLOSED_QUOTE)
		fprintf(stderr, "������ ���� : ������ ���� ����ǥ\n");
	else if (error_code == ERROR_WRONG_LABEL)
		fprintf(stderr, "������ ���� : �߸��� label\n");
	else if (error_code == ERROR_WRONG_OPERATOR)
		fprintf(stderr, "������ ���� : �߸��� operator\n");
	else if (error_code == ERROR_WRONG_OPERAND)
		fprintf(stderr, "������ ���� : �߸��� operand\n");
	else if (error_code == ERROR_WRONG_EXPRESSION)
		fprintf(stderr, "������ ���� : �߸��� ǥ����\n");
	else if (error_code == ERROR_NO_START)
		fprintf(stderr, "������ ���� : START�� �������� ����\n");
	else if (error_code == ERROR_NO_LABEL)
		fprintf(stderr, "������ ���� : ���̺��� ��õ��� ����\n");
	else if (error_code == ERROR_DECLARE_SAME_LABEL)
		fprintf(stderr, "������ ���� : �ߺ��� �̸����� ����\n");
	else if (error_code == ERROR_DECLARE_REFER_AGAIN)
		fprintf(stderr, "������ ���� : �ܺ� �ɺ� ������\n");
	else
		fprintf(stderr, "������ ���� : �� �� ���� ����. ���� �ڵ� : %d\n", error_code);

	fprintf(stderr, "%s\n", str);
}

static void print_compile_error_token(int error_code, const token* tok)
{
	int i;

	if (error_code == ERROR_MEMORY_ASSIGNMENT_FAIL)
		fprintf(stderr, "������ ���� : �޸� �Ҵ� ����\n");
	else if (error_code == ERROR_UNRECOGNIZABLE_TEXT)
		fprintf(stderr, "������ ���� : �߸��� ����\n");
	else if (error_code == ERROR_UNCLOSED_QUOTE)
		fprintf(stderr, "������ ���� : ������ ���� ����ǥ\n");
	else if (error_code == ERROR_WRONG_LABEL)
		fprintf(stderr, "������ ���� : �߸��� label\n");
	else if (error_code == ERROR_WRONG_OPERATOR)
		fprintf(stderr, "������ ���� : �߸��� operator\n");
	else if (error_code == ERROR_WRONG_OPERAND)
		fprintf(stderr, "������ ���� : �߸��� operand\n");
	else if (error_code == ERROR_WRONG_EXPRESSION)
		fprintf(stderr, "������ ���� : �߸��� ǥ����\n");
	else if (error_code == ERROR_NO_START)
		fprintf(stderr, "������ ���� : START�� �������� ����\n");
	else if (error_code == ERROR_NO_LABEL)
		fprintf(stderr, "������ ���� : ���̺��� ��õ��� ����\n");
	else if (error_code == ERROR_DECLARE_SAME_LABEL)
		fprintf(stderr, "������ ���� : �ߺ��� �̸����� ����\n");
	else if (error_code == ERROR_DECLARE_REFER_AGAIN)
		fprintf(stderr, "������ ���� : �ܺ� �ɺ� ������\n");
	else
		fprintf(stderr, "������ ���� : �� �� ���� ����. ���� �ڵ� : %d\n", error_code);

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
 * ���� : ����ڷ� ���� ����� ������ �޾Ƽ� ��ɾ��� OPCODE�� ã�� ����Ѵ�.
 * �Ű� : ���� ����, ����� ���� 
 * ��ȯ : ���� = 0, ���� = < 0 
 * ���� : ���� ����� ���α׷��� ����Ʈ ������ �����ϴ� ��ƾ�� ������ �ʾҴ�. 
 *		   ���� �߰������� �������� �ʴ´�. 
 * ----------------------------------------------------------------------------------
 */
int main(int argc, uchar *argv[])
{
	if (init_my_assembler() < 0)
	{
		printf("init_my_assembler: ���α׷� �ʱ�ȭ�� ���� �߽��ϴ�.\n");
		return -1;
	}

	if (assem_pass1() < 0)
	{
		printf("assem_pass1: �н�1 �������� �����Ͽ����ϴ�.  \n");
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
		printf(" assem_pass2: �н�2 �������� �����Ͽ����ϴ�.  \n");
		return -1;
	}

	make_objectcode_output("output.txt");
	//make_objectcode_output(NULL);

	return 0;
}

/* ----------------------------------------------------------------------------------
 * ���� : ���α׷� �ʱ�ȭ�� ���� �ڷᱸ�� ���� �� ������ �д� �Լ��̴�. 
 * �Ű� : ����
 * ��ȯ : �������� = 0 , ���� �߻� = -1
 * ���� : ������ ��ɾ� ���̺��� ���ο� �������� �ʰ� ������ �����ϰ� �ϱ� 
 *		   ���ؼ� ���� ������ �����Ͽ� ���α׷� �ʱ�ȭ�� ���� ������ �о� �� �� �ֵ���
 *		   �����Ͽ���. 
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
 * ���� : �ӽ��� ���� ��� �ڵ��� ������ �о� ���� ��� ���̺�(inst_table)�� 
 *        �����ϴ� �Լ��̴�. 
 * �Ű� : ���� ��� ����
 * ��ȯ : �������� = 0 , ���� < 0 
 * ���� : ���� ������� ������ �����Ӱ� �����Ѵ�. ���ô� ������ ����.
 *	
 *	===============================================================================
 *		   | �̸� | ���� | ���� �ڵ� | ���۷����� ���� | NULL|
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
 * ���� : ����ڵ� ��� �� ���� �޾�, ��� ���̺��� �����Ѵ�.
 * �Ű� : ����ڵ� ��� ���ڿ�
 * ��ȯ : �������� = 0 , ���� < 0  
 * ���� : �޸� �Ҵ� ���
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
 * ���� : ����� �� �ҽ��ڵ带 �о� �ҽ��ڵ� ���̺�(input_data)�� �����ϴ� �Լ��̴�. 
 * �Ű� : ������� �ҽ����ϸ�
 * ��ȯ : �������� = 0 , ���� < 0  
 * ���� : ���δ����� �����Ѵ�.
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
 * ���� : �ҽ� �ڵ带 �о�� ��ū������ �м��ϰ� ��ū ���̺��� �ۼ��ϴ� �Լ��̴�. 
 *        �н� 1�� ���� ȣ��ȴ�. 
 * �Ű� : �Ľ��� ���ϴ� ���ڿ�  
 * ��ȯ : �������� = 0, �ڸ�Ʈ = 1, ���� < 0
 * ���� : my_assembler ���α׷������� ���δ����� ��ū �� ������Ʈ ������ �ϰ� �ִ�. 
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
 * ���� : token_table�� label���� �ִ´�. 
 * �Ű� : token �ּ�, ���ڿ� ���� �ּ�, ���ڿ� ����
 * ��ȯ : ���� = 0, ���� < 0 
 * ���� : 
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
 * ���� : token_table�� operator�� �ִ´�. 
 * �Ű� : token �ּ�, ���ڿ� ���� �ּ�, ���ڿ� ����
 * ��ȯ : ���� = �ش� operator�� operand ����, ���� < 0 
 * ���� : 
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
 * ���� : token_table�� operand�� �ִ´�. 
 * �Ű� : token �ּ�, ���ڿ� ���� �ּ�, ���ڿ� ����
 * ��ȯ : ���� = 0, ���� < 0 
 * ���� : 
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
 * ���� : token_table�� comment���� �ִ´�. 
 * �Ű� : token �ּ�, ���ڿ� ���� �ּ�
 * ��ȯ : ���� 
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void add_comment(token* tok, const uchar* ptr, int length)
{
	strncpy(tok->comment, ptr, length);
	tok->comment[length] = 0;
}

/* ----------------------------------------------------------------------------------
 * ���� : token�� nixbpe ���� �����Ѵ�.
 * �Ű� : token �ּ�
 * ��ȯ : ���� 
 * ���� : 
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
 * ���� : �ҽ� �ڵ� ���� �տ� �ִ� ��ū�� ã�´�. 
 * �Ű� : �ҽ��ڵ�, �ڸ�Ʈ ����, ���� ��ġ�� ���� ������
 * ��ȯ : ��ū ����. ���� < 0 
 * ���� : 
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
 * ���� : �Է� ���ڿ��� ���� �ڵ������� �˻��ϴ� �Լ��̴�. 
 * �Ű� : ��ū ������ ���е� ���ڿ� 
 * ��ȯ : �������� = ���� ���̺� �ε���, ���� < 0 
 * ���� : 
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
 * ���� : �Է� ���ڿ��� ���� �ڵ������� �˻��ϴ� �Լ��̴�. 
 * �Ű� : ��ū ������ ���е� ���ڿ�, ���ڿ� ����
 * ��ȯ : �������� = ���� ���̺� �ε���, ���� < 0 
 * ���� : 
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
 * ���� : bsearch�� ���� uchar* & inst->str �� �Լ� 
 * �Ű� : uchar*, inst* 
 * ��ȯ : �񱳰� 
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int compare(const void* first, const void* second)
{
	return strcmp(first, (*((inst**)second))->str);
}

/* ----------------------------------------------------------------------------------
 * ���� : �ɺ��� ���̺� �߰����ִ� �Լ�
 * �Ű� : �ɺ� �̸�, �ɺ� �ּ�, ����, CS �ѹ�
 * ��ȯ : �ɺ� �ּ�
 * ���� : 
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
 * ���� : �ɺ��� ���̺� �߰����ִ� �Լ�
 * �Ű� : �ɺ� �̸�, �ɺ� �ּ�, ����, CS �ѹ�
 * ��ȯ : �ɺ� �ּ�
 * ���� : 
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
 * ���� : �ܺ� �ɺ��� ���̺� �߰����ִ� �Լ�
 * �Ű� : �ɺ� �̸�, CS �ѹ�
 * ��ȯ : 
 * ���� : 
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
	int parenthesis_stack[100]; // ��ȣ ��ȣ ����
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
 * ���� : EQU�� ���̺� �߰����ִ� �Լ�
 * �Ű� : �ɺ� �̸�, �ɺ� �ּ�, ����, CS �ѹ�
 * ��ȯ :  
 * ���� : 
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
 * ���� : ���ͷ��� ���̺� �߰����ִ� �Լ�
 * �Ű� : ���ͷ� �̸�, CS �ѹ�
 * ��ȯ : ���� ���� = size of literal>=0, ���� = <0
 * ���� : 
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
 * ���� : ���ڰ� hex���� ���� Ȯ��
 * �Ű� : Ȯ���� ����
 * ��ȯ : hex�� 1, �ƴϸ� 0
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int is_hex(uchar c)
{
	return ('0' <= c && c <= '9') || ('A' <= c && c <= 'F');
}

/* ----------------------------------------------------------------------------------
 * ���� : ���ڿ����� hex ���ͷ� �Ľ�
 * �Ű� : ����ǥ�� �׿� �ִ� �Ľ��� ���ڿ�
 * ��ȯ : ���� ���� = hex ��>=0, ���� = <0
 * ���� : 
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
 * ���� : ���ڿ����� ���ڿ� ���ͷ� �Ľ�
 * �Ű� : ����ǥ�� �׿� �ִ� �Ľ��� ���ڿ�
 * ��ȯ : ���� ���� = �Ľ��� ���ڿ� ũ��>=0, ���� = <0
 * ���� : 
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
 * ���� : operand���� ���� �Ľ�
 * �Ű� : operand �迭
 * ��ȯ : ���� ���� = �Ľ��� ����>=0, ���� = <0
 * ���� : 
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
 * ���� : ������ cs ���� symtab���� symbol ã��
 * �Ű� : symbol �̸�, CS �ѹ�
 * ��ȯ : symbol index>=0, ã�� ���� = -1
 * ���� : 
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
 * ���� : ������ cs ���� littab���� literal ã��
 * �Ű� : literal �̸�, CS �ѹ�
 * ��ȯ : literal index>=0, ã�� ���� = -1
 * ���� : 
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
 * ���� : �޸� ��ġ�� �������� ���� ���ͷ� ��ġ ����
 * �Ű� : locctr
 * ��ȯ : �������� = >=0(���� locctr ��ġ), ���� = -1
 * ���� : 
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
 * ���� : str���� Ư�� ���ڼ� ����
 * �Ű� : �����Ҵ����� ����� ������ ���ڿ�
 * ��ȯ : ���ڿ� ������
 * ���� : 
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
* ���� : ����� �ڵ带 ���� �н�1������ �����ϴ� �Լ��̴�.
*		   �н�1������..
*		   1. ���α׷� �ҽ��� ��ĵ�Ͽ� �ش��ϴ� ��ū������ �и��Ͽ� ���α׷� ���κ� ��ū
*		   ���̺��� �����Ѵ�.
*
* �Ű� : ����
* ��ȯ : ���� ���� = 0 , ���� = < 0
* ���� : ���� �ʱ� ���������� ������ ���� �˻縦 ���� �ʰ� �Ѿ �����̴�.
*	  ���� ������ ���� �˻� ��ƾ�� �߰��ؾ� �Ѵ�.
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
				print_compile_error(-1, "�߸��� ���ͷ� �ν���");
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
				print_compile_error(-1, "�߸��� ���ͷ� �ν���");
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
				print_compile_error(-1, "�߸��� ���ͷ� �ν���");
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
* ���� : �Էµ� ���ڿ��� �̸��� ���� ���Ͽ� ���α׷��� ����� �����ϴ� �Լ��̴�.
*        ���⼭ ��µǴ� ������ ��ɾ� ���� OPCODE�� ��ϵ� ǥ(���� 3��) �̴�.
* �Ű� : ������ ������Ʈ ���ϸ�
* ��ȯ : ����
* ���� : ���� ���ڷ� NULL���� ���´ٸ� ���α׷��� ����� ǥ��������� ������
*        ȭ�鿡 ������ش�.
*        ���� ���� 3�������� ���̴� �Լ��̹Ƿ� ������ ������Ʈ������ ������ �ʴ´�.
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
* ���� : �Էµ� ���ڿ��� �̸��� ���� ���Ͽ� ���α׷��� ����� �����ϴ� �Լ��̴�.
*        ���⼭ ��µǴ� ������ SYMBOL�� �ּҰ��� ����� TABLE�̴�.
* �Ű� : ������ ������Ʈ ���ϸ�
* ��ȯ : ����
* ���� : ���� ���ڷ� NULL���� ���´ٸ� ���α׷��� ����� ǥ��������� ������
*        ȭ�鿡 ������ش�.
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
* ���� : �Էµ� ���ڿ��� �̸��� ���� ���Ͽ� ���α׷��� ����� �����ϴ� �Լ��̴�.
*        ���⼭ ��µǴ� ������ LITERAL�� �ּҰ��� ����� TABLE�̴�.
* �Ű� : ������ ������Ʈ ���ϸ�
* ��ȯ : ����
* ���� : ���� ���ڷ� NULL���� ���´ٸ� ���α׷��� ����� ǥ��������� ������
*        ȭ�鿡 ������ش�.
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
 * ���� : hex string ���� int�� ��ȯ
 * �Ű� : NULL���ڷ� ������ hex string
 * ��ȯ : int ��
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int h2i(const uchar* hex)
{
	return strtol(hex, NULL, 16);
}

/* ----------------------------------------------------------------------------------
 * ���� : hex string ���� int�� ��ȯ
 * �Ű� : hex string, string ����
 * ��ȯ : int ��
 * ���� : 
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
 * ���� : int string ���� int�� ��ȯ
 * �Ű� : NULL���ڷ� ������ int string
 * ��ȯ : int ��
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */
static int a2i(const uchar* str)
{
	return atoi(str);
}

/* ----------------------------------------------------------------------------------
 * ���� : int string ���� int�� ��ȯ
 * �Ű� : int string, string ����
 * ��ȯ : int ��
 * ���� : 
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
 * ���� : Register string�� �ش� register value�� ��ȯ
 * �Ű� : register string
 * ��ȯ : register value
 * ���� : 
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
 * ���� : obejct program�� T record �� length �κ��� ���� ���ϴ� ��ŭ ������Ŵ
 * �Ű� : record string, ������ų ��
 * ��ȯ : 
 * ���� : 
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
 * ���� : object program�� H record �ۼ�
 * �Ű� : ���α׷� �̸�, ���� �ּ�, ����
 * ��ȯ : 
 * ���� : 
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
 * ���� : object program�� D record �ۼ�
 * �Ű� : EXTDEF ��ɾ��� operand, �ش� ��ɾ ���� CS �ѹ�
 * ��ȯ : 
 * ���� : 
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
 * ���� : object program�� R record �ۼ�
 * �Ű� : EXTREF ��ɾ��� oeprand
 * ��ȯ : 
 * ���� : 
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
 * ���� : object program�� M record �ۼ�
 * �Ű� : modification �ּ�
 * ��ȯ : 
 * ���� : write_all_modification_record �Լ� �ܿ����� ����ϸ� �ȵ�
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
 * ���� : object program�� M record �ۼ�
 * �Ű� : 
 * ��ȯ : 
 * ���� : �ش� �Լ� ���� �� clear_modification_record() �Լ��� �����Ͽ��� ��
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
 * ���� : mod_table �ʱ�ȭ
 * �Ű� : 
 * ��ȯ : 
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void clear_modification_record()
{
	mod_num = 0;
}

/* ----------------------------------------------------------------------------------
 * ���� : object program�� T record �ۼ�
 * �Ű� : locctr, �ۼ��� data�� ũ��, data
 * ��ȯ : 
 * ���� : 
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
 * ���� : object program�� T record �� literal �ۼ�
 * �Ű� : locctr, literal string �ּ�
 * ��ȯ : �ۼ��� literal ũ��
 * ���� : literal string�� literal �������� 'C' �Ǵ� 'X'���� �����Ͽ��� ��
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
 * ���� : object program�� E record �ۼ�
 * �Ű� : ���� �ּ� (���� ��� -1)
 * ��ȯ : 
 * ���� : 
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
 * ���� : �ܼ� modification ����
 * �Ű� : ���� ������ �ּ�, ������ ũ��(half byte)
 * ��ȯ : 
 * ���� : 
 *		
 * ----------------------------------------------------------------------------------
 */
static void create_simple_modification(int addr, int half_byte)
{
	create_external_modification("", addr, half_byte, 0);
}

/* ----------------------------------------------------------------------------------
 * ���� : �ܺ� modification ����
 * �Ű� : ���� ������ �ּ�, ������ ũ��(half byte), flag('+' or '-'), �ɺ� �̸� string
 * ��ȯ : 
 * ���� : 
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
 * ���� : operand�� ���� �ִ� �ܺ� ������ ��� ã�� modification�� �ۼ�
 * �Ű� : operand string, �ش� operand�� CS �ѹ�, ���� ������ �ּ�, ������ ũ��(half byte)
 * ��ȯ : 
 * ���� : 
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
* ���� : ����� �ڵ带 ���� �ڵ�� �ٲٱ� ���� �н�2 ������ �����ϴ� �Լ��̴�.
*		   �н� 2������ ���α׷��� ����� �ٲٴ� �۾��� ���� ������ ����ȴ�.
*		   ������ ���� �۾��� ����Ǿ� ����.
*		   1. ������ �ش� ����� ��ɾ ����� �ٲٴ� �۾��� �����Ѵ�.
* �Ű� : ����
* ��ȯ : �������� = 0, �����߻� = < 0
* ���� :
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
* ���� : �Էµ� ���ڿ��� �̸��� ���� ���Ͽ� ���α׷��� ����� �����ϴ� �Լ��̴�.
*        ���⼭ ��µǴ� ������ object code (������Ʈ 1��) �̴�.
* �Ű� : ������ ������Ʈ ���ϸ�
* ��ȯ : ����
* ���� : ���� ���ڷ� NULL���� ���´ٸ� ���α׷��� ����� ǥ��������� ������
*        ȭ�鿡 ������ش�.
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