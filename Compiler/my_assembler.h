/* 
 * my_assembler �Լ��� ���� ���� ���� �� ��ũ�θ� ��� �ִ� ��� �����̴�. 
 * 
 */
#define MAX_INST 256
#define MAX_LINES 5000
#define MAX_OPERAND 4
#define MAX_OPERAND_LENGTH 100
#define MAX_SYMBOL_NAME 6
#define MAX_SYMBOL_NUMBER 10
#define SYMBOL_NAME_STRING (MAX_SYMBOL_NAME + 1)
#define MAX_CONTROL_SECTION 10
#define MODIFICATION_TABLE_LENGTH 100

#define MAX(A,B) ((A) > (B) ? (A) : (B))
#define MAX_OBJECT_CODE_TEXT_WIDTH 69
#define MAX_OBJECT_CODE_DEFINE_REFER_WIDTH 73
#define OBJECT_CODE_STRING MAX(MAX_OBJECT_CODE_TEXT_WIDTH + 1, MAX_OBJECT_CODE_DEFINE_REFER_WIDTH + 1)

typedef unsigned char uchar;

/*
 * instruction ��� ���Ϸ� ���� ������ �޾ƿͼ� �����ϴ� ����ü �����̴�.
 * ������ ������ instruction set�� ��Ŀ� ���� ���� �����ϵ�
 * ���� ���� �ϳ��� instruction�� �����Ѵ�.
 */
struct inst_unit
{
	uchar str[10];
	uchar op;
	int format; // 0:not SIC/XE code	1:format 1	2:format 2		3:format 3/4
	int ops; //	0:-		1:M		2:R		3:N		4:RR	5:RN
};

// instruction�� ������ ���� ����ü�� �����ϴ� ���̺� ����
typedef struct inst_unit inst;
inst *inst_table[MAX_INST];
int inst_index;

/*
 * ����� �� �ҽ��ڵ带 �Է¹޴� ���̺��̴�. ���� ������ ������ �� �ִ�.
 */
uchar *input_data[MAX_LINES];
static int line_num;

/*
 * ����� �� �ҽ��ڵ带 ��ū������ �����ϱ� ���� ����ü �����̴�.
 * operator�� renaming�� ����Ѵ�.
 * nixbpe�� 8bit �� ���� 6���� bit�� �̿��Ͽ� n,i,x,b,p,e�� ǥ���Ѵ�.
 */
struct token_unit
{
	uchar *label;
	uchar *operator;
	uchar operand[MAX_OPERAND][MAX_OPERAND_LENGTH];
	uchar comment[100];
	uchar nixbpe;
};

typedef struct token_unit token;
token *token_table[MAX_LINES];
static int token_line;

/*
 * �ɺ��� �����ϴ� ����ü�̴�.
 * �ɺ� ���̺��� �ɺ� �̸�, �ɺ��� ��ġ�� �����ȴ�.
 */
typedef struct symbol_unit
{
	uchar *symbol;
	int addr;
	int cs_num; // CS �ѹ�
	int is_external; // 1�̸� �ܺ� �ɺ�
	struct symbol_unit* op[2][MAX_SYMBOL_NUMBER]; // 0�� +, 1�� -
	int op_len[2]; // 0�� +, 1�� -
} symbol;

symbol sym_table[MAX_LINES];
int sym_num;

/*
* ���ͷ��� �����ϴ� ����ü�̴�.
* ���ͷ� ���̺��� ���ͷ��� �̸�, ���ͷ��� ��ġ�� �����ȴ�.
*/
typedef struct literal_unit
{
	uchar *literal;
	int addr; // -1�̸� ���� �޸� �Ҵ���� ���� ���ͷ�
	int cs_num; // CS �ѹ�
} literal;

literal literal_table[MAX_LINES];
int literal_num;

typedef struct modification
{
	uchar name[MAX_SYMBOL_NAME];
	int addr;
	int length; // half byte
	int flag; // 0�̸� simple modification, 1 or -1�̸� external modification
} modification;

modification mod_table[MODIFICATION_TABLE_LENGTH];
int mod_num;

static int locctr;
int start_address;
int cs_length[MAX_CONTROL_SECTION]; // �ش� CS�� ���α׷� ����

uchar object_code[MAX_LINES][OBJECT_CODE_STRING]; // ������Ʈ �ڵ� ���� ����
int object_code_num; // ������Ʈ �ڵ� ���� ��

//--------------

static uchar *input_file;
static uchar *output_file;
int init_my_assembler(void);
int init_inst_file(uchar *inst_file);
int init_input_file(uchar *input_file);
int token_parsing(uchar *str);
int search_opcode(uchar *str);
static int assem_pass1(void);
void make_opcode_output(uchar *file_name);
void make_symtab_output(uchar *file_name);
void make_literaltab_output(uchar *file_name);
static int assem_pass2(void);
void make_objectcode_output(uchar *file_name);
