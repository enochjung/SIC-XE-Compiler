/* 
 * my_assembler 함수를 위한 변수 선언 및 매크로를 담고 있는 헤더 파일이다. 
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
 * instruction 목록 파일로 부터 정보를 받아와서 생성하는 구조체 변수이다.
 * 구조는 각자의 instruction set의 양식에 맞춰 직접 구현하되
 * 라인 별로 하나의 instruction을 저장한다.
 */
struct inst_unit
{
	uchar str[10];
	uchar op;
	int format; // 0:not SIC/XE code	1:format 1	2:format 2		3:format 3/4
	int ops; //	0:-		1:M		2:R		3:N		4:RR	5:RN
};

// instruction의 정보를 가진 구조체를 관리하는 테이블 생성
typedef struct inst_unit inst;
inst *inst_table[MAX_INST];
int inst_index;

/*
 * 어셈블리 할 소스코드를 입력받는 테이블이다. 라인 단위로 관리할 수 있다.
 */
uchar *input_data[MAX_LINES];
static int line_num;

/*
 * 어셈블리 할 소스코드를 토큰단위로 관리하기 위한 구조체 변수이다.
 * operator는 renaming을 허용한다.
 * nixbpe는 8bit 중 하위 6개의 bit를 이용하여 n,i,x,b,p,e를 표시한다.
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
 * 심볼을 관리하는 구조체이다.
 * 심볼 테이블은 심볼 이름, 심볼의 위치로 구성된다.
 */
typedef struct symbol_unit
{
	uchar *symbol;
	int addr;
	int cs_num; // CS 넘버
	int is_external; // 1이면 외부 심볼
	struct symbol_unit* op[2][MAX_SYMBOL_NUMBER]; // 0은 +, 1은 -
	int op_len[2]; // 0은 +, 1은 -
} symbol;

symbol sym_table[MAX_LINES];
int sym_num;

/*
* 리터럴을 관리하는 구조체이다.
* 리터럴 테이블은 리터럴의 이름, 리터럴의 위치로 구성된다.
*/
typedef struct literal_unit
{
	uchar *literal;
	int addr; // -1이면 아직 메모리 할당되지 않은 리터럴
	int cs_num; // CS 넘버
} literal;

literal literal_table[MAX_LINES];
int literal_num;

typedef struct modification
{
	uchar name[MAX_SYMBOL_NAME];
	int addr;
	int length; // half byte
	int flag; // 0이면 simple modification, 1 or -1이면 external modification
} modification;

modification mod_table[MODIFICATION_TABLE_LENGTH];
int mod_num;

static int locctr;
int start_address;
int cs_length[MAX_CONTROL_SECTION]; // 해당 CS의 프로그램 길이

uchar object_code[MAX_LINES][OBJECT_CODE_STRING]; // 오브젝트 코드 저장 버퍼
int object_code_num; // 오브젝트 코드 라인 수

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
