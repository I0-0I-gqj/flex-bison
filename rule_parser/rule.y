%{
#include "rule.h"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wunused-function"

%}

%union {
    int op;
    int fn;
    int pvid;
    int proto;
    int match;

    bos_bool b;
    bos_time tm;
    bos_ip ip;
    mtx_lex_t *ast;
    char *s;
    double f;
    bos_i64 i;
    bos_i64 macro;
    bos_binstr bin;
    bos_mac mac;
}

%token <s> NAME HALF_STRING
%token <f> FLOAT
%token <i> INTEGER CHAR
%token <b> BOOLEAN
%token <v> PROTO MATCH PVB PVL PVL_IP
%token <bin> STRING
%token <tm> TIME
%token <mac> MAC
%token <macro> STOKEN_MASK HTTP_METHOD
%token <ip> IPV4

%token <fn> FUNC_TIME_time
%token <fn> FUNC_STRING_substr
%token <fn> FUNC_INT_length
%token <fn> FUNC_INT_ntohs
%token <fn> FUNC_INT_ntohl
%token <fn> FUNC_IP_toip
%token <fn> FUNC_IP_toint
%token <fn> FUNC_TIME_totime
%token <fn> FUNC_STRING_string
%token <fn> FUNC_IP_network
%token <fn> FUNC_SET_sequence
%token <fn> FUNC_SET_stoken
%token <fn> FUNC_SET_sarray
%token <fn> FUNC_SET_iparray
%token <fn> FUNC_SET_narray
%token <fn> FUNC_STRING_charset
%token <fn> FUNC_PROC_nothing
%token <fn> FUNC_PROC_usocket
%token <fn> FUNC_BOOL_elimit
%token <fn> FUNC_BOOL_emax
%token <fn> FUNC_BOOL_efreq
%token <fn> FUNC_PROC_setmap
%token <fn> FUNC_BOOL_querymap


%token <fn> FUNC_STRING_BY_IP
%token <fn> FUNC_STRING_BY_NONE
%token <fn> FUNC_STRING_BY_STRING
%token <fn> FUNC_STRING_BY_STRING_INT
%token <fn> FUNC_INT_BY_STRING_INT
%token <fn> FUNC_PROC_BY_STRING_INT3
%token <fn> FUNC_PROC_BY_VARIANTS
%token <fn> FUNC_IP_BY_IP


%token <op> SUB ADD
%token <op> MUL DIV MOD
%token <op> AND OR NOT
%token <op> EQ NEQ CMP
%token <op> BXOR BLOGIC BSHIFT BNOT
%token <op> STR PCRE
%token <op> LP RP LBRA RBRA
%token <op> NS COMMA SEM NEXT
%token EOL

 /* low pri*/
%left NEXT
%left NOT
%left AND OR
%left SEM
%left EQ NEQ CMP
%left STR PCRE
%left BXOR BLOGIC BSHIFT BNOT
%left ADD SUB
%left MUL DIV MOD
%precedence UBNOT
%precedence UMINUS
 /* %nonassoc <op> UBNOT */
 /* %nonassoc <op> UMINUS */
%nonassoc NS
 /* high pri*/

%type <ast> r_cond r_action
%type <ast> expr_bool expr_int expr_string expr_time expr_ip
%type <ast> cmp_set cmp_int cmp_ip cmp_time cmp_pcre cmp_string
%type <ast> const_float const_int const_string const_ip const_time
%type <ast> var_ip var_int var_string
%type <ast> func_plugin func_int func_string func_bool func_ip func_time func_proc
%type <ast> func_set_string func_set_int func_set_ip

%type <ast> list_cond           cond
%type <ast> list_action         action
%type <ast> list_param          param
%type <ast> list_param_string   param_string
%type <ast> list_param_int      param_int
%type <ast> list_param_ip       param_ip
%type <ast> param_time

%type <ast> func_time_time
%type <ast> func_string_substr
%type <ast> func_int_length
%type <ast> func_int_ntohs
%type <ast> func_int_ntohl
%type <ast> func_ip_toip
%type <ast> func_ip_toint
%type <ast> func_time_totime
%type <ast> func_string_string
%type <ast> func_ip_network
%type <ast> func_set_sequence
%type <ast> func_set_stoken
%type <ast> func_set_sarray
%type <ast> func_set_iparray
%type <ast> func_set_narray
%type <ast> func_string_charset
%type <ast> func_proc_nothing
%type <ast> func_proc_usocket
%type <ast> func_bool_elimit
%type <ast> func_bool_emax
%type <ast> func_bool_efreq
%type <ast> func_proc_setmap
%type <ast> func_bool_querymap


%type <ast> func_string_by_ip
%type <ast> func_string_by_none
%type <ast> func_string_by_string
%type <ast> func_string_by_string_int
%type <ast> func_int_by_string_int
%type <ast> func_proc_by_string_int3
%type <ast> func_proc_by_variants
%type <ast> func_ip_by_ip

%start r_rules
%%

r_rules: /* nothing */
    | /* nothing */ EOL
    | error EOL { 
        mtx_lex_ddd("rules ERROR EOL ERROR EOL ERROR EOL ERROR");

        yyclearin;
        yyerrok;
    }
    | r_rules EOL
    | r_rules r_rule EOL {
        // mtx_lex_ddd("rules EOL EOL EOL EOL EOL EOL EOL EOL EOL EOL EOL EOL");
        mtx_rule_ctx_pv_show(ctx);
        bos_tmpool_show(ctx->pool.global, "global");
    }
    ;
r_rule: r_id r_name r_proto r_match r_cond r_action r_reverse r_report r_event r_react r_level r_pri {
        mtx_rule_setup(ctx, $5, $6, &krule, &vrule);

        bos_memzero(&krule, sizeof(krule));
        bos_memzero(&vrule, sizeof(vrule));
        bos_tmpool_reset(ctx->pool.line);
    }
    ;
r_id: INTEGER   { mtx_lex_ddd("rule id=%ld", yylval.i); vrule.id = yylval.i; }
    ;
r_name: NAME    { mtx_lex_ddd("rule name=%s", yylval.s); vrule.name = bos_sym_insert_string(MTX_CTX_NAME(ctx), yylval.s); }
    ;
r_proto: PROTO  { mtx_lex_ddd("rule proto=%s", mtx_proto_getname(yylval.proto)); krule.proto = yylval.proto; }
    ;
r_match: MATCH  { mtx_lex_ddd("rule match=%s", mtx_match_getname(yylval.match)); krule.match = yylval.match; }
    ;
r_cond: list_cond       { show_rule_cond(ctx, $1, vrule.id); }
    ;
r_action: list_action   { show_rule_action(ctx, $1, vrule.id); }
    ;
r_reverse: INTEGER  { mtx_lex_ddd("rule reverse=%ld", yylval.i); krule.reverse = !!yylval.i; }
    ;
r_report: INTEGER   { mtx_lex_ddd("rule report=%ld", yylval.i); krule.report = (bos_u32)yylval.i; }
    ;
r_event: INTEGER    { mtx_lex_ddd("rule event=%ld", yylval.i); vrule.event = (bos_u32)yylval.i; }
    ;
r_react: NAME       { mtx_lex_ddd("rule react=%s", yylval.s); vrule.react = bos_sym_insert_string(MTX_CTX_NAME(ctx), yylval.s); }
    ;
r_level: INTEGER    { mtx_lex_ddd("rule level=%ld", yylval.i); vrule.level = (bos_u32)yylval.i; }
    ;
r_pri: INTEGER      { mtx_lex_ddd("rule pri=%ld", yylval.i); vrule.pri = (bos_u32)yylval.i; }
    ;

list_cond: cond                 { $$ = new_mtx_lex_list_cond(ctx, $1); }
    | list_cond NEXT cond       { $$ = mtx_lex_merge(ctx, $1, $3); }
    ;
cond: expr_bool
    ;

list_action: action             { $$ = new_mtx_lex_list_action(ctx, $1); }
    | list_action SEM action    { $$ = mtx_lex_merge(ctx, $1, $3); }
    ;
action: func_proc
    ;

list_param: param                       { $$ = new_mtx_lex_list_param(ctx, $1); }
    | list_param COMMA param            { $$ = mtx_lex_merge(ctx, $1, $3); }
    ;
 /* for iparray */
list_param_ip: param_ip                 { $$ = new_mtx_lex_list_param(ctx, $1); }
    | list_param_ip COMMA param_ip      { $$ = mtx_lex_merge(ctx, $1, $3); }
    ;
 /* for sarray */
list_param_string: const_string             { $$ = new_mtx_lex_list_param(ctx, $1); }
    | list_param_string COMMA const_string  { $$ = mtx_lex_merge(ctx, $1, $3); }
    ;
 /* for narray */
list_param_int: param_int                       { $$ = new_mtx_lex_list_param(ctx, $1); }
    | list_param_int COMMA param_int            { $$ = mtx_lex_merge(ctx, $1, $3); }
    ;

 /* no param_float */
param: param_ip
    | param_time
    | param_int
    | param_string
    ;

param_ip: expr_ip
    ;
param_time: expr_time
    ;
param_string: expr_string
    ;
param_int: expr_int
    ;

 /* no expr_float */
 /* not support: int - ip */
expr_ip: LP expr_ip RP          { $$ = $2; }
    | const_ip
    | var_ip
    | func_ip
    | BNOT expr_ip              { $$ = new_mtx_lex_expr_ip_bnot(ctx, $1, $2); mtx_lex_ip_fold(ctx, $$); }
    | expr_ip BLOGIC expr_ip    { $$ = new_mtx_lex_expr_ip(ctx, $2, $1, $3); mtx_lex_ip_fold(ctx, $$); }
    ;
 /* not support: int - time */
expr_time: LP expr_time RP      { $$ = $2; }
    | const_time
    | func_time                 { $$ = $1; mtx_lex_time_fold(ctx, $$); }
    | expr_time SUB expr_int    { $$ = new_mtx_lex_expr_time(ctx, $2, $1, $3); mtx_lex_time_fold(ctx, $$); }
    | expr_time ADD expr_int    { $$ = new_mtx_lex_expr_time(ctx, $2, $1, $3); mtx_lex_time_fold(ctx, $$); }
    | expr_int  ADD expr_time   { $$ = new_mtx_lex_expr_time(ctx, $2, $3, $1); mtx_lex_time_fold(ctx, $$); }
    ;
expr_int: LP expr_int RP        { $$ = $2; }
    | const_int
    | var_int
    | func_int
    | expr_int BXOR expr_int    { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | expr_int BLOGIC expr_int  { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | expr_int BSHIFT expr_int  { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | expr_int ADD expr_int     { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | expr_int SUB expr_int     { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | expr_int MUL expr_int     { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | expr_int DIV expr_int     { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | expr_int MOD expr_int     { $$ = new_mtx_lex_expr_int(ctx, $2, $1, $3); mtx_lex_int_fold(ctx, $$); }
    | BNOT expr_int %prec UBNOT   { $$ = new_mtx_lex_expr_int_bnot(ctx, $1, $2);  mtx_lex_int_fold(ctx, $$); }
    | SUB  expr_int %prec UMINUS  { $$ = new_mtx_lex_expr_int_minus(ctx, $1, $2); mtx_lex_int_fold(ctx, $$); }
    ;
expr_string: LP expr_string RP  { $$ = $2; }
    | const_string
    | var_string
    | func_string
    | expr_string LBRA expr_int RBRA { 
        $$ = new_mtx_lex_expr_substring(ctx, $1, 1, $3, NULL); 
        mtx_lex_string_fold(ctx, $$); 
    }
    | expr_string LBRA expr_int COMMA expr_int RBRA { 
        $$ = new_mtx_lex_expr_substring(ctx, $1, 2, $3, $5);
        mtx_lex_string_fold(ctx, $$);
    }
    ;
expr_bool: LP expr_bool RP      { $$ = $2; }
    | NOT expr_bool             { $$ = new_mtx_lex_expr_not(ctx, $1, $2); }
    | expr_bool AND expr_bool   { $$ = new_mtx_lex_expr_bool(ctx, $2, $1, $3); }
    | expr_bool OR expr_bool    { $$ = new_mtx_lex_expr_bool(ctx, $2, $1, $3); }
    | cmp_set
    | cmp_int
    | cmp_ip
    | cmp_time
    | cmp_pcre
    | cmp_string
    | func_bool
    | func_plugin
    ;

cmp_int: LP cmp_int RP              { $$ = $2; }
    | expr_int EQ expr_int          { $$ = new_mtx_lex_cmp_int(ctx, $2, $1, $3); }
    | expr_int NEQ expr_int         { $$ = new_mtx_lex_cmp_int(ctx, $2, $1, $3); }
    | expr_int CMP expr_int         { $$ = new_mtx_lex_cmp_int(ctx, $2, $1, $3); }
    ;
cmp_ip: LP cmp_ip RP                { $$ = $2; }
    | expr_ip EQ expr_ip            { $$ = new_mtx_lex_cmp_ip(ctx, $2, $1, $3); }
    | expr_ip NEQ expr_ip           { $$ = new_mtx_lex_cmp_ip(ctx, $2, $1, $3); }
    | expr_ip CMP expr_ip           { $$ = new_mtx_lex_cmp_ip(ctx, $2, $1, $3); }
    ;
cmp_time: LP cmp_time RP            { $$ = $2; }
    | expr_time EQ expr_time        { $$ = new_mtx_lex_cmp_time(ctx, $2, $1, $3); }
    | expr_time NEQ expr_time       { $$ = new_mtx_lex_cmp_time(ctx, $2, $1, $3); }
    | expr_time CMP expr_time       { $$ = new_mtx_lex_cmp_time(ctx, $2, $1, $3); }
    ;
cmp_string: LP cmp_string RP        { $$ = $2; }
    | expr_string EQ expr_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_string(ctx, $2, $1, $3); 
    }
    | expr_string NEQ expr_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_string(ctx, $2, $1, $3); 
    }
    | expr_string BXOR expr_string   { 
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_string(ctx, $2, $1, $3);
    }
    | expr_string STR expr_string   { 
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_string(ctx, $2, $1, $3);
    }
    ;
cmp_pcre: LP cmp_pcre RP            { $$ = $2; }
    | expr_string BNOT expr_string  { $$ = new_mtx_lex_cmp_pcre(ctx, $2, $1, $3); }
    | expr_string PCRE expr_string  { $$ = new_mtx_lex_cmp_pcre(ctx, $2, $1, $3); }
    ;
cmp_set: LP cmp_set RP                  { $$ = $2; }
    | expr_int EQ func_set_int          { $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); }
    | func_set_int EQ expr_int          { $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); }
    | expr_int NEQ func_set_int         { $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); }
    | func_set_int NEQ expr_int         { $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); }
    | expr_ip EQ func_set_ip            { $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); }
    | func_set_ip EQ expr_ip            { $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); }
    | expr_ip NEQ func_set_ip           { $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); }
    | func_set_ip NEQ expr_ip           { $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); }
    | expr_string PCRE func_set_string  { $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); }
    | func_set_string PCRE expr_string  { $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); }
    | expr_string EQ func_set_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); 
    }
    | func_set_string EQ expr_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); 
    }
    | expr_string NEQ func_set_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); 
    }
    | func_set_string NEQ expr_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); 
    }
    | expr_string BXOR func_set_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); 
    }
    | func_set_string BXOR expr_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); 
    }
    | expr_string STR func_set_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $1, $3); 
    }
    | func_set_string STR expr_string    {
        yyEscape(ctx, $1);
        yyEscape(ctx, $3);

        $$ = new_mtx_lex_cmp_set(ctx, $2, $3, $1); 
    }
    ;

 /* const values */
const_float: LP const_float RP  { $$ = $2; }
    | FLOAT         { $$ = new_mtx_lex_const_float(ctx, yylval.f); }
    ;
const_ip: LP const_ip RP        { $$ = $2; }
    | IPV4          { $$ = new_mtx_lex_const_ip(ctx, yylval.ip); }
    ;
const_time: LP const_time RP    { $$ = $2; }
    | TIME          { $$ = new_mtx_lex_const_time(ctx, yylval.tm); }
    ;
const_int: LP const_int RP      { $$ = $2; }
    | CHAR          { $$ = new_mtx_lex_const_int(ctx, yylval.i); }
    | INTEGER       { $$ = new_mtx_lex_const_int(ctx, yylval.i); }
    | STOKEN_MASK   { $$ = new_mtx_lex_const_int(ctx, yylval.macro); }
    | HTTP_METHOD   { $$ = new_mtx_lex_const_int(ctx, yylval.macro); }
    ;
const_string: LP const_string RP { $$ = $2; }
    | STRING    {
        bos_binstr bin = yylval.bin;

#if MTX_AST_DEBUG_STRING
        mtx_lex_ddd("rule STRING=");
        bos_dump_buffer(bin.obj, bin.len);
#endif
        $$ = new_mtx_lex_const_binstr(ctx, bin);
    }
    ;

var_ip: LP var_ip RP            { $$ = $2; }
    | PVL_IP { 
        $$ = new_mtx_lex_var_pvl(ctx, yylval.pvid); 
    }
    ;
var_int: LP var_int RP          { $$ = $2; }
    | PVL {
        int proto = krule.proto;

        if (bos_false==is_mtx_pvl_match_proto_bypvid(yylval.pvid, proto)) {
            yyError("pvl: %s not match proto: %s", mtx_pvl_getname_bypvid(yylval.pvid), mtx_proto_getname(proto));
        }

        $$ = new_mtx_lex_var_pvl(ctx, yylval.pvid); 
    }
    ;
var_string: LP var_string RP    { $$ = $2; }
    | PVB {
        int proto = krule.proto;

        if (bos_false==is_mtx_pvb_match_proto_bypvid(yylval.pvid, proto)) {
            yyError("pvb: %s not match proto: %s", mtx_pvb_getname_bypvid(yylval.pvid), mtx_proto_getname(proto));
        }

        $$ = new_mtx_lex_var_pvb(ctx, yylval.pvid);
    }
    ;

 /* without param */
func_plugin: NAME NS NAME LP RP { $$ = new_mtx_lex_func_plug(ctx, $1, $3); }
    ;
func_int: func_int_by_string_int
    | func_int_length
    | func_int_ntohs
    | func_int_ntohl
    | func_ip_toint
    ;
func_time: func_time_time
    | func_time_totime
    ;
func_ip: func_ip_by_ip
    | func_ip_toip
    | func_ip_network
    ;
func_string: func_string_by_none
    | func_string_by_ip
    | func_string_by_string
    | func_string_by_string_int
    | func_string_substr
    | func_string_string
    | func_string_charset
    ;
func_bool: func_bool_elimit
    | func_bool_emax
    | func_bool_efreq
    | func_bool_querymap
    | func_set_stoken
    ;
func_proc: func_proc_by_string_int3
    | func_proc_by_variants
    | func_proc_nothing
    | func_proc_usocket
    | func_proc_setmap
    ;

func_set_ip: func_set_iparray
    ;
func_set_int: func_set_narray
    ;
func_set_string: func_set_sequence
    | func_set_sarray
    ;

 /* buildin functions */
func_time_time: FUNC_TIME_time LP RP { 
        $$ = new_mtx_lex_func(ctx, MTX_AST(func, time), $1, NULL); 
    }
    ;
func_string_substr: FUNC_STRING_substr LP param_string COMMA param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, string), $1, $3, $5); 
    }
    | FUNC_STRING_substr LP param_string COMMA param_int COMMA param_int RP {
        $$ = new_mtx_lex_func_by4(ctx, MTX_AST(func, string), $1, $3, $5, $7, NULL); 
    }
    ;
func_int_length: FUNC_INT_length LP param_string RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, int), $1, $3, NULL); 
    }
    ;
func_int_ntohs: FUNC_INT_ntohs LP param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, int), $1, $3, NULL); 
    }
    ;
func_int_ntohl: FUNC_INT_ntohl LP param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, int), $1, $3, NULL); 
    }
    ;
func_ip_toip: FUNC_IP_toip LP param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, ip), $1, $3, NULL);

        mtx_lex_ip_fold(ctx, $$);
    }
    ;
func_ip_toint: FUNC_IP_toint LP param_ip RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, int), $1, $3, NULL);
    }
    ;
func_time_totime: FUNC_TIME_totime LP param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, time), $1, $3, NULL); 
    }
    | FUNC_TIME_totime LP param_time RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, time), $1, $3, NULL); 
    }
    ;
func_string_string: FUNC_STRING_string LP list_param RP { 
        $$ = new_mtx_lex_func(ctx, MTX_AST(func, string), $1, $3); 
    }
    ;
func_ip_network: FUNC_IP_network LP param_ip COMMA param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, ip), $1, $3, $5); 

        mtx_lex_ip_fold(ctx, $$);
    }
    ;
func_set_sequence: FUNC_SET_sequence LP list_param_string RP { 
        $$ = new_mtx_lex_set_string(ctx, $1, $3);
    }
    ;
func_set_stoken: FUNC_SET_stoken LP param_int COMMA list_param_string RP {
        mtx_lex_t *mask = $3;

        if (!mtx_lex_int_fold(ctx, mask)) {
            yyError("stoken(const expr int, ......)");
        }

        $$ = new_mtx_lex_set_stoken(ctx, $1, $3, $5); 
    }
    ;
func_set_sarray: FUNC_SET_sarray LP list_param_string RP { 
        $$ = new_mtx_lex_set_string(ctx, $1, $3); 
    }
    ;
func_set_iparray: FUNC_SET_iparray LP list_param_ip RP {
        mtx_lex_t *param = $3;

        mtx_lex_list_ip_param_fold(ctx, param);

        $$ = new_mtx_lex_set_ip(ctx, $1, param); 
    }
    ;
func_set_narray: FUNC_SET_narray LP list_param_int RP {
        mtx_lex_t *param = $3;

        mtx_lex_list_int_param_fold(ctx, param);

        $$ = new_mtx_lex_set_int(ctx, $1, param); 
    }
    ;
func_string_charset: FUNC_STRING_charset LP param_string COMMA param_string COMMA param_string RP { 
        $$ = new_mtx_lex_func_by4(ctx, MTX_AST(func, string), $1, $3, $5, $7, NULL); 
    }
    ;
func_proc_nothing: FUNC_PROC_nothing LP RP { 
        $$ = new_mtx_lex_func(ctx, MTX_AST(func, proc), $1, NULL); 
    }
    ;
func_proc_usocket: FUNC_PROC_usocket LP param_ip COMMA param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, proc), $1, $3, $5); 
    }
    ;
func_bool_elimit: FUNC_BOOL_elimit LP param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, boolean), $1, $3, NULL); 
    }
    | FUNC_BOOL_elimit LP param_int COMMA param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, boolean), $1, $3, $5); 
    }
    ;
func_bool_emax: FUNC_BOOL_emax LP param_int COMMA param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, boolean), $1, $3, $5); 
    }
    ;
func_bool_efreq: FUNC_BOOL_efreq LP const_float RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, boolean), $1, $3, NULL);
    }
    ;
func_proc_setmap: FUNC_PROC_setmap LP param_string COMMA param COMMA param COMMA param COMMA param_int RP { 
        $$ = new_mtx_lex_func_by6(ctx, MTX_AST(func, proc), $1, $3, $5, $7, $9, $11, NULL);
    }
    ;
func_bool_querymap: FUNC_BOOL_querymap LP param_string RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, boolean), $1, $3, NULL);
    }
    ;

 /* common functons */
func_ip_by_ip: FUNC_IP_BY_IP LP param_ip RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, ip), $1, $3, NULL); 

        mtx_lex_ip_fold(ctx, $$);
    }
    ;
func_int_by_string_int: FUNC_INT_BY_STRING_INT LP param_string COMMA param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, int), $1, $3, $5); 
    }
    ;
func_string_by_ip: FUNC_STRING_BY_IP LP param_ip RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, string), $1, $3, NULL); 
    }
    ;
func_string_by_none: FUNC_STRING_BY_NONE LP RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, string), $1, NULL, NULL); 
    }
    ;
func_string_by_string: FUNC_STRING_BY_STRING LP param_string RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, string), $1, $3, NULL); 
    }
    ;
func_string_by_string_int: FUNC_STRING_BY_STRING_INT LP param_string COMMA param_int RP { 
        $$ = new_mtx_lex_func_by2(ctx, MTX_AST(func, string), $1, $3, $5); 
    }
    ;
func_proc_by_string_int3: FUNC_PROC_BY_STRING_INT3 LP param_string COMMA param_int COMMA param_int COMMA param_int RP { 
        $$ = new_mtx_lex_func_by4(ctx, MTX_AST(func, proc), $1, $3, $5, $7, $9);
    }
    ;
func_proc_by_variants: FUNC_PROC_BY_VARIANTS LP RP {
        $$ = new_mtx_lex_func(ctx, MTX_AST(func, proc), $1, NULL); 
    }
    | FUNC_PROC_BY_VARIANTS LP list_param RP { 
        $$ = new_mtx_lex_func(ctx, MTX_AST(func, proc), $1, $3); 
    }
    ;
%%
