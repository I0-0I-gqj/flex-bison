/* 
    计算器声明部分
*/

/* 词法分析接口 */
extern int yylineno;
void yyerror(char *s, ...);

/* 语法树节点 */
struct ast {
    int nodetype;
    struct ast *l;
    struct ast *r;   
};

struct numval {
    int nodetype;
    double number;
};

/* 构造语法树 */
struct ast *newast(int nodetype, struct ast*l, struct ast *r);
struct ast *newnum(double d);

/* 计算语法树 */
double eval(struct ast *);

/* 删除和释放语法树 */
void treefree(struct ast *);

