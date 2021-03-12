#include "rule.h"
#include "rule.tab.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wunused-function"

mtx_rule_ctx_desc_t descs[MTX_SYM_CTX_END] = MTX_RULE_CTX_DESC_INITER;

mtx_rule_ctx_t   CTX;
mtx_rule_ctx_t*  ctx = &CTX;
mtx_rule_key_t   krule;
mtx_rule_value_t vrule;

static const char* self;

static void
init_lex_dump(bos_bool load) {
#if MTX_LEX_DUMP
    if (load) {
        ctx->dump.lex = fopen("rule.load.lex.lisp", "w+");
    } else {
        ctx->dump.lex = fopen("rule.build.lex.lisp", "w+");
    }
#endif
}

static void
init_ast_dump(bos_bool load) {
#if MTX_AST_DUMP
    if (load) {
        ctx->dump.ast = fopen("rule.load.ast.lisp", "w+");
    } else {
        ctx->dump.ast = fopen("rule.build.ast.lisp", "w+");
    }
#endif
}

int load(void) {
    void*   mem;
    ssize_t size;
    int     i, err;

    mtx_init();

    err = mtx_rule_ctx_load(ctx, descs);
    if (err < 0) {
        return bos_shell_error(err);
    }

    size = mtx_rule_ctx_calc(ctx);
    bos_ddd("total size: %ld", size);

    mem = bos_malloc(size);
    if (NULL == mem) {
        return bos_shell_error(ENOMEM);
    }

    err = mtx_rule_ctx_merge(ctx, mem, size);
    if (err < 0) {
        return bos_shell_error(err);
    }
    bos_ddd("OK: ctx merge");

    init_ast_dump(bos_true);

    int kcount = ctx->kdb->table.count;
    int vcount = ctx->vdb->table.count;
    if (kcount !=vcount) {
        bos_assert(0);
    }

    for (i = 0; i < kcount; i++) {
        mtx_rule_key_t*   k = mtx_rule_db_kget(ctx->kdb, i);
        mtx_rule_value_t* v = mtx_rule_db_vget(ctx->vdb, i);

        show_ast_sym(ctx, k->cond, "cond", kcount, i);
        show_ast_sym(ctx, v->action, "action", kcount, i);
    }

    mtx_rule_ctx_fini(ctx);
    if (err < 0) {
        return bos_shell_error(err);
    }

    return 0;
}

int build(void) {
    int err;

    mtx_init();

    err = mtx_rule_ctx_init(ctx, descs);
    if (err < 0) {
        return bos_shell_error(err);
    }

    init_lex_dump(bos_false);
    init_ast_dump(bos_false);

#if defined(YYDEBUG) && YYDEBUG
    yydebug = 1;
#endif

    bos_ddd("BEFORE yyparse");
    yyparse();
    bos_ddd("AFTER yyparse");

    mtx_rule_ctx_fini(ctx);
    if (err < 0) {
        return bos_shell_error(err);
    }

    return 0;
}

int help(int err) {
    bos_println("%s build RULE-FILE", self);
    bos_println("%s load", self);
    bos_println("%s help", self);

    return bos_shell_error(err);
}

int main(int argc, char* argv[]) {
    char* acton = argv[1];
    char* file  = argv[2];

    self = (const char*)argv[0];

    switch (argc) {
        case 2:
            if (0 == strcmp("load", acton)) {
                return load();
            }

            break;
        case 3:
            if (0 == strcmp("build", acton)) {
                yyin = fopen(file, "r");
                if (NULL == yyin) {
                    perror(file);
                    return (1);
                }

                return build();
            }

            break;
    }

    return help(EHELP);
}

void yyerror(const char* fmt, ...) {
    va_list args;

    fprintf(stderr, "ERROR[%d: at %s]: ", yylineno, yytext);

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}
