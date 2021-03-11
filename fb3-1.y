%{
#include <stdio.h>
#include <stdlib.h>
#include "fb3-1.h"

int yylex();
%}

%union {
struct ast *a;
double d;
}

%token <d> NUMBER
%token EOL

%type <a> exp factor term

%%
calclist: /* 空 */
    | calclist exp EOL {
        printf("= %4.4g\n", eval($2));
        treefree($2);
        printf("> ");
    }
    | calclist EOL {printf("> ");}
    ;

exp: factor
    | exp '+' factor { printf(" <in + > ");  $$ = newast('+', $1,$3);}
    | exp '-' factor { printf(" <in - > ");  $$ = newast('-', $1,$3);}
    ;

factor: term
    | factor '*' term { printf(" <in * > "); $$ = newast('*', $1,$3); } 
    | factor '/' term { printf(" <in / > "); $$ = newast('/', $1,$3); } 
    ;

term: NUMBER {$$ = newnum($1);}
    | '|' term { printf(" <in | > "); $$ = newast('|', $2, NULL); }
    | '(' term ')' { $$ = $2; }
    | '-' term {$$ = newast('M', $2, NULL);}
    ;
%%