%option noyywrap nodefault yylineno

%{
#include "rule.h"
#include "rule.tab.h"

#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wunused-function"

char *dup_name(char *s) {
    int len = strlen(s);
    char *d = (char *)bos_tmpool_alloc(ctx->pool.line, 1+len);

    bos_memcpy(d, s, len);
    d[len] = 0;

    return d; 
}

bos_binstr dup_string(char *s, int len) {
    char *d = (char *)bos_tmpool_alloc(ctx->pool.line, 1+len);

    bos_memcpy(d, s, len);
    d[len] = 0;

    return MAKE_BINSTR(d, len); 
}

char *dup_const_string(char *s) {
    int len = strlen(s) - 2;
    char *d = (char *)bos_tmpool_alloc(ctx->pool.line, 1+len);
    
    bos_memcpy(d, s+1, len);
    d[len] = 0;

    return d; 
}

%}

OCT         ([0-7])
OCT3        ({OCT}{3})
DIGIT       ([0-9])
NZERO       ([1-9])
LETTER      ([a-zA-Z_])
HEX         ([0-9a-fA-F])
HEX2        ({HEX}{2})

 /* 标识符 */
IDENTIFY    ({LETTER}({LETTER}|{DIGIT})*)

 /* signed suffix */
ISFX        ("l"|"L"|"ll"|"LL")

 /* unsigned suffix */
USFX        ([uU]|[uU]?{ISFX}|{ISFX}[uU])

 /* float suffix */
FSFX        (f|F)

 /* float exponent */
EXP	        ([Ee][-+]?{DIGIT}+)

 /* ip */
IPSUBx      ({DIGIT})
IPSUBxx     ({NZERO}{DIGIT})
IPSUB1xx    ("1"{DIGIT}{DIGIT})
IPSUB25x    ("25"[0-5])
IPSUB2xx    ("2"[0-4]{DIGIT})
IPSUB       ({IPSUBx}|{IPSUBxx}|{IPSUB1xx}|{IPSUB25x}|{IPSUB2xx})

 /* date time */
YEAR        ({DIGIT}{4})

 /* 01 ~ 09 */
MONTH0      ("0"{NZERO})
 /* 10 ~ 12 */
MONTH1      ("1"[0-2])
MONTH       ({MONTH0}|{MONTH1})

 /* 01 ~ 09 */
DAY0        ("0"{NZERO})
 /* 10 ~ 29 */
DAYx        ([1-2]{DIGIT})
 /* 30 ~ 31 */
DAY3        ("3"[0-1])
DAY         ({DAY0}|{DAYx}|{DAY3})

 /* 01 ~ 19 */
HOURx       ([0-1]{DIGIT})
 /* 20 ~ 23 */
HOUR2       ("2"[0-3])
HOUR        ({HOURx}|{HOUR2})

 /* 00 ~ 59 */
MINUTE      ([0-5]{DIGIT})
SECOND      ([0-5]{DIGIT})

DATE        ({YEAR}"-"{MONTH}"-"{DAY})
TIME        ({HOUR}":"{MINUTE}":"{SECOND})


%%
 /* rule proto */
"ip"        { yylval.proto = MTX_PROTO(ip); return PROTO; }
"ipv6"      { yylval.proto = MTX_PROTO(ipv6); return PROTO; }
"udp"       { yylval.proto = MTX_PROTO(udp); return PROTO; }
"tcp"       { yylval.proto = MTX_PROTO(tcp); return PROTO; }
"tcpstream" { yylval.proto = MTX_PROTO(tcpstream); return PROTO; }
"dns"       { yylval.proto = MTX_PROTO(dns); return PROTO; }
"http"      { yylval.proto = MTX_PROTO(http); return PROTO; }
"smtp"      { yylval.proto = MTX_PROTO(smtp); return PROTO; }
"pop3"      { yylval.proto = MTX_PROTO(pop3); return PROTO; }

 /* rule match */
"packet"    { yylval.match = MTX_MATCH(packet); return MATCH; }
"stream"    { yylval.match = MTX_MATCH(stream); return MATCH; }

"("     { yylval.op = MTX_OP(LP); return LP; }
")"     { yylval.op = MTX_OP(RP); return RP; }
"::"    { yylval.op = MTX_OP(NS); return NS; }
"~"     { yylval.op = MTX_OP(BNOT); return BNOT; }
"+"     { yylval.op = MTX_OP(ADD); return ADD; }
"-"     { yylval.op = MTX_OP(SUB); return SUB; }
"*"     { yylval.op = MTX_OP(MUL); return MUL; }
"/"     { yylval.op = MTX_OP(DIV); return DIV; }
"%"     { yylval.op = MTX_OP(MOD); return MOD; }
"^"     { yylval.op = MTX_OP(BXOR); return BXOR; }
"<<"    { yylval.op = MTX_OP(LSH); return BSHIFT; }
">>"    { yylval.op = MTX_OP(RSH); return BSHIFT; }
"|"     { yylval.op = MTX_OP(BOR); return BLOGIC; }
"&"     { yylval.op = MTX_OP(BAND); return BLOGIC; }
","     { yylval.op = MTX_OP(COMMA); return COMMA; }
"["     { yylval.op = MTX_OP(LBRA);  return LBRA; }
"]"     { yylval.op = MTX_OP(RBRA); return RBRA; }
"*="    { yylval.op = MTX_OP(STREQI); return STR; }
"^="    { yylval.op = MTX_OP(STRREQ); return STR; }
"*^"    { yylval.op = MTX_OP(STRINCI); return STR; }
"!^"    { yylval.op = MTX_OP(STRINCN); return STR; }
"!~"    { yylval.op = MTX_OP(PCREN); return PCRE; }
"*~"    { yylval.op = MTX_OP(PCREI); return PCRE; }
"=="    { yylval.op = MTX_OP(EQ); return EQ; }
"!="    { yylval.op = MTX_OP(NEQ); return NEQ; }
">"     { yylval.op = MTX_OP(GT); return CMP; }
">="    { yylval.op = MTX_OP(GE); return CMP; }
"<"     { yylval.op = MTX_OP(LT); return CMP; }
"<="    { yylval.op = MTX_OP(LE); return CMP; }
";"     { yylval.op = MTX_OP(SEM); return SEM; }
"&&"    { yylval.op = MTX_OP(AND); return AND; }
"||"    { yylval.op = MTX_OP(OR); return OR; }
"!"     { yylval.op = MTX_OP(NOT); return NOT; }
"=>"    { yylval.op = MTX_OP(NEXT); return NEXT; }

 /* proto var [len] */
"pkt.raw.len"       { yylval.pvid = MTX_PVLID(pkt, raw); return PVL; }
"pkt.padding.len"   { yylval.pvid = MTX_PVLID(pkt, padding); return PVL; }

"eth.smac.len"      { yylval.pvid = MTX_PVLID(eth, smac); return PVL; }
"eth.dmac.len"      { yylval.pvid = MTX_PVLID(eth, dmac); return PVL; }

"ip.hdr.len"        { yylval.pvid = MTX_PVLID(ip, hdr); return PVL; }
"ip.payload.len"    { yylval.pvid = MTX_PVLID(ip, payload); return PVL; }
"ip.src"            { yylval.pvid = MTX_PVLID(ip, src); return PVL_IP; }
"ip.dst"            { yylval.pvid = MTX_PVLID(ip, dst); return PVL_IP; }
"ip.proto"          { yylval.pvid = MTX_PVLID(ip, proto); return PVL; }
"ip.version"        { yylval.pvid = MTX_PVLID(ip, version); return PVL; }
"ip.len"            { yylval.pvid = MTX_PVLID(ip, len); return PVL; }

"udp.payload.len"   { yylval.pvid = MTX_PVLID(udp, payload); return PVL; }
"udp.sport"         { yylval.pvid = MTX_PVLID(udp, sport); return PVL; }
"udp.dport"         { yylval.pvid = MTX_PVLID(udp, dport); return PVL; }

"tcp.stream0.len"   { yylval.pvid = MTX_PVLID(tcp, stream0); return PVL; }
"tcp.stream1.len"   { yylval.pvid = MTX_PVLID(tcp, stream1); return PVL; }
"tcp.streamf.len"   { yylval.pvid = MTX_PVLID(tcp, streamf); return PVL; }
"tcp.payload.len"   { yylval.pvid = MTX_PVLID(tcp, payload); return PVL; }
"tcp.sport"         { yylval.pvid = MTX_PVLID(tcp, sport); return PVL; }
"tcp.dport"         { yylval.pvid = MTX_PVLID(tcp, dport); return PVL; }
"tcp.flags"         { yylval.pvid = MTX_PVLID(tcp, flags); return PVL; }
"tcp.flags.syn"     { yylval.pvid = MTX_PVLID(tcp, syn); return PVL; }
"tcp.flags.ack"     { yylval.pvid = MTX_PVLID(tcp, ack); return PVL; }
"tcp.flags.reset"   { yylval.pvid = MTX_PVLID(tcp, reset); return PVL; }
"tcp.flags.fin"     { yylval.pvid = MTX_PVLID(tcp, fin); return PVL; }
"tcp.flags.push"    { yylval.pvid = MTX_PVLID(tcp, push); return PVL; }
"tcp.flags.urg"     { yylval.pvid = MTX_PVLID(tcp, urg); return PVL; }
"tcp.seq"           { yylval.pvid = MTX_PVLID(tcp, seq); return PVL; }
"tcp.nxtseq"        { yylval.pvid = MTX_PVLID(tcp, nxtseq); return PVL; }
"tcp.window_size"   { yylval.pvid = MTX_PVLID(tcp, win); return PVL; }

"dns.flags"         { yylval.pvid = MTX_PVLID(dns, flags); return PVL; }
"dns.flags.z"       { yylval.pvid = MTX_PVLID(dns, zflags); return PVL; }
"dns.qry.type"      { yylval.pvid = MTX_PVLID(dns, qrytype); return PVL; }
"dns.qry.class"     { yylval.pvid = MTX_PVLID(dns, qryclass); return PVL; }
"dns.ip.count"      { yylval.pvid = MTX_PVLID(dns, ipcount); return PVL; }
"dns.ip.len"        { yylval.pvid = MTX_PVLID(dns, ip); return PVL; }
"dns.qry.name.len"  { yylval.pvid = MTX_PVLID(dns, qryname); return PVL; }
"dns.resp.name.len" { yylval.pvid = MTX_PVLID(dns, respname); return PVL; }

"http.method"       { yylval.pvid = MTX_PVLID(http, method); return PVL; }
"http.length"       { yylval.pvid = MTX_PVLID(http, length); return PVL; }
"http.url.len"      { yylval.pvid = MTX_PVLID(http, url); return PVL; }
"http.uri.len"      { yylval.pvid = MTX_PVLID(http, uri); return PVL; }
"http.host.len"     { yylval.pvid = MTX_PVLID(http, host); return PVL; }
"http.hosturi.len"  { yylval.pvid = MTX_PVLID(http, hosturi); return PVL; }
"http.referer.len"  { yylval.pvid = MTX_PVLID(http, referer); return PVL; }
"http.user_agent.len"   { yylval.pvid = MTX_PVLID(http, user_agent); return PVL; }
"http.cookie.len"   { yylval.pvid = MTX_PVLID(http, cookie); return PVL; }
"http.location.len" { yylval.pvid = MTX_PVLID(http, location); return PVL; }
"http.proxy_authenticate.len"   { yylval.pvid = MTX_PVLID(http, proxy_authenticate); return PVL; }
"http.msghead0.len" { yylval.pvid = MTX_PVLID(http, msghead0); return PVL; }
"http.msghead1.len" { yylval.pvid = MTX_PVLID(http, msghead1); return PVL; }
"http.msgbody0.len" { yylval.pvid = MTX_PVLID(http, msgbody0); return PVL; }
"http.msgbody1.len" { yylval.pvid = MTX_PVLID(http, msgbody1); return PVL; }
"http.retcode.len"  { yylval.pvid = MTX_PVLID(http, retcode); return PVL; }

"smtp.from.len"     { yylval.pvid = MTX_PVLID(smtp, from); return PVL; }
"smtp.to.len"       { yylval.pvid = MTX_PVLID(smtp, to); return PVL; }
"smtp.cc.len"       { yylval.pvid = MTX_PVLID(smtp, cc); return PVL; }
"smtp.date.len"     { yylval.pvid = MTX_PVLID(smtp, date); return PVL; }
"smtp.subject.len"  { yylval.pvid = MTX_PVLID(smtp, subject); return PVL; }
"smtp.msgbody.len"  { yylval.pvid = MTX_PVLID(smtp, msgbody); return PVL; }

"pop3.from.len"     { yylval.pvid = MTX_PVLID(pop3, from); return PVL; }
"pop3.to.len"       { yylval.pvid = MTX_PVLID(pop3, to); return PVL; }
"pop3.cc.len"       { yylval.pvid = MTX_PVLID(pop3, cc); return PVL; }
"pop3.date.len"     { yylval.pvid = MTX_PVLID(pop3, date); return PVL; }
"pop3.subject.len"  { yylval.pvid = MTX_PVLID(pop3, subject); return PVL; }
"pop3.msgbody.len"  { yylval.pvid = MTX_PVLID(pop3, msgbody); return PVL; }

 /* proto var [bin] */
"pkt.raw"           { yylval.pvid = MTX_PVBID(pkt, raw); return PVB; }
"pkt.padding"       { yylval.pvid = MTX_PVBID(pkt, padding); return PVB; }

"eth.smac"          { yylval.pvid = MTX_PVBID(eth, smac); return PVB; }
"eth.dmac"          { yylval.pvid = MTX_PVBID(eth, dmac); return PVB; }

"ip.hdr"            { yylval.pvid = MTX_PVBID(ip, hdr); return PVB; }
"ip.payload"        { yylval.pvid = MTX_PVBID(ip, payload); return PVB; }

"udp.payload"       { yylval.pvid = MTX_PVBID(udp, payload); return PVB; }

"tcp.stream0"       { yylval.pvid = MTX_PVBID(tcp, stream0); return PVB; }
"tcp.stream1"       { yylval.pvid = MTX_PVBID(tcp, stream1); return PVB; }
"tcp.streamf"       { yylval.pvid = MTX_PVBID(tcp, streamf); return PVB; }
"tcp.payload"       { yylval.pvid = MTX_PVBID(tcp, payload); return PVB; }

"dns.ip"            { yylval.pvid = MTX_PVBID(dns, ip); return PVB; }
"dns.qry.name"      { yylval.pvid = MTX_PVBID(dns, qryname); return PVB; }
"dns.resp.name"     { yylval.pvid = MTX_PVBID(dns, respname); return PVB; }

"http.url"          { yylval.pvid = MTX_PVBID(http, url); return PVB; }
"http.uri"          { yylval.pvid = MTX_PVBID(http, uri); return PVB; }
"http.host"         { yylval.pvid = MTX_PVBID(http, host); return PVB; }
"http.hosturi"      { yylval.pvid = MTX_PVBID(http, hosturi); return PVB; }
"http.referer"      { yylval.pvid = MTX_PVBID(http, referer); return PVB; }
"http.user_agent"   { yylval.pvid = MTX_PVBID(http, user_agent); return PVB; }
"http.cookie"       { yylval.pvid = MTX_PVBID(http, cookie); return PVB; }
"http.location"     { yylval.pvid = MTX_PVBID(http, location); return PVB; }
"http.proxy_authenticate"    { yylval.pvid = MTX_PVBID(http, proxy_authenticate); return PVB; }
"http.msghead0"     { yylval.pvid = MTX_PVBID(http, msghead0); return PVB; }
"http.msghead1"     { yylval.pvid = MTX_PVBID(http, msghead1); return PVB; }
"http.msgbody0"     { yylval.pvid = MTX_PVBID(http, msgbody0); return PVB; }
"http.msgbody1"     { yylval.pvid = MTX_PVBID(http, msgbody1); return PVB; }
"http.retcode"      { yylval.pvid = MTX_PVBID(http, retcode); return PVB; }

"smtp.from"         { yylval.pvid = MTX_PVBID(smtp, from); return PVB; }
"smtp.to"           { yylval.pvid = MTX_PVBID(smtp, to); return PVB; }
"smtp.cc"           { yylval.pvid = MTX_PVBID(smtp, cc); return PVB; }
"smtp.date"         { yylval.pvid = MTX_PVBID(smtp, date); return PVB; }
"smtp.subject"      { yylval.pvid = MTX_PVBID(smtp, subject); return PVB; }
"smtp.msgbody"      { yylval.pvid = MTX_PVBID(smtp, msgbody); return PVB; }

"pop3.from"         { yylval.pvid = MTX_PVBID(pop3, from); return PVB; }
"pop3.to"           { yylval.pvid = MTX_PVBID(pop3, to); return PVB; }
"pop3.cc"           { yylval.pvid = MTX_PVBID(pop3, cc); return PVB; }
"pop3.date"         { yylval.pvid = MTX_PVBID(pop3, date); return PVB; }
"pop3.subject"      { yylval.pvid = MTX_PVBID(pop3, subject); return PVB; }
"pop3.msgbody"      { yylval.pvid = MTX_PVBID(pop3, msgbody); return PVB; }

 /* auto var [len] */
"imsi.len"          { yylval.pvid = MTX_PVLID(mobile, imsi); return PVL; }
"msisdn.len"        { yylval.pvid = MTX_PVLID(mobile, msisdn); return PVL; }
"meid.len"          { yylval.pvid = MTX_PVLID(mobile, meid); return PVL; }
"apn.len"           { yylval.pvid = MTX_PVLID(mobile, apn); return PVL; }
"user_loc.len"      { yylval.pvid = MTX_PVLID(mobile, user_loc); return PVL; }

 /* auto var [bin] */
"imsi"              { yylval.pvid = MTX_PVBID(mobile, imsi); return PVB; }
"msisdn"            { yylval.pvid = MTX_PVBID(mobile, msisdn); return PVB; }
"meid"              { yylval.pvid = MTX_PVBID(mobile, meid); return PVB; }
"apn"               { yylval.pvid = MTX_PVBID(mobile, apn); return PVB; }
"user_loc"          { yylval.pvid = MTX_PVBID(mobile, user_loc); return PVB; }

 /* auto var [len] */
"$inc.len"  { yylval.pvid = MTX_PVLID(auto, inc); return PVL; }
"$re1.len"  { yylval.pvid = MTX_PVLID(auto, re1); return PVL; }
"$re2.len"  { yylval.pvid = MTX_PVLID(auto, re2); return PVL; }
"$re3.len"  { yylval.pvid = MTX_PVLID(auto, re3); return PVL; }
"$re4.len"  { yylval.pvid = MTX_PVLID(auto, re4); return PVL; }
"$re5.len"  { yylval.pvid = MTX_PVLID(auto, re5); return PVL; }
"$re6.len"  { yylval.pvid = MTX_PVLID(auto, re6); return PVL; }
"$re7.len"  { yylval.pvid = MTX_PVLID(auto, re7); return PVL; }
"$re8.len"  { yylval.pvid = MTX_PVLID(auto, re8); return PVL; }
"$re9.len"  { yylval.pvid = MTX_PVLID(auto, re9); return PVL; }

 /* auto var [bin] */
"$inc"      { yylval.pvid = MTX_PVBID(auto, inc); return PVB; }
"$re1"      { yylval.pvid = MTX_PVBID(auto, re1); return PVB; }
"$re2"      { yylval.pvid = MTX_PVBID(auto, re2); return PVB; }
"$re3"      { yylval.pvid = MTX_PVBID(auto, re3); return PVB; }
"$re4"      { yylval.pvid = MTX_PVBID(auto, re4); return PVB; }
"$re5"      { yylval.pvid = MTX_PVBID(auto, re5); return PVB; }
"$re6"      { yylval.pvid = MTX_PVBID(auto, re6); return PVB; }
"$re7"      { yylval.pvid = MTX_PVBID(auto, re7); return PVB; }
"$re8"      { yylval.pvid = MTX_PVBID(auto, re8); return PVB; }
"$re9"      { yylval.pvid = MTX_PVBID(auto, re9); return PVB; }
"$m1"       { yylval.pvid = MTX_PVBID(auto, m1); return PVB; }
"$m2"       { yylval.pvid = MTX_PVBID(auto, m2); return PVB; }
"$m3"       { yylval.pvid = MTX_PVBID(auto, m3); return PVB; }

 /* function */
"byteget"   { yylval.fn = MTX_FN(byteget); return FUNC_INT_BY_STRING_INT; } // INT byteget(BINSTR data, INT offset)
"wordget"   { yylval.fn = MTX_FN(wordget); return FUNC_INT_BY_STRING_INT; } // INT wordget(BINSTR data, INT offset)
"wordget2"  { yylval.fn = MTX_FN(wordget2); return FUNC_INT_BY_STRING_INT; } // INT wordget2(BINSTR data, INT offset)
"dwordget"  { yylval.fn = MTX_FN(dwordget); return FUNC_INT_BY_STRING_INT; } // INT dwordget(BINSTR data, INT offset)
"dwordget2" { yylval.fn = MTX_FN(dwordget2); return FUNC_INT_BY_STRING_INT; } // INT dwordget2(BINSTR data, INT offset)
"time"      { yylval.fn = MTX_FN(time); return FUNC_TIME_time; } // TIME time()
"hex"       { yylval.fn = MTX_FN(hex); return FUNC_STRING_BY_STRING; } // BINSTR hex(BINSTR)
"lower"     { yylval.fn = MTX_FN(lower); return FUNC_STRING_BY_STRING; } // BINSTR lower(BINSTR)
"upper"     { yylval.fn = MTX_FN(upper); return FUNC_STRING_BY_STRING; } // BINSTR upper(BINSTR)
"charadd"   { yylval.fn = MTX_FN(charadd); return FUNC_STRING_BY_STRING_INT; } // BINSTR charadd(BINSTR, INT)
"charsub"   { yylval.fn = MTX_FN(charsub); return FUNC_STRING_BY_STRING_INT; } // BINSTR charsub(BINSTR, INT)
"charxor"   { yylval.fn = MTX_FN(charxor); return FUNC_STRING_BY_STRING_INT; } // BINSTR charxor(BINSTR, INT)
"substr"    { yylval.fn = MTX_FN(substr); return FUNC_STRING_substr; } // BINSTR substr(BINSTR, INT from , [INT to])
"length"    { yylval.fn = MTX_FN(length); return FUNC_INT_length; } // INT length(BINSTR)
"udec"      { yylval.fn = MTX_FN(udec); return FUNC_STRING_BY_STRING; } // BINSTR udec(BINSTR)
"ntohs"     { yylval.fn = MTX_FN(ntohs); return FUNC_INT_ntohs; } // INT ntohs(INT)
"ntohl"     { yylval.fn = MTX_FN(ntohl); return FUNC_INT_ntohl; } // INT ntohl(INT)
"toip"      { yylval.fn = MTX_FN(toip); return FUNC_IP_toip; } // IP toip(INT)
"toint"     { yylval.fn = MTX_FN(toint); return FUNC_IP_toint; } // IP toint(IP)
"totime"    { yylval.fn = MTX_FN(totime); return FUNC_TIME_totime; } // TIME totime(INT | BINSTR), here BINSTR as TIME
"string"    { yylval.fn = MTX_FN(string); return FUNC_STRING_string; } // BINSTR string(VARIANT, ...)
"networka"  { yylval.fn = MTX_FN(networka); return FUNC_IP_BY_IP; } // IP networka(IP)
"networkb"  { yylval.fn = MTX_FN(networkb); return FUNC_IP_BY_IP; } // IP networkb(IP)
"networkc"  { yylval.fn = MTX_FN(networkc); return FUNC_IP_BY_IP; } // IP networkc(IP)
"network"   { yylval.fn = MTX_FN(network); return FUNC_IP_network; } // IP network(IP IP, INT mask)
"sequence"  { yylval.fn = MTX_FN(sequence); return FUNC_SET_sequence; } // SET sequence(BINSTR tok1, ...)
"stoken"    { yylval.fn = MTX_FN(stoken); return FUNC_SET_stoken; } // SET stoken(INT mask, BINSTR cmd, BINSTR tok1, ...)
"sarray"    { yylval.fn = MTX_FN(sarray); return FUNC_SET_sarray; } // SET sarray(BINSTR, BINSTR, BINSTR, ...)
"iparray"   { yylval.fn = MTX_FN(iparray); return FUNC_SET_iparray; } // SET iparray(IP, IP, IP, ...)
"narray"    { yylval.fn = MTX_FN(narray); return FUNC_SET_narray; } // SET narray(INT, INT, INT, ...)
"base64d"   { yylval.fn = MTX_FN(base64d); return FUNC_STRING_BY_STRING; } // BINSTR base64d(BINSTR)
"base64e"   { yylval.fn = MTX_FN(base64e); return FUNC_STRING_BY_STRING; } // BINSTR base64e(BINSTR)
"zip"       { yylval.fn = MTX_FN(zip); return FUNC_STRING_BY_STRING; } // BINSTR zip(BINSTR)
"unzip"     { yylval.fn = MTX_FN(unzip); return FUNC_STRING_BY_STRING; } // BINSTR unzip(BINSTR)
"ungzip"    { yylval.fn = MTX_FN(ungzip); return FUNC_STRING_BY_STRING; } // BINSTR ungzip(BINSTR)
"undeflate" { yylval.fn = MTX_FN(undeflate); return FUNC_STRING_BY_STRING; } // BINSTR undeflate(BINSTR)
"charset"   { yylval.fn = MTX_FN(charset); return FUNC_STRING_charset; } // BINSTR charset(BINSTR, BINSTR srcdec, BINSTR dstdec)
"event"     { yylval.fn = MTX_FN(event); return FUNC_PROC_BY_VARIANTS; } // PROC event(VARIANT,...)
"eventr"    { yylval.fn = MTX_FN(eventr); return FUNC_PROC_BY_VARIANTS; } // PROC eventr(VARIANT, ...)
"nothing"   { yylval.fn = MTX_FN(nothing); return FUNC_PROC_nothing; } // PROC nothing()
"usocket"   { yylval.fn = MTX_FN(usocket); return FUNC_PROC_usocket; } // PROC usocket(IP ip, INT port)
"mtcpdump"  { yylval.fn = MTX_FN(mtcpdump); return FUNC_PROC_BY_STRING_INT3; } // PROC mtcpdump(BINSTR fmt, INT packets, INT bytes, INT seconds)
"record2k"  { yylval.fn = MTX_FN(record2k); return FUNC_PROC_BY_STRING_INT3; } // PROC record2k(BINSTR fmt, INT packets, INT bytes, INT seconds)
"record5k"  { yylval.fn = MTX_FN(record5k); return FUNC_PROC_BY_STRING_INT3; } // PROC record5k(BINSTR fmt, INT packets, INT bytes, INT seconds)
"border"    { yylval.fn = MTX_FN(border); return FUNC_STRING_BY_IP; } // BINSTR border(IP ip)
"country"   { yylval.fn = MTX_FN(country); return FUNC_STRING_BY_IP; } // BINSTR country (IP ip)
"province"  { yylval.fn = MTX_FN(province); return FUNC_STRING_BY_IP; } // BINSTR province (IP ip)
"isp"       { yylval.fn = MTX_FN(isp); return FUNC_STRING_BY_IP; } // BINSTR isp (IP ip)
"elimit"    { yylval.fn = MTX_FN(elimit); return FUNC_BOOL_elimit; } // BOOL elimit(INT limit, [INT delay])
"emax"      { yylval.fn = MTX_FN(emax); return FUNC_BOOL_emax; } // BOOL emax(INT max, INT interval)
"efreq"     { yylval.fn = MTX_FN(efreq); return FUNC_BOOL_efreq; } // BOOL efreq(FLOAT freq)
"key2"      { yylval.fn = MTX_FN(key2); return FUNC_STRING_BY_NONE; } // BINSTR key2()
"key3"      { yylval.fn = MTX_FN(key3); return FUNC_STRING_BY_NONE; } // BINSTR key3()
"key4"      { yylval.fn = MTX_FN(key4); return FUNC_STRING_BY_NONE; } // BINSTR key4()
"setmap"    { yylval.fn = MTX_FN(setmap);   return FUNC_PROC_setmap; } // PROC setmap(BINSTR key, BINSTR|INT|IP|MAC data1, data2, data3, INT elapse)
"querymap"  { yylval.fn = MTX_FN(querymap); return FUNC_BOOL_querymap; } // BOOL querymap(BINSTR key)

 /* stoken cmd */
"ST_CMD"    { yylval.macro = MTX_STOKEN_CMD; return STOKEN_MASK; }
"ST_ALL"    { yylval.macro = MTX_STOKEN_ALL; return STOKEN_MASK; }
"ST_NONE"   { yylval.macro = MTX_STOKEN_NONE; return STOKEN_MASK; }
"ST_SHUF"   { yylval.macro = MTX_STOKEN_SHUF; return STOKEN_MASK; }

 /* http method */
"HTTP_GET"  { yylval.macro = MTX_HTTP_GET;  return HTTP_METHOD; }
"HTTP_POST" { yylval.macro = MTX_HTTP_POST; return HTTP_METHOD; }
"HTTP_HEAD" { yylval.macro = MTX_HTTP_HEAD; return HTTP_METHOD; }
"HTTP_PUT"  { yylval.macro = MTX_HTTP_PUT;  return HTTP_METHOD; }

 /* int number */
{NZERO}{DIGIT}*{USFX}?      { yylval.i = (bos_i64)strtoll(yytext, NULL, 10); return INTEGER; }
0{OCT}*{USFX}?              { yylval.i = (bos_i64)strtoll(yytext, NULL,  8); return INTEGER; }
0[xX]{HEX}+{USFX}?          { yylval.i = (bos_i64)strtoll(yytext, NULL, 16); return INTEGER; }

 /* const char: 'A' */
\'([^\\'\n])\'              { yylval.i = yytext[1]; return CHAR; }
 /* const char: '\n' */
\'(\\.)\'   {
    switch(yytext[2]) {
        case 'r':
            yylval.i = '\r';
            break;
        case 'n':
            yylval.i = '\n';
            break;
        case 't':
            yylval.i = '\t';
            break;
        case 'v':
            yylval.i = '\v';
            break;
        case 'a':
            yylval.i = '\a';
            break;
        case 'b':
            yylval.i = '\b';
            break;
        case 'f':
            yylval.i = '\f';
            break;
        case '0':
            yylval.i = '\0';
            break;
        default:
            yylval.i = yytext[2];
            break;
    }

    return CHAR;
}

 /* const char: '\x0f' */
\'("\\x"{HEX2})\'           { yylval.i = bos_hex2byte(yytext+3); return CHAR; }

 /* const char: '\777' */
\'("\\"{OCT3})\'            { yylval.i = bos_oct2byte(yytext+2); return CHAR; }

 /* float number */
{DIGIT}+"."{DIGIT}*{EXP}?{FSFX}? |
"."?{DIGIT}+{EXP}?{FSFX}?   { yylval.f = atof(yytext); return FLOAT; }

 /* names */
{IDENTIFY}                  { yylval.s = dup_name(yytext); return NAME; }

 /* ip */
({IPSUB}"."){3}{IPSUB}      { yylval.ip = bos_ipaddr(yytext); return IPV4; }

 /* mac */
({HEX2}":"){5}{HEX2}        { yylval.mac = bos_getmac(yytext); return MAC; }

 /* time */
\"{DATE}" "{TIME}\"         {
    char *s = dup_const_string(yytext);

    yylval.tm = bos_fulltime(s); 

    return TIME; 
}

 /* hex string: "\x00\x01\x02" */
\"("\\x"{HEX2})+\"          {
    int len = strlen(yytext) - 2;
    int i, count = len/4;
    char *s = yytext + 1;
    bos_binstr bin = BOS_BINSTR_ALLOC(len);

    for (i=0; i<count; i++) {
        bin.obj[i] = bos_hex2byte(s + 4*i + 2);
    }

    yylval.bin = bin;

    return STRING; 
}

 /* string */
\"(\\.|[^\\"\n])*\"         {
    int len = strlen(yytext) - 2;
    char *s = yytext + 1;

    yylval.bin = dup_string(s, len);

    return STRING;
}

 /* unterminated string */
\"[^\"]*$ {
    yylval.s = yytext;

    yyerror("unterminated string");

    return HALF_STRING;
}

#.*                         /* ignore */
[ \t\r]                     /* ignore */
[\n]                        { return EOL; }

 /* <<EOF>>                     { return EOL; } */
.   { yyerror(""); }

%%
