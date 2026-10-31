/* Bounded optional FortiGate lexer. Keep the original line for stable IDs.
 * Match ([A-Za-z0-9_]+)=("(?:[^"\\]|\\.)*"|[^ \r\n]+). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif
#define MAX_KEYS 256
#define HASH_SIZE 1024
typedef struct { const unsigned char *p; size_t n; } Slice;
static unsigned char input[1024*1024];
static size_t input_pos=0,input_size=0;
static unsigned long long input_remaining=ULLONG_MAX;
static unsigned char output[1024*1024];
static size_t output_size=0;
static int output_error=0;
static unsigned long long output_total=0;
static void flush_output(void){if(output_size&&fwrite(output,1,output_size,stdout)!=output_size)output_error=1;output_size=0;}
static void emit(const unsigned char *p,size_t n){
    output_total+=n;
    while(n){size_t room=sizeof(output)-output_size,take=n<room?n:room;memcpy(output+output_size,p,take);output_size+=take;p+=take;n-=take;if(output_size==sizeof(output))flush_output();}
}
static void emitbyte(unsigned char c){output_total++;output[output_size++]=c;if(output_size==sizeof(output))flush_output();}
static int record(unsigned char *line,size_t *length,size_t maximum) {
    *length=0;
    for(;;){
        if(input_pos==input_size){size_t take=input_remaining<sizeof(input)?(size_t)input_remaining:sizeof(input);if(!take)return *length?1:0;input_size=fread(input,1,take,stdin);input_remaining-=input_size;input_pos=0;if(!input_size)return ferror(stdin)?-2:(*length?1:0);}
        size_t available=input_size-input_pos;
        unsigned char *end=memchr(input+input_pos,'\n',available);
        size_t take=end?(size_t)(end-(input+input_pos))+1:available;
        if(take>maximum-*length)return -1;
        memcpy(line+*length,input+input_pos,take);*length+=take;input_pos+=take;
        if(end)return 1;
    }
}
static int word(unsigned char c) { return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'; }
static unsigned hash(const unsigned char *p,size_t n) { unsigned h=2166136261u; while(n--) h=(h^*p++)*16777619u; return h; }
static int utf8(const unsigned char *s,size_t n) {
    size_t i=0; while(i<n) {
        if(n-i>=8){uint64_t block;memcpy(&block,s+i,8);if(!(block&UINT64_C(0x8080808080808080))){i+=8;continue;}}
        unsigned c=s[i++],cp,min;int more;if(c<128)continue;
        if(c>=0xc2&&c<=0xdf){more=1;cp=c&31;min=128;}
        else if(c>=0xe0&&c<=0xef){more=2;cp=c&15;min=2048;}
        else if(c>=0xf0&&c<=0xf4){more=3;cp=c&7;min=65536;}else return 0;
        if(i+more>n)return 0;
        while(more--){c=s[i++];if((c&192)!=128)return 0;cp=(cp<<6)|(c&63);}
        if(cp<min||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))return 0;
    }return 1;
}
static void csv(Slice s) {
    size_t start=0;emitbyte('"');
    while(start<s.n){const unsigned char *quote=memchr(s.p+start,'"',s.n-start);if(!quote)break;size_t end=(size_t)(quote-s.p)+1;emit(s.p+start,end-start);emitbyte('"');start=end;}
    if(s.n>start)emit(s.p+start,s.n-start);emitbyte('"');
}
static void json_string(Slice s){
    const char hex[]="0123456789abcdef";size_t start=0,i;emitbyte('"');
    for(i=0;i<s.n;i++){
        unsigned char c=s.p[i];
        if(c=='"'||c=='\\'||c<32){
            if(i>start)emit(s.p+start,i-start);
            emitbyte('\\');
            if(c=='"'||c=='\\')emitbyte(c);
            else{emitbyte('u');emitbyte('0');emitbyte('0');emitbyte(hex[c>>4]);emitbyte(hex[c&15]);}
            start=i+1;
        }
    }
    if(s.n>start)emit(s.p+start,s.n-start);emitbyte('"');
}
int main(int argc,char **argv) {
    char *names[MAX_KEYS],*part;int count=0,j,first=1,json_mode=0;size_t maximum,n=0;unsigned long long max_csv_line=0;
    unsigned char *line;Slice values[MAX_KEYS],seen[HASH_SIZE];int requested[HASH_SIZE]={0};size_t lengths[MAX_KEYS];
    if(argc<3||argc>5)return 64;if(argc>=4)input_remaining=strtoull(argv[3],NULL,10);
    if(argc==5)json_mode=!strcmp(argv[4],"json");
    maximum=(size_t)strtoull(argv[2],NULL,10);if(maximum<1)return 64;
    line=malloc(maximum+2);if(!line)return 70;
    for(part=strtok(argv[1],",");part;part=strtok(NULL,",")){if(count==MAX_KEYS)return 64;names[count++]=part;}
    for(j=0;j<count;j++){lengths[j]=strlen(names[j]);unsigned slot=hash((unsigned char*)names[j],lengths[j])&(HASH_SIZE-1);while(requested[slot])slot=(slot+1)&(HASH_SIZE-1);requested[slot]=j+1;}
#ifdef _WIN32
    _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
    setvbuf(stdin,NULL,_IOFBF,1024*1024);setvbuf(stdout,NULL,_IOFBF,1024*1024);
    for(;;){
        int status=record(line,&n,maximum);if(status==0)break;
        if(status==-2)return 74;
        if(status<0){fputs("CSV Error: record exceeds maximum_object_size",stderr);return 2;}
        if(first&&n>=3&&line[0]==0xef&&line[1]==0xbb&&line[2]==0xbf){memmove(line,line+3,n-3);n-=3;}first=0;
        if(!utf8(line,n)){fputs("Invalid unicode",stderr);return 2;}
        if(memchr(line,31,n)){fputs("Unsupported raw delimiter; use SQL reader",stderr);return 65;}
        memset(values,0,sizeof(values));memset(seen,0,sizeof(seen));
        size_t i=0;
        while(i<n){
            if(!word(line[i])){i++;continue;}
            size_t k=i;while(i<n&&word(line[i]))i++;
            size_t kn=i-k;if(i>=n||line[i]!='=')continue;i++;
            size_t v=i,end=i;if(i>=n||line[i]==' '||line[i]=='\r'||line[i]=='\n')continue;
            if(line[i]=='"'){
                size_t q=i+1;int closed=0;
                while(q<n){if(line[q]=='\\'){if(q+1<n){q+=2;continue;}break;}if(line[q++]=='"'){closed=1;break;}}
                if(closed)end=q;
            }
            if(end==v){end=v;while(end<n&&line[end]!=' '&&line[end]!='\r'&&line[end]!='\n')end++;}
            i=end;unsigned slot=hash(line+k,kn)&(HASH_SIZE-1),probes=0;
            while(seen[slot].p){
                if(seen[slot].n==kn&&!memcmp(seen[slot].p,line+k,kn)){fputs("Map keys must be unique",stderr);return 2;}
                slot=(slot+1)&(HASH_SIZE-1);if(++probes==HASH_SIZE){fputs("Unsupported field count; use SQL reader",stderr);return 65;}
            }
            seen[slot]=(Slice){line+k,kn};
            while(v<end&&line[v]=='"')v++;while(end>v&&line[end-1]=='"')end--;
            slot=hash(line+k,kn)&(HASH_SIZE-1);
            while(requested[slot]){j=requested[slot]-1;if(lengths[j]==kn&&!memcmp(names[j],line+k,kn)){values[j]=(Slice){line+v,end-v};break;}slot=(slot+1)&(HASH_SIZE-1);}
        }
        size_t ln=n;while(ln&&(line[ln-1]=='\r'||line[ln-1]=='\n'))ln--;
        unsigned long long row_start=output_total;
        if(json_mode){
            emit((const unsigned char*)"{\"line\":",8);json_string((Slice){line,ln});
            emit((const unsigned char*)",\"kv\":{",7);int comma=0;
            for(j=0;j<count;j++)if(values[j].p){
                if(comma)emitbyte(',');comma=1;
                json_string((Slice){(const unsigned char*)names[j],lengths[j]});emitbyte(':');json_string(values[j]);
            }
            emitbyte('}');emitbyte('}');
        }else{
            csv((Slice){line,ln});for(j=0;j<count;j++){emitbyte(',');if(values[j].p)csv(values[j]);}
        }
        emitbyte('\n');if(output_total-row_start>max_csv_line)max_csv_line=output_total-row_start;
        n=0;
    }
    free(line);flush_output();fprintf(stderr,"max_csv_line_bytes=%llu",max_csv_line);
    return !output_error&&fflush(stdout)==0?0:74;
}
