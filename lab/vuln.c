#include <stdio.h>
#include <string.h>
int main(){ char b[64]; char line[8192];
  if(!fgets(line,sizeof line,stdin)) return 0; line[strcspn(line,"\n")]=0;
  strcpy(b,line);            /* overflow if >63 */
  puts("ok"); return 0; }
