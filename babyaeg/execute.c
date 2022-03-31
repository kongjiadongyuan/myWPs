#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void explode_first(int (* firsttype)(char , char , char ), char *a, char *b, char *c){
  int i = 0;
  for(i = 0; i < 256; i ++){
    if(firsttype((char)i, 0, 0) != 1){
      *a = i;
      break;
    }
  }
  for(i = 0; i < 256; i ++){
    if(firsttype(*a, (char)i, 0) != 2){
      *b = i;
      break;
    }
  }
  for(i = 0; i < 256; i ++){
    if(firsttype(*a, *b, i) != 3){
      *c = i;
      break;
    }
  }
}

void explode_second(int (* secondtype)(int), int *a){
  int i = 0;
  int res;
  for(i = 0; i < 256; i ++){
    res = secondtype(i);
    if(res != 1){
      *a = i;
      break;
    }
  }
}

void first(){
  void *funcspace = malloc(0x500);
  char a, b, c;
  int (* firsttype)(char a, char b, char c);
  firsttype = (int (*)(char, char, char))funcspace;
  read(0, firsttype, 0x400);
  explode_first(firsttype, &a, &b, &c);
  write(1, &a, 1);
  write(1, &b, 1);
  write(1, &c, 1);
}

void second(){
  void *funcspace = malloc(0x500);
  int a;
  char c;
  int (* secondtype)(int);
  secondtype = (int (*)(int)) funcspace;
  read(0, secondtype, 0x400);
  explode_second(secondtype, &a);
  c = a;
  write(1, &c, 1);
}

int main(){
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stderr, 0, 2, 0);
  char choice;
  while(1){
    read(0, &choice, 1);
    switch(choice){
      case 1:
        first();
        break;
      case 2:
        second();
        break;
      case 10:
        return 1;
    }
  }
}


