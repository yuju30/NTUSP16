#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char* argv[]){
  int fd,sum,cr;
  fd=open(argv[1],O_RDONLY);
  char c;
  if(fd!=-1){
  	sum=0;
  	while(read(fd,&c,sizeof(char))){
  	  if(c=='a'||c=='e'||c=='i'||c=='o'||c=='u'||c=='A'||c=='E'||c=='I'||c=='O'||c=='U')
     	sum++;
  	}
    close(fd);	
    cr=open(argv[2],O_RDWR|O_CREAT,0644);
    char ans[100];
    sprintf(ans,"%d",sum);
    write(cr,&ans,sizeof(int)); 
    close(cr);
  }
    
}
