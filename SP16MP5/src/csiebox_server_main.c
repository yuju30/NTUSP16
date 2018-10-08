#include "csiebox_server.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/select.h>
#include <fts.h>
#include <dirent.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>

//where the server starts
int main(int argc, char** argv) {
  csiebox_server* box = 0;

   pid_t pcs_id = 0;
   pid_t sid = 0;
   pcs_id = fork();
  if(pcs_id < 0){
    fprintf(stderr, "fork failed\n");
    exit(1); 
  }
  if(pcs_id > 0){
    exit(0);
  }
  umask(0);
  sid = setsid();
  if(sid<0){ 
    exit(1);
  }
  if(chdir("/tmp")<0){
  	fprintf(stderr, "can't switch to temp memory");
  }
  int fd0=open("/dev/null",O_RDWR);
  int fd1=dup(0);
  int fd2=dup(0);
 
  csiebox_server_init(&box, argc, argv);
  if (box) {
    csiebox_server_run(box);
  }
  csiebox_server_destroy(&box);
  return 0;
}
