#include "csiebox_client.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <sys/inotify.h>

#include <sys/inotify.h> //header for inotify
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <fcntl.h>

#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))

static int parse_arg(csiebox_client* client, int argc, char** argv);
static int login(csiebox_client* client);
#define PATH_MAX 4096
int MAX(int a,int b){ return (a >= b? a:b); }

void sync_meta(char *curname,char *sercurname,csiebox_client* client);
int ino_fd;
typedef struct hash{
  int md;
  char cpath[PATH_MAX];
}Hash;
Hash map[105];
int hash_cou=0;
typedef struct inonum{
  ino_t inum;
  char linpath[PATH_MAX];
}Inonum;
Inonum snum_path[105];
int snum_path_cou=0;

ino_t sameinum[105];
int same_cou=0;
int nullcou=0;

//read config file, and connect to server
void csiebox_client_init(
  csiebox_client** client, int argc, char** argv) {
  csiebox_client* tmp = (csiebox_client*)malloc(sizeof(csiebox_client));
  if (!tmp) {
    fprintf(stderr, "client malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_client));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = client_start(tmp->arg.name, tmp->arg.server);
  if (fd < 0) {
    fprintf(stderr, "connect fail\n");
    free(tmp);
    return;
  }
  tmp->conn_fd = fd;
  *client = tmp;
}

void inotify_test(int fd,csiebox_client* client){
  int length, i = 0;
  char buffer[EVENT_BUF_LEN];
  memset(buffer, 0, EVENT_BUF_LEN);


  while ((length = read(fd, buffer, EVENT_BUF_LEN)) > 0) {
    i = 0;
    while (i < length) {
      struct inotify_event* event = (struct inotify_event*)&buffer[i];
      printf("event: (%d, %d, %s)\ntype: ", event->wd, strlen(event->name), event->name);
         //get_from_hash(childpath,event->wd)
         char childpath[PATH_MAX];
         memset(childpath,0,sizeof(childpath));
         for (int k = 0; k < hash_cou; ++k){
           if(map[k].md==event->wd){
            memcpy(childpath,map[k].cpath,sizeof(map[k].cpath));
            break;
            }
          } 
         // construct path 
         char curname[PATH_MAX];
         memset(curname,0,sizeof(curname));
         sprintf(curname,"%s%s/%s",client->arg.path,childpath,event->name);
         char sercurname[PATH_MAX];
         memset(sercurname,0,sizeof(sercurname));
         sprintf(sercurname,"../sdir/%s%s/%s",client->arg.user,childpath,event->name);

      if ((event->mask & IN_CREATE)||(event->mask & IN_ATTRIB)||(event->mask & IN_MODIFY)){
         sync_meta(curname,sercurname,client);
         if((event->mask & IN_CREATE)&&(event->mask & IN_ISDIR)){
            int crewd = inotify_add_watch(ino_fd,curname, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
            map[hash_cou].md=crewd;
            char addpath[PATH_MAX];
            memset(addpath,0,sizeof(addpath));
            sprintf(addpath,"%s/%s",childpath,event->name);
            memcpy(map[hash_cou].cpath,addpath,strlen(addpath));
            hash_cou++;
         }//create 
      }
      if (event->mask & IN_DELETE) {
        csiebox_protocol_rm RM;
        memset(&RM,0,sizeof(csiebox_protocol_rm));
        RM.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
        RM.message.header.req.op = CSIEBOX_PROTOCOL_OP_RM;
        RM.message.header.req.datalen =sizeof(RM)-sizeof(RM.message.header);
        RM.message.body.pathlen = strlen(sercurname);    
        fprintf(stderr, "start to send Delete meta\n");
        if(!send_message(client->conn_fd,&RM,sizeof(RM))){
          fprintf(stderr, "send Delete REQ fail\n");
          return;
        }
        fprintf(stderr, "start to send Delete filepath\n");
        if(!send_message(client->conn_fd,sercurname,RM.message.body.pathlen)){
          fprintf(stderr, "send Delete filepath fail\n");
          return;
        }    
      }//delete
      i += EVENT_SIZE + event->len;
    }
    memset(buffer, 0, EVENT_BUF_LEN);
  }
  //inotify_rm_watch(fd, wd);
  close(fd);
  return ; 
}
void pull(char *dir,char *noexit,csiebox_client* client){
    csiebox_protocol_meta PULL;
    memset(&PULL,0,sizeof(csiebox_protocol_meta));
    PULL.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
    PULL.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
    PULL.message.header.req.datalen =sizeof(PULL)-sizeof(PULL.message.header);
    PULL.message.body.pathlen = strlen(noexit);
    fprintf(stderr, "start to send pull meta(pull)\n");
    if(!send_message(client->conn_fd,&PULL,sizeof(PULL))){
      fprintf(stderr, "send pull meta fail(pull)\n");
      return;
    }
    fprintf(stderr, "start to send noexit path(pull)\n");
    if(!send_message(client->conn_fd,noexit,PULL.message.body.pathlen)){
      fprintf(stderr, "send noexit path fail(pull)\n");
      return;
    }
   csiebox_protocol_meta pullrec;
   memset(&pullrec,0,sizeof(pullrec));
   while(recv_message(client->conn_fd,&pullrec, sizeof(pullrec))){
       if(pullrec.message.header.req.op == CSIEBOX_PROTOCOL_OP_SYNC_FILE){
           char tempath[PATH_MAX];
           memset(tempath,0,sizeof(tempath));
           fprintf(stderr, "receive file path(pull)\n");
           if(!recv_message(client->conn_fd,tempath,pullrec.message.body.pathlen)){
              fprintf(stderr, "receive path fail(pull)\n");
              break;
            } 
           fprintf(stderr, "receive file path success(pull)\n");
           char path[PATH_MAX];
           memset(path,0,sizeof(path));
           sprintf(path,"%s%s",client->arg.path,tempath);

           if(S_ISDIR(pullrec.message.body.stat.st_mode)){
              fprintf(stderr, "file is DIR(pull)\n");
              DIR *dp=opendir(path);
              if(errno==ENOENT){
                int che=mkdir(path,pullrec.message.body.stat.st_mode);
                if(che<0)fprintf(stderr, "DIR open fail(pull)\n");
              }
              else{
                chmod(path,pullrec.message.body.stat.st_mode);
                struct timespec revtime[2];
                memset(&revtime,0,sizeof(revtime)); 
                revtime[1]=pullrec.message.body.stat.st_mtim;  
                utimensat(AT_FDCWD,path,revtime,0);//AT_SYMLINK_NOFOLLOW
                
                int wd = inotify_add_watch(ino_fd,path, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
                map[hash_cou].md=wd;
                memcpy(map[hash_cou].cpath,tempath,strlen(tempath));
                hash_cou++;
                fprintf(stderr, "=====construct %s's  inotify wd : %d(pull)\n",path,wd);
              }
              
              fprintf(stderr, "%s\n",path);
              fprintf(stderr, "print DIR err : %s\n",strerror(errno));
              //judge the dir have inotify or not 
              
              closedir(dp);
            }//DIR

           if(S_ISREG(pullrec.message.body.stat.st_mode)){
              fprintf(stderr, "file is REG(pull)\n");
              int fd=open(path,O_RDWR|O_CREAT,pullrec.message.body.stat.st_mode);
              if(fd<0){
                fprintf(stderr, "file open fail(pull)\n");
                fprintf(stderr, "print FILE err : %s\n",strerror(errno));
              }
              fprintf(stderr, "%s\n",path);//
                  //======recv file
                csiebox_protocol_file recFile;
                char recvbuf[PATH_MAX];
                memset(recvbuf,0,sizeof(recvbuf));
                fprintf(stderr, "start to receive file header(pull)\n");
                while(recv_message(client->conn_fd,&recFile,sizeof(recFile))){
                  fprintf(stderr, "receive file content's header(pull)\n");
                   if(recFile.message.header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ&&
                       recFile.message.header.req.op == CSIEBOX_PROTOCOL_OP_SYNC_FILE){ 

                   if(recFile.message.body.datalen==0) break;

                  fprintf(stderr, "receive file content(pull)\n");
                    if(!recv_message(client->conn_fd,recvbuf,sizeof(recvbuf))){
                      fprintf(stderr, "receive filecontent fail(pull)\n");
                      break;
                     }
                    int rec_dlen=recFile.message.body.datalen;
                    if(rec_dlen!=write(fd,recvbuf,sizeof(char)*rec_dlen)){
                       fprintf(stderr, "write file err(pull)\n");
                       break;
                     }
                    }        
                }//while recv
                chmod(path,pullrec.message.body.stat.st_mode);
                struct timespec revtime[2];
                memset(&revtime,0,sizeof(revtime)); 
                revtime[1]=pullrec.message.body.stat.st_mtim;  
                utimensat(AT_FDCWD,path,revtime,0);  
                close(fd);     
            }//REG
             
            if(S_ISLNK(pullrec.message.body.stat.st_mode)){
                // ======recv symbolic link
                char recvbuf[PATH_MAX]; 
                memset(recvbuf,0,sizeof(recvbuf));
                fprintf(stderr, "receive link content(pull)\n");
                if(!recv_message(client->conn_fd,recvbuf,sizeof(recvbuf))){
                  fprintf(stderr, "receive symbolic link content fail(pull)\n");
                  break;
                }

                fprintf(stderr, "%s\n",recvbuf);
                if(symlink(recvbuf,path)==-1){
                  fprintf(stderr, "code: %s\n", strerror(errno));
                  fprintf(stderr, "construct symbolic link fail(pull)\n");
                  break;
                }
                struct timespec revtime[2];
                memset(&revtime,0,sizeof(revtime)); 
                revtime[1]=pullrec.message.body.stat.st_mtim;  
                utimensat(AT_FDCWD,path,revtime,AT_SYMLINK_NOFOLLOW);  
              }//symbolic link
            } //FILE
        if(pullrec.message.header.req.op == CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK){
            fprintf(stderr, "sync hardlink\n");
            csiebox_protocol_hardlink hardlink;
            if(!recv_message(client->conn_fd,&hardlink,sizeof(hardlink))){
              fprintf(stderr, "receive hardlink protocol fail\n");
              break;
            }
              char selfpath[PATH_MAX];
              memset(selfpath,0,sizeof(selfpath));
              fprintf(stderr, "receive selfpath(pull) \n");
              if(!recv_message(client->conn_fd,selfpath,hardlink.message.body.srclen)){
                 fprintf(stderr, "receive selfpath fail(pull)\n");
                 break;
              }
              char targetpath[PATH_MAX];
              memset(targetpath,0,sizeof(targetpath));  
              fprintf(stderr, "receive targetpath(pull) \n");
              if(!recv_message(client->conn_fd,targetpath,hardlink.message.body.targetlen)){
                 fprintf(stderr, "receive targetpath fail(pull)\n");
                 break;
              }
              char fullt[PATH_MAX];char fulls[PATH_MAX];
              memset(fullt,0,sizeof(fullt));
              memset(fulls,0,sizeof(fulls));
              sprintf(fullt,"%s%s",client->arg.path,targetpath);
              sprintf(fulls,"%s%s",client->arg.path,selfpath);  
              link(fullt,fulls);

        }
        if(pullrec.message.header.req.op == CSIEBOX_PROTOCOL_OP_SYNC_END){
          break;
        }
      memset(&pullrec,0,sizeof(pullrec));  
    }//while recv message          
  return;
 }//pull

void sync_meta(char *curname,char *sercurname,csiebox_client* client){
    fprintf(stderr, "start to sync meta\n");
    int FD = open(curname, O_RDONLY | O_CREAT | O_TRUNC); 
    flock(FD,LOCK_SH);

    csiebox_protocol_meta REQ;
    memset(&REQ,0,sizeof(csiebox_protocol_meta));
    REQ.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
    REQ.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
    REQ.message.header.req.datalen =sizeof(REQ)-sizeof(REQ.message.header);
    REQ.message.body.pathlen = strlen(sercurname);
    lstat(curname,&(REQ.message.body.stat));
    if(S_ISREG(REQ.message.body.stat.st_mode))
       md5_file(curname,REQ.message.body.hash);
    if(S_ISLNK(REQ.message.body.stat.st_mode)){
      char buf[PATH_MAX]; int len;
      memset(buf,0,PATH_MAX);
      len = readlink(curname,buf,PATH_MAX);
       md5(buf,len,REQ.message.body.hash);
    }
    //send meta
    
    fprintf(stderr, "start to send meta\n");
    if(!send_message(client->conn_fd,&REQ,sizeof(REQ))){
      fprintf(stderr, "send REQ fail\n");
      return;
    }
    fprintf(stderr, "start to send filepath\n");
    sercurname[REQ.message.body.pathlen]='\0';
    if(!send_message(client->conn_fd,sercurname,REQ.message.body.pathlen)){
      fprintf(stderr, "send filepath fail\n");
      return;
    }    

    
     csiebox_protocol_header header;
     memset(&header, 0, sizeof(header));
     fprintf(stderr, "receive header from server\n");//
     if (recv_message(client->conn_fd, &header, sizeof(header))) {
        if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
          header.res.op == CSIEBOX_PROTOCOL_OP_SYNC_META) {
          if(header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) return;
          if(header.res.status == CSIEBOX_PROTOCOL_STATUS_MORE){
            if(S_ISREG(REQ.message.body.stat.st_mode)){
               FILE *fin=fopen(curname,"r");
               char buf[PATH_MAX];
               memset(buf,0,sizeof(buf));
               int tem_datalen;
               fprintf(stderr, "start to read local file\n");
               while((tem_datalen=fread(buf,sizeof(char),PATH_MAX,fin))>=0){ 
                 csiebox_protocol_file File;
                 File.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
                 File.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
                 File.message.header.req.datalen =sizeof(File)-sizeof(File.message.header);
                 File.message.body.datalen = tem_datalen;
                 fprintf(stderr, "send FILE header\n"); 
                 if(!send_message(client->conn_fd,&File,sizeof(File))){
                   fprintf(stderr, "send fileheader fail\n");
                   break;
                  }
                 if(tem_datalen==0) break; 
                 fprintf(stderr, "send file content\n");
                 if(!send_message(client->conn_fd,buf,sizeof(buf))){
                   fprintf(stderr, "send filecontent fail\n");
                   break;
                  }
                  memset(buf,0,sizeof(buf));
                } //while send buf
                fclose(fin);
              }//REG
            if(S_ISLNK(REQ.message.body.stat.st_mode)){
               int linklen;
               char linkbuf[PATH_MAX];
               memset(linkbuf,0,sizeof(linkbuf));
               linklen = readlink(curname,linkbuf,PATH_MAX);
               fprintf(stderr, "send link content\n");
               if(!send_message(client->conn_fd,linkbuf,sizeof(linkbuf))){
                fprintf(stderr, "send link content fail\n");
                return;
               } 
            }//symbolic link           
          }//more
          if(header.res.status == CSIEBOX_PROTOCOL_STATUS_LOCK){
            fprintf(stdout, "Server block\n");
            sleep(3);
            sync_meta(curname,sercurname,client);  
          }
          if(header.res.status == CSIEBOX_PROTOCOL_STATUS_BUSY){
            fprintf(stdout, "Server busy\n");
            sleep(3);
            sync_meta(curname,sercurname,client);  
          }
          
        }// if CSIEBOX_PROTOCOL_OP_SYNC_META
      }
     else{
          fprintf(stderr, "receive from server fail\n");
          return ;
        }
     csiebox_protocol_meta END;
      memset(&END,0,sizeof(csiebox_protocol_meta));
      END.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
      END.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
      END.message.header.req.datalen =sizeof(END)-sizeof(END.message.header);  
      if(!send_message(client->conn_fd,&END,sizeof(END))){
      fprintf(stderr, "send END fail\n");
      return;
      }   
     flock(FD,LOCK_UN);
     close(FD);      
  return;
}

void search(char *dir,char *serdir,char *childpath,csiebox_client* client){
  fprintf(stderr, "%s : search path\n",dir);
  DIR *dp=opendir(dir);
  struct dirent *dirp;
  if(dp==NULL) fprintf(stderr, "open file fail\n");
  fprintf(stderr, "open file success\n");
  while((dirp = readdir(dp)) != NULL){
    char name[PATH_MAX];
    memset(name,0,sizeof(name));
    strcpy(name,dirp->d_name);
    if(name[0]=='.') continue;
    if(nullcou < 10) nullcou++;//judge null
    char curchildpath[PATH_MAX];
    memset(curchildpath,0,sizeof(curchildpath));
    char curname[PATH_MAX];
    memset(curname,0,sizeof(curname));
    char sercurname[PATH_MAX];
    memset(sercurname,0,sizeof(sercurname));
    
    sprintf(curchildpath,"%s/%s",childpath,name); 
    sprintf(curname,"%s/%s",dir,name);
    sprintf(sercurname,"%s/%s",serdir,name);
    curchildpath[strlen(curchildpath)]='\0';
    curname[strlen(curname)]='\0';
    sercurname[strlen(sercurname)]='\0';
    // judge hardlink
    struct stat stat; int hard=0;
    lstat(curname,&stat);
    if(stat.st_nlink > 2){
      int have=0,h;
      for(h = 0;h < same_cou;h++){ if(stat.st_ino==sameinum[h]){have=1;break;} }
     //doesn't
      if(have==0){
        sameinum[same_cou]=stat.st_ino; same_cou++;
        snum_path[snum_path_cou].inum=stat.st_ino;
        memcpy(snum_path[snum_path_cou].linpath,sercurname,strlen(sercurname));
        snum_path_cou++;
      }
      //exist
      else{
        int q;hard=1;
        char getpath[PATH_MAX];
        memset(getpath,0,sizeof(getpath));
        for (q = 0; q < snum_path_cou; ++q){
          if(sameinum[h]==snum_path[q].inum){
           memcpy(getpath,snum_path[q].linpath,sizeof(snum_path[q].linpath));
           break;
          } 
        }
        csiebox_protocol_hardlink hardreq;
        memset(&hardreq,0,sizeof(hardreq));
        hardreq.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
        hardreq.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
        hardreq.message.header.req.datalen =sizeof(hardreq)-sizeof(hardreq.message.header);
        hardreq.message.body.srclen = strlen(sercurname);
        hardreq.message.body.targetlen = strlen(getpath);
         fprintf(stderr, "start to send hardlink protocol\n");
          if(!send_message(client->conn_fd,&hardreq,sizeof(hardreq))){
            fprintf(stderr, "send hardlink protocol fail\n");
            return;
          }
         fprintf(stderr, "start to send self path\n");
          if(!send_message(client->conn_fd,sercurname,hardreq.message.body.srclen)){
            fprintf(stderr, "send self path fail\n");
            return;
          }     
         fprintf(stderr, "start to send target path\n");
          if(!send_message(client->conn_fd,getpath,hardreq.message.body.targetlen)){
            fprintf(stderr, "send target path fail\n");
            return;
          }  
      }//hardlink  
      
    }//if 
    //finish judge hardlink
    if(hard==0)
       sync_meta(curname,sercurname,client);
    if(dirp->d_type==DT_DIR&&hard==0){  
      int wd = inotify_add_watch(ino_fd,curname, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
      map[hash_cou].md=wd;
      memcpy(map[hash_cou].cpath,curchildpath,strlen(curchildpath));
      hash_cou++;
      fprintf(stderr, "=====construct %s's  inotify wd : %d  \n",curname,wd);
      search(curname,sercurname,curchildpath,client);
      sync_meta(curname,sercurname,client);
    } //is DIR 
  }
  closedir(dp);   
  return;
}

//this is where client sends request, you sould write your code here//to_do
int csiebox_client_run(csiebox_client* client) {
  if (!login(client)) {
    fprintf(stderr, "login fail\n");
    return 0;
  }
  fprintf(stderr, "login success\n");
  char dir[PATH_MAX];
  memset(dir,0,sizeof(dir));
  sprintf(dir,"%s",client->arg.path);
  fprintf(stderr, "%s : client path\n",dir);//

  char serdir[PATH_MAX];
  memset(serdir,0,sizeof(serdir));
  sprintf(serdir,"../sdir/%s",client->arg.user);

  char childpath[PATH_MAX];
  memset(childpath,0,sizeof(childpath));
  // construct inotify fd
  ino_fd = inotify_init();
  if (ino_fd < 0) {
    perror("inotify_init");
  }
  // add cdir
  
  fprintf(stderr, "inotify_init success\n");
  // monitor inotify
  nullcou=0; snum_path_cou=0; same_cou=0;hash_cou=0; 
  fprintf(stderr, "ininullcou : %d \n",nullcou);
  search(dir,serdir,childpath,client);
  fprintf(stderr, "nullcou : %d \n",nullcou);
  if(nullcou==0){
    fprintf(stderr, "cdir is NULL\n");
    char noexit[PATH_MAX];
    memset(noexit,0,sizeof(noexit));
    sprintf(noexit,"../cdir/%s",client->arg.user);
    pull(dir,noexit,client); 
    fprintf(stderr, "finish pull\n");
  }//null
  int wd = inotify_add_watch(ino_fd,dir, IN_CREATE | IN_DELETE | IN_ATTRIB | IN_MODIFY);
  map[hash_cou].md=wd;
  char inipath[PATH_MAX];
  memset(inipath,0,sizeof(inipath));
  memcpy(map[hash_cou].cpath,inipath,strlen(inipath));
  hash_cou++;
  inotify_test(ino_fd,client);
  return 1;
}

void csiebox_client_destroy(csiebox_client** client) {
  csiebox_client* tmp = *client;
  *client = 0;
  if (!tmp) {
    return;
  }
  close(tmp->conn_fd);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_client* client, int argc, char** argv) {
  if (argc != 2) {
    return 0;
  }
  FILE* file = fopen(argv[1], "r");
  if (!file) {
    return 0;
  }
  fprintf(stderr, "reading config...\n");
  size_t keysize = 20, valsize = 20;
  char* key = (char*)malloc(sizeof(char) * keysize);
  char* val = (char*)malloc(sizeof(char) * valsize);
  ssize_t keylen, vallen;
  int accept_config_total = 5;
  int accept_config[5] = {0, 0, 0, 0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("name", key) == 0) {
      if (vallen <= sizeof(client->arg.name)) {
        strncpy(client->arg.name, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("server", key) == 0) {
      if (vallen <= sizeof(client->arg.server)) {
        strncpy(client->arg.server, val, vallen);
        accept_config[1] = 1;
      }
    } else if (strcmp("user", key) == 0) {
      if (vallen <= sizeof(client->arg.user)) {
        strncpy(client->arg.user, val, vallen);
        accept_config[2] = 1;
      }
    } else if (strcmp("passwd", key) == 0) {
      if (vallen <= sizeof(client->arg.passwd)) {
        strncpy(client->arg.passwd, val, vallen);
        accept_config[3] = 1;
      }
    } else if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(client->arg.path)) {
        strncpy(client->arg.path, val, vallen);
        accept_config[4] = 1;
      }
    }
  }
  free(key);
  free(val);
  fclose(file);
  int i, test = 1;
  for (i = 0; i < accept_config_total; ++i) {
    test = test & accept_config[i];
  }
  if (!test) {
    fprintf(stderr, "config error\n");
    return 0;
  }
  return 1;
}

static int login(csiebox_client* client) {
  csiebox_protocol_login req;
  memset(&req, 0, sizeof(req));
  req.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
  req.message.header.req.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  req.message.header.req.datalen = sizeof(req) - sizeof(req.message.header);
  memcpy(req.message.body.user, client->arg.user, strlen(client->arg.user));
    md5(client->arg.passwd,
       strlen(client->arg.passwd),
        req.message.body.passwd_hash);
  if (!send_message(client->conn_fd, &req, sizeof(req))) {
    fprintf(stderr, "send fail\n");
    return 0;
  }
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  if (recv_message(client->conn_fd, &header, sizeof(header))) {
    if (header.res.magic == CSIEBOX_PROTOCOL_MAGIC_RES &&
        header.res.op == CSIEBOX_PROTOCOL_OP_LOGIN &&
        header.res.status == CSIEBOX_PROTOCOL_STATUS_OK) {
      client->client_id = header.res.client_id;
      return 1;
    } else {
      return 0;
    }
  }
  return 0;
}
