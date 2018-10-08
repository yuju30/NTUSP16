#include "csiebox_server.h"

#include "csiebox_common.h"
#include "connect.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/epoll.h>

static int parse_arg(csiebox_server* server, int argc, char** argv);
static void handle_request(csiebox_server* server, int conn_fd);
static void handle_request_single(csiebox_server* server, int conn_fd);
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info);
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login);
static void logout(csiebox_server* server, int conn_fd);
static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info);
void traversal(char *dir,char *childpath,int conn_fd);

#define DIR_S_FLAG (S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)//permission you can use to create new file
#define REG_S_FLAG (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)//permission you can use to create new directory
#define PATH_MAX 4096
#define MAXEVENTS 64

typedef struct inonum{
  ino_t inum;
  char linpath[PATH_MAX];
}Inonum;
Inonum snum_path[105];
int snum_path_cou=0;

ino_t sameinum[105];
int same_cou=0;


//read config file, and start to listen
void csiebox_server_init(
  csiebox_server** server, int argc, char** argv) {
  csiebox_server* tmp = (csiebox_server*)malloc(sizeof(csiebox_server));
  if (!tmp) {
    fprintf(stderr, "server malloc fail\n");
    return;
  }
  memset(tmp, 0, sizeof(csiebox_server));
  if (!parse_arg(tmp, argc, argv)) {
    fprintf(stderr, "Usage: %s [config file]\n", argv[0]);
    free(tmp);
    return;
  }
  int fd = server_start();
  if (fd < 0) {
    fprintf(stderr, "server fail\n");
    free(tmp);
    return;
  }
  tmp->client = (csiebox_client_info**)
      malloc(sizeof(csiebox_client_info*) * getdtablesize());
  if (!tmp->client) {
    fprintf(stderr, "client list malloc fail\n");
    close(fd);
    free(tmp);
    return;
  }
  memset(tmp->client, 0, sizeof(csiebox_client_info*) * getdtablesize());
  tmp->listen_fd = fd;
  *server = tmp;
}

//wait client to connect and handle requests from connected socket fd
//===============================
//		TODO: you need to modify code in here and handle_request() to support I/O multiplexing
//===============================
int csiebox_server_run(csiebox_server* server) { 
  int conn_fd, conn_len;
  struct sockaddr_in addr;
  struct epoll_event event;
  struct epoll_event *events;
  
  int efd = epoll_create1 (0);
  if (efd == -1){
      perror ("epoll_create");
      //abort ();
    }
  event.data.fd = server->listen_fd;
  event.events = EPOLLIN | EPOLLET;
  if (epoll_ctl (efd, EPOLL_CTL_ADD, server->listen_fd, &event)== -1){
      perror ("epoll_ctl");
    //   abort ();
  }
  events = calloc(MAXEVENTS, sizeof(event));
  while (1) {
    int n = epoll_wait (efd, events, MAXEVENTS, -1); 

    for (int i = 0; i < n; ++i){
       if(server->listen_fd == events[i].data.fd){
          // waiting client connect 
           memset(&addr, 0, sizeof(addr));
           conn_len = 0;
           conn_fd = accept(
                server->listen_fd, (struct sockaddr*)&addr, (socklen_t*)&conn_len);
              if (conn_fd < 0) {
                if (errno == ENFILE) {
                    fprintf(stderr, "out of file descriptor table\n");
                    continue;
                  } else if (errno == EAGAIN || errno == EINTR) {
                    continue;
                  } else {
                    fprintf(stderr, "accept err\n");
                    fprintf(stderr, "code: %s\n", strerror(errno));
                    break;
                  }
              }
            event.data.fd = conn_fd;
            event.events = EPOLLIN | EPOLLET;
            if (epoll_ctl (efd, EPOLL_CTL_ADD, conn_fd, &event)== -1){
                perror ("epoll_ctl");
                //abort ();
            }   
       }//listen_fd
    // handle request from connected socket fd
           fprintf(stderr, "handle_request events %d  \n",i);
           handle_request(server, events[i].data.fd);
   
    }//for
   
  }//while 1
  free (events);
  close (efd);
  return 1;
}

void csiebox_server_destroy(csiebox_server** server) {
  csiebox_server* tmp = *server;
  *server = 0;
  if (!tmp) {
    return;
  }
  close(tmp->listen_fd);
  int i = getdtablesize() - 1;
  for (; i >= 0; --i) {
    if (tmp->client[i]) {
      free(tmp->client[i]);
    }
  }
  free(tmp->client);
  free(tmp);
}

//read config file
static int parse_arg(csiebox_server* server, int argc, char** argv) {
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
  int accept_config_total = 2;
  int accept_config[2] = {0, 0};
  while ((keylen = getdelim(&key, &keysize, '=', file) - 1) > 0) {
    key[keylen] = '\0';
    vallen = getline(&val, &valsize, file) - 1;
    val[vallen] = '\0';
    fprintf(stderr, "config (%d, %s)=(%d, %s)\n", keylen, key, vallen, val);
    if (strcmp("path", key) == 0) {
      if (vallen <= sizeof(server->arg.path)) {
        strncpy(server->arg.path, val, vallen);
        accept_config[0] = 1;
      }
    } else if (strcmp("account_path", key) == 0) {
      if (vallen <= sizeof(server->arg.account_path)) {
        strncpy(server->arg.account_path, val, vallen);
        accept_config[1] = 1;
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


//this is where the server handle requests, you should write your code here
static void handle_request(csiebox_server* server, int conn_fd) {
  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  fprintf(stderr, "start to receive requests file\n");
  if(recv_message(conn_fd, &header, sizeof(header))) {
    if (header.req.magic != CSIEBOX_PROTOCOL_MAGIC_REQ) {
      return;
    }
    switch (header.req.op) {
      case CSIEBOX_PROTOCOL_OP_LOGIN:
        fprintf(stderr, "login\n");
        csiebox_protocol_login req;
        if (complete_message_with_header(conn_fd, &header, &req)) {
          login(server, conn_fd, &req);
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_META:
        fprintf(stderr, "sync meta\n");
        csiebox_protocol_meta meta;
        if (complete_message_with_header(conn_fd, &header, &meta)) {
           char path[meta.message.body.pathlen+10];
           memset(path,0,sizeof(path));
           fprintf(stderr, "receive file path\n");
           if(!recv_message(conn_fd,path,meta.message.body.pathlen)){
              fprintf(stderr, "receive path fail\n");
              return;
            } 
           fprintf(stderr, "receive file path success\n");
           //check pull
           char clidir[PATH_MAX];
           memset(clidir,0,sizeof(clidir));
           sprintf(clidir,"../cdir/"); int noexistche=0;
           for (int i = 0; i < 8; ++i){
             if(clidir[i]!=path[i])noexistche=1;
           }
           if(noexistche==0){
             path[3]='s';
             char tempchild[PATH_MAX];
             memset(tempchild,0,sizeof(tempchild));
             traversal(path,tempchild,conn_fd);
             fprintf(stderr, "traversal finish\n");
             csiebox_protocol_meta END;
             memset(&END,0,sizeof(csiebox_protocol_meta)); 
              END.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
              END.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_END;
              END.message.header.req.datalen =sizeof(END)-sizeof(END.message.header);
              if(!send_message(conn_fd,&END,sizeof(END))){
                fprintf(stderr, "send message fail\n");
                return;
              }
              return;
           }
           if(S_ISDIR(meta.message.body.stat.st_mode)){
              fprintf(stderr, "file is DIR\n");
              DIR *dp=opendir(path);
              if(errno==ENOENT){
                int che=mkdir(path,meta.message.body.stat.st_mode);
                if(che<0)fprintf(stderr, "DIR open fail\n");
              }
              fprintf(stderr, "%s\n",path);
              fprintf(stderr, "print DIR err : %s\n",strerror(errno));

              chmod(path,meta.message.body.stat.st_mode);
              struct timespec revtime[2];
              memset(&revtime,0,sizeof(revtime)); 
              revtime[1]=meta.message.body.stat.st_mtim;  
              utimensat(AT_FDCWD,path,revtime,0);//AT_SYMLINK_NOFOLLOW
              csiebox_protocol_header retheader;
              retheader.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES; 
              retheader.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
              retheader.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
              fprintf(stderr, "start to send return_header\n");
              if(!send_message(conn_fd,&retheader,sizeof(retheader))){
                fprintf(stderr, "after receive return header fail\n");
                return;
              }
              closedir(dp);  
            }//DIR
           if(S_ISREG(meta.message.body.stat.st_mode)){
              fprintf(stderr, "file is REG\n");
              int fd=open(path,O_RDWR|O_CREAT,meta.message.body.stat.st_mode);
              if(fd<0){
                fprintf(stderr, "file open fail\n");
                fprintf(stderr, "print FILE err : %s\n",strerror(errno));
              }
              fprintf(stderr, "%s\n",path);//
                 // ask more(file)
                   csiebox_protocol_header retheader;
                   retheader.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES; 
                   retheader.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
                   retheader.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
                   fprintf(stderr, "start to send file different return_header\n");
                   if(!send_message(conn_fd,&retheader,sizeof(retheader))){
                    fprintf(stderr, "after receive return header fail\n");
                    return;
                    } 
                  //======recv file
                   csiebox_protocol_file recFile;
                   char recvbuf[PATH_MAX];
                   memset(recvbuf,0,sizeof(recvbuf));
                   fprintf(stderr, "start to receive file header\n");
                   while(recv_message(conn_fd,&recFile,sizeof(recFile))){
                      fprintf(stderr, "receive file content's header\n");
                      if(recFile.message.header.req.magic == CSIEBOX_PROTOCOL_MAGIC_REQ&&
                          recFile.message.header.req.op == CSIEBOX_PROTOCOL_OP_SYNC_FILE){
                      
                      if(recFile.message.body.datalen==0) break;
                      
                      fprintf(stderr, "receive file content\n");
                        if(!recv_message(conn_fd,recvbuf,sizeof(recvbuf))){
                          fprintf(stderr, "receive filecontent fail\n");
                          break;
                        }
                        int rec_dlen=recFile.message.body.datalen;
                        if(rec_dlen!=write(fd,recvbuf,sizeof(char)*rec_dlen)){
                          fprintf(stderr, "write file err\n");
                          break;
                        }

                      }        
                   }//while recv       
          
                    chmod(path,meta.message.body.stat.st_mode);
                    struct timespec revtime[2];
                    memset(&revtime,0,sizeof(revtime)); 
                    revtime[1]=meta.message.body.stat.st_mtim;  
                    utimensat(AT_FDCWD,path,revtime,0);//AT_SYMLINK_NOFOLLOW
                  close(fd);
                  }//REG
                   
            if(S_ISLNK(meta.message.body.stat.st_mode)){
                // ask more (symbolic link)
                
                csiebox_protocol_header retheader;
                retheader.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES; 
                retheader.res.op = CSIEBOX_PROTOCOL_OP_SYNC_META;
                retheader.res.status = CSIEBOX_PROTOCOL_STATUS_MORE;
                
                fprintf(stderr, "start to send link return_header\n");
                  if(!send_message(conn_fd,&retheader,sizeof(retheader))){
                     fprintf(stderr, "after receive return header fail\n");
                     return;
                  }
                
                // ======recv symbolic link
                char recvbuf[PATH_MAX]; 
                memset(recvbuf,0,sizeof(recvbuf));
                fprintf(stderr, "receive link content\n");
                if(!recv_message(conn_fd,recvbuf,sizeof(recvbuf))){
                  fprintf(stderr, "receive symbolic link content fail\n");
                  return;
                }
                fprintf(stderr, "%s\n",recvbuf);
                if(symlink(recvbuf,path)==-1){
                  fprintf(stderr, "code: %s\n", strerror(errno));
                  fprintf(stderr, "construct symbolic link fail\n");
                  return;
                }
                struct timespec revtime[2];
                memset(&revtime,0,sizeof(revtime)); 
                revtime[1]=meta.message.body.stat.st_mtim;  
                utimensat(AT_FDCWD,path,revtime,AT_SYMLINK_NOFOLLOW);//AT_SYMLINK_NOFOLLOW  
            }//symbolic link
      
          //====================
          //        TODO: here is where you handle sync_meta and even sync_file request from client
          //==================== 
         }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK:
        fprintf(stderr, "sync hardlink\n");
        csiebox_protocol_hardlink hardlink;
        if (complete_message_with_header(conn_fd, &header, &hardlink)){
           char selfpath[PATH_MAX];
           memset(selfpath,0,sizeof(selfpath));
           fprintf(stderr, "receive selfpath \n");
           if(!recv_message(conn_fd,selfpath,hardlink.message.body.srclen)){
              fprintf(stderr, "receive selfpath fail\n");
              return;
            }
           char targetpath[PATH_MAX];
           memset(targetpath,0,sizeof(targetpath));  
           fprintf(stderr, "receive targetpath \n");
           if(!recv_message(conn_fd,targetpath,hardlink.message.body.targetlen)){
              fprintf(stderr, "receive targetpath fail\n");
              return;
            }  
           link(targetpath,selfpath);
          //====================
          //        TODO: here is where you handle sync_hardlink request from client
          //====================
        }
        break;
      case CSIEBOX_PROTOCOL_OP_SYNC_END:
        fprintf(stderr, "sync end\n");
        csiebox_protocol_header end;
          //====================
          //        TODO: here is where you handle end of synchronization request from client
          //====================
        break;
      case CSIEBOX_PROTOCOL_OP_RM:
        fprintf(stderr, "rm\n");
        csiebox_protocol_rm rm;
        if (complete_message_with_header(conn_fd, &header, &rm)) {
           char path[PATH_MAX];
           memset(path,0,sizeof(path));
           fprintf(stderr, "receive delete file path\n");
           if(!recv_message(conn_fd,path,rm.message.body.pathlen)){
              fprintf(stderr, "receive delete path fail\n");
              return;
            } 
           fprintf(stderr, "receive delete file path %s \n",path);
           if(remove(path)==-1){
            fprintf(stderr, "remove fail!!\n");
            return;
           }
          //====================
          //        TODO: here is where you handle rm file or directory request from client
          //====================
        }
        break;
      default:
        fprintf(stderr, "unknown op %x\n", header.req.op);
        break;
    }
    fprintf(stderr, "end of request\n");
  }
  else{
    logout(server, conn_fd);
  }
}

//open account file to get account information
static int get_account_info(
  csiebox_server* server,  const char* user, csiebox_account_info* info) {
  FILE* file = fopen(server->arg.account_path, "r");
  if (!file) {
    return 0;
  }
  size_t buflen = 100;
  char* buf = (char*)malloc(sizeof(char) * buflen);
  memset(buf, 0, buflen);
  ssize_t len;
  int ret = 0;
  int line = 0;
  while ((len = getline(&buf, &buflen, file) - 1) > 0) {
    ++line;
    buf[len] = '\0';
    char* u = strtok(buf, ",");
    if (!u) {
      fprintf(stderr, "illegal form in account file, line %d\n", line);
      continue;
    }
    if (strcmp(user, u) == 0) {
      memcpy(info->user, user, strlen(user));
      char* passwd = strtok(NULL, ",");
      if (!passwd) {
        fprintf(stderr, "illegal form in account file, line %d\n", line);
        continue;
      }
      md5(passwd, strlen(passwd), info->passwd_hash);
      ret = 1;
      break;
    }
  }
  free(buf);
  fclose(file);
  return ret;
}


//handle the login request from client
static void login(
  csiebox_server* server, int conn_fd, csiebox_protocol_login* login) {
  int succ = 1;
  csiebox_client_info* info =
    (csiebox_client_info*)malloc(sizeof(csiebox_client_info));
  memset(info, 0, sizeof(csiebox_client_info));
  if (!get_account_info(server, login->message.body.user, &(info->account))) {
    fprintf(stderr, "cannot find account\n");
    succ = 0;
  }
  if (succ &&
      memcmp(login->message.body.passwd_hash,
             info->account.passwd_hash,
             MD5_DIGEST_LENGTH) != 0) {
    fprintf(stderr, "passwd miss match\n");
    succ = 0;
  }

  csiebox_protocol_header header;
  memset(&header, 0, sizeof(header));
  header.res.magic = CSIEBOX_PROTOCOL_MAGIC_RES;
  header.res.op = CSIEBOX_PROTOCOL_OP_LOGIN;
  header.res.datalen = 0;
  if (succ) {
    if (server->client[conn_fd]) {
      free(server->client[conn_fd]);
    }
    info->conn_fd = conn_fd;
    server->client[conn_fd] = info;
    header.res.status = CSIEBOX_PROTOCOL_STATUS_OK;
    header.res.client_id = info->conn_fd;
    char* homedir = get_user_homedir(server, info);
    mkdir(homedir, DIR_S_FLAG);
    free(homedir);
  } else {
    header.res.status = CSIEBOX_PROTOCOL_STATUS_FAIL;
    free(info);
  }
  send_message(conn_fd, &header, sizeof(header));
}

static void logout(csiebox_server* server, int conn_fd) {
  free(server->client[conn_fd]);
  server->client[conn_fd] = 0;
  close(conn_fd);
}

static char* get_user_homedir(
  csiebox_server* server, csiebox_client_info* info) {
  char* ret = (char*)malloc(sizeof(char) * PATH_MAX);
  memset(ret, 0, PATH_MAX);
  sprintf(ret, "%s/%s", server->arg.path, info->account.user);
  return ret;
}

void sync_file(char *curname,char *curchildpath,int conn_fd){
    fprintf(stderr, "start to sync file(pull)\n");
    csiebox_protocol_meta REQ;
    memset(&REQ,0,sizeof(csiebox_protocol_meta));
    REQ.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
    REQ.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_FILE;
    REQ.message.header.req.datalen =sizeof(REQ)-sizeof(REQ.message.header);
    REQ.message.body.pathlen = strlen(curchildpath);
    lstat(curname,&(REQ.message.body.stat));

    fprintf(stderr, "start to send sync file meta(pull)\n");
    if(!send_message(conn_fd,&REQ,sizeof(REQ))){
      fprintf(stderr, "send sync file meta fail(pull)\n");
      return;
    }
    fprintf(stderr, "start to send filepath(pull)\n");
    if(!send_message(conn_fd,curchildpath,REQ.message.body.pathlen)){
      fprintf(stderr, "send filepath fail(pull)\n");
      return;
    }
    
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
        if(!send_message(conn_fd,&File,sizeof(File))){
          fprintf(stderr, "send fileheader fail\n");
          break;
         }
        if(tem_datalen==0) break; 
        fprintf(stderr, "send file content\n");
        if(!send_message(conn_fd,buf,sizeof(buf))){
          fprintf(stderr, "send filecontent fail\n");
          break;
        }
      } //while send buf
      fclose(fin);
    }//REG
    if(S_ISLNK(REQ.message.body.stat.st_mode)){
      int linklen;
      char linkbuf[PATH_MAX];
      memset(linkbuf,0,sizeof(linkbuf));
      linklen = readlink(curname,linkbuf,PATH_MAX);
       fprintf(stderr, "send link content\n");
      if(!send_message(conn_fd,linkbuf,sizeof(linkbuf))){
        fprintf(stderr, "send link content fail\n");
        return;
        } 
    }//symbolic link           

}//pull

void traversal(char *dir,char *childpath,int conn_fd){
  fprintf(stderr, "%s : search path (pull)\n",dir);
  DIR *dp=opendir(dir);
  struct dirent *dirp;
  if(dp==NULL) fprintf(stderr, "open file fail (pull)\n");
  while((dirp = readdir(dp)) != NULL){
    char name[PATH_MAX];
    memset(name,0,sizeof(name));
    strcpy(name,dirp->d_name);
    if(name[0]=='.') continue;
    char curchildpath[PATH_MAX];
    memset(curchildpath,0,sizeof(curchildpath));
    char curname[PATH_MAX];
    memset(curname,0,sizeof(curname));
    
    sprintf(curchildpath,"%s/%s",childpath,name); 
    sprintf(curname,"%s/%s",dir,name);
    curchildpath[strlen(curchildpath)]='\0';
    curname[strlen(curname)]='\0';
   
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
        memcpy(snum_path[snum_path_cou].linpath,curchildpath,strlen(curchildpath));
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
        csiebox_protocol_meta hardreq;
        memset(&hardreq,0,sizeof(hardreq));
        hardreq.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
        hardreq.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
        hardreq.message.header.req.datalen =sizeof(hardreq)-sizeof(hardreq.message.header);
        hardreq.message.body.pathlen = strlen(curchildpath);

        fprintf(stderr, "start to send hardlink meta (pull)\n");
          if(!send_message(conn_fd,&hardreq,sizeof(hardreq))){
            fprintf(stderr, "send hardlink meta fail(pull)\n");
            return;
          }
          //send hardlink
          csiebox_protocol_hardlink hardlink;
          memset(&hardlink,0,sizeof(hardlink));
          hardlink.message.header.req.magic = CSIEBOX_PROTOCOL_MAGIC_REQ;
          hardlink.message.header.req.op = CSIEBOX_PROTOCOL_OP_SYNC_HARDLINK;
          hardlink.message.header.req.datalen =sizeof(hardlink)-sizeof(hardlink.message.header);
          hardlink.message.body.srclen = strlen(curchildpath);
          hardlink.message.body.targetlen = strlen(getpath);

          fprintf(stderr, "start to send hardlink protocol(pull)\n");
           if(!send_message(conn_fd,&hardlink,sizeof(hardlink))){
            fprintf(stderr, "send hardlink protocol fail(pull)\n");
            return;
          }
          fprintf(stderr, "start to send self path(pull)\n");
           if(!send_message(conn_fd,curchildpath,hardlink.message.body.srclen)){
            fprintf(stderr, "send self path fail(pull)\n");
            return;
          }     
          fprintf(stderr, "start to send target path(pull)\n");
           if(!send_message(conn_fd,getpath,hardlink.message.body.targetlen)){
            fprintf(stderr, "send target path fail(pull)\n");
            return;
          }  
      }//hardlink  
      
    }//if 
    //===================finish judge hardlink
    if(hard==0) sync_file(curname,curchildpath,conn_fd);
    if(dirp->d_type==DT_DIR&&hard==0){  
      traversal(curname,curchildpath,conn_fd);
      sync_file(curname,curchildpath,conn_fd);
    } //is DIR 
  }
  closedir(dp);   
  return;
}


