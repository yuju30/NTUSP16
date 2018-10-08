#include <iostream>
#include <dirent.h>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
using namespace std;

void search(string dir,string fullname){
	DIR *dp;
    struct dirent *dirp;
    dp = opendir(dir.c_str());
   if(dp!= NULL){
   	while((dirp = readdir(dp)) != NULL){
   	  string name=string(dirp->d_name);
   	  if(name[0]=='.') continue;
   	  string curname=fullname+"/"+name;

   	  if (dirp->d_type==DT_LNK){
   	  	string copy="cp -RP ./client"+curname+" ./server"+fullname; system(copy.c_str());
   	    printf("%s\n",name.c_str()); 
   	  }
   	  if(dirp->d_type==DT_REG){
         string copy="cp ./client"+curname+" ./server"+fullname; system(copy.c_str());
         printf("%s\n",name.c_str()); 
   	  }
   	  if(dirp->d_type==DT_DIR){
   	  	string mk="mkdir -p ./server"+curname; system(mk.c_str());
   	  	string dirname=dir+"/"+name;
   	    search(dirname,curname);
   	    printf("%s\n",name.c_str()); 
   	  } 
     }
   }
 closedir(dp);   
 return;
}

int main(){
	string dir="client";
	string full="";
	search(dir,full);
    return 0;
}
