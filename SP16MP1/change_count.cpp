#include <iostream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
using namespace std;

int DP[1050][1050]={{0}};

int max(int x,int y){return (x>y? x:y);}

int LCS(unsigned long long int a[],unsigned long long int b[],int an,int bn){
    int MAXLEN=0;
    for (int i = 1; i < an; i++)
        for (int j = 1; j < bn; j++){
			if(a[i]==b[j])
                DP[i][j]=DP[i-1][j-1]+1;
            else
                DP[i][j]=max(DP[i-1][j],DP[i][j-1]);
            
            if(DP[i][j]>MAXLEN) MAXLEN=DP[i][j]; 
        }
    return MAXLEN;
}
void ini_DP(){for (int i = 0; i < 1050; ++i)for (int j = 0; j < 1050; ++j)DP[i][j]=0;}

int main(){
   string cmmd,fil_name;
   int A,D;
   while(cin>>cmmd){
    if(cmmd=="exit") break;
    else{
        cin>>fil_name;
        int fdc=open(("./client/"+fil_name).c_str(),O_RDONLY);
        int fds=open(("./server/"+fil_name).c_str(),O_RDONLY);
        if(fdc==-1&&fds!=-1) {string del = "rm ./server/"+fil_name; system(del.c_str());}
        if(fds==-1&&fdc!=-1) {string copy ="cp ./client/"+fil_name+" ./server"; system(copy.c_str());}

        char bufc[1024];
        unsigned long long int hashc[2000]={0};
        ssize_t cn;
        int cline=1;
        while ((cn = read(fdc, bufc, 1024)) > 0) {
          for (ssize_t i = 0; i < cn; ++i) {
             if(bufc[i]=='\n') cline++;
             else
             hashc[cline]=hashc[cline]*131+int(bufc[i]);   
          }
        }
        char bufs[1024];
        unsigned long long int hashs[2000]={0};
        ssize_t sn;
        int sline=1;
        while ((sn = read(fds, bufs, 1024)) > 0) {
          for (ssize_t i = 0; i < sn; ++i) {
             if(bufs[i]=='\n') sline++;
             else
             hashs[sline]=hashs[sline]*131+int(bufs[i]);
          }
        }
        ini_DP();
        int lcs_num=LCS(hashc,hashs,cline,sline);
        A=cline-lcs_num-1;
        D=sline-lcs_num-1;

        cout<<A<<" "<<D<<endl;
        cout.flush();
        
        string COPY ="cp ./client/"+fil_name+" ./server"; 
        system(COPY.c_str());
       }
    }   
 return 0;
}