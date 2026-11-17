/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Read-only diagnostic: streams /dev/klog to one TCP client at a time on port 3232. */
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define KLOG_PORT 3232

static int send_all(int fd,const char *buf,size_t len){
    while(len){ssize_t n=write(fd,buf,len);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;buf+=n;len-=(size_t)n;}
    return 0;
}

int main(void){
    signal(SIGPIPE,SIG_IGN);
    int server=socket(AF_INET,SOCK_STREAM,0);if(server<0)return 1;
    int on=1;setsockopt(server,SOL_SOCKET,SO_REUSEADDR,&on,sizeof on);
    struct sockaddr_in addr={0};addr.sin_family=AF_INET;addr.sin_port=htons(KLOG_PORT);addr.sin_addr.s_addr=htonl(INADDR_ANY);
    if(bind(server,(struct sockaddr *)&addr,sizeof addr)||listen(server,1)){close(server);return 1;}
    for(;;){
        int client=accept(server,NULL,NULL);if(client<0){if(errno==EINTR)continue;break;}
        int klog=open("/dev/klog",O_RDONLY);
        if(klog<0){char msg[96];int n=snprintf(msg,sizeof msg,"klog-server: open /dev/klog failed errno=%d\n",errno);send_all(client,msg,(size_t)n);close(client);continue;}
        char buf[4096];
        for(;;){
            ssize_t n=read(klog,buf,sizeof buf);
            if(n<0&&errno==EINTR)continue;
            if(n<=0||send_all(client,buf,(size_t)n))break;
        }
        close(klog);close(client);
    }
    close(server);return 0;
}
