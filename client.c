#include<stdio.h> 
#include<arpa/inet.h> /* internet socket */
#include<string.h>
//#define NDEBUG
#include<assert.h>

#define PORT    5001
#define IP_ADDR "127.0.0.1"
#define MAX_CONNECT_QUEUE   1024
#define MAX_BUF_LEN         1024

int main()
{
    int sockfd = -1;
    char buf[MAX_BUF_LEN];
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(PORT);
    serveraddr.sin_addr.s_addr = inet_addr(IP_ADDR);
    //bzero(&(serveraddr.sin_zero), 8);/* in string.h */
    memset(&serveraddr.sin_zero, 0, 8);
    sockfd = socket(PF_INET,SOCK_STREAM,0);
    assert((sockfd != -1));
    int ret = connect(sockfd,(struct sockaddr *)&serveraddr,sizeof(struct sockaddr));
/*    
    if(ret == -1)
    {
        fprintf(stderr,"Connect Error,%s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    /* talk with client here *
    ret = recv(sockfd,buf,MAX_BUF_LEN,0);
    if(ret > 0)
    {
        printf("Server send:%s\n",buf);   
    }
    ret = send(sockfd,"hello",sizeof("hello"),0);
    if(ret > 0)
    {
        printf("send \"hello\" to %s:%d\n",(char*)inet_ntoa(serveraddr.sin_addr),ntohs(serveraddr.sin_port));
    }
*/

    while(1)
    {
         ret = read(sockfd,buf,MAX_BUF_LEN);
	 if(ret>0)
          printf("Server send:%s\n",buf);
    }
    close(sockfd);
    return 0;
}
