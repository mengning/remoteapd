/*
 * Linux 80211 wrapper functions
 * Copyright (c) 2013-2014, Mengning <mengning@ustc.edu.cn>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>
#include "nl80211_copy.h"

#include<stdio.h>
#include<arpa/inet.h>
#include<assert.h>
#include<string.h>

#define PORT                    5001
#define IP_ADDR                 "127.0.0.1"
#define MAX_CONNECT_QUEUE       1024
#define MAX_BUF_LEN             1024

#include "common.h"
#include "eloop.h"
#include "utils/list.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "l2_packet/l2_packet.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "radiotap.h"
#include "radiotap_iter.h"
#include "rfkill.h"
#include "driver.h"

#include "linux_80211_wrapper.h"

#ifdef CONFIG_LIBNL20
/* libnl 2.0 compatibility code */
#define nl_handle nl_sock
#define nl80211_handle_alloc nl_socket_alloc_cb
#define nl80211_handle_destroy nl_socket_free
#else
/*
 * libnl 1.1 has a bug, it tries to allocate socket numbers densely
 * but when you free a socket again it will mess up its bitmap and
 * and use the wrong number the next time it needs a socket ID.
 * Therefore, we wrap the handle alloc/destroy and add our own pid
 * accounting.
 */
static uint32_t port_bitmap[32] = { 0 };


static struct nl_handle *nl80211_handle_alloc(void *cb)
{
	struct nl_handle *handle;
	uint32_t pid = getpid() & 0x3FFFFF;
	int i;

	handle = nl_handle_alloc_cb(cb);

	for (i = 0; i < 1024; i++) {
		if (port_bitmap[i / 32] & (1 << (i % 32)))
			continue;
		port_bitmap[i / 32] |= 1 << (i % 32);
		pid += i << 22;
		break;
	}

	nl_socket_set_local_port(handle, pid);

	return handle;
}

static void nl80211_handle_destroy(struct nl_handle *handle)
{
	uint32_t port = nl_socket_get_local_port(handle);

	port >>= 22;
	port_bitmap[port / 32] &= ~(1 << (port % 32));

	nl_handle_destroy(handle);
}
#endif /* CONFIG_LIBNL20 */

struct nl_handle * nl_create_handle(struct nl_cb *cb, const char *dbg)
{
	struct nl_handle *handle;

	handle = nl80211_handle_alloc(cb);
	if (handle == NULL) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to allocate netlink "
			   "callbacks (%s)", dbg);
		return NULL;
	}

	if (genl_connect(handle)) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to connect to generic "
			   "netlink (%s)", dbg);
		nl80211_handle_destroy(handle);
		return NULL;
	}

	return handle;
}


void nl_destroy_handles(struct nl_handle **handle)
{
	if (*handle == NULL)
		return;
	nl80211_handle_destroy(*handle);
	*handle = NULL;
}

int nl_send_wrapper(struct nl_handle *handle, struct nl_msg *msg)
{   
    return nl_send_auto_complete(handle, msg);
}

int nl_recv_wrapper(struct nl_handle *handle, struct nl_cb *cb)
{
    return nl_recvmsgs(handle,cb);
}

int epoll_wrapper(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data)
{
    return eloop_register_read_sock(sock,handler,eloop_data,user_data);
}

int epoll_register_wrapper(int sock, eloop_sock_handler handler,
                  void *eloop_data, void *user_data)
{
    return eloop_register_read_sock(sock,handler,eloop_data,user_data);
}

void epoll_unregister_wrapper(int sock)
{
    eloop_unregister_read_sock(sock);
}


int eapol_socket_create_wrapper()
{
    return socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_PAE));
}

int eapol_tx_socket_create_wrapper()
{
    return socket(PF_PACKET, SOCK_DGRAM, 0);
}



int i80211ext_server_init()
{
    
    int fd = -1;//用来监听的fd
    int ret = -1;
    char buf[MAX_BUF_LEN];
    struct sockaddr_in serveradd;//server的地址
    struct sockaddr_in clientaddr;//client的地址吧
    socklen_t clientaddr_len = sizeof(struct sockaddr);
    serveradd.sin_family = AF_INET;//类型
    serveradd.sin_port = ntohs(PORT);//端口
    serveradd.sin_addr.s_addr = inet_addr(IP_ADDR);//IP地址

    bzero(&(serveradd.sin_zero),8);
    fd = socket(PF_INET,SOCK_STREAM,0);
    assert(fd != -1);

    ret = bind(fd,(struct sockaddr *)&serveradd,sizeof(struct sockaddr));
    if(ret == -1)
    {
        fprintf(stderr,"Bind Error %s:%d\n",__FILE__,__LINE__);
        return -1;
    }
    ret = listen(fd,MAX_CONNECT_QUEUE);
    assert(ret != -1);

    //已经建立了
    newfd = accept(fd,(struct sockaddr *)&clientaddr,&clientaddr_len);
    
    return 1;
    //write(newfd,"nimei",sizeof("nimei"));
}

int send_msg_to_client(char* a,int len)
{
    return write(newfd,a,len);
}



