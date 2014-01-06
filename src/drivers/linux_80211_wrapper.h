/*
 * Linux 80211 wrapper functions
 * Copyright (c) 2013-2014, Mengning <mengning@ustc.edu.cn>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef LINUX_80211_WRAPPER_H
#define LINUX_80211_WRAPPER_H
/*
 * nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
 */
struct nl_handle * nl_create_handle(struct nl_cb *cb, const char *dbg);
/* 
 * "nl80211" to id
 * nl80211_id = genl_ctrl_resolve(global->nl, "nl80211"); 
 * Resolve generic netlink family name to its identifier. 
 * msg = nlmsg_alloc();
 * genlmsg_put(msg, 0, 0, nl80211_id, 0, flags, cmd, 0);
 * NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, "nl80211");
 * 
 */

int nl_send_wrapper(struct nl_handle *handle, struct nl_msg *msg);
/* 
 * int process_event(struct nl_msg *msg, void *arg);
 * nl_cb_set(nl_cb, NL_CB_VALID, NL_CB_CUSTOM,
 *		  process_event, arg);
 */
int nl_recv_wrapper(struct nl_handle *handle, struct nl_cb *cb);
void nl_destroy_handles(struct nl_handle **handle);

/* 
 * callback:typedef void (*eloop_sock_handler)(int sock, void *eloop_data, void *user_data);
 */
int epoll_wrapper(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data);

/* 
 * callback:typedef void (*eloop_sock_handler)(int sock);
 */			     
int epoll_un_wrapper(int sock)

/* 
 * create socket
 */	
int epoll_create_socket_wrapper(int domain, int type, int protocol)

/* 
 * close socket
 */	
int epoll_close_wrapper(int sock);

/* 
 * set option
 */	
int epoll_setsockopt_wrapper(int sockfd, int level, int optname, void *optval, socklen_t optlen);

/* 
 * send socket
 */	
int epoll_sendto_wrapper (int sock, void * msg, int len, unsigned int flags, struct sockaddr * to, int tolen);

/* 
 * recieve msg
 */
int epoll_recvfrom_wrapper(int sock,void * msg, int len, unsigned int flags, struct sockaddr *from, socklen_t * fromlen);

#endif /* LINUX_80211_WRAPPER_H */
