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
int send_and_recv_wrapper(struct nl_cb *nl_cb,
			 struct nl_handle *nl_handle, struct nl_msg *msg,
			 int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data);
void nl_destroy_handles(struct nl_handle **handle);

int nl_get_multicast_id_wrapper(struct nl_cb *nl_cb,
			        struct nl_handle *nl_handle,
			       const char *family, const char *group);

typedef void (*eloop_sock_handler)(int sock, void *eloop_data, void *user_data);
int eloop_register_wrapper(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data);
			     
int nl80211_init_event(struct nl_cb ** nl_cb,struct nl_handle ** nl_handle);

typedef void (*nl80211_event_rtm_handler)(void *ctx, struct ifinfomsg *ifi, u8 *buf, size_t len);
int netlink_init_nl80211_event_rtm(struct netlink_data ** netlink,void * ctx,
                                    nl80211_event_rtm_handler newlink,
                                    nl80211_event_rtm_handler dellink );
int init_ioctl_sock();
int no_seq_check(struct nl_msg *msg, void *arg);

void nl80211_get_phy_name(char phyname[32],char ifname[IFNAMSIZ + 1]);

#endif /* LINUX_80211_WRAPPER_H */
