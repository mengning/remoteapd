/*
 * Linux 80211 wrapper functions
 * Copyright (c) 2013-2014, Mengning <mengning@ustc.edu.cn>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef LINUX_80211_WRAPPER_H
#define LINUX_80211_WRAPPER_H

struct nl_handle * nl_create_handle(struct nl_cb *cb, const char *dbg);
void nl_destroy_handles(struct nl_handle **handle);
int nl_send_wrapper(struct nl_handle *handle, struct nl_msg *msg);
int nl_recv_wrapper(struct nl_handle *handle, struct nl_cb *cb);

#endif /* LINUX_80211_WRAPPER_H */
