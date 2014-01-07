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

#include "common.h"
#include "eloop.h"
#include "utils/list.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "l2_packet/l2_packet.h"
#include "netlink.h"
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

int eloop_register_wrapper(int sock, eloop_sock_handler handler,
			     void *eloop_data, void *user_data)
{
    return eloop_register_read_sock(sock,handler,eloop_data,user_data);
}

int no_seq_check(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

/* nl80211 code */
static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;
	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			 void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_SKIP;
}

int send_and_recv_wrapper(struct nl_cb *nl_cb,
			 struct nl_handle *nl_handle, struct nl_msg *msg,
			 int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;

	cb = nl_cb_clone(nl_cb);
	if (!cb)
		goto out;

	err = nl_send_wrapper(nl_handle, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	if (valid_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  valid_handler, valid_data);

	while (err > 0)
		nl_recv_wrapper(nl_handle, cb);
 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	return err;
}

struct family_data {
	const char *group;
	int id;
};


static int family_handler(struct nl_msg *msg, void *arg)
{
	struct family_data *res = arg;
	struct nlattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *mcgrp;
	int i;

	nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);
	if (!tb[CTRL_ATTR_MCAST_GROUPS])
		return NL_SKIP;

	nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], i) {
		struct nlattr *tb2[CTRL_ATTR_MCAST_GRP_MAX + 1];
		nla_parse(tb2, CTRL_ATTR_MCAST_GRP_MAX, nla_data(mcgrp),
			  nla_len(mcgrp), NULL);
		if (!tb2[CTRL_ATTR_MCAST_GRP_NAME] ||
		    !tb2[CTRL_ATTR_MCAST_GRP_ID] ||
		    os_strncmp(nla_data(tb2[CTRL_ATTR_MCAST_GRP_NAME]),
			       res->group,
			       nla_len(tb2[CTRL_ATTR_MCAST_GRP_NAME])) != 0)
			continue;
		res->id = nla_get_u32(tb2[CTRL_ATTR_MCAST_GRP_ID]);
		break;
	};

	return NL_SKIP;
}


int nl_get_multicast_id_wrapper(struct nl_cb *nl_cb,
			        struct nl_handle *nl_handle,
			       const char *family, const char *group)
{
	struct nl_msg *msg;
	int ret = -1;
	struct family_data res = { group, -ENOENT };

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;
	genlmsg_put(msg, 0, 0, genl_ctrl_resolve(nl_handle, "nlctrl"),
		    0, 0, CTRL_CMD_GETFAMILY, 0);
	NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

	ret = send_and_recv_wrapper(nl_cb, nl_handle, msg, family_handler, &res);
	msg = NULL;
	if (ret == 0)
		ret = res.id;

nla_put_failure:
	nlmsg_free(msg);
	return ret;
}

int nl80211_init_event(struct nl_cb ** nl_cb,struct nl_handle ** nl_handle)
{
    int ret;
    
    *nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
    if (*nl_cb == NULL) 
    {
        wpa_printf(MSG_ERROR, "nl80211: Failed to allocate netlink "
               "callbacks");
        return -1;
    }
    *nl_handle = nl_create_handle(*nl_cb,"nl80211");
    if (*nl_handle == NULL)
    {
        goto err;
    }
    ret = nl_get_multicast_id_wrapper(*nl_cb, *nl_handle, "nl80211", "scan");
    if (ret >= 0)
    {
        ret = nl_socket_add_membership(*nl_handle, ret);
    }
	if (ret < 0) 
	{
        wpa_printf(MSG_ERROR, "nl80211: Could not add multicast "
               "membership for scan events: %d (%s)",
               ret, strerror(-ret));
        goto err;
    }

    ret = nl_get_multicast_id_wrapper(*nl_cb, *nl_handle, "nl80211", "mlme");
	if (ret >= 0)
	{
        ret = nl_socket_add_membership(*nl_handle, ret);
    }
    if (ret < 0) 
    {
        wpa_printf(MSG_ERROR, "nl80211: Could not add multicast "
               "membership for mlme events: %d (%s)",
               ret, strerror(-ret));
        goto err;
    }

    ret = nl_get_multicast_id_wrapper(*nl_cb, *nl_handle, "nl80211", "regulatory");
    if (ret >= 0)
    {
        ret = nl_socket_add_membership(*nl_handle, ret);
    }
	if (ret < 0) 
	{
        wpa_printf(MSG_DEBUG, "nl80211: Could not add multicast "
               "membership for regulatory events: %d (%s)",
               ret, strerror(-ret));
        /* Continue without regulatory events */
    } 
    return 0;
err:
    nl_destroy_handles(nl_handle);
    nl_cb_put(*nl_cb);
    *nl_cb = NULL;
    return -1;      
}

int netlink_init_nl80211_event_rtm(struct netlink_data ** netlink,void * ctx,
                                    nl80211_event_rtm_handler newlink,
                                    nl80211_event_rtm_handler dellink)
{
    struct netlink_config * cfg;
    cfg = os_zalloc(sizeof(struct netlink_config));
    if (cfg == NULL)
    {
        goto err;
    }
    
    cfg->ctx = ctx;
    cfg->newlink_cb = newlink;
    cfg->dellink_cb = dellink;
    *netlink = netlink_init(cfg);
    if (*netlink == NULL) 
    {
        os_free(cfg);
        goto err;
    }
    return 0;
err:
    return -1;   
}
int init_ioctl_sock()
{
    int ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (ioctl_sock < 0) 
	{
        perror("socket(PF_INET,SOCK_DGRAM)");
        return -1;
	}
	return ioctl_sock;
}


void nl80211_get_phy_name(char phyname[32],char ifname[IFNAMSIZ + 1])
{
	/* Find phy (radio) to which this interface belongs */
	char buf[90], *pos;
	int f, rv;

	phyname[0] = '\0';
	snprintf(buf, sizeof(buf) - 1, "/sys/class/net/%s/phy80211/name",
		 ifname);
	f = open(buf, O_RDONLY);
	if (f < 0) {
		wpa_printf(MSG_DEBUG, "Could not open file %s: %s",
			   buf, strerror(errno));
		return;
	}

	rv = read(f, phyname, sizeof(phyname) - 1);
	close(f);
	if (rv < 0) {
		wpa_printf(MSG_DEBUG, "Could not read file %s: %s",
			   buf, strerror(errno));
		return;
	}

	phyname[rv] = '\0';
	pos = os_strchr(phyname, '\n');
	if (pos)
		*pos = '\0';
	wpa_printf(MSG_DEBUG, "nl80211: interface %s in phy %s",
		   ifname, phyname);
}
