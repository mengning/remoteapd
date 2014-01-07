/*
 * Linux 80211 wrapper functions
 * Copyright (c) 2013-2014, Mengning <mengning@ustc.edu.cn>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef LINUX_80211_WRAPPER_H
#define LINUX_80211_WRAPPER_H

struct nl80211_global {
	struct dl_list interfaces;
	int if_add_ifindex;
	struct netlink_data *netlink;
	struct nl_cb *nl_cb;
	struct nl_handle *nl;
	int nl80211_id;
	int ioctl_sock; /* socket for ioctl() use */

	struct nl_handle *nl_event;
};

struct nl80211_wiphy_data {
	struct dl_list list;
	struct dl_list bsss;
	struct dl_list drvs;

	struct nl_handle *nl_beacons;
	struct nl_cb *nl_cb;

	int wiphy_idx;
};


struct i802_bss {
	struct wpa_driver_nl80211_data *drv;
	struct i802_bss *next;
	int ifindex;
	char ifname[IFNAMSIZ + 1];
	char brname[IFNAMSIZ];
	unsigned int beacon_set:1;
	unsigned int added_if_into_bridge:1;
	unsigned int added_bridge:1;
	unsigned int in_deinit:1;

	u8 addr[ETH_ALEN];

	int freq;

	void *ctx;
	struct nl_handle *nl_preq, *nl_mgmt;
	struct nl_cb *nl_cb;

	struct nl80211_wiphy_data *wiphy_data;
	struct dl_list wiphy_list;
};

struct wpa_driver_nl80211_data {
	struct nl80211_global *global;
	struct dl_list list;
	struct dl_list wiphy_list;
	char phyname[32];
	void *ctx;
	int ifindex;
	int if_removed;
	int if_disabled;
	int ignore_if_down_event;
	struct rfkill_data *rfkill;
	struct wpa_driver_capa capa;
	int has_capability;

	int operstate;

	int scan_complete_events;

	struct nl_cb *nl_cb;

	u8 auth_bssid[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	int associated;
	u8 ssid[32];
	size_t ssid_len;
	enum nl80211_iftype nlmode;
	enum nl80211_iftype ap_scan_as_station;
	unsigned int assoc_freq;

	int monitor_sock;
	int monitor_ifidx;
	int monitor_refcount;

	unsigned int disabled_11b_rates:1;
	unsigned int pending_remain_on_chan:1;
	unsigned int in_interface_list:1;
	unsigned int device_ap_sme:1;
	unsigned int poll_command_supported:1;
	unsigned int data_tx_status:1;
	unsigned int scan_for_auth:1;
	unsigned int retry_auth:1;
	unsigned int use_monitor:1;
	unsigned int ignore_next_local_disconnect:1;

	u64 remain_on_chan_cookie;
	u64 send_action_cookie;

	unsigned int last_mgmt_freq;

	struct wpa_driver_scan_filter *filter_ssids;
	size_t num_filter_ssids;

	struct i802_bss first_bss;

	int eapol_tx_sock;

#ifdef HOSTAPD
	int eapol_sock; /* socket for EAPOL frames */

	int default_if_indices[16];
	int *if_indices;
	int num_if_indices;

	int last_freq;
	int last_freq_ht;
#endif /* HOSTAPD */

	/* From failed authentication command */
	int auth_freq;
	u8 auth_bssid_[ETH_ALEN];
	u8 auth_ssid[32];
	size_t auth_ssid_len;
	int auth_alg;
	u8 *auth_ie;
	size_t auth_ie_len;
	u8 auth_wep_key[4][16];
	size_t auth_wep_key_len[4];
	int auth_wep_tx_keyidx;
	int auth_local_state_change;
	int auth_p2p;
};

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
