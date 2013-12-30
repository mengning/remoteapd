remoteapd
=========

Remote NL80211-Extent driver for Hostapd 2.0

Next Milestone:分析driver_nl80211ext.c 使用方案1或方案2将stream网络服务器集成进来，当然首先要弄清楚数据收发的位置并确定集成方案。

Milestone(已完成):为Hostapd 2.0增加一个driver,取名叫nl80211ext（配置文件中的名字），参照driver_nl80211.c增加一个driver_nl80211ext.c 功能保持nl80211不变。

编译Hostapd和构建无线AP的方法参见http://teampal.mc2lab.com/projects/fwn/wiki/SetupHostapd
