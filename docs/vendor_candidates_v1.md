# Embedded/IoT Vendor Candidates v1 (data-driven discovery, corrected inclusion rule)

Retrieved: 2026-09-04T23:53:30+00:00 from NVD CVE API 2.0 (full corpus, no date filter).

**v1 vs v0:** v0 (`docs/vendor_candidates.md`) required `part:h` marked `vulnerable: true`, which excludes nearly every embedded CVE published after ~2011 (NVD moved to an AND-node pair: firmware as `part:o` `..._firmware` marked vulnerable, hardware as `part:h` marked `vulnerable: false` as the running-on target). v1 matches `part:h` regardless of the `vulnerable` flag, plus `part:o` products ending in `_firmware`. See `src/corpus_filter.py` for the rule.

**Rule-tag breakdown across the full corpus** (a CVE can match more than one tag, so these do not sum to the inclusion-hit total):

| Rule tag | CVE count |
|---|---:|
| `h_any` (v1 Include A) | 32,306 |
| `h_vulnerable_true` (old v0 rule, subset of h_any) | 3,042 |
| `o_firmware` (v1 Include C) | 25,786 |

**Method:** a CVE is counted if it matches corpus_filter's inclusion rule (v1), AND its English description matches a category keyword restricting scope to consumer/small-business network equipment, broadband gateways, IP cameras, or NAS. Vendor names are taken verbatim from the CPE `criteria` vendor field (not normalized/deduplicated across spelling variants). Include B (curated vendor + model-designator pattern) is not applied here -- no curated vendor list yet.

**This is a candidate list for manual pruning, not the final curated vendor list.** Known limitations:
- Vendor spelling variants are not merged (e.g. `tp-link` vs `tplink` would appear as separate rows if both occur).
- Description-keyword category matching is a heuristic and can miss or miscategorize records.
- Since April 15, 2026 NIST limits routine NVD enrichment (and therefore `configurations` population) to CISA KEV / federal-government / EO 14028 software. Triage-era (post-2026-03-01) CVEs are structurally under-represented here regardless of vendor — this list skews toward vendors with a long pre-2026 history and should not be read as current market share.
- Soft exclusion categories (enterprise/ICS/medical/automotive/mobile/general-purpose computer) are deferred to Week 4 -- entries like enterprise gateway appliances may still appear here.

**Corpus:** 386,755 CVEs scanned; 32,964 matched the inclusion rule; 3,106 matched the category filter; 553 distinct vendors.

| Rank | Vendor (CPE field, verbatim) | CVE count | Distinct products | Example products |
|---:|---|---:|---:|---|
| 1 | cisco | 207 | 1555 | asr_9010, asr_9904, asr_9910, asr_9912, asr_9922 |
| 2 | qualcomm | 177 | 2443 | wcd9380, wcd9380_firmware, wsa8830, wsa8835, wsa8830_firmware |
| 3 | dlink | 174 | 375 | dir-605l, dir-605l_firmware, dwr-932b, dwr-932b_firmware, dir-878 |
| 4 | samsung | 98 | 113 | exynos_980_firmware, exynos_980, exynos_1080_firmware, exynos_1080, exynos_2200_firmware |
| 5 | mediatek | 98 | 254 | mt6853, mt6873, mt6877, mt6893, mt6833 |
| 6 | netgear | 95 | 315 | rax50, rax50_firmware, rax30, rax30_firmware, fvs318 |
| 7 | tenda | 88 | 56 | ac18_firmware, ac18, ac9, ac9_firmware, ac7 |
| 8 | tp-link | 86 | 98 | tl-wr886n_firmware, tapo_c200_firmware, tl-wr886n, eap225, eap225_firmware |
| 9 | citrix | 57 | 31 | netscaler_gateway_firmware, application_delivery_controller_firmware, netscaler_application_delivery_controller_firmware, netscaler_access_gateway_firmware, application_delivery_controller |
| 10 | linksys | 54 | 48 | wrt54g, befsr41, befw11s4, wap11, wag54gs |
| 11 | unisoc | 51 | 24 | t610, t618, s8000, sc7731e, sc9863a |
| 12 | siemens | 46 | 469 | scalance_w1750d, scalance_w1750d_firmware, scalance_m804pb, scalance_m874-2, scalance_m874-3 |
| 13 | zyxel | 43 | 144 | prestige, p-660hw, n300_netusb_nbg-419n, zynos, p-2602hw-d1a |
| 14 | huawei | 39 | 91 | honor_4c_firmware, eva-l09_firmware, me60, vie-l09_firmware, p8_firmware |
| 15 | totolink | 38 | 62 | a7100ru, a7100ru_firmware, a720r, a720r_firmware, a3002ru |
| 16 | asus | 36 | 247 | rt-ac68u, rt-ax56u, rt-n10e_firmware, rt-ac1900p, rt-ax3000 |
| 17 | wavlink | 35 | 45 | wl-wn533a8, wl-wn533a8_firmware, wn530h4, wn530h4_firmware, wifi-repeater_firmware |
| 18 | mi | 33 | 24 | ax3600, ax3600_firmware, xiaomi_r3600, xiaomi_r3600_firmware, ax1800 |
| 19 | motorola | 32 | 27 | cx2, cx2_firmware, surfboard, cx2l, cx2l_firmware |
| 20 | d-link | 31 | 45 | dl-704, dwl-900ap\+, dcs-900_internet_camera, di-604, dwl-1000ap |
| 21 | foscam | 30 | 16 | c1, c1_firmware, c1_indoor_hd_camera, c1_indoor_hd_camera_firmware, fi8919w |
| 22 | inhandnetworks | 27 | 8 | ir615, ir615_firmware, inrouter_900, inrouter_900_firmware, inrouter302 |
| 23 | belkin | 25 | 23 | f5d7230-4, n300, n900, belkin_54g_wireless_router, n300_firmware |
| 24 | skyworthdigital | 25 | 2 | cm5100, cm5100_firmware |
| 25 | symantec | 24 | 28 | gateway_security, brightmail_gateway_appliance, web_gateway_appliance_8450, web_gateway_appliance_8490, gateway_security_5400 |
| 26 | tendacn | 24 | 28 | ac9, ac9_firmware, ac18_firmware, ac15, ac15_firmware |
| 27 | juniper | 23 | 94 | mx2010, mx2020, mx480, mx960, mx240 |
| 28 | moxa | 23 | 44 | awk-3131a, awk-3131a_firmware, edr-g903, edr-g903_firmware, vport_06ec-2v26m |
| 29 | axis | 21 | 28 | 2400_video_server, 2401_video_server, 2100_network_camera, 2420_network_camera, 2110_network_camera |
| 30 | edimax | 21 | 21 | br-6476ac, br-6476ac_firmware, br-6478ac_v3, br-6478ac_v3_firmware, br-6428ns |
| 31 | trendnet | 20 | 25 | tew-812dru, tew-827dru, tew-827dru_firmware, securview_wireless_internet_camera, tv-ip422w |
| 32 | zte | 17 | 30 | zxv10_w300, zxv10_w300_firmware, zxhn_f670, zxhn_f670_firmware, e8820v3 |
| 33 | 3com | 16 | 11 | 3cp4144, 3crwe454g72, 3crwe754g72-a, 3crwe554g72t, hiperarc |
| 34 | lenovo | 16 | 99 | ez_media_\&_backup_center, ez_media_\&_backup_center_firmware, storcenter_px12-450r, storcenter_px12-400r, storcenter_px4-300r |
| 35 | vivotek | 16 | 400 | camera, pt7135_firmware, ip7137, ip7137_firmware, pt7135 |
| 36 | dahuasecurity | 15 | 166 | dvr0404hd-a, dvr0404hd-l, dvr0404hd-s, dvr0404hd-u, dvr0404hf-a-e |
| 37 | geutebrueck | 14 | 38 | g-cam_ebc-2110_firmware, g-cam_ebc-2111_firmware, g-cam_efd-2241_firmware, g-cam_efd-2250_firmware, g-cam_ethc-2230_firmware |
| 38 | drobo | 14 | 2 | 5n2, 5n2_firmware |
| 39 | hikvision | 13 | 100 | ds-2cd7153-e, ds-2cd7153-e_firmware, ds-7604ni-e1\/4p, ds-7608ni-12\/8p, ds-7608ni-e1\/8p |
| 40 | chinamobile | 13 | 6 | an_lianbao_wf-1, an_lianbao_wf-1_firmware, intelligent_home_gateway, intelligent_home_gateway_firmware, gpn2.4p21-c-cn |
| 41 | intel | 12 | 47 | xmm_7560, xmm_7560_firmware, express_8100, xmm_7360, xmm_7360_firmware |
| 42 | intelbras | 12 | 12 | iwr_3000n, iwr_3000n_firmware, rx_1500, rx_1500_firmware, nplug |
| 43 | ruckuswireless | 12 | 101 | vsz_firmware, sz-300_firmware, sz-100_firmware, vsz, sz-300 |
| 44 | abb | 12 | 68 | tg\/s3.2, tg\/s3.2_firmware, ip_gateway, ip_gateway_firmware, gate-e1 |
| 45 | yitechnology | 12 | 2 | yi_home_camera, yi_home_camera_firmware |
| 46 | bosch | 11 | 171 | cpp7.3_firmware, cpp7_firmware, cpp6_firmware, cpp6, cpp7 |
| 47 | westerndigital | 11 | 23 | my_cloud_ex4100, my_cloud_pr2100, my_cloud_pr4100, my_cloud_ex2_ultra, my_cloud_mirror_gen_2 |
| 48 | hanwhavision | 11 | 1112 | pnm-7002vd, pnm-9002vq, pnm-9084qz1, pnm-9084rqz, pnm-9085rqz |
| 49 | qnap | 10 | 33 | nas, viostor_network_video_recorder, ej1600, tl-r1620sdc, tl-r1620sep-rp |
| 50 | schneider-electric | 10 | 147 | d6220, d6220l, d6230, d6230l, imes19-1i |
| 51 | toshiba | 10 | 4 | hem-gw16a, hem-gw26a, hem-gw16a_firmware, hem-gw26a_firmware |
| 52 | synology | 10 | 12 | bc500, tc500, bc500_firmware, tc500_firmware, ds107 |
| 53 | sv3c | 10 | 4 | sv-b01poe-1080p-l, sv-b11vpoe-1080p-l, sv-d02poe-1080p-l, h.264_poe_ip_camera_firmware |
| 54 | billion | 10 | 4 | 5200w-t, 5200w-t_firmware, sg600_r2, sg600_r2_firmware |
| 55 | realtek | 9 | 13 | rtl8195a, rtl8195a_firmware, rtk_11n_ap, rtk_11n_ap_firmware, adsl_router_soc_firmware |
| 56 | byzoro | 9 | 2 | smart_s45f, smart_s45f_firmware |
| 57 | binardat | 9 | 2 | 10g08-0800gsm, 10g08-0800gsm_firmware |
| 58 | dell | 8 | 31 | edge_gateway_5200, edge_gateway_3200, truemobile_2300_wireless_broadband_router, edge_gateway_5200_firmware, edge_gateway_3200_firmware |
| 59 | advantech | 8 | 8 | eki-6333ac-2g, eki-6333ac-2gd, eki-6333ac-1gpo, eki-6333ac-2g_firmware, eki-6333ac-2gd_firmware |
| 60 | iptime | 8 | 348 | c200, c200_firmware, nas1dual, nas2dual, nas4dual |
| 61 | pepperl-fuchs | 8 | 6 | wha-gw-f2d2-0-as-z2-eth_firmware, wha-gw-f2d2-0-as-z2-eth, wha-gw-f2d2-0-as-z2-eth.eip_firmware, wha-gw-f2d2-0-as-z2-eth.eip, wha-gw-f2d2-0-as-_z2-eth.eip |
| 62 | syrotech | 8 | 2 | sy-gpon-1110-wdont, sy-gpon-1110-wdont_firmware |
| 63 | level1 | 8 | 2 | wbr-6012, wbr-6012_firmware |
| 64 | aqara | 8 | 6 | camera_hub_g3, camera_hub_g3_firmware, hub_m2, hub_m3, hub_m2_firmware |
| 65 | nortel | 7 | 16 | contivity, vpn_router_5000, vpn_router_1010, vpn_router_1050, vpn_router_1100 |
| 66 | ibm | 7 | 24 | websphere_datapower_xml_security_gateway_xs40, websphere_datapower_xml_accelerator_xa35, websphere_datapower_datapower_integration_appliance_xi50, websphere_datapower_b2b_appliance_xb60, websphere_datapower_low_latency_appliance_xm70 |
| 67 | seagate | 7 | 12 | blackarmor_nas_220, blackarmor_nas_220_firmware, blackarmor_nas_110, blackarmor_nas_110_firmware, business_nas |
| 68 | xiongmaitech | 7 | 180 | nbd80x09s-kl, nbd80x09ra-kl, mbd6304t, nbd6808t-pl, nbd7004t-p |
| 69 | milesight | 7 | 56 | ncr\/camera, ncr\/camera_firmware, video_management_systems_firmware, ms-n5008-uc, ms-n1008-unc |
| 70 | buffalo | 7 | 96 | wcr-1166dhpl, wsr3600be4-kh, wsr3600be4p, wxr-1750dhp, wxr-1750dhp2 |
| 71 | ruijie | 7 | 8 | eg-2000se_firmware, eg-2000se, rg-nbr700gw, rg-nbr700gw_firmware, nbr3000d-e |
| 72 | red-m | 6 | 1 | 1050ap_lan_acess_point |
| 73 | smc_networks | 6 | 4 | smcd3g-ccr, smc7004vbr, barricade_wireless_cable_dsl_broadband_router, smc7904wbra |
| 74 | conceptronic | 6 | 5 | c54apm, c54apm_firmware, cadslr1_adsl_router, cipcamptiwl, cipcamptiwl_1.0_firmware |
| 75 | sony | 6 | 129 | sony_network_camera_snc-p5, snc_ch140, snc_ch180, snc_ch240, snc_ch280 |
| 76 | arubanetworks | 6 | 21 | 7010, 7030, 7205, 7210, 7220 |
| 77 | hot | 6 | 2 | hotbox_router, hotbox_router_firmware |
| 78 | sierrawireless | 6 | 54 | airlink_mp_at\&t, airlink_mp_at\&t_wifi, airlink_mp_bell, airlink_mp_bell_wifi, airlink_mp_row |
| 79 | commscope | 6 | 6 | arris_sbg901, arris_tg1682g, arris_tg1682g_firmware, dg3450, dg3450_firmware |
| 80 | iodata | 6 | 19 | ts-wrlp, ts-wrlp\/e, ts-wrla, ts-wrlp_firmware, ts-wrlp\/e_firmware |
| 81 | technicolor | 6 | 7 | td5130_router_firmware, xfinity_gateway_router_dpc3941t, xfinity_gateway_router_dpc3941t_firmware, tc7337, tc7337_firmware |
| 82 | fiberhome | 6 | 8 | vdsl2_modem_hg_150-ub, vdsl2_modem_hg_150-ub_firmware, hg150-ub, hg150-ub_firmware, adsl_an1020-25 |
| 83 | honeywell | 6 | 26 | maxpro_nvr_se, maxpro_nvr_xe, maxpro_nvr_pe, maxpro_nvr_se_firmware, maxpro_nvr_xe_firmware |
| 84 | watchguard | 6 | 44 | firebox_m270, firebox_m290, firebox_m370, firebox_m390, firebox_m440 |
| 85 | netcommwireless | 6 | 8 | nwl-25, nwl-25_firmware, nf20, nf20mesh, nl1902 |
| 86 | kraftway | 6 | 2 | 24f2xg_router, 24f2xg_router_firmware |
| 87 | chinamobileltd | 6 | 3 | gpn2.4p21-c-cn, gpn2.4p21-c-cn_firmware, an_lianbao_wf-1 |
| 88 | elecom | 6 | 46 | wrc-2533ghbk-i, wrc-2533ghbk-i_firmware, wrc-300febk-r, wrc-300febk-r_firmware, wab-s600-ps |
| 89 | hitron | 6 | 12 | hvr-4781, hvr-4781_firmware, hvr-8781, hvr-8781_firmware, hvr-16781 |
| 90 | tormach | 6 | 1 | xstech_cnc_router |
| 91 | lb-link | 6 | 6 | ac1900, ac1900_firmware, bl-w1210m, bl-w1210m_firmware, bl-cpe300m |
| 92 | alcatel | 5 | 2 | speed_touch_home, speedtouch_7g_router |
| 93 | bt | 5 | 2 | home_hub, voyager_2000_wireless_adsl_router |
| 94 | sitecom | 5 | 5 | wlx-2006, wlx-2006_firmware, wl-153, wl-153_router_firmware, wlm-2501 |
| 95 | camtron | 5 | 1 | cmnc-200 |
| 96 | tecvoz | 5 | 1 | cmnc-200 |
| 97 | ovislink | 5 | 7 | airlive_wl2600cam, airlive_od-2025hd, airlive_od-2060hd, airlive_poe100hd, airlive_poe200hd |
| 98 | grandstream | 5 | 34 | gxv_device_firmware, gxv3500, gxv3501, gxv3504, gxv3601 |
| 99 | f5 | 5 | 25 | big-ip_access_policy_manager, big-ip_i10600, big-ip_i10800, big-ip_i11600, big-ip_i11800 |
| 100 | compal_broadband_networks | 5 | 2 | cg6640e_wireless_gateway, ch664oe_wireless_gateway |
| 101 | lg | 5 | 48 | l-04d, l-09c, l-03e, lnb5110, lnb5320 |
| 102 | broadcom | 5 | 24 | symantec_advanced_secure_gateway_s200-30_firmware, symantec_advanced_secure_gateway_s200-40_firmware, symantec_advanced_secure_gateway_s400-20_firmware, symantec_advanced_secure_gateway_s400-30_firmware, symantec_advanced_secure_gateway_s400-40_firmware |
| 103 | wificam | 5 | 2 | wireless_ip_camera_\(p2p\), wireless_ip_camera_\(p2p\)_firmware |
| 104 | twsz | 5 | 4 | wifi_repeater, wifi_repeater_firmware, be126, be126_firmware |
| 105 | phoenixcontact | 5 | 44 | tc_router_3002t-4g, tc_router_3002t-4g_vzw, tc_router_3002t-4g_att, tc_cloud_client_1002-4g, tc_router_3002t-4g_firmware |
| 106 | orange | 5 | 4 | arv7519rw22_livebox_2.1_firmware, arv7519rw22_livebox_2.1, airbox, airbox_firmware |
| 107 | kunbus | 5 | 2 | pr100088_modbus_gateway, pr100088_modbus_gateway_firmware |
| 108 | ishekar | 5 | 2 | endoscope_camera, endoscope_camera_firmware |
| 109 | insma | 5 | 2 | wifi_mini_spy_1080p_hd_security_ip_camera, wifi_mini_spy_1080p_hd_security_ip_camera_firmware |
| 110 | sannce | 5 | 2 | smart_hd_wifi_security_camera_ean_2_950004_595317, smart_hd_wifi_security_camera_ean_2_950004_595317_firmware |
| 111 | meritlilin | 5 | 86 | p2r8852e2, p2r8852e4, p2r6852e2, p2r6852e4, p2r6552e2 |
| 112 | airangel | 5 | 10 | hsmx-app-25, hsmx-app-100, hsmx-app-1000, hsmx-app-5000, hsmx-app-20000 |
| 113 | comfast_project | 5 | 2 | cf-wr623n, cf-wr623n_firmware |
| 114 | blurams | 5 | 6 | lumi_security_camera_a31c, lumi_security_camera_a31c_firmware, dome_flare, dome_flare_firmware, a31c |
| 115 | tesla | 5 | 4 | model_s, model_s_firmware, model_3, model_3_firmware |
| 116 | enphase | 5 | 2 | iq_gateway, iq_gateway_firmware |
| 117 | selea | 5 | 22 | izero_box_full, izero_column_entry\/8, izero_column_full\/8, targa_504, targa_512 |
| 118 | cayman | 4 | 2 | gatorsurf, 3220-h_dsl_router |
| 119 | apple | 4 | 7 | airport_express_base_station_firmware, airport_extreme_base_station_firmware, airport_base_station_firmware, airport_express, airport_extreme |
| 120 | thomson | 4 | 4 | speedtouch, tcm_cable_modem, tcw_cable_modem, thomson_cable_modem |
| 121 | mentor | 4 | 1 | adslfr4ii |
| 122 | 2wire | 4 | 9 | 1701hg_router, 2071_router, 1800hw_router, 1700hg, 1701hg |
| 123 | marvell | 4 | 3 | 88w8361w-bem1, 88w8361p-bem_chipset, 88w8361p-bem1 |
| 124 | intellicom | 4 | 7 | netbiter_easyconnect_ec150, netbiter_modbus_rtu-tcp_gateway_mb100, netbiter_serial_ethernet_server_ss100, netbiter_webscada_ws100, netbiter_webscada_ws200 |
| 125 | mercurycom | 4 | 6 | mr804, mipc252w, mipc252w_firmware, mr804_firmware, mr816 |
| 126 | verizon | 4 | 4 | fios_quantum_gateway_g1100, fios_quantum_gateway_g1100_firmware, fios_actiontec_mi424wr-gen31_router, fios_actiontec_mi424wr-gen31_router_firmware |
| 127 | google | 4 | 44 | glass, nest_cam_iq_indoor, nest_cam_iq_indoor_firmware, nest_hub_max, nest_hub |
| 128 | draytek | 4 | 186 | vigor_2700_router, vigor3910, vigor3910_firmware, vigor_2700_router_firmware, vigor2860 |
| 129 | arris | 4 | 2 | touchstone_tg862g\/ct, touchstone_dg950a |
| 130 | adcon | 4 | 1 | a840_telemetry_gateway_base_station_firmware |
| 131 | humaxdigital | 4 | 4 | hg100r, hg100r_firmware, hgb10r-02, hgb10r-02_firmware |
| 132 | meetcircle | 4 | 2 | circle_with_disney_firmware, circle_with_disney |
| 133 | - | 4 | 1 | wireless_ip_camera_360 |
| 134 | hanwha-security | 4 | 28 | snh-v6410pn, snh-v6410pnw, snh-v6410pn_firmware, snh-v6410pnw_firmware, hrd-1642 |
| 135 | planex | 4 | 4 | cs-wmv02g, cs-wmv02g_firmware, cs-w50hd, cs-w50hd_firmware |
| 136 | coship | 4 | 9 | wm3300_firmware, rt3050, rt3052, rt7620, wm3300 |
| 137 | four-faith | 4 | 4 | f3x36, f3x36_firmware, f3x24, f3x24_firmware |
| 138 | pix-link | 4 | 4 | lv-wr09, lv-wr09_firmware, lv-wr07, lv-wr07_firmware |
| 139 | amcrest | 4 | 38 | ipm-721s, ipm-721s_firmware, 1080-lite_8ch, amdv10814-h5, ipm-721 |
| 140 | loftek | 4 | 2 | nexus_543, nexus_543_firmware |
| 141 | netis-systems | 4 | 4 | netcore_router, netcore_router_firmware, wf2419_firmware, wf2419 |
| 142 | busch-jaeger | 4 | 2 | 6186\/11, 6186\/11_firmware |
| 143 | juplink | 4 | 2 | rx4-1500_firmware, rx4-1500 |
| 144 | gira | 4 | 4 | knx_ip_router_firmware, tks-ip-gateway, tks-ip-gateway_firmware, knx_ip_router |
| 145 | castel | 4 | 2 | nextgen_dvr, nextgen_dvr_firmware |
| 146 | genexis | 4 | 2 | platinum_4410, platinum_4410_firmware |
| 147 | ui | 4 | 11 | camera_g3_flex, camera_g3_flex_firmware, unifi_meshing_access_point, unifi_controller, unifi_meshing_access_point_firmware |
| 148 | reolink | 4 | 18 | e1_zoom, e1_zoom_firmware, rln8-410, rlc-422, rlc-510a |
| 149 | accfly | 4 | 2 | 720p, 720p_firmware |
| 150 | mc-technologies | 4 | 2 | mc_lr_router, mc_lr_router_firmware |
| 151 | waveshare | 4 | 2 | rs232\/485_to_wifi_eth_\(b\), rs232\/485_to_wifi_eth_\(b\)_firmware |
| 152 | zspace | 4 | 4 | q2c_nas, q2c_nas_firmware, q2c, q2c_firmware |
| 153 | seekswan | 4 | 2 | zikestor_sks8310-8x, zikestor_sks8310-8x_firmware |
| 154 | telesquare | 4 | 2 | sdt-cs3b1, sdt-cs3b1_firmware |
| 155 | qntmnet | 4 | 2 | qn-i-470, qn-i-470_firmware |
| 156 | u-speed | 4 | 4 | n300, n300_firmware, t18-21k, t18-21k_firmware |
| 157 | netopia | 3 | 3 | r-series_routers, 650-st_isdn_router, r9100_router |
| 158 | lucent | 3 | 7 | ascend_pipeline_router, ascend_max_router, orinoco_rg-1000, dslterminator, access_point_service_router_1500 |
| 159 | arescom | 3 | 1 | netdsl |
| 160 | iomega | 3 | 4 | network_attached_storage, nas, nas_a300u, nas_a300u_firmware |
| 161 | rca | 3 | 1 | digital_cable_modem |
| 162 | astaro | 3 | 1 | security_gateway |
| 163 | aztech | 3 | 2 | adsl2\/2\+4-port_router, dsl_600eu_router |
| 164 | panasonic | 3 | 12 | bb_hcm511, bb_hcm515, bb_hcm527, bb_hcm531, bb_hcm580 |
| 165 | sonicwall | 3 | 122 | tz300p_firmware, tz300w_firmware, tz350_firmware, tz350w_firmware, tz370_firmware |
| 166 | thecus | 3 | 2 | n8800_nas_server, n8800_nas_server_firmware |
| 167 | avtech | 3 | 2 | avn801_dvr, avn801_dvr_firmware |
| 168 | oleumtech | 3 | 2 | sensor_wireless_i\/o_module, wio_dh2_wireless_gateway |
| 169 | servision | 3 | 2 | hvg400, hvg_video_gateway_firmware |
| 170 | y-cam | 3 | 30 | ycbl03, ycblb3, ycw004, ycb002, ycb004 |
| 171 | systech | 3 | 2 | syslink_sl-1000_modular_gateway, syslink_sl-1000_modular_gateway_firmware |
| 172 | viprinet | 3 | 2 | multichannel_vpn_router_300_firmware, multichannel_vpn_router_300 |
| 173 | digisol | 3 | 6 | dg-hr1400, dg-hr1400_firmware, dg-hr1400_router, dg-hr1400_router_firmware, dg-hr-3300 |
| 174 | televes | 3 | 2 | coaxdata_gateway_1gbps, coaxdata_gateway_1gbps_firmware |
| 175 | qacctv | 3 | 4 | jooan_ja-q1h_wi-fi_camera, jooan_ja-q1h_wi-fi_camera_firmware, jooan_a5_ip_camera, jooan_a5_ip_camera_firmware |
| 176 | dasannetworks | 3 | 6 | h640x_firmware, h640x, gpon_router, gpon_router_firmware, h660rm |
| 177 | seasofsolutions | 3 | 2 | ip_camera, ip_camera_firmware |
| 178 | philips | 3 | 8 | intellivue_mx40, intellivue_mx40_firmware, veradius_unity, pulsera, endura |
| 179 | hughes | 3 | 16 | hn7000s, hn7000s_firmware, hn7740s, dw7000, hn7000sm |
| 180 | getvera | 3 | 6 | veraedge, veralite, veraedge_firmware, veralite_firmware, vera_edge |
| 181 | compal | 3 | 2 | ch7465lg, ch7465lg_firmware |
| 182 | comtech | 3 | 8 | h8_heights_remote_gateway, h8_heights_remote_gateway_firmware, stampede_fx-1010, stampede_fx-1010_firmware, cdm-625 |
| 183 | 360 | 3 | 16 | safe_router_p0, safe_router_p1, safe_router_p2, safe_router_p3, safe_router_p4 |
| 184 | siedle | 3 | 2 | sg_150-0, sg_150-0_firmware |
| 185 | farsite | 3 | 2 | farlinx_x25_gateway, farlinx_x25_gateway_firmware |
| 186 | avertx | 3 | 4 | hd838, hd438, hd838_firmware, hd438_firmware |
| 187 | nec | 3 | 22 | um8000, um8000_firmware, sv8100, sv9100, sl1100 |
| 188 | sagemcom | 3 | 6 | f\@st_5280_router, f\@st_5280_router_firmware, f\@st_3486_router, f\@st_3486_router_firmware, f\@st_3686 |
| 189 | company | 3 | 2 | cs-c2shw, cs-c2shw_firmware |
| 190 | emerson | 3 | 8 | wireless_1420_gateway, wireless_1420_gateway_firmware, smart_wireless_gateway_1420, smart_wireless_gateway_1420_firmware, wireless_1410_gateway |
| 191 | nvidia | 3 | 7 | jetson_agx_xavier, jetson_xavier_nx, jetson_nano, jetson_nano_2gb, jetson_tx1 |
| 192 | phicomm | 3 | 12 | k2, k3, k3c, k2g, k2p |
| 193 | ruijienetworks | 3 | 4 | rg-nbr2100g-e, rg-nbr2100g-e_firmware, rg-eg350, rg-eg350_firmware |
| 194 | ezviz | 3 | 26 | cs-c6n-b0-1g2wf, cs-c6n-b0-1g2wf_firmware, cs-c6n-r101-1g2wf, cs-cv310-a0-1b2wfr, cs-cv310-a0-1c2wfr-c |
| 195 | zbt | 3 | 2 | we1626, we1626_firmware |
| 196 | contec | 3 | 38 | cps-mg341-adsc1-111, cps-mg341-adsc1-931, cps-mg341g-adsc1-111, cps-mg341g-adsc1-930, cps-mg341g5-adsc1-931 |
| 197 | aigital | 3 | 2 | wireless-n_repeater_mini_router, wireless-n_repeater_mini_router_firmware |
| 198 | cpplusworld | 3 | 26 | cp-uvr-1601e1-hc, cp-uvr-0401l1-4kh, cp-uvr-0401l1b-4kh, cp-uvr-0801f1-hc, cp-uvr-0801k1-h |
| 199 | jaycar | 3 | 2 | la5570, la5570_firmware |
| 200 | netentsec | 3 | 4 | ns-asg, application_security_gateway_firmware, ns-asg_firmware, application_security_gateway |
| 201 | furunosystems | 3 | 28 | acera_1210, acera_1150i, acera_1150w, acera_1110, acera_1020 |
| 202 | gncchome | 3 | 2 | _gncc_c2, gncc_c2_firmware |
| 203 | asrmicro | 3 | 4 | asr1803, asr1806, asr1901, asr1903 |
| 204 | dbitnet | 3 | 2 | dbit_n300_t1_pro, dbit_n300_t1_pro_firmware |
| 205 | atmel | 2 | 2 | 802.11b_vnet-b_access_point, firmware |
| 206 | nokia | 2 | 3 | firewall_appliance, i-240w-q_gpon_ont, i-240w-q_gpon_ont_firmware |
| 207 | telindus | 2 | 2 | adsl_router, 1120_adsl_router |
| 208 | x-micro | 2 | 1 | wlan_11b_broadband_router_firmware |
| 209 | hawking_technology | 2 | 2 | har11a_dsl_router, wr254-ca_wireless_router |
| 210 | vocaltec | 2 | 1 | vgw4_8_telephony_gateway |
| 211 | sweex | 2 | 2 | wireless_broadband_router_accesspoint_802.11g, ro002_router |
| 212 | gigafast_ethernet | 2 | 1 | gigafast_router |
| 213 | securecomputing | 2 | 1 | samsung_adsl_modem |
| 214 | netcomm | 2 | 3 | nb1300, nb16wv-02, nb16wv-02_firmware |
| 215 | eci_telecom | 2 | 2 | b-focus_router, b-focus_wireless_802.11bg_adsl2\+_router |
| 216 | march_networks | 2 | 5 | 3204_dvr, 3108_dvr, 4210_dvr, 4310_dvr, 4410_dvr |
| 217 | avaya | 2 | 2 | s8300c_server, ag250 |
| 218 | atheros | 2 | 2 | ar5416-ac1e_chipset, ar9160-bc1a_chipset |
| 219 | armassa | 2 | 1 | ard-9808 |
| 220 | lifesize | 2 | 1 | lifesize_room_appliance |
| 221 | sophos | 2 | 3 | unified_threat_management, astaro_security_gateway_firmware, astaro_security_gateway |
| 222 | hp | 2 | 668 | 0150a129, 0150a12a, 0150a12b, 0150a12c, 0231a0av |
| 223 | brickcom | 2 | 7 | fb-100ap, md-100ap, ob-100ae, osd-040e, wcb-100ap |
| 224 | tvt | 2 | 8 | dvr_firmware, avision_av108t_firmware, td-2104ts-cl_firmware, td-2108ts-hp_firmware, dvr |
| 225 | upc | 2 | 3 | ireland_cisco_epc2425, connect_box_eurodocsis, connect_box_eurodocsis_firmware |
| 226 | beetel | 2 | 4 | 450tc2_router, 450tc2_router_firmware, 777vr1, 777vr1_firmware |
| 227 | qeiinc | 2 | 1 | epaq-9410_substation_gateway |
| 228 | zteusa | 2 | 9 | zxdsl_831cii, zte_blade_vantage, zte_blade_spark, zte_zmax_pro, zte_zmax_champ |
| 229 | teracom | 2 | 1 | t2-b-gawv1.4u10y-bi |
| 230 | iball | 2 | 2 | ib-wra150n, ib-wra150n_firmware |
| 231 | mikrotik | 2 | 3 | router_hap_lite, router, router_firmware |
| 232 | intellinet-network | 2 | 2 | nfc-30ir, nfc-30ir_firmware |
| 233 | asuswrt-merlin_project | 2 | 56 | rt-ac5300, rt_ac1900p_, rt-ac68u, rt-ac68p, rt-ac88u |
| 234 | tbkvision | 2 | 4 | tbk-dvr4216, tbk-dvr4104, tbk-dvr4216_firmware, tbk-dvr4104_firmware |
| 235 | insteon | 2 | 2 | 2864-222, 2864-222_firmware |
| 236 | intex | 2 | 2 | n150, n150_firmware |
| 237 | softcase | 2 | 2 | t-router, t-router_firmware |
| 238 | ee | 2 | 4 | ee40vb, ee40vb_firmware, 4gee, 4gee_firmware |
| 239 | keruigroup | 2 | 2 | ypc99, ypc99_firmware |
| 240 | actiontec | 2 | 4 | c1000a, c1000a_firmware, mi424wr-gen3i, mi424wr-gen3i_firmware |
| 241 | carel | 2 | 2 | pcoweb_card, pcoweb_card_firmware |
| 242 | starry | 2 | 2 | s00111, s00111_firmware |
| 243 | bd | 2 | 10 | alaris_gateway_workstation_firmware, alaris_gateway_workstation, alaris_gs_syringe_pump, alaris_gh_syringe_pump, alaris_cc_syringe_pump |
| 244 | securifi | 2 | 5 | almond_2015, almond\+, almond, almond_2015_firmware, almond_firmware |
| 245 | cylan | 2 | 4 | clever_dog_smart_camera_panorama_dog-2w, clever_dog_smart_camera_plus_dog-2w-v4, clever_dog_smart_camera_panorama_dog-2w_firmware, clever_dog_smart_camera_plus_dog-2w-v4_firmware |
| 246 | annke | 2 | 4 | sp1, sp1_firmware, crater_2, crater_2_firmware |
| 247 | ntt-east | 2 | 48 | pr-s300ne, rt-s300ne, rv-s340ne, pr-s300hi, rt-s300hi |
| 248 | ntt-west | 2 | 44 | pr-s300ne, rt-s300ne, rv-s340ne, pr-s300hi, rt-s300hi |
| 249 | ztehome | 2 | 2 | c520v21, c520v21_firmware |
| 250 | sapido | 2 | 2 | gr297n, gr297n_firmware |
| 251 | ciktel | 2 | 2 | mesh_router, mesh_router_firmware |
| 252 | kctvjeju | 2 | 2 | wireless_ap, wireless_ap_firmware |
| 253 | fg-products | 2 | 2 | fgn-r2, fgn-r2_firmware |
| 254 | hiwifi | 2 | 2 | max-c300n, max-c300n_firmware |
| 255 | tbroad | 2 | 2 | gn-866ac, gn-866ac_firmware |
| 256 | hcn_max-c300n_project | 2 | 2 | hcn_max-c300n, hcn_max-c300n_firmware |
| 257 | miele | 2 | 2 | xgw_3000_zigbee_gateway, xgw_3000_zigbee_gateway_firmware |
| 258 | tonnet | 2 | 16 | tat-77104g1, tat-70432n, tat-71416g1, tat-71832g1, tat-76104g3 |
| 259 | wago | 2 | 2 | pfc200, pfc200_firmware |
| 260 | yamaha | 2 | 30 | rtx830, nvr510, nvr700w, rtx1210, rtx5000 |
| 261 | cacagoo | 2 | 2 | tv-288zd-2mp, tv-288zd-2mp_firmware |
| 262 | rubetek | 2 | 6 | rv-3406_firmware, rv-3409_firmware, rv-3411_firmware, rv-3406, rv-3409 |
| 263 | mygeeni | 2 | 2 | gnc-cw013, gnc-cw013_firmware |
| 264 | askey | 2 | 4 | rtf3505vw-n1_br_sv_g000_r3505vwn1001_s32_7, rtf3505vw-n1_br_sv_g000_r3505vwn1001_s32_7_firmware, rtf3505vw-n1, rtf3505vw-n1_firmware |
| 265 | acexy | 2 | 2 | wireless-n_wifi_repeater, wireless-n_wifi_repeater_firmware |
| 266 | aruba | 2 | 1 | aruba_instant |
| 267 | govicture | 2 | 4 | pc420, pc420_firmware, wr1200, wr1200_firmware |
| 268 | meross | 2 | 4 | mss550x, mss550x_firmware, msh30q, msh30q_firmware |
| 269 | bkw | 2 | 2 | solar-log_500_firmware, solar-log_500 |
| 270 | gryphonconnect | 2 | 2 | gryphon_tower, gryphon_tower_firmware |
| 271 | digi | 2 | 17 | transport_wr41_firmware, transport_wr11, transport_wr11_xt, transport_wr21, transport_wr31 |
| 272 | allwinnertech | 2 | 1 | r818 |
| 273 | irz | 2 | 12 | ru21, ru21w, rl21, ru41, rl01 |
| 274 | razer | 2 | 2 | sila, sila_firmware |
| 275 | qvis | 2 | 4 | dvr, nvr, dvr_firmware, nvr_firmware |
| 276 | cellinx | 2 | 2 | cellinx_nvt_-_ip_ptz_camera_firmware, cellinx_nvt_-_ip_ptz_camera |
| 277 | hitachi | 2 | 2 | hc-ip9100hd, hc-ip9100hd_firmware |
| 278 | mipcm | 2 | 2 | mipc_camera, mipc_camera_firmware |
| 279 | optilinknetwork | 2 | 2 | op-xt71000n, op-xt71000n_firmware |
| 280 | solar-log | 2 | 20 | solar-log_500_firmware, solar-log_500, solar-log_250_firmware, solar-log_300_firmware, solar-log_800e_firmware |
| 281 | siretta | 2 | 2 | quartz-gold, quartz-gold_firmware |
| 282 | terra-master | 2 | 29 | f2-210, f2-221, f2-223, f2-422, f2-423 |
| 283 | comfast | 2 | 2 | cf-wr610n, cf-wr610n_firmware |
| 284 | sunellsecurity | 2 | 14 | sn-xvr3804e1, sn-xvr3808e2, sn-adr3804e1, sn-adr3808e1, sn-adr3816e1 |
| 285 | prolink2u | 2 | 4 | prs1841, prs1841_firmware, pgn6401v, pgn6401v_firmware |
| 286 | barracuda | 2 | 24 | t100b, t200c, t400c, t600d, t900b |
| 287 | redline | 2 | 1 | router_firmware |
| 288 | teltonika-networks | 2 | 36 | rut200, rut240, rut241, rut300, rut360 |
| 289 | uniview | 2 | 3 | ipc322lb-sf28-a, ipc322lb-sf28-a_firmware, camera_firmware |
| 290 | telstra | 2 | 2 | arcadyan_lh1000, arcadyan_lh1000_firmware |
| 291 | thorntech | 2 | 2 | sftp_gateway_firmware, sftp_gateway |
| 292 | uniwayinfo | 2 | 10 | uw-302vp, uw-301vpw, uw-311vpw, uw-101x, uw-323dac |
| 293 | wyze | 2 | 4 | cam_v3, cam_v3_firmware, cam_v4, cam_v4_firmware |
| 294 | nepstech | 2 | 2 | ntpl-xpon1gfevn, ntpl-xpon1gfevn_firmware |
| 295 | ptzoptics | 2 | 4 | pt30x-sdi, pt30x-ndi-xx-g2, pt30x-sdi_firmware, pt30x-ndi-xx-g2_firmware |
| 296 | lsc | 2 | 4 | ptz_dual_band_camera, ptz_dual_band_camera_firmware, smart_connect_indoor_ip_camera, smart_connect_indoor_ip_camera_firmware |
| 297 | alfa | 2 | 2 | wifi_camppro, wifi_camppro_firmware |
| 298 | macro-video | 2 | 2 | v380e6_c1, v380e6_c1_firmware |
| 299 | flir | 2 | 2 | flir_ax8, flir_ax8_firmware |
| 300 | geovision | 2 | 2 | gv-vms, gv-vms_firmware |
| 301 | ascom | 1 | 1 | timeplex_routers |
| 302 | diamond | 1 | 1 | supra |
| 303 | us_robotics | 1 | 1 | us_robotics |
| 304 | ramp_networks | 1 | 1 | webramp |
| 305 | flowpoint | 1 | 1 | flowpoint_dsl_router |
| 306 | cabletron | 1 | 1 | smartswitch_router_8000_firmware |
| 307 | nbase-xyplex | 1 | 1 | edgeblaster |
| 308 | bintec | 1 | 3 | x1000, x1200, x4000 |
| 309 | alliedtelesyn | 1 | 1 | at-ar220e |
| 310 | speedxess | 1 | 1 | ha-120_dsl_router |
| 311 | hpe | 1 | 2 | compaq_wl310, compaq_wl310_firmware |
| 312 | proxim | 1 | 4 | orinoco_rg-1000, orinoco_rg-1100, orinoco_rg-1000_firmware, orinoco_rg-1100_firmware |
| 313 | com21 | 1 | 1 | doxport_1100 |
| 314 | surecom | 1 | 1 | ep-4501 |
| 315 | enterasys | 1 | 1 | smartswitch_ssr8000 |
| 316 | gateway | 1 | 1 | gs-400 |
| 317 | iptel | 1 | 1 | sip_express_router |
| 318 | efficient_networks | 1 | 1 | 5861_dsl_router |
| 319 | longshine_technologie | 1 | 1 | longshine_wireless_ethernet_access_point |
| 320 | ericsson | 1 | 1 | hm220dp_adsl_modem |
| 321 | origo | 1 | 2 | asr-8100, asr-8400 |
| 322 | u.s.robotics | 1 | 1 | usr808054 |
| 323 | zoom | 1 | 1 | model_5560_x3_ethernet_adsl_modem |
| 324 | gigabyte | 1 | 1 | gn-b46b |
| 325 | innomedia | 1 | 1 | innomedia_videophone |
| 326 | microsoft | 1 | 1 | mn-500_wireless_base_station |
| 327 | micronet | 1 | 1 | sp916bm |
| 328 | nexland | 1 | 1 | pro800turbo |
| 329 | arcowave_systems | 1 | 1 | wlan_ap_\+_adsl_router |
| 330 | scientific_atlanta | 1 | 1 | dpx2100_cable_modem |
| 331 | uniden | 1 | 1 | uip1868p |
| 332 | compex | 1 | 1 | netpassage_wpe54g |
| 333 | canon | 1 | 3 | network_camera_server_vb100, network_camera_server_vb101, network_camera_server_vb150 |
| 334 | planet_technology_corp | 1 | 1 | vc-200m_vdsl2 |
| 335 | level_one | 1 | 1 | wbr3404tx |
| 336 | funkwerk | 1 | 1 | x2300 |
| 337 | deutsche_telekom | 1 | 1 | speedport_w500_dsl_router |
| 338 | alice | 1 | 1 | gate2_plus_wi-fi |
| 339 | raidsonic_technology | 1 | 1 | nas-4220-b |
| 340 | axesstel | 1 | 1 | akw-d800 |
| 341 | tp | 1 | 1 | neostrada_livebox_adsl_router |
| 342 | radware | 1 | 1 | appwall |
| 343 | raidsonic | 1 | 1 | icy_box_nas |
| 344 | everfocus | 1 | 1 | edr1600 |
| 345 | aladdin | 1 | 1 | safenet_securewire_access_gateway |
| 346 | stonesoft | 1 | 1 | stonegate |
| 347 | comtrend | 1 | 1 | ct-507it_adsl_router |
| 348 | sterlitetechnologies | 1 | 1 | sam300_ax_router |
| 349 | nas_adapter | 1 | 1 | nasu2fw41 |
| 350 | qlogic | 1 | 1 | ethernet |
| 351 | emc | 1 | 1 | celerra_network_attached_storage |
| 352 | landesk | 1 | 1 | management_gateway |
| 353 | fon | 1 | 1 | la_fonera\+ |
| 354 | emobile | 1 | 1 | pocket_wifi |
| 355 | seil | 1 | 5 | b1, x1, x2, b1_firmware, x86_firmware |
| 356 | palo_alto | 1 | 1 | networks |
| 357 | arecont | 1 | 1 | vision_av1355dn_megadome_camera |
| 358 | turck | 1 | 4 | bl20_programmable_gateway, bl67_programmable_gateway, bl20_programmable_gateway_firmware, bl67_programmable_gateway_firmware |
| 359 | choice-wireless | 1 | 1 | wixfmr-111 |
| 360 | choice_wireless | 1 | 1 | wixfmr-111 |
| 361 | satechi | 1 | 1 | smart_travel_router |
| 362 | elecsyscorp | 1 | 1 | director_industrial_communication_gateway |
| 363 | nisuta | 1 | 4 | ns-wir150ne, ns-wir300n, ns-wir150ne_firmware, ns-wir300n_firmware |
| 364 | media5 | 1 | 1 | mediatrix_voip_gateway |
| 365 | sfr | 1 | 2 | sfr_box_router, sfr_box_router_firmware |
| 366 | alliedtelesis | 1 | 8 | img646bd, at-rg634a, img624a, img616lh, img646bd_firmware |
| 367 | netmaster | 1 | 1 | netmaster_cbw700n |
| 368 | digicom | 1 | 2 | dg-5514t_adsl_router, dg-5514t_adsl_router_firmware |
| 369 | airties | 1 | 1 | air_6372 |
| 370 | adb | 1 | 2 | p.dga4001n, p.dga4001n_firmware |
| 371 | n-tron | 1 | 1 | 702w_industrial_wireless_access_point |
| 372 | alcatel-lucent | 1 | 2 | cellpipe_7130_router, cellpipe_7130_router_firmware |
| 373 | zmodo | 1 | 2 | zp-ibh-13w, zp-ne-14-s |
| 374 | adcon_telemetry | 1 | 2 | a850_telemetry_gateway_base_station, a850_telemetry_gateway_base_station_firmware |
| 375 | eir | 1 | 2 | d1000_modem, d1000_modem_firmware |
| 376 | geutebruck | 1 | 2 | ip_camera_g-cam_efd-2250, ip_camera_g-cam_efd-2250_firmware |
| 377 | aries_networks | 1 | 2 | qwr-1104_wireless-n_router, qwr-1104_wireless-n_router_firmware |
| 378 | airlink101 | 1 | 2 | skyipcam1620w_wireless_n_mpeg4_3gpp, skyipcam1620w_wireless_n_mpeg4_3gpp_firmware |
| 379 | techroutes | 1 | 2 | tr_1803-3g, tr_1803-3g_firmware |
| 380 | selinc | 1 | 4 | sel-3620_firmware, sel-3622_firmware, sel-3620, sel-3622 |
| 381 | asuswrt-merlin | 1 | 28 | rt-ac1200, rt-ac3100, rt-ac3200, rt-ac51u, rt-ac52u |
| 382 | rtsindia | 1 | 2 | rwr-3g-100, rwr-3g-100_firmware |
| 383 | utstar | 1 | 2 | wa3002g4, wa3002g4_firmware |
| 384 | mirion | 1 | 16 | dmc_3000_transmitter, ipam_transmitter_f\/dmc_2000, rds-31_itx, drm-1\/2, drm-2 |
| 385 | mirion_technologies | 1 | 14 | dmc_3000, ipam_transmitter_f\/dmc_2000, telepole_ii, rds-31_itx, rsd31-am |
| 386 | amazon | 1 | 2 | amazon_key, amazon_key_firmware |
| 387 | vonage | 1 | 2 | vdv-23, vdv-23_firmware |
| 388 | cohuhd | 1 | 2 | 3960hd, 3960hd_firmware |
| 389 | ichano | 1 | 2 | athome_ip_camera, athome_ip_camera_firmware |
| 390 | apexis | 1 | 2 | apm-h803-mpc, apm-h803-mpc_firmware |
| 391 | wanscam | 1 | 2 | hw0021, hw0021_firmware |
| 392 | kongtop | 1 | 10 | d303, d305, d403, a303, a403 |
| 393 | velotismart_project | 1 | 2 | velotismart_wifi, velotismart_wifi_firmware |
| 394 | dbpower | 1 | 2 | u818a, u818a_firmware |
| 395 | aterm | 1 | 2 | wg2600hp2, wg2600hp2_firmware |
| 396 | qbeecam | 1 | 2 | qbee_multi-sensor_camera, qbee_multi-sensor_camera_firmware |
| 397 | fxc | 1 | 20 | fxc5210, fxc5218, fxc5224, fxc5426f, fxc5428 |
| 398 | nuuo | 1 | 1 | nvrmini2_firmware |
| 399 | floureon | 1 | 1 | sp012 |
| 400 | guardzilla | 1 | 12 | 360_outdoor, 180_outdoor, 360_indoor, 180_indoor, outdoor_hd_camera |
| 401 | august | 1 | 2 | august_connect, august_connect_firmware |
| 402 | nttdocomo | 1 | 2 | v20_pro_l-01j_firmware, v20_pro_l-01j |
| 403 | psigridconnect | 1 | 10 | telecontrol_gateway_xs-mu_firmware, telecontrol_gateway_vm_firmware, telecontrol_gateway_3g_firmware, smart_telecontrol_unit_tcg_firmware, telecontrol_gateway_xs-mu |
| 404 | hisilicon | 1 | 2 | hi3510, hi3510_firmware |
| 405 | engeniustech | 1 | 2 | ews660ap, ews660ap_firmware |
| 406 | virginmedia | 1 | 2 | hub_3.0, hub_3.0_firmware |
| 407 | anker-in | 1 | 2 | roav_dashcam_a1, roav_dashcam_a1_firmware |
| 408 | goahead | 1 | 2 | wireless_ip_camera_wificam, wireless_ip_camera_wificam_firmware |
| 409 | genieaccess | 1 | 2 | wip3bvaf, wip3bvaf_firmware |
| 410 | alarm | 1 | 2 | adc-v522ir, adc-v522ir_firmware |
| 411 | microdigital | 1 | 6 | mdc-n4090, mdc-n4090w, mdc-n2190v, mdc-n4090_firmware, mdc-n4090w_firmware |
| 412 | progradegrill | 1 | 2 | wifi_grilling_thermometer, wifi_grilling_thermometer_firmware |
| 413 | xiaoyi | 1 | 2 | yi_m1_mirrorless_camera, yi_m1_mirrorless_camera_firmware |
| 414 | ifw8 | 1 | 10 | fr6, fr8, fr5, fr5-e, fr6-s |
| 415 | avstar | 1 | 2 | pe204, pe204_firmware |
| 416 | huntcctv | 1 | 22 | dvr-04ch, dvr-04nc, dvr-08ch, dvr-08nc, dvr-16ch |
| 417 | capturecctv | 1 | 4 | cdr_0410ve, cdr_0820vde, cdr_0410ve_firmware, cdr_0820vde_firmware |
| 418 | hachi | 1 | 4 | hv-04rd_pro, hv-08rd_pro, hv-04rd_pro_firmware, hv-08rd_pro_firmware |
| 419 | novuscctv | 1 | 6 | nv-dvr1204, nv-dvr1208, nv-dvr1216, nv-dvr1204_firmware, nv-dvr1208_firmware |
| 420 | vsp | 1 | 4 | tw-dvr604, tw-dvr616, tw-dvr604_firmware, tw-dvr616_firmware |
| 421 | nssglobal | 1 | 3 | satlink_2000, satlink_2900, satlink_2910 |
| 422 | usriot | 1 | 8 | usr-wifi232-s, usr-wifi232-t, usr-wifi232-g2, usr-wifi232-h, usr-wifi232-s_firmware |
| 423 | adbglobal | 1 | 2 | p.dga4001n, p.dga4001n_firmware |
| 424 | sumavision | 1 | 2 | enhanced_multimedia_router, enhanced_multimedia_router_firmware |
| 425 | swisscom | 1 | 2 | centro_grande, centro_grande_firmware |
| 426 | swann | 1 | 8 | dvr04b, dvr08b, dvr-16cif, dvr16b, dvr04b_firmware |
| 427 | hms-networks | 1 | 4 | ewon_flexy, ewon_cosy, ewon_flexy_firmware, ewon_cosy_firmware |
| 428 | icatchinc | 1 | 1 | dvr_firmware |
| 429 | netatmo | 1 | 2 | smart_indoor_camera, smart_indoor_camera_firmware |
| 430 | ayision | 1 | 2 | ays-wr01, ays-wr01_firmware |
| 431 | nintendo | 1 | 1 | nintendo_64 |
| 432 | aliasrobotics | 1 | 10 | mir100, mir200, mir250, mir500, mir1000 |
| 433 | mobile-industrial-robotics | 1 | 2 | er200, er200_firmware |
| 434 | enabled-robotics | 1 | 6 | er-lite, er-flex, er-one, er-lite_firmware, er-flex_firmware |
| 435 | uvd-robots | 1 | 2 | uvd_robots, uvd_robots_firmware |
| 436 | stengg | 1 | 2 | vpncrypt_m10, vpncrypt_m10_firmware |
| 437 | atoptechnology | 1 | 14 | se5901, se5901b, se5904d, se5908, se5908a |
| 438 | basetech | 1 | 2 | ge-131_bt-1837836, ge-131_bt-1837836_firmware |
| 439 | planet | 1 | 4 | nvr-915, nvr-1615, nvr-915_firmware, nvr-1615_firmware |
| 440 | fastweb | 1 | 2 | fastgate_gpon_fga2130fwb, fastgate_gpon_fga2130fwb_firmware |
| 441 | atx | 1 | 2 | minicmts200a, minicmts200a_firmware |
| 442 | macally | 1 | 2 | wifisd2-2a82, wifisd2-2a82_firmware |
| 443 | assaabloy | 1 | 2 | yale_wipc-303w, yale_wipc-303w_firmware |
| 444 | merkuryinnovations | 1 | 8 | geeni_gnc-cw028, geeni_gnc-cw025, merkury_mi-cw024, merkury_mi-cw017, geeni_gnc-cw028_firmware |
| 445 | svakom | 1 | 2 | siime_eye, siime_eye_firmware |
| 446 | acexy_wireless-n_wifi_repeater_project | 1 | 2 | acexy_wireless-n_wifi_repeater, acexy_wireless-n_wifi_repeater_firmware |
| 447 | multilaser | 1 | 2 | ac1200_re018, ac1200_re018_firmware |
| 448 | nightowlsp | 1 | 2 | wdb-20, wdb-20_firmware |
| 449 | arista | 1 | 30 | c-100, c-110, c-120, c-130, c-200 |
| 450 | sing4g | 1 | 2 | 4gee_router_hh70vb, 4gee_router_hh70vb_firmware |
| 451 | tieline | 1 | 2 | ip_audtio_gateway, ip_audtio_gateway_firmware |
| 452 | prolink | 1 | 2 | prc2402m, prc2402m_firmware |
| 453 | acuitybrands | 1 | 2 | nlight_eclypse_system_controller, nlight_eclypse_system_controller_firmware |
| 454 | riconmobile | 1 | 2 | s9922l, s9922l_firmware |
| 455 | chinatelecom | 1 | 2 | epon_tianyi_gateway_zxhn_f450, epon_tianyi_gateway_zxhn_f450_firmware |
| 456 | visual-tools | 1 | 2 | dvr_vx16, dvr_vx16_firmware |
| 457 | telus | 1 | 2 | prv65b444a-s-ts, prv65b444a-s-ts_firmware |
| 458 | mercury | 1 | 4 | mer1200, mer1200g, mer1200_firmware, mer1200g_firmware |
| 459 | ubeeinteractive | 1 | 2 | ubc1319, ubc1319_firmware |
| 460 | hej | 1 | 2 | hejhome_gkw-ic052_firmware, hejhome_gkw-ic052 |
| 461 | kingjim | 1 | 6 | tepura_pro_sr5900p, tepura_pro_sr-7900p, spc10, tepura_pro_sr5900p_firmware, tepura_pro_sr-7900p_firmware |
| 462 | alecto | 1 | 2 | dvc-215ip, dvc-215ip_firmware |
| 463 | netapp | 1 | 16 | h300s, h500s, h700s, h300e, h500e |
| 464 | claro | 1 | 2 | kaon_cg3000, kaon_cg3000_firmware |
| 465 | i3international | 1 | 6 | ax46, ax68, ax78, ax46_firmware, ax68_firmware |
| 466 | swiftsensors | 1 | 2 | sg3-1010, sg3-1010_firmware |
| 467 | seowonintech | 1 | 2 | 130-slc, 130-slc_firmware |
| 468 | mdt | 1 | 4 | scn-ip000.03, scn-ip100.03, scn-ip000.03_firmware, scn-ip100.03_firmware |
| 469 | bdt-121_project | 1 | 2 | bdt-121, bdt-121_firmware |
| 470 | sooteway_wi-fi_range_extender_project | 1 | 1 | sooteway_wi-fi_range_extender |
| 471 | eufylife | 1 | 4 | solo_indoorcam_c24, solo_indoorcam_p24, solo_indoorcam_c24_firmware, solo_indoorcam_p24_firmware |
| 472 | usr | 1 | 10 | usr-g808, usr-g807, usr-g806, usr-g800v2, usr-lg220-l |
| 473 | netwavepr | 1 | 4 | indoor_ip_camera, outdoor_ip_camera, indoor_ip_camera_firmware, outdoor_ip_camera_firmware |
| 474 | quectel | 1 | 2 | rg502q-ea, rg502q-ea_firmware |
| 475 | yokogawa | 1 | 2 | aw810d, aw810d_firmware |
| 476 | chcnav | 1 | 2 | p5e_gnss_firmware, p5e_gnss |
| 477 | allnet | 1 | 2 | all-wr0500ac, all-wr0500ac_firmware |
| 478 | baxter | 1 | 8 | spectrum_wireless_battery_module_firmware, spectrum_wireless_battery_module, sigma_spectrum_35700bax, sigma_spectrum_35700bax2, baxter_spectrum_iq_35700bax3 |
| 479 | proscend | 1 | 16 | m330-w, m330-w5, m350-5g, m350-w5g, m350-6 |
| 480 | advice | 1 | 2 | icr_111wg, icr_111wg_firmware |
| 481 | contechealth | 1 | 2 | cms8000, cms8000_firmware |
| 482 | tenhot | 1 | 2 | tws-100, tws-100_firmware |
| 483 | foresightsports | 1 | 2 | gc3_launch_monitor, gc3_launch_monitor_firmware |
| 484 | bushnellgolf | 1 | 2 | launch_pro, launch_pro_firmware |
| 485 | ikea | 1 | 2 | tradfri_gateway_e1526, tradfri_gateway_e1526_firmware |
| 486 | mvpower | 1 | 4 | tv-7104he, tv7108he, tv-7104he_firmware, tv7108he_firmware |
| 487 | dinstar | 1 | 2 | dag2000-16o, dag2000-16o_firmware |
| 488 | force1rc | 1 | 2 | discovery_wifi_u818a_hd\+_fpv, discovery_wifi_u818a_hd\+_fpv_firmware |
| 489 | arcadyan | 1 | 2 | vrv9506jac23, vrv9506jac23_firmware |
| 490 | uniswap | 1 | 2 | universal_router, universal_router_firmware |
| 491 | biltema | 1 | 4 | baby_camera, ip_camera, baby_camera_firmware, ip_camera_firmware |
| 492 | deyeinverter | 1 | 2 | inverter_firmware, inverter |
| 493 | revolt-power | 1 | 2 | inverter_firmware, inverter |
| 494 | bosswerk | 1 | 2 | inverter_firmware, inverter |
| 495 | akuvox | 1 | 2 | e11, e11_firmware |
| 496 | arraynetworks | 1 | 13 | ag1000, ag1000t, ag1000v5, ag1100v5, ag1150 |
| 497 | lancombg | 1 | 2 | sa-wr915nd, sa-wr915nd_firmware |
| 498 | jcgcn.com | 1 | 2 | jhr-n916r, jhr-n916r_firmware |
| 499 | silabs | 1 | 2 | wireless_smart_ubiquitous_network_linux_border_router, wireless_smart_ubiquitous_network_linux_border_router_firmware |
| 500 | agasio_camera_project | 1 | 2 | agasio_camera, agasio_camera_firmware |
| 501 | furbo | 1 | 2 | dog_camera, dog_camera_firmware |
| 502 | mitrastar | 1 | 2 | gpt-2741gnac, gpt-2741gnac_firmware |
| 503 | adslr | 1 | 2 | vw2100, vw2100_firmware |
| 504 | assmann | 1 | 2 | ht-ip211hdp, ht-ip211hdp_firmware |
| 505 | hichip | 1 | 1 | shenzhen_hichip_vision_technology_firmware |
| 506 | tianyisc | 1 | 2 | tewa-700g, tewa-700g_firmware |
| 507 | eaton | 1 | 8 | smp_4\/dp_firmware, smp_sg-4250_firmware, smp_16_firmware, smp_sg-4260_firmware, smp_sg-4260 |
| 508 | rtautomation | 1 | 6 | 460etcmm, 460mcbms, 460mcbs, 460mmbms, 460mmbs |
| 509 | netmodule | 1 | 8 | nb1601, nb1800, nb1810, nb2800, nb2810 |
| 510 | digitalcomtech | 1 | 2 | syrus_4g_iot_telematics_gateway, syrus_4g_iot_telematics_gateway_firmware |
| 511 | unitree | 1 | 2 | a1, a1_firmware |
| 512 | neutron | 1 | 34 | neu-ipb210-28, ntl-pt-06wod-3mp, neu-ipb410-28, ntl-bc-01w, neu-ipbm211 |
| 513 | nadatel | 1 | 36 | at-0402r, at-0815r, at-1623r, at-0402l, at-0815l |
| 514 | cassianetworks | 1 | 4 | xc1000, xc2000, xc1000_firmware, xc2000_firmware |
| 515 | hongdian | 1 | 2 | h8951-4g-esp, h8951-4g-esp_firmware |
| 516 | 3rrr-btob | 1 | 12 | 3r-tmc01, 3r-tmc02, 3r-tmc03, 3r-tmc04, 3r-tmc05 |
| 517 | mokosmart | 1 | 2 | mkgw1_gateway, mkgw1_gateway_firmware |
| 518 | solax | 1 | 2 | pocket_wifi_3, pocket_wifi_3_firmware |
| 519 | systemk-corp | 1 | 6 | nvr_504, nvr_508, nvr_516, nvr_504_firmware, nvr_508_firmware |
| 520 | roku | 1 | 2 | indoor_camera_se, indoor_camera_se_firmware |
| 521 | intrado | 1 | 2 | 911_emergency_gateway, 911_emergency_gateway_firmware |
| 522 | adtran | 1 | 1 | 834-5 |
| 523 | provision-isr | 1 | 2 | sh-4050a5-5l\(mm\)_firmware, sh-4050a5-5l\(mm\) |
| 524 | kaongroup | 1 | 2 | ar2140, ar2140_firmware |
| 525 | d3dsecurity | 1 | 2 | d8801, d8801_firmware |
| 526 | teldat | 1 | 4 | rs123, rs123w, rs123_firmware, rs123w_firmware |
| 527 | hathway | 1 | 2 | skyworth_cm5100-511, skyworth_cm5100-511_firmware |
| 528 | viloliving | 1 | 2 | vilo_5, vilo_5_firmware |
| 529 | ecovacs | 1 | 28 | deebot_n8, deebot_900, deebot_t8, deebot_n9, deebot_t9 |
| 530 | checkpoint | 1 | 2 | multi-domain_management, quantum_security_management |
| 531 | think | 1 | 2 | tk-rt-wr135g, tk-rt-wr135g_firmware |
| 532 | nextu | 1 | 2 | fleta_ax1500, fleta_ax1500_firmware |
| 533 | aziot | 1 | 2 | 2mp_full_hd_smart_wi-fi_cctv_home_security_camera, 2mp_full_hd_smart_wi-fi_cctv_home_security_camera_firmware |
| 534 | kapsch | 1 | 4 | ris-9160_firmware, ris-9260_firmware, ris-9160, ris-9260 |
| 535 | ghostrobotics | 1 | 2 | vision_60, vision_60_firmware |
| 536 | keruistore | 1 | 2 | kerui_k259, kerui_k259_firmware |
| 537 | alagaai | 1 | 2 | s-cw2503c-h, s-cw2503c-h_firmware |
| 538 | itel | 1 | 2 | idgateway, idgateway_firmware |
| 539 | meatmeet | 1 | 2 | meatmeet_pro_wifi_\&_bluetooth_meat_thermometer, meatmeet_pro_wifi_\&_bluetooth_meat_thermometer_firmware |
| 540 | microhardcorp | 1 | 22 | ipn4gb, ipn4gb_firmware, bullet-3g, vip4gb, bullet-3g_firmware |
| 541 | jdcloud | 1 | 12 | ax1800, ax3000, ax6600, be6500, er1 |
| 542 | h3c | 1 | 4 | mc102-g, magic_ba1500l, mc102-g_firmware, magic_ba1500l_firmware |
| 543 | gl-inet | 1 | 2 | gl-axt1800_firmware, gl-axt1800 |
| 544 | tycc | 1 | 2 | tongyu_ax1800, tongyu_ax1800_firmware |
| 545 | eachitaly | 1 | 2 | wireless_mini_router_wireless-n_300m, wireless_mini_router_wireless-n_300m_firmware |
| 546 | orico | 1 | 2 | cd3510, cd3510_firmware |
| 547 | yottamaster | 1 | 6 | dm2, dm3, dm200, dm2_firmware, dm3_firmware |
| 548 | belden | 1 | 2 | ppc_2k05x, ppc_2k05x_firmware |
| 549 | utt | 1 | 2 | 810, 810_firmware |
| 550 | sodola-network | 1 | 2 | sl902-swtgw124as, sl902-swtgw124as_firmware |
| 551 | buffaloamericas | 1 | 2 | terastation_nas_ts5400r, terastation_nas_ts5400r_firmware |
| 552 | anviz | 1 | 2 | cx7, cx7_firmware |
| 553 | senselive | 1 | 2 | x3500, x3500_firmware |
