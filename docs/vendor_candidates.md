# Embedded/IoT Vendor Candidates (data-driven discovery)

Retrieved: 2026-09-04T22:52:43+00:00 from NVD CVE API 2.0 (full corpus, no date filter).

**Method:** a CVE is counted if NVD's `configurations` contain at least one CPE `criteria` string with `part:h` marked `vulnerable: true`, AND the CVE's English description matches a category keyword restricting scope to consumer/small-business network equipment, broadband gateways, IP cameras, or NAS. Vendor names are taken verbatim from the CPE `criteria` vendor field (not normalized/deduplicated across spelling variants).

**This is a candidate list for manual pruning, not the final curated vendor list.** Known limitations:
- Vendor spelling variants are not merged (e.g. `tp-link` vs `tplink` would appear as separate rows if both occur).
- Description-keyword category matching is a heuristic and can miss or miscategorize records.
- Since April 15, 2026 NIST limits routine NVD enrichment (and therefore `configurations` population) to CISA KEV / federal-government / EO 14028 software. Triage-era (post-2026-03-01) CVEs are structurally under-represented here regardless of vendor — this list skews toward vendors with a long pre-2026 history and should not be read as current market share.

**Corpus:** 386,750 CVEs scanned; 3,042 had a vulnerable part:h CPE; 542 matched the category filter; 173 distinct vendors.

| Rank | Vendor (CPE field, verbatim) | CVE count | Distinct products | Example products |
|---:|---|---:|---:|---|
| 1 | cisco | 52 | 103 | wvc54gca, wrvs4400n, nexus_1000v, rvs4000, wvc54gc |
| 2 | linksys | 34 | 22 | wrt54g, befsr41, befw11s4, wap11, wag54gs |
| 3 | zyxel | 22 | 14 | prestige, p-660hw, n300_netusb_nbg-419n, zynos, p-2602hw-d1a |
| 4 | symantec | 21 | 25 | gateway_security, brightmail_gateway_appliance, web_gateway_appliance_8450, web_gateway_appliance_8490, gateway_security_5400 |
| 5 | d-link | 20 | 18 | dl-704, dwl-900ap\+, dcs-900_internet_camera, di-604, dwl-1000ap |
| 6 | belkin | 20 | 15 | f5d7230-4, n300, n900, f5d6130_wnap, f5d5230-4_4-port_cable_dsl_gateway_router |
| 7 | 3com | 16 | 11 | 3cp4144, 3crwe454g72, 3crwe754g72-a, 3crwe554g72t, hiperarc |
| 8 | netgear | 16 | 11 | fvs318, rt314, wg602, me102, rp114 |
| 9 | dlink | 16 | 13 | di-624, di-524, dcs-2121, dsl-2740b, dir-685 |
| 10 | axis | 14 | 21 | 2400_video_server, 2401_video_server, 2100_network_camera, 2420_network_camera, 2110_network_camera |
| 11 | motorola | 10 | 8 | surfboard, cpei300, motorola_cablerouter, wr850g, motorola_cable_modem |
| 12 | citrix | 8 | 3 | netscaler_access_gateway, netscaler_application_delivery_controller, netscaler_gateway |
| 13 | nortel | 7 | 16 | contivity, vpn_router_5000, vpn_router_1010, vpn_router_1050, vpn_router_1100 |
| 14 | huawei | 7 | 16 | me60, cx600, ne40e\&80e, ne5000e, e5332 |
| 15 | red-m | 6 | 1 | 1050ap_lan_acess_point |
| 16 | smc_networks | 6 | 4 | smcd3g-ccr, smc7004vbr, barricade_wireless_cable_dsl_broadband_router, smc7904wbra |
| 17 | conceptronic | 6 | 3 | c54apm, cadslr1_adsl_router, cipcamptiwl |
| 18 | siemens | 6 | 5 | gigaset_se361_wlan_router, speedstream_wireless_router, speedstream_6520, gigaset_se461__wimax_router, gigaset_wlan_camera |
| 19 | asus | 6 | 5 | asus_wl-500w, rt-n56u, rt-n10e, wl-330nul, tm-1900 |
| 20 | hot | 6 | 1 | hotbox_router |
| 21 | alcatel | 5 | 2 | speed_touch_home, speedtouch_7g_router |
| 22 | bt | 5 | 2 | home_hub, voyager_2000_wireless_adsl_router |
| 23 | samsung | 5 | 4 | exynos, dvr_shr2040, dvr, exynos_smp1300 |
| 24 | ibm | 5 | 13 | websphere_datapower_xml_security_gateway_xs40, websphere_datapower_xml_accelerator_xa35, websphere_datapower_datapower_integration_appliance_xi50, websphere_datapower_b2b_appliance_xb60, websphere_datapower_low_latency_appliance_xm70 |
| 25 | camtron | 5 | 1 | cmnc-200 |
| 26 | tecvoz | 5 | 1 | cmnc-200 |
| 27 | tp-link | 5 | 2 | tl-wr841n, tl-wdr4300 |
| 28 | dahuasecurity | 5 | 65 | dvr0404hd-a, dvr0404hd-l, dvr0404hd-s, dvr0404hd-u, dvr0404hf-a-e |
| 29 | ovislink | 5 | 7 | airlive_wl2600cam, airlive_od-2025hd, airlive_od-2060hd, airlive_poe100hd, airlive_poe200hd |
| 30 | compal_broadband_networks | 5 | 2 | cg6640e_wireless_gateway, ch664oe_wireless_gateway |
| 31 | vivotek | 5 | 1 | camera |
| 32 | cayman | 4 | 2 | gatorsurf, 3220-h_dsl_router |
| 33 | 2wire | 4 | 9 | 1701hg_router, 2071_router, 1800hw_router, 1700hg, 1701hg |
| 34 | intellicom | 4 | 7 | netbiter_easyconnect_ec150, netbiter_modbus_rtu-tcp_gateway_mb100, netbiter_serial_ethernet_server_ss100, netbiter_webscada_ws100, netbiter_webscada_ws200 |
| 35 | trendnet | 4 | 4 | tew-812dru, securview_wireless_internet_camera, tv-ip422w, tv-ip422wn |
| 36 | f5 | 4 | 2 | big-ip_access_policy_manager, enterprise_manager |
| 37 | zte | 4 | 1 | zxv10_w300 |
| 38 | - | 4 | 1 | wireless_ip_camera_360 |
| 39 | netopia | 3 | 3 | r-series_routers, 650-st_isdn_router, r9100_router |
| 40 | lucent | 3 | 7 | ascend_pipeline_router, ascend_max_router, orinoco_rg-1000, dslterminator, access_point_service_router_1500 |
| 41 | rca | 3 | 1 | digital_cable_modem |
| 42 | apple | 3 | 6 | airport_express_base_station_firmware, airport_extreme_base_station_firmware, airport_express, airport_extreme, time_capsule |
| 43 | thomson | 3 | 2 | speedtouch, thomson_cable_modem |
| 44 | mentor | 3 | 1 | adslfr4ii |
| 45 | astaro | 3 | 1 | security_gateway |
| 46 | aztech | 3 | 2 | adsl2\/2\+4-port_router, dsl_600eu_router |
| 47 | marvell | 3 | 2 | 88w8361w-bem1, 88w8361p-bem_chipset |
| 48 | qnap | 3 | 2 | viostor_network_video_recorder, nas |
| 49 | thecus | 3 | 1 | n8800_nas_server |
| 50 | oleumtech | 3 | 2 | sensor_wireless_i\/o_module, wio_dh2_wireless_gateway |
| 51 | y-cam | 3 | 3 | ycbl03, ycblb3, ycw004 |
| 52 | atmel | 2 | 2 | 802.11b_vnet-b_access_point, firmware |
| 53 | arescom | 2 | 1 | netdsl |
| 54 | telindus | 2 | 2 | adsl_router, 1120_adsl_router |
| 55 | iomega | 2 | 2 | network_attached_storage, nas |
| 56 | x-micro | 2 | 1 | wlan_11b_broadband_router_firmware |
| 57 | hawking_technology | 2 | 2 | har11a_dsl_router, wr254-ca_wireless_router |
| 58 | vocaltec | 2 | 1 | vgw4_8_telephony_gateway |
| 59 | sweex | 2 | 2 | wireless_broadband_router_accesspoint_802.11g, ro002_router |
| 60 | gigafast_ethernet | 2 | 1 | gigafast_router |
| 61 | securecomputing | 2 | 1 | samsung_adsl_modem |
| 62 | eci_telecom | 2 | 2 | b-focus_router, b-focus_wireless_802.11bg_adsl2\+_router |
| 63 | sitecom | 2 | 2 | wl-153, wlm-2501 |
| 64 | march_networks | 2 | 5 | 3204_dvr, 3108_dvr, 4210_dvr, 4310_dvr, 4410_dvr |
| 65 | sony | 2 | 11 | sony_network_camera_snc-p5, snc_ch140, snc_ch180, snc_ch240, snc_ch280 |
| 66 | atheros | 2 | 2 | ar5416-ac1e_chipset, ar9160-bc1a_chipset |
| 67 | armassa | 2 | 1 | ard-9808 |
| 68 | juniper | 2 | 12 | srx100, srx110, srx1400, srx210, srx220 |
| 69 | brickcom | 2 | 6 | fb-100ap, md-100ap, ob-100ae, osd-040e, wcb-100ap |
| 70 | grandstream | 2 | 10 | gxv3500, gxv3501, gxv3504, gxv3601, gxv3601hd\/ll |
| 71 | seagate | 2 | 1 | blackarmor_nas_220 |
| 72 | sierrawireless | 2 | 18 | airlink_mp_at\&t, airlink_mp_at\&t_wifi, airlink_mp_bell, airlink_mp_bell_wifi, airlink_mp_row |
| 73 | avtech | 2 | 1 | avn801_dvr |
| 74 | tenda | 2 | 2 | a5s, a32 |
| 75 | qeiinc | 2 | 1 | epaq-9410_substation_gateway |
| 76 | teracom | 2 | 1 | t2-b-gawv1.4u10y-bi |
| 77 | schneider-electric | 2 | 4 | tsxetg3000, tsxetg3010, tsxetg3021, tsxetg3022 |
| 78 | qualcomm | 2 | 303 | aqt1000, ar8031, ar8035, csra6620, csra6640 |
| 79 | aruba | 2 | 1 | aruba_instant |
| 80 | ascom | 1 | 1 | timeplex_routers |
| 81 | diamond | 1 | 1 | supra |
| 82 | us_robotics | 1 | 1 | us_robotics |
| 83 | ramp_networks | 1 | 1 | webramp |
| 84 | flowpoint | 1 | 1 | flowpoint_dsl_router |
| 85 | cabletron | 1 | 1 | smartswitch_router_8000_firmware |
| 86 | nbase-xyplex | 1 | 1 | edgeblaster |
| 87 | intel | 1 | 1 | express_8100 |
| 88 | bintec | 1 | 3 | x1000, x1200, x4000 |
| 89 | alliedtelesyn | 1 | 1 | at-ar220e |
| 90 | nokia | 1 | 1 | firewall_appliance |
| 91 | speedxess | 1 | 1 | ha-120_dsl_router |
| 92 | com21 | 1 | 1 | doxport_1100 |
| 93 | surecom | 1 | 1 | ep-4501 |
| 94 | enterasys | 1 | 1 | smartswitch_ssr8000 |
| 95 | gateway | 1 | 1 | gs-400 |
| 96 | iptel | 1 | 1 | sip_express_router |
| 97 | efficient_networks | 1 | 1 | 5861_dsl_router |
| 98 | longshine_technologie | 1 | 1 | longshine_wireless_ethernet_access_point |
| 99 | ericsson | 1 | 1 | hm220dp_adsl_modem |
| 100 | origo | 1 | 2 | asr-8100, asr-8400 |
| 101 | u.s.robotics | 1 | 1 | usr808054 |
| 102 | zoom | 1 | 1 | model_5560_x3_ethernet_adsl_modem |
| 103 | gigabyte | 1 | 1 | gn-b46b |
| 104 | innomedia | 1 | 1 | innomedia_videophone |
| 105 | microsoft | 1 | 1 | mn-500_wireless_base_station |
| 106 | micronet | 1 | 1 | sp916bm |
| 107 | nexland | 1 | 1 | pro800turbo |
| 108 | netcomm | 1 | 1 | nb1300 |
| 109 | arcowave_systems | 1 | 1 | wlan_ap_\+_adsl_router |
| 110 | dell | 1 | 1 | truemobile_2300_wireless_broadband_router |
| 111 | scientific_atlanta | 1 | 1 | dpx2100_cable_modem |
| 112 | uniden | 1 | 1 | uip1868p |
| 113 | compex | 1 | 1 | netpassage_wpe54g |
| 114 | edimax | 1 | 1 | br_6104k |
| 115 | canon | 1 | 3 | network_camera_server_vb100, network_camera_server_vb101, network_camera_server_vb150 |
| 116 | planet_technology_corp | 1 | 1 | vc-200m_vdsl2 |
| 117 | level_one | 1 | 1 | wbr3404tx |
| 118 | deutsche_telekom | 1 | 1 | speedport_w500_dsl_router |
| 119 | alice | 1 | 1 | gate2_plus_wi-fi |
| 120 | axesstel | 1 | 1 | akw-d800 |
| 121 | panasonic | 1 | 8 | bb_hcm511, bb_hcm515, bb_hcm527, bb_hcm531, bb_hcm580 |
| 122 | tp | 1 | 1 | neostrada_livebox_adsl_router |
| 123 | radware | 1 | 1 | appwall |
| 124 | raidsonic | 1 | 1 | icy_box_nas |
| 125 | everfocus | 1 | 1 | edr1600 |
| 126 | arubanetworks | 1 | 1 | aruba_mobility_controller |
| 127 | aladdin | 1 | 1 | safenet_securewire_access_gateway |
| 128 | sonicwall | 1 | 2 | e-class_ssl_vpn, ssl_vpn |
| 129 | stonesoft | 1 | 1 | stonegate |
| 130 | comtrend | 1 | 1 | ct-507it_adsl_router |
| 131 | sterlitetechnologies | 1 | 1 | sam300_ax_router |
| 132 | nas_adapter | 1 | 1 | nasu2fw41 |
| 133 | emc | 1 | 1 | celerra_network_attached_storage |
| 134 | landesk | 1 | 1 | management_gateway |
| 135 | fon | 1 | 1 | la_fonera\+ |
| 136 | emobile | 1 | 1 | pocket_wifi |
| 137 | seil | 1 | 3 | b1, x1, x2 |
| 138 | sophos | 1 | 1 | unified_threat_management |
| 139 | palo_alto | 1 | 1 | networks |
| 140 | mercurycom | 1 | 1 | mr804 |
| 141 | hp | 1 | 664 | 0150a129, 0150a12a, 0150a12b, 0150a12c, 0231a0av |
| 142 | verizon | 1 | 1 | fios_actiontec_mi424wr-gen31_router |
| 143 | arecont | 1 | 1 | vision_av1355dn_megadome_camera |
| 144 | turck | 1 | 2 | bl20_programmable_gateway, bl67_programmable_gateway |
| 145 | choice-wireless | 1 | 1 | wixfmr-111 |
| 146 | choice_wireless | 1 | 1 | wixfmr-111 |
| 147 | google | 1 | 1 | glass |
| 148 | moxa | 1 | 4 | oncell_gateway_g3111, oncell_gateway_g3151, oncell_gateway_g3211, oncell_gateway_g3251 |
| 149 | draytek | 1 | 1 | vigor_2700_router |
| 150 | tvt | 1 | 1 | dvr |
| 151 | satechi | 1 | 1 | smart_travel_router |
| 152 | elecsyscorp | 1 | 1 | director_industrial_communication_gateway |
| 153 | upc | 1 | 1 | ireland_cisco_epc2425 |
| 154 | nisuta | 1 | 2 | ns-wir150ne, ns-wir300n |
| 155 | media5 | 1 | 1 | mediatrix_voip_gateway |
| 156 | hikvision | 1 | 1 | ds-2cd7153-e |
| 157 | foscam | 1 | 1 | fi8919w |
| 158 | sfr | 1 | 1 | sfr_box_router |
| 159 | alliedtelesis | 1 | 4 | img646bd, at-rg634a, img624a, img616lh |
| 160 | beetel | 1 | 1 | 450tc2_router |
| 161 | commscope | 1 | 1 | arris_sbg901 |
| 162 | iodata | 1 | 7 | ts-wlcam\/v_camera, ts-wptcam_camera, ts-wlcam_camera, ts-ptcam\/poe_camera_firmware, ts-ptcam\/poe_camera |
| 163 | netmaster | 1 | 1 | netmaster_cbw700n |
| 164 | arris | 1 | 1 | touchstone_dg950a |
| 165 | advantech | 1 | 1 | eki-6340 |
| 166 | zteusa | 1 | 1 | zxdsl_831cii |
| 167 | lg | 1 | 3 | l-04d, l-09c, l-03e |
| 168 | airties | 1 | 1 | air_6372 |
| 169 | n-tron | 1 | 1 | 702w_industrial_wireless_access_point |
| 170 | zmodo | 1 | 2 | zp-ibh-13w, zp-ne-14-s |
| 171 | floureon | 1 | 1 | sp012 |
| 172 | tendacn | 1 | 1 | adsl_firmware |
| 173 | xiongmaitech | 1 | 72 | mbd6304t, nbd6808t-pl, nbd7004t-p, nbd7008t-p, nbd7016t-f-v2 |
