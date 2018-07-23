/*
* Copyright 2017 Cisco Systems, Inc.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


#include "config.h" 

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/reassemble.h>

#define NFAPI_HEADER_LENGTH 8
#define NFAPI_P7_HEADER_LENGTH 16

typedef int(*Decode_operation)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset);

static const value_string nfapi_error_vals[] = {
	{ 0x0, "MSG_OK" },
	{ 0x1, "MSG_INVALID_STATE" },
	{ 0x2, "MSG_INVALID_CONFIG" },
	{ 0x3, "SFN_OUT_OF_SYNC" },
	{ 0x4, "MSG_SUBFRAME_ERR" },
	{ 0x5, "MSG_BCH_MISSING" },
	{ 0x6, "MSG_BCH_MISSING" },
	{ 0x7, "MSG_HI_ERR" },
	{ 0x8, "MSG_TX_ERR" },
	{ 0, NULL },
};

static const value_string nfapi_p4_error_vals[] = {
	{ 100, "MSG_OK" },
	{ 101, "MSG_INVALID_STATE" },
	{ 102, "MSG_INVALID_CONFIG" },
	{ 103, "MSG_RAT_NOT_SUPPORTED" },
	{ 200, "MSG_NMM_STOP_OK" },
	{ 201, "MSG_NMM_STOP_IGNORED" },
	{ 202, "MSG_NMM_STOP_INVALID_STATE" },
	{ 300, "MSG_PROCEDURE_COMPLETE" },
	{ 301, "MSG_PROCEDURE_STOPPED" },
	{ 302, "MSG_PARTIAL_RESULTS" },
	{ 303, "MSG_TIMEOUT" },
	{ 0, NULL },
};

static const value_string nfapi_rat_type_vals[] = {
	{ 0, "LTE" },
	{ 1, "UTRAN" },
	{ 2, "GERAN" },
	{ 0, NULL },
};

typedef enum{
	UN_ALIGNED_SYNCHRONIZATION = 0,
	INTERNAL_PNF_FRAME_ALIGNMENT,
	ABSOLUTE_TIME_ALIGNED_SYNCHRONIZATION
} nfapi_sync_mode_e;

static const value_string nfapi_sync_mode_vals[] = {
	{ UN_ALIGNED_SYNCHRONIZATION, "UN-ALIGNED SYNCHRONIZATION" },
	{ INTERNAL_PNF_FRAME_ALIGNMENT, "INTERNAL PNF FRAME ALIGNMENT" },
	{ ABSOLUTE_TIME_ALIGNED_SYNCHRONIZATION, "ABSOLUTE TIME ALIGNED SYNCHRONIZATION" }
};

typedef enum {
	NONE = 0,
	GPS,
	GLONASS,
	BEIDOU
} location_mode_e;

static const value_string location_mode_vals[] = {
	{ NONE, "NONE" },
	{ GPS, "GPS" },
	{ GLONASS, "GLONASS" },
	{ BEIDOU, "BeiDou" },
	{ 0, NULL }
};

static const value_string nfapi_uplink_rs_hopping_vals[] = {
	{ 0, "RS_NO_HOPPING" },
	{ 1, "RS_GROUP_HOPPING" },
	{ 2, "RS_SEQUENCE_HOPPING" },
	{ 0, NULL }
};

static const value_string nfapi_laa_carrier_type_vals[] = {
	{ 0, "No multi carrier support" },
	{ 1, "Mode A1" },
	{ 2, "Mode A12" },
	{ 3, "Mode B1" },
	{ 4, "Mode B2" },
	{ 0, NULL }
};

static const value_string nfapi_mutli_carrier_lbt_support_vals[] = {
	{ 0, "Multi carrier Mode A1" },
	{ 1, "Multi carrier Mode A2" },
	{ 2, "Multi carrier Mode B1" },
	{ 3, "Multi carrier Mode B2" },
	{ 0, NULL }
};

static const value_string nfapi_lbt_dl_req_pdu_type[] = {
	{ 0, "LBT_PDSCH_REQ PDU" },
	{ 1, "LBT_DRS_REQ PDU" },
	{ 0, NULL }
};


static const value_string nfapi_lbt_dl_ind_pdu_type[] = {
	{ 0, "LBT_PDSCH_RSP PDU" },
	{ 1, "LBT_DRS_RSP PDU" },

	{ 0, NULL }
};




/* These are definitions where data 0 & 1 represent/provide a string name*/

static const true_false_string true_false_strname = {
	"TRUE",
	"FALSE"
};

static const true_false_string  nfapi_csi_report_type_strname = {
	"Periodic",
	"Aperiodic",
};

static const true_false_string nfapi_control_type_string_name = {
	"CQI/PMI",
	"RI",
};

static const true_false_string transport_block_to_codeword_swap_flag = {
	"NO_SWAPPING",
	"SWAPPED"
};

static const true_false_string virtual_resource_block_assignment_flag = {
	"LOCALIZED",
	"DISTRIBUTED"
};

static const true_false_string ngap_string_name = {
	"N-GAP 1",
	"N-GAP 2"
};

static const true_false_string  nprb_strname = {
	"= 2",
	"= 3",
};

static const true_false_string cyclic_prefix_type_strname = {
	"CP_NORMAL",
	"CP_EXTENDED"
};

static const true_false_string support_strname = {
	"No Support",
	"Support"
};

static const true_false_string partial_sf_support_strname =
{
	"Start partial SF support",
	"End partial SF support"
};

static const true_false_string phich_duration_strname = {
	"PHICH_D_NORMAL",
	"PHICH_D_EXTENDED"
};

static const true_false_string high_speed_flag_strname = {
	"HS_UNRESTRICTED_SET",
	"HS_RESTRICTED_SET"
};

static const true_false_string hopping_mode_strname = {
	"HM_INTER_SF",
	"HM_INTRA_INTER_SF"
};

static const true_false_string enabled_disabled_strname = {
	"Enabled",
	"Disabled"
};

static const true_false_string srs_simult_tx_strname = {
	"No Simultaneous Transmission",
	"Simultaneous Transmission"
};

static const true_false_string crc_flag_strname = {
	"CRC_CORRECT",
	"CRC_ERROR"
};

static const true_false_string hi_value_strname = {
	"HI_NACK",
	"HI_ACK"
};

static const true_false_string flag_tb2_strname = {
	"HI_NOT_PRESENT",
	"HI_PRESENT"
};

static const true_false_string nfapi_multi_carrier_tx_strname = {
	"Mutual transmission (self-deferral support for current carrier)",
	"Transmit on channel access win (no self-deferral)"
};

static const true_false_string nfapi_multi_carrier_freeze_strname = {
	"Absence of other technology isn’t guaranteed",
	"Absence of other technology is guaranteed"
};

static const value_string nfapi_dl_config_pdu_type_vals[] = {
	{ 0, "DL_CONFIG_DCI_DL_PDU" },
	{ 1, "DL_CONFIG_BCH_PDU" },
	{ 2, "DL_CONFIG_MCH_PDU" },
	{ 3, "DL_CONFIG_DLSCH_PDU" },
	{ 4, "DL_CONFIG_PCH_PDU" },
	{ 5, "DL_CONFIG_PRS_PDU" },
	{ 6, "DL_CONFIG_CSI_RS_PDU" },
	{ 7, "DL_CONFIG_EPDCCH_DL_PDU" },
	{ 8, "DL_CONFIG_EPDCCH_DL_PDU" },
	{ 0, NULL }
};

static const value_string nfapi_duplex_mode_vals[] = {
	{ 0, "TDD" },
	{ 1, "FDD" },
	{ 2, "HD-FDD" },
	{ 0, NULL }
};

static const value_string modulation_vals[] = {
	{ 2, "QPSK" },
	{ 4, "16QAM" },
	{ 6, "64QAM" },
	{ 8, "256QAM" },
	{ 0, NULL }
};

static const value_string pch_modulation_vals[] = {
	{ 0, "QPSK" },
	{ 0, NULL }
};

static const value_string ue_mode_vals[] = {
	{ 0, "non LC/CE UE" },
	{ 1, "LC/CE UE" },
	{ 0, NULL }
};

static const value_string csi_rs_class_vals[] = {
	{ 0, "not used" },
	{ 1, "Class A" },
	{ 1, "Class B" },
	{ 0, NULL }
};

static const value_string csi_rs_cdm_type_vals[] = {
	{ 0, "cdm 2" },
	{ 1, "cdm 4" },
	{ 0, NULL }
};

static const value_string antenna_ports_vals[] = {
	{ 0, "1 antenna ports" },
	{ 1, "2 antenna ports" },
	{ 2, "4 antenna ports" },
	{ 0, NULL }
};

static const value_string combs_vals[] = {
	{ 0, "2 TC" },
	{ 1, "4 TC" },
	{ 0, NULL }
};

static const value_string resource_allocation_type_vals[] = {
	{ 0, "type 0" },
	{ 1, "type 1" },
	{ 2, "type 2 1A/1B/1D" },
	{ 3, "type 2 1C" },
	{ 4, "type 2 6-1A" },
	{ 5, "type UEModeB" },
	{ 0, NULL }
};

static const value_string transmission_scheme_vals[] = {
	{ 0, "SINGLE_ANTENNA_PORT_0" },
	{ 1, "TX_DIVERSITY" },
	{ 2, "LARGE_DELAY_CDD" },
	{ 3, "CLOSED_LOOP_SPATIAL_MULTIPLEXING" },
	{ 4, "MULTI_USER_MIMO" },
	{ 5, "CLOSED_LOOP_RANK_1_PRECODING" },
	{ 6, "SINGLE_ANTENNA_PORT_5" },
	{ 7, "SINGLE_ANTENNA_PORT_7" },
	{ 8, "SINGLE_ANTENNA_PORT_8" },
	{ 9, "DUAL_LAYER_TX_PORT_7_AND_8" },
	{ 10, "UP_TO_8_LAYER_TX" },
	{ 11, "SINGLE_ANTENNA_PORT_11" },
	{ 12, "SINGLE_ANTENNA_PORT_13" },
	{ 13, "SINGLE_ANTENNA_PORT_11_13" },
	{ 0, NULL }
};

static const value_string ul_transmission_scheme_vals[] = {
	{ 0, "SINGLE_ANTENNA_PORT_10" },
	{ 1, "CLOSED_LOOP_SPATIAL_MULTIPLEXING" },
};

static const value_string dci_format_vals[] = {
	{ 0, "1" },
	{ 1, "1A" },
	{ 2, "1B" },
	{ 3, "1C" },
	{ 4, "1D" },
	{ 5, "2" },
	{ 6, "2A" },
	{ 7, "2B" },
	{ 8, "2C" },
	{ 9, "2D" },
	{ 0, NULL }
};

static const value_string pa_vals[] = {
	{ 0, "-6dB" },
	{ 1, "-4.77dB" },
	{ 2, "-3dB" },
	{ 3, "-1.77dB" },
	{ 4, "0dB" },
	{ 5, "1dB" },
	{ 6, "2dB" },
	{ 7, "3dB" },
	{ 0, NULL }
};

static const value_string transmission_mode_vals[] = {
	{ 1, "Mode 1" },
	{ 2, "Mode 2" },
	{ 3, "Mode 3" },
	{ 4, "Mode 4" },
	{ 5, "Mode 5" },
	{ 6, "Mode 6" },
	{ 7, "Mode 7" },
	{ 8, "Mode 8" },
	{ 9, "Mode 9" },
	{ 10, "Mode 10" },
	{ 0, NULL }
};

static const value_string nfapi_ul_config_pdu_type_vals[] = {
	{ 0, "ULSCH" },
	{ 1, "ULSCH_CQI_RI" },
	{ 2, "ULSCH_HARQ" },
	{ 3, "ULSCH_CQI_HARQ_RI" },
	{ 4, "UCI_CQI" },
	{ 5, "UCI_SR" },
	{ 6, "UCI_HARQ" },
	{ 7, "UCI_SR_HARQ" },
	{ 8, "UCI_CQI_HARQ" },
	{ 9, "UCI_CQI_SR" },
	{ 10, "UCI_CQI_SR_HARQ" },
	{ 11, "SRS" },
	{ 12, "HARQ_BUFFER" },
	{ 13, "ULSCH_UCI_CSI" },
	{ 14, "ULSCH_UCI_HARQ" },
	{ 15, "ULSCH_CSI_UCI_HARQ" },
	{ 0, NULL }
};

typedef enum {
	NFAPI_ACK_NACK_MODE_BUNDLING = 0,
	NFAPI_ACK_NACK_MODE_MULTIPLEXING,
	NFAPI_ACK_NACK_MODE_FORMAT_1B_WITH_CHAN_SEL,
	NFAPI_ACK_NACK_MODE_FORMAT_3,
} nfapi_ack_nack_mode_e;

static const value_string nfapi_ack_nack_mode_vals[] = {
	{ NFAPI_ACK_NACK_MODE_BUNDLING, "Bundling" },
	{ NFAPI_ACK_NACK_MODE_MULTIPLEXING, "Multiplexing" },
	{ NFAPI_ACK_NACK_MODE_FORMAT_1B_WITH_CHAN_SEL, "Format 1b with channel selection" },
	{ NFAPI_ACK_NACK_MODE_FORMAT_3, "Format 3" },
	{ 0, NULL }
};

typedef enum {
	NFAPI_ANTENNA_PORT1 = 0,
	NFAPI_ANTENNA_PORT2,
	NFAPI_ANTENNA_PORT4,
} nfapi_ack_nack_mode_e;

static const value_string nfapi_antenna_port_vals[] = {
	{ NFAPI_ANTENNA_PORT1, "1 " },
	{ NFAPI_ANTENNA_PORT2, "2 " },
	{ NFAPI_ANTENNA_PORT4, "4 " },
	{ 0, NULL }
};

typedef enum{
	PHICH_R_ONE_SIXTH = 0,
	PHICH_R_HALF,
	PHICH_R_ONE,
	PHICH_R_TWO
} nfapi_phich_resource_e;

static const value_string nfapi_phich_resource_vals[] = {
	{ PHICH_R_ONE_SIXTH, "PHICH_R_ONE_SIXTH " },
	{ PHICH_R_HALF, "PHICH_R_HALF" },
	{ PHICH_R_ONE, "PHICH_R_ONE" },
	{ PHICH_R_TWO, "PHICH_R_TWO" },
	{ 0, NULL }
};

static const value_string local_distributed_vals[] = {
	{ 0, "localized" },
	{ 1, "distributed" },
	{ 0, NULL }
};

static const value_string transport_block_to_codeword_swap_flag_vals[] = {
	{ 0, "no swapping" },
	{ 1, "swapped" },
	{ 0, NULL }
};

static const value_string ngap_vals[] = {
	{ 0, "Ngap1" },
	{ 1, "Ngap2" },
	{ 0, NULL }
};

static const value_string true_false_vals[] = {
	{ 0, "false" },
	{ 1, "true" },
	{ 0, NULL }
};

static const value_string exhustive_search_vals[] = {
	{ 0, "non-exhaustive search" },
	{ 1, "exhaustive search" },
	{ 0, NULL }
};

static const value_string not_used_enabled_vals[] = {
	{ 0, "not used" },
	{ 1, "enabled" },
	{ 0, NULL }
};

static const value_string hopping_vals[] = {
	{ 0, "no hopping" },
	{ 1, "hopping enabled" },
	{ 0, NULL }
};


static const value_string rnti_type_vals[] = {
	{ 1, "C-RNTI" },
	{ 2, "RA-RNTI, P-RNTI, SI-RNTI, SC-RNTI, G-RNTI" },
	{ 3, "SPS-CRNTI" },
	{ 0, NULL }
};

static const value_string primary_cells_type_vals[] = {
	{ 1, "TDD" },
	{ 2, "FDD" },
	{ 3, "HD_FDD" },
	{ 0, NULL }
};

static const value_string ul_rssi_supported_vals[] = {
	{ 0, "Uplink RSSI not supported" },
	{ 1, "Uplink RSSI supported" },
	{ 0, NULL}
};


typedef enum
{
	NMM_NONE = 0,
	NMM_ONLY,
	NMM_IN_CONFIGURED_STATE,
	NMM_IN_RUNNING_STATE,
	NMM_IN_CONFIGURED_AND_RUNNING_STATE
} nmm_modes_supported_e;

static const value_string nmm_modes_supported_vals[] =
{
	{ NMM_NONE, "NONE" },
	{ NMM_ONLY, "NMM_ONLY" },
	{ NMM_IN_CONFIGURED_STATE, "NMM_IN_CONFIGURED_STATE" },
	{ NMM_IN_RUNNING_STATE, "NMM_IN_RUNNING_STATE" },
	{ NMM_IN_CONFIGURED_AND_RUNNING_STATE, "NMM_IN_CONFIGURED_AND_RUNNING_STAT" },
	{ 0, NULL }
};





static int proto_nfapi = -1;

/* These are for the subtrees */
static gint ett_nfapi_message_tree = -1;
static gint ett_nfapi_p4_p5_message_header = -1;
static gint ett_nfapi_p7_message_header = -1;
static gint ett_nfapi_tlv_tree = -1;
static gint ett_nfapi_tl = -1;
static gint ett_nfapi_pnf_param_response = -1;
static gint ett_nfapi_pnf_phy = -1;
static gint ett_nfapi_pnf_phy_rel10 = -1;
static gint ett_nfapi_pnf_phy_rel11 = -1;
static gint ett_nfapi_pnf_phy_rel12 = -1;
static gint ett_nfapi_pnf_phy_rel13 = -1;
static gint ett_nfapi_pnf_rf = -1;
static gint ett_nfapi_phy_rf_config_info = -1;
static gint ett_nfapi_pnf_phy_rf_config = -1;
static gint ett_nfapi_pnf_phy_rf_config_instance = -1;
static gint ett_nfapi_phy_state = -1;
static gint ett_nfapi_l1_status = -1;
static gint ett_nfapi_rf_bands = -1;
static gint ett_nfapi_tx_antenna_ports = -1;
static gint ett_nfapi_harq_ack_nack_data = -1;
static gint ett_nfapi_harq_data = -1;
static gint ett_nfapi_cc = -1;
static gint ett_nfapi_rbs = -1;
static gint ett_nfapi_antennas = -1;
static gint ett_nfapi_dl_config_dci_dl_pdu_rel8 = -1;
static gint ett_nfapi_dl_config_dci_dl_pdu_rel9 = -1;
static gint ett_nfapi_dl_config_dci_dl_pdu_rel10 = -1;
static gint ett_nfapi_dl_config_dci_dl_pdu = -1;
static gint ett_nfapi_dl_config_request_pdu = -1;
static gint ett_nfapi_dl_config_request_body = -1;
static gint ett_nfapi_dl_config_request_pdu_list = -1;
static gint ett_nfapi_ul_config_request_pdu_list = -1;
static gint ett_nfapi_hi_dci0_request_pdu_list = -1;
static gint ett_nfapi_tx_request_pdu_list = -1;
static gint ett_nfapi_rx_indication_pdu_list = -1;
static gint ett_nfapi_harq_indication_pdu_list = -1;
static gint ett_nfapi_crc_indication_pdu_list = -1;
static gint ett_nfapi_sr_indication_pdu_list = -1;
static gint ett_nfapi_cqi_indication_pdu_list = -1;
static gint ett_nfapi_preamble_indication_pdu_list = -1;
static gint ett_nfapi_srs_indication_pdu_list = -1;
static gint ett_nfapi_lbt_dl_config_pdu_list = -1;
static gint ett_nfapi_lbt_dl_indication_pdu_list = -1;
static gint ett_nfapi_dl_node_sync = -1;
static gint ett_nfapi_ul_node_sync = -1;
static gint ett_nfapi_timing_info = -1;
static gint ett_nfapi_dl_config_request_dlsch_pdu_rel8 = -1;
static gint ett_nfapi_subbands = -1;
static gint ett_nfapi_dl_config_request_dlsch_pdu_rel9 = -1;
static gint ett_nfapi_dl_config_request_dlsch_pdu_rel10 = -1;
static gint ett_nfapi_dl_config_bch_pdu_rel8 = -1;
static gint ett_nfapi_dl_config_mch_pdu_rel8 = -1;
static gint ett_nfapi_dl_config_pch_pdu_rel8 = -1;
static gint ett_nfapi_dl_config_prs_pdu_rel9 = -1;
static gint ett_nfapi_dl_config_csi_rs_pdu_rel10 = -1;
static gint ett_nfapi_ul_config_request_body = -1;
static gint ett_nfapi_ul_config_harq_buffer_pdu = -1;
static gint ett_nfapi_ul_config_ue_information_rel8 = -1;
static gint ett_nfapi_ul_config_sr_information_pdu_rel8 = -1;
static gint ett_nfapi_ul_config_ulsch_pdu_rel8 = -1;
static gint ett_nfapi_ul_config_ulsch_pdu_rel10 = -1;
static gint ett_nfapi_ul_config_cqi_ri_information_rel8 = -1;
static gint ett_nfapi_ul_config_cqi_ri_information_rel9 = -1;
static gint ett_nfapi_ul_config_ulsch_harq_information_rel10 = -1;
static gint ett_nfapi_ul_config_initial_transmission_parameters_rel8 = -1;
static gint ett_nfapi_ul_config_cqi_information_rel8 = -1;
static gint ett_nfapi_ul_config_cqi_information_rel10 = -1;
static gint ett_nfapi_ul_config_sr_information_rel8 = -1;
static gint ett_nfapi_ul_config_sr_information_rel10 = -1;
static gint ett_nfapi_ul_config_harq_information_rel10_tdd = -1;
static gint ett_nfapi_ul_config_harq_information_rel8_fdd = -1;
static gint ett_nfapi_ul_config_harq_information_rel9_fdd = -1;
static gint ett_nfapi_ul_config_srs_pdu_rel8 = -1;
static gint ett_nfapi_ul_config_srs_pdu_rel10 = -1;
static gint ett_nfapi_crc_indication_body = -1;
static gint ett_nfapi_bf_vector_antennas = -1;
static gint ett_nfapi_bf_vectors = -1;
static gint ett_nfapi_csi_rs_resource_configs = -1;
static gint ett_nfapi_csi_rs_bf_vector = -1;
static gint ett_nfapi_epdcch_prbs = -1;
static gint ett_nfapi_precoding = -1;
static gint ett_nfapi_earfcn_list = -1;
static gint ett_nfapi_uarfcn_list = -1;
static gint ett_nfapi_arfcn_list = -1;
static gint ett_nfapi_rssi_list = -1;
static gint ett_nfapi_pci_list = -1;
static gint ett_nfapi_psc_list = -1;
static gint ett_nfapi_lte_cells_found_list = -1;
static gint ett_nfapi_utran_cells_found_list = -1;
static gint ett_nfapi_geran_cells_found_list = -1;
static gint ett_nfapi_si_periodicity_list = -1;

static expert_field ei_invalid_range = EI_INIT;
static expert_field ei_power_invalid = EI_INIT;
static expert_field ei_ref_sig_power_invalid = EI_INIT;


static int hf_nfapi_message_tree = -1;

static int hf_nfapi_p4_p5_message_header = -1;
static int hf_nfapi_p4_p5_message_header_phy_id = -1;
static int hf_nfapi_p4_p5_message_header_message_id = -1;
static int hf_nfapi_p4_p5_message_header_message_length = -1;
static int hf_nfapi_p4_p5_message_header_spare = -1;

static int hf_nfapi_p7_message_header = -1;
static int hf_nfapi_p7_message_header_phy_id = -1;
static int hf_nfapi_p7_message_header_message_id = -1;
static int hf_nfapi_p7_message_header_message_length = -1;
static int hf_nfapi_p7_message_header_m = -1;
static int hf_nfapi_p7_message_header_segment = -1;
static int hf_nfapi_p7_message_header_sequence_number = -1;
static int hf_nfapi_p7_message_header_checksum = -1;
static int hf_nfapi_p7_message_header_transmit_timestamp = -1;

static int hf_nfapi_tlv_tree = -1;

static int hf_nfapi_tl = -1;
static int hf_nfapi_tl_tag = -1;
static int hf_nfapi_tl_length = -1;
static int hf_nfapi_tag_uint8_value = -1;
static int hf_nfapi_tag_uint16_value = -1;

static int hf_nfapi_pnf_param_general = -1;
static int hf_nfapi_sync_mode = -1;
static int hf_nfapi_location_mode = -1;
static int hf_nfapi_location_coordinates = -1;
static int hf_nfapi_location_coordinates_length = -1;
static int hf_nfapi_dl_config_timing = -1;
static int hf_nfapi_tx_timing = -1;
static int hf_nfapi_ul_config_timing = -1;
static int hf_nfapi_hi_dci0_timing = -1;
static int hf_nfapi_maximum_number_phys = -1;
static int hf_nfapi_maximum_total_bandwidth = -1;
static int hf_nfapi_maximum_total_number_dl_layers = -1;
static int hf_nfapi_maximum_total_number_ul_layers = -1;
static int hf_nfapi_shared_bands = -1;
static int hf_nfapi_shared_pa = -1;
static int hf_nfapi_maximum_total_power = -1;
static int hf_nfapi_oui= -1;

static int hf_nfapi_pdu = -1;

static int hf_nfapi_pnf_phy = -1;
static int hf_nfapi_pnf_phy_nfapi_tl = -1; /* structure hf_nfapi_tl*/
static int hf_nfapi_pnf_phy_number_phy = -1;
static int hf_nfapi_pnf_phy_config_index = -1;
static int hf_nfapi_number_of_rf_exclusions = -1;
static int hf_nfapi_dl_bandwidth_support = -1;
static int hf_nfapi_ul_bandwidth_support = -1;
static int hf_nfapi_downlink_channel_bandwidth_supported = -1;
static int hf_nfapi_uplink_channel_bandwidth_supported = -1;
static int hf_nfapi_number_of_dl_layers_supported = -1;
static int hf_nfapi_number_of_ul_layers_supported = -1;
static int hf_nfapi_maximum_3gpp_release_supported = -1;
static int hf_nfapi_nmm_modes_supported = -1;


static int hf_nfapi_pnf_rf = -1;
static int hf_nfapi_pnf_rf_nfapi_tl = -1;
static int hf_nfapi_number_of_rfs = -1;
static int hf_nfapi_rf_config_index = -1;
static int hf_nfapi_band = -1;
static int hf_nfapi_maximum_transmit_power = -1;
static int hf_nfapi_earfcn = -1;
static int hf_nfapi_minimum_transmit_power = -1;
static int hf_nfapi_number_of_antennas_suppported = -1;
static int hf_nfapi_minimum_downlink_frequency = -1;
static int hf_nfapi_maximum_downlink_frequency = -1;
static int hf_nfapi_minimum_uplink_frequency = -1;
static int hf_nfapi_maximum_uplink_frequency = -1;

static int hf_nfapi_number_of_rf_bands = -1;
static int hf_nfapi_nmm_uplink_rssi_supported = -1;

static int hf_nfapi_phy_rf_config_info = -1;
static int hf_nfapi_phy_rf_config_info_phy_id = -1;
static int hf_nfapi_phy_rf_config_info_band = -1;

static int hf_nfapi_pnf_phy_rf_config = -1;
static int hf_nfapi_pnf_phy_rf_config_number_phy_rf_config_info = -1;
static int hf_nfapi_pnf_phy_rf_config_array_phy_rf_config_info = -1;

static int hf_nfapi_pnf_phy_rel10 = -1;
static int hf_nfapi_transmission_mode7_supported = -1;
static int hi_nfapi_transmission_mode8_supported = -1;
static int hi_nfapi_two_antennas_ports_for_pucch = -1;
static int hi_nfapi_transmission_mode_9_supported = -1;
static int hi_nfapi_simultaneous_pucch_pusch = -1;
static int hi_nfapi_for_layer_tx_with_tm3_and_tm4 = -1;

static int hf_nfapi_pnf_phy_rel11 = -1;
static int hf_nfapi_epdcch_supported = -1;
static int hi_nfapi_multi_ack_csi_reporting = -1;
static int hi_nfapi_pucch_tx_diversity_with_channel_selection = -1;
static int hi_nfapi_ul_comp_supported = -1;
static int hi_nfapi_transmission_mode_5_supported = -1;

static int hf_nfapi_pnf_phy_rel12 = -1;
static int hf_nfapi_csi_subframe_set = -1;
static int hi_nfapi_enhanced_4tx_codebook = -1;
static int hi_nfapi_drs_supported = -1;
static int hi_nfapi_ul_64qam_supported = -1;
static int hi_nfapi_transmission_mode_10_supported = -1;
static int hi_nfapi_alternative_tbs_indices = -1;

static int hf_nfapi_pnf_phy_rel13 = -1;
static int hf_nfapi_pucch_format_4_supported = -1;
static int hf_nfapi_pucch_format_5_supported = -1;
static int hf_nfapi_more_than_5_ca_supported = -1;
static int hf_nfapi_laa_supported = -1;
static int hf_nfapi_laa_ending_in_dwpts_supported = -1;
static int hf_nfapi_laa_starting_in_second_slot_supported = -1;
static int hf_nfapi_beamforming_supported = -1;
static int hf_nfapi_csi_rs_enhancements_supported = -1;
static int hf_nfapi_drms_enhancements_supported = -1;
static int hf_nfapi_srs_enhancements_supported = -1;


// P5 Message Structures
static int hf_nfapi_pnf_param_response_pnf_param_general = -1;
static int hf_nfapi_pnf_param_response_pnf_phy = -1;
static int hf_nfapi_pnf_param_response_pnf_rf = -1;

static int hf_nfapi_pnf_param_request = -1;
static int hf_nfapi_pnf_param_response = -1;
static int hf_nfapi_pnf_config_request = -1;
static int hf_nfapi_pnf_config_response = -1;
static int hf_nfapi_pnf_start_request = -1;
static int hf_nfapi_pnf_start_response = -1;
static int hf_nfapi_pnf_stop_request = -1;
static int hf_nfapi_pnf_stop_response = -1;
static int hf_nfapi_param_response = -1;
static int hf_nfapi_start_request = -1;
static int hf_nfapi_start_response = -1;
static int hf_nfapi_stop_request = -1;
static int hf_nfapi_stop_response = -1;

static int hf_nfapi_uint8_tag = -1;
static int hf_nfapi_uint16_tag = -1;

static int hf_nfapi_error_code = -1;
static int hf_nfapi_p4_error_code = -1;
static int hf_nfapi_rat_type = -1;
static int hf_nfapi_num_tlv = -1;
static int hf_nfapi_phy_state = -1;
//	static int hf_nfapi_bandwidth_support = -1;
	
static int hf_nfapi_modulation_support = -1;
static int hf_nfapi_phy_antenna_capability = -1;
static int hf_nfapi_release_capability = -1;
static int hf_nfapi_mbsfn_capability = -1;

static int hf_nfapi_laa_capability = -1;
static int hf_nfapi_pd_sensing_lbt_support = -1;
static int hf_nfapi_multi_carrier_lbt_support = -1;
static int hf_nfapi_partial_sf_support = -1;
	
/* nfapi nfapi */
static int hf_nfapi_pnf_address = -1;
static int hf_nfapi_pnf_address_ipv4 = -1;
static int hf_nfapi_pnf_address_ipv6 = -1;

static int hf_nfapi_vnf_address = -1;
static int hf_nfapi_vnf_address_ipv4 = -1;
static int hf_nfapi_vnf_address_ipv6 = -1;
	
static int hf_nfapi_pnf_port = -1;
static int hf_nfapi_vnf_port = -1;
static int hf_nfapi_dl_ue_per_sf = -1;
static int hf_nfapi_ul_ue_per_sf = -1;

static int hf_nfapi_rf_bands = -1;
static int hf_nfapi_rf_bands_nfapi_tl = -1;
static int hf_nfapi_rf_bands_count = -1;
static int hf_nfapi_rf_bands_value = -1;

static int hf_nfapi_timing_window = -1;
static int hf_nfapi_timing_info_mode = -1;
static int hf_nfapi_timing_info_period = -1;
static int hf_nfapi_max_transmit_power = -1;
	
/* subframe config */
static int hf_nfapi_duplex_mode = -1;
static int hf_nfapi_pcfich_power_offset = -1;
static int hf_nfapi_pb = -1;
static int hf_nfapi_dl_cyclic_prefix_type = -1;
static int hf_nfapi_ul_cyclic_prefix_type = -1;

static int hf_nfapi_tx_antenna_ports = -1;
static int hf_nfapi_rx_antenna_ports = -1;



/* RF Config */
static int hf_nfapi_downlink_channel_bandwidth = -1;
static int hf_nfapi_uplink_channel_bandwidth = -1;
static int hf_nfapi_reference_signal_power = -1;

/* PHICH config*/
static int hf_nfapi_phich_resource = -1;
static int hf_nfapi_phich_duration = -1;
static int hf_nfapi_phich_power_offset = -1;

static int hf_nfapi_value_float = -1;

/* SCH Config */
static int hf_nfapi_primary_synchronization_signal_epre_eprers = -1;
static int hf_nfapi_secondary_synchronization_signal_epre_eprers = -1;
static int hf_nfapi_physical_cell_id = -1;

/* PRACH config */
static int hf_nfapi_configuration_index = -1;
static int hf_nfapi_root_sequence_index = -1;
static int hf_nfapi_zero_correlation_zone_configuration = -1;
static int hf_nfapi_high_speed_flag = -1;
static int hf_nfapi_frequency_offset = -1;

/* PUSCH config */
static int hf_nfapi_hopping_mode = -1;
static int hf_nfapi_hopping_offset = -1;

/* PUCCH config */
static int hf_nfapi_delta_pucch_shift = -1;
static int hf_nfapi_n_cqi_rb = -1;
static int hf_nfapi_n_an_cs = -1;
static int hf_nfapi_n1_pucch_an = -1;

/* SRS config */
static int hf_nfapi_bandwidth_configuration = -1;
static int hf_nfapi_max_up_pts = -1;
static int hf_nfapi_srs_subframe_configuration = -1;
static int hf_nfapi_srs_acknack_srs_simultaneous_transmission = -1;

/* uplink reference signal config */
static int hf_nfapi_uplink_rs_hopping = -1;
static int hf_nfapi_group_assignment = -1;
static int hf_nfapi_cyclic_shift_1_for_drms = -1;

/* tdd frame structure */
static int hf_nfapi_subframe_assignment = -1;
static int hf_nfapi_special_subframe_patterns = -1;

/* laa config */
static int hf_nfapi_ed_threshold_for_lbt_for_pdsch = -1;
static int hf_nfapi_ed_threshold_for_lbt_for_drs = -1;
static int hf_nfapi_pd_threshold = -1;
static int hf_nfapi_multi_carrier_type = -1;
static int hf_nfapi_multi_carrier_tx = -1;
static int hf_nfapi_multi_carrier_freeze = -1;
static int hf_nfapi_tx_antenna_ports_for_drs = -1;
static int hf_nfapi_transmission_power_for_drs = -1;

/* eMTC config */
static int hf_nfapi_pbch_repetitions_enabled_r13 = -1;
static int hf_nfapi_prach_cat_m_root_sequence_index = -1;
static int hf_nfapi_prach_cat_m_zero_correlation_zone_configuration = -1;
static int hf_nfapi_prach_cat_m_high_speed_flag = -1;

static int hf_nfapi_prach_ce_level_0_enable = -1;
static int hf_nfapi_prach_ce_level_0_configuration_index = -1;
static int hf_nfapi_prach_ce_level_0_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_0_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_0_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_0_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_0_hopping_offset = -1;

static int hf_nfapi_prach_ce_level_1_enable = -1;
static int hf_nfapi_prach_ce_level_1_configuration_index = -1;
static int hf_nfapi_prach_ce_level_1_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_1_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_1_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_1_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_1_hopping_offset = -1;

static int hf_nfapi_prach_ce_level_2_enable = -1;
static int hf_nfapi_prach_ce_level_2_configuration_index = -1;
static int hf_nfapi_prach_ce_level_2_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_2_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_2_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_2_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_2_hopping_offset = -1;

static int hf_nfapi_prach_ce_level_3_enable = -1;
static int hf_nfapi_prach_ce_level_3_configuration_index = -1;
static int hf_nfapi_prach_ce_level_3_frequency_offset = -1;
static int hf_nfapi_prach_ce_level_3_number_of_repetitions_per_attempt = -1;
static int hf_nfapi_prach_ce_level_3_starting_subframe_periodicity = -1;
static int hf_nfapi_prach_ce_level_3_hopping_enabled = -1;
static int hf_nfapi_prach_ce_level_3_hopping_offset = -1;
static int hf_nfapi_pucch_internal_ul_hopping_config_common_mode_b = -1;
static int hf_nfapi_pucch_internal_ul_hopping_config_common_mode_a = -1;

static int hf_nfapi_dl_modulation_support = -1;
static int hf_nfapi_ul_modulation_support = -1;

/* 123 config */
static int hf_nfapi_data_report_mode = -1;
static int hf_nfapi_sfnsf = -1;

// P7 Sub Structures
static int hf_nfapi_dl_config_dci_dl_pdu_rel8 = -1;
static int hf_nfapi_dci_format = -1;
static int hf_nfapi_cce_idx = -1;
static int hf_nfapi_aggregation_level = -1;
static int hf_nfapi_mcs_1 = -1;
static int hf_nfapi_redundancy_version_1 = -1;
static int hf_nfapi_new_data_indicator_1 = -1;
static int hf_nfapi_mcs_2 = -1;
static int hf_nfapi_redundancy_version_2 = -1;
static int hf_nfapi_new_data_indicator_2 = -1;
static int hf_nfapi_harq_process = -1;
static int hf_nfapi_tpmi = -1;
static int hf_nfapi_pmi = -1;
static int hf_nfapi_precoding_information = -1;
static int hf_nfapi_tpc = -1;
static int hf_nfapi_downlink_assignment_index = -1;
static int hf_nfapi_transport_block_size_index = -1;
static int hf_nfapi_downlink_power_offset = -1;
static int hf_nfapi_allocate_prach_flag = -1;
static int hf_nfapi_preamble_index = -1;
static int hf_nfapi_prach_mask_index = -1;
static int hf_nfapi_rnti_type = -1;

static int hf_nfapi_dl_config_dci_dl_pdu_rel9 = -1;
static int hf_nfapi_mcch_flag = -1;
static int hf_nfapi_mcch_change_notification = -1;
static int hf_nfapi_scrambling_identity = -1;

static int hf_nfapi_dl_config_dci_dl_pdu_rel10 = -1;
static int hf_nfapi_cross_carrier_scheduling_flag = -1;
static int hf_nfapi_carrier_indicator = -1;
static int hf_nfapi_srs_flag = -1;
static int hf_nfapi_srs_request = -1;
static int hf_nfapi_antenna_ports_scrambling_and_layers = -1;
static int hf_nfapi_total_dci_length_including_padding = -1;
static int hf_nfapi_n_dl_rb = -1;

static int hf_nfapi_dl_config_dci_dl_pdu_rel11 = -1;
static int hf_nfapi_harq_ack_resource_offset = -1;
static int hf_nfapi_pdsch_re_mapping_and_quasi_co_location_indicator = -1;
static int hf_nfapi_dl_config_dci_dl_pdu_rel12 = -1;
static int hf_nfapi_primary_cell_type = -1;
static int hf_nfapi_ul_dl_configuration_flag = -1;
static int hf_nfapi_number_of_ul_dl_configurations = -1;
static int hf_nfapi_ul_dl_configuration_index = -1;
static int hf_nfapi_dl_config_dci_dl_pdu_rel13 = -1;
static int hf_nfapi_laa_end_partial_sf_flag = -1;
static int hf_nfapi_laa_end_partial_sf_configuration = -1;
static int hf_nfapi_initial_lbt_sf = -1;
static int hf_nfapi_codebooksize_determination_r13 = -1;
static int hf_nfapi_rel13_drms_table_flag = -1;


static int hf_nfapi_dl_config_dci_dl_pdu = -1;
static int hf_nfapi_dl_config_dci_dl_pdu_nfapi_dl_config_dci_dl_pdu_rel8 = -1;
static int hf_nfapi_dl_config_dci_dl_pdu_nfapi_dl_config_dci_dl_pdu_rel9 = -1;
static int hf_nfapi_dl_config_dci_dl_pdu_nfapi_dl_config_dci_dl_pdu_rel10 = -1;

static int hf_nfapi_bf_vector_antennas = -1;
static int hf_nfapi_subbands = -1;
static int hf_nfapi_bf_vectors = -1;
static int hf_nfapi_csi_rs_resource_config = -1;
static int hf_nfapi_csi_rs_number_if_nzp_configurations = -1;
static int hf_nfapi_csi_rs_resource_configs = -1;
static int hf_nfapi_pdsch_start = -1;
static int hf_nfapi_drms_config_flag = -1;
static int hf_nfapi_drms_scrambling = -1;
static int hf_nfapi_csi_config_flag = -1;
static int hf_nfapi_csi_scrambling = -1;
static int hf_nfapi_pdsch_re_mapping_flag = -1;
static int hf_nfapi_pdsch_re_mapping_antenna_ports = -1;
static int hf_nfapi_pdsch_re_mapping_freq_shift = -1;
static int hf_nfapi_alt_cqi_table_r12 = -1;
static int hf_nfapi_max_layers = -1;
static int hf_nfapi_n_dl_harq = -1;
static int hf_nfapi_dwpts_symbols = -1;
static int hf_nfapi_ue_type = -1;
static int hf_nfapi_pdsch_payload_type = -1;
static int hf_nfapi_initial_transmission_sf = -1;
static int hf_nfapi_req13_drms_table_flag = -1;
static int hf_nfapi_prnti = -1;
static int hf_nfapi_mcs = -1;
static int hf_nfapi_number_of_transport_blocks = -1;
static int hf_nfapi_ue_mode = -1;
static int hf_prs_bandwidth = -1;
static int hf_prs_cyclic_prefix_type = -1;
static int hf_prs_muting = -1;
static int hf_nfapi_csi_rs_number_of_nzp_configuration = -1;
static int hf_nfapi_csi_rs_resource_index = -1;
static int hf_nfapi_csi_rs_class = -1;
static int hf_nfapi_cdm_type = -1;
static int hf_nfapi_csi_rs_bf_vector = -1;
static int hf_nfapi_edpcch_prb_index = -1;
static int hf_nfapi_epdcch_resource_assignment_flag = -1;
static int hf_nfapi_epdcch_id = -1;
static int hf_nfapi_epdcch_start_symbol = -1;
static int hf_nfapi_epdcch_num_prb = -1;
static int hf_nfapi_epdcch_prbs = -1;
static int hf_nfapi_precoding_value = -1;
static int hf_nfapi_mpdcch_narrowband = -1;
static int hf_nfapi_number_of_prb_pairs = -1;
static int hf_nfapi_resource_block_assignment = -1;
static int hf_nfapi_start_symbol = -1;
static int hf_nfapi_ecce_index = -1;
static int hf_nfapi_ce_mode = -1;
static int hf_nfapi_drms_scrabmling_init = -1;
static int hf_nfapi_pdsch_reception_levels = -1;
static int hf_nfapi_new_data_indicator = -1;
static int hf_nfapi_tpmi_length = -1;
static int hf_nfapi_pmi_flag = -1;
static int hf_nfapi_harq_resource_offset = -1;
static int hf_nfapi_dci_subframe_repetition_number = -1;
static int hf_nfapi_downlink_assignment_index_length = -1;
static int hf_nfapi_starting_ce_level = -1;
static int hf_nfapi_antenna_ports_and_scrambling_identity_flag = -1;
static int hf_nfapi_antenna_ports_and_scrambling_identity = -1;
static int hf_nfapi_paging_direct_indication_differentiation_flag = -1;
static int hf_nfapi_direct_indication = -1;
static int hf_nfapi_number_of_tx_antenna_ports = -1;
static int hf_nfapi_precoding = -1;



// P7 Message Structures
static int hf_nfapi_dl_node_sync = -1;
static int hf_nfapi_dl_node_sync_nfapi_p7_message_header = -1;
static int hf_nfapi_dl_node_sync_t1 = -1;
static int hf_nfapi_dl_node_sync_delta_sfn_sf = -1;

static int hf_nfapi_ul_node_sync = -1;
static int hf_nfapi_ul_node_sync_nfapi_p7_message_header = -1;
static int hf_nfapi_ul_node_sync_t1 = -1;
static int hf_nfapi_ul_node_sync_t2 = -1;
static int hf_nfapi_ul_node_sync_t3 = -1;

static int hf_nfapi_timing_info = -1;
static int hf_nfapi_timing_info_nfapi_p7_message_header = -1;
static int hf_nfapi_timing_info_last_sfn_sf = -1;
static int hf_nfapi_timing_info_time_since_last_timing_info = -1;
static int hf_nfapi_timing_info_dl_config_jitter = -1;
static int hf_nfapi_timing_info_tx_request_jitter = -1;
static int hf_nfapi_timing_info_ul_config_jitter = -1;
static int hf_nfapi_timing_info_hi_dci0_jitter = -1;
static int hf_nfapi_timing_info_dl_config_latest_delay = -1;
static int hf_nfapi_timing_info_tx_request_latest_delay = -1;
static int hf_nfapi_timing_info_ul_config_latest_delay = -1;
static int hf_nfapi_timing_info_hi_dci0_latest_delay = -1;
static int hf_nfapi_timing_info_dl_config_earliest_arrival = -1;
static int hf_nfapi_timing_info_tx_request_earliest_arrival = -1;
static int hf_nfapi_timing_info_ul_config_earliest_arrival = -1;
static int hf_nfapi_timing_info_hi_dci0_earliest_arrival = -1;

static int hf_nfapi_dl_config_request = -1;
static int hf_nfapi_sfn_sf = -1;

static int hf_nfapi_dl_config_request_body = -1;
static int hf_nfapi_number_pdcch_ofdm_symbols = -1;
static int hf_nfapi_number_dci = -1;
static int hf_nfapi_number_pdus = -1;
static int hf_nfapi_number_pdsch_rnti = -1;
static int hf_nfapi_transmission_power_pcfich = -1;

static int hf_nfapi_number_of_harqs = -1;
static int hf_nfapi_number_of_crcs = -1;
static int hf_nfapi_number_of_srs = -1;
static int hf_nfapi_number_of_cqi = -1;
static int hf_nfapi_number_of_preambles = -1;
static int hf_nfapi_number_of_srss = -1;
static int hf_nfapi_lbt_dl_req_pdu_type = -1;
static int hf_nfapi_lbt_dl_ind_pdu_type = -1;

static int hf_nfapi_dl_config_request_pdu_list = -1;
static int hf_nfapi_ul_config_request_pdu_list = -1;
static int hf_nfapi_hi_dci0_request_pdu_list = -1;
static int hf_nfapi_tx_request_pdu_list = -1;
static int hf_nfapi_rx_indication_pdu_list = -1;
static int hf_nfapi_harq_indication_pdu_list = -1;
static int hf_nfapi_crc_indication_pdu_list = -1;
static int hf_nfapi_sr_indication_pdu_list = -1;
static int hf_nfapi_cqi_indication_pdu_list = -1;
static int hf_nfapi_preamble_indication_pdu_list = -1;
static int hf_nfapi_srs_indication_pdu_list = -1;
static int hf_nfapi_lbt_dl_config_pdu_list = -1;
static int hf_nfapi_lbt_dl_indication_pdu_list = -1;


static int hf_nfapi_dl_config_pdu_type = -1;
static int hf_nfapi_pdu_size = -1;
static int hf_nfapi_instance_length = -1;

static int hf_nfapi_dl_config_dlsch_pdu_rel8 = -1;
static int hf_nfapi_length;
static int hf_nfapi_pdu_index = -1;
static int hf_nfapi_rnti = -1;
static int hf_nfapi_resource_allocation_type = -1;
static int hf_nfapi_virtual_resource_block_assignment_flag = -1;
static int hf_nfapi_resource_block_coding = -1;
static int hf_nfapi_modulation = -1;
static int hf_nfapi_redundancy_version = -1;
static int hf_nfapi_transport_blocks = -1;
static int hf_nfapi_transport_block_to_codeword_swap_flag = -1;
static int hf_nfapi_transmission_scheme = -1;
static int hf_nfapi_ul_transmission_scheme = -1;
static int hf_nfapi_number_of_layers = -1;
static int hf_nfapi_number_of_subbands = -1;
static int hf_nfapi_codebook_index = -1;
static int hf_nfapi_ue_category_capacity = -1;
static int hf_nfapi_pa = -1;
static int hf_nfapi_delta_power_offset_index = -1;
static int hf_nfapi_ngap = -1;
static int hf_nfapi_nprb = -1;
static int hf_nfapi_transmission_mode = -1;
static int hf_nfapi_num_bf_prb_per_subband = -1;

static int hf_nfapi_num_bf_vector = -1;
static int hf_nfapi_bf_vector_subband_index = -1;
static int hf_nfapi_bf_vector_num_antennas = -1;
static int hf_nfapi_bf_vector_bf_value = -1;

static int hf_nfapi_dl_config_dlsch_pdu_rel9 = -1;
static int hf_nfapi_nscid = -1;

static int hf_nfapi_dl_config_dlsch_pdu_rel10 = -1;
static int hf_nfapi_csi_rs_flag = -1;
static int hf_nfapi_csi_rs_resource_config_r10 = -1;
static int hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10 = -1;

static int hf_nfapi_dl_config_bch_pdu_rel8 = -1;
static int hf_nfapi_transmission_power = -1;

static int hf_nfapi_dl_config_mch_pdu_rel8 = -1;
static int hf_nfapi_mbsfn_area_id = -1;

static int hf_nfapi_dl_config_pch_pdu_rel8 = -1;

static int hf_nfapi_dl_config_prs_pdu_rel9 = -1;
static int hf_nfapi_prs_bandwidth = -1;
static int hf_nfapi_prs_cyclic_prefix_type = -1;
		
static int hf_nfapi_dl_config_csi_rs_pdu_rel10 = -1;
static int hf_nfapi_csi_rs_antenna_port_count_r10 = -1;

static int hf_nfapi_ul_config_request = -1;
static int hf_nfapi_ul_config_request_body = -1;
static int hf_nfapi_ul_config_pdu_type = -1;

static int hf_nfapi_rach_prach_frequency_resources = -1;
static int hf_nfapi_srs_present = -1;
static int hf_nfapi_ul_config_harq_buffer_pdu = -1;

static int hf_nfapi_ul_config_ue_information_rel8 = -1;
static int hf_nfapi_handle = -1;
static int hf_nfapi_ul_config_sr_information_pdu_rel8 = -1;
static int hf_nfapi_pucch_index = -1;
static int hf_nfapi_size = -1;
static int hf_nfapi_resource_block_start = -1;
static int hf_nfapi_number_of_resource_blocks = -1;
static int hf_nfapi_cyclic_shift_2_for_drms = -1;
static int hf_nfapi_frequency_hopping_enabled_flag = -1;
static int hf_nfapi_frequency_hopping_bits = -1;
static int hf_nfapi_new_data_indication = -1;
static int hf_nfapi_harq_process_number = -1;
static int hf_nfapi_ul_tx_mode = -1;
static int hf_nfapi_current_tx_nb = -1;
static int hf_nfapi_n_srs = -1;
static int hf_nfapi_disable_sequence_hopping_flag = -1;
static int hf_nfapi_dl_cqi_pmi_size_rank_1 = -1;
static int hf_nfapi_dl_cqi_pmi_size_rank_greater_1 = -1;
static int hf_nfapi_ri_size = -1;
static int hf_nfapi_delta_offset_cqi = -1;
static int hf_nfapi_delta_offset_ri = -1;
static int hf_nfapi_harq_size = -1;
static int hf_nfapi_delta_offset_harq = -1;
static int hf_nfapi_ack_nack_mode = -1;
static int hf_nfapi_n_srs_initial = -1;
static int hf_nfapi_initial_number_of_resource_blocks = -1;
static int hf_nfapi_dl_cqi_pmi_size = -1;
static int hf_nfapi_report_type = -1;
static int hf_nfapi_dl_cqi_ri_pmi_size = -1;
static int hf_nfapi_control_type = -1;
static int hf_nfapi_number_of_cc = -1;
static int hf_nfapi_virtual_cell_id_enabled_flag = -1;
static int hf_nfapi_npusch_identity = -1;
static int hf_nfapi_ndrms_csh_identity = -1;
static int hf_nfapi_total_number_of_repetitions = -1;
static int hf_nfapi_repetition_number = -1;
static int hf_nfapi_initial_sf_io = -1;
static int hf_nfapi_empty_symbols_due_to_retunning = -1;
static int hf_nfapi_dl_cqi_ri_pmi_size_2 = -1;
static int hf_nfapi_npucch_identity = -1;
static int hf_nfapi_harq_size_2 = -1;
static int hf_nfapi_delta_offset_harq_2 = -1;
static int hf_nfapi_empty_symbols = -1;
static int hf_nfapi_total_number_of_repetitons = -1;
static int hf_nfapi_csi_mode = -1;
static int hf_nfapi_dl_cqi_pmi_size_2 = -1;
static int hf_nfapi_statring_prb = -1;
static int hf_nfapi_cdm_index = -1;
static int hf_nfapi_nsrs = -1;
static int hf_nfapi_num_ant_ports = -1;
static int hf_nfapi_n_pucch_2_0 = -1;
static int hf_nfapi_n_pucch_2_1 = -1;
static int hf_nfapi_n_pucch_2_2 = -1;
static int hf_nfapi_n_pucch_2_3 = -1;
static int hf_nfapi_starting_prb = -1;
static int hf_nfapi_antenna_port = -1;
static int hf_nfapi_number_of_combs = -1;



static int hf_nfapi_number_of_pucch_resource = -1;
static int hf_nfapi_pucch_index_p1 = -1;
static int hf_nfapi_n_pucch_1_0 = -1;
static int hf_nfapi_n_pucch_1_1 = -1;
static int hf_nfapi_n_pucch_1_2 = -1;
static int hf_nfapi_n_pucch_1_3 = -1;
static int hf_nfapi_srs_bandwidth = -1;
static int hf_nfapi_frequency_domain_position = -1;
static int hf_nfapi_srs_hopping_bandwidth = -1;
static int hf_nfapi_transmission_comb = -1;
static int hf_nfapi_i_srs = -1;
static int hf_nfapi_sounding_reference_cyclic_shift = -1;
static int hf_nfapi_antenna_ports = -1;
static int hf_nfapi_ul_config_srs_pdu_rel10 = -1;
static int hf_nfapi_ul_config_srs_pdu_rel8 = -1;
static int hf_nfapi_ul_config_harq_information_rel9_fdd = -1;
static int hf_nfapi_ul_config_harq_information_rel8_fdd = -1;
static int hf_nfapi_ul_config_harq_information_rel10_tdd = -1;
static int hf_nfapi_ul_config_sr_information_rel10 = -1;
static int hf_nfapi_ul_config_sr_information_rel8 = -1;
static int hf_nfapi_ul_config_cqi_information_rel10 = -1;
static int hf_nfapi_ul_config_cqi_information_rel8 = -1;
static int hf_nfapi_ul_config_initial_transmission_parameters_rel8 = -1;
static int hf_nfapi_ul_config_ulsch_harq_information_rel10 = -1;

/* Tx request */
static int hf_nfapi_pdu_length = -1;
static int hf_nfapi_num_segments = -1;
static int hf_nfapi_segment_length = -1;
static int hf_nfapi_segment_data = -1;

/* CRC Indication */
static int hf_nfapi_crc_indication_body = -1;
static int hf_nfapi_crc_flag = -1;

static int hf_nfapi_number_of_hi_pdus = -1;
static int hf_nfapi_number_of_dci_pdus = -1;
static int hf_nfapi_pdu_type = -1;
static int hf_nfapi_hi_value = -1;
static int hf_nfapi_i_phich = -1;
static int hf_nfapi_flag_tb2 = -1;
static int hf_nfapi_hi_value_2 = -1;
static int hf_nfapi_ue_tx_antenna_selection = -1;
static int hf_nfapi_cqi_csi_request = -1;
static int hf_nfapi_ul_index = -1;
static int hf_nfapi_dl_assignment_index = -1;
static int hf_nfapi_tpc_bitmap = -1;
static int hf_nfapi_new_data_indication_two = -1;
static int hf_nfapi_size_of_cqi_csi_feild = -1;
static int hf_nfapi_resource_allocation_flag = -1;
static int hf_nfapi_number_of_antenna_ports =-1 ;

static int hf_nfapi_n_ul_rb = -1;
static int hf_nfapi_pscch_resource = -1;
static int hf_nfapi_time_resource_pattern = -1;
static int hf_nfapi_mpdcch_transmission_type = -1;
static int hf_nfapi_drms_scrambling_init = -1;
static int hf_nfapi_pusch_repetition_levels = -1;
static int hf_nfapi_frequency_hopping_flag = -1;
static int hf_nfapi_csi_request = -1;
static int hf_nfapi_dai_presence_flag = -1;
static int hf_nfapi_total_dci_length_include_padding = -1;
static int hf_nfapi_data_offset = -1;
static int hf_nfapi_ul_cqi = -1;
static int hf_nfapi_timing_advance_r9 = -1;
static int hf_nfapi_timing_advance = -1;
static int hf_nfapi_harq_data_value_0 = -1;
static int hf_nfapi_harq_data_value_1 = -1;
static int hf_nfapi_harq_data_value_2 = -1;
static int hf_nfapi_harq_data_value_3 = -1;
static int hf_nfapi_harq_mode = -1;
static int hf_nfapi_number_of_ack_nack = -1;
static int hf_nfapi_harq_ack_nack_data = -1;
static int hf_nfapi_harq_tb_1 = -1;
static int hf_nfapi_harq_tb_2 = -1;
static int hf_nfapi_harq_tb_n = -1;
static int hf_nfapi_harq_data = -1;
static int hf_nfapi_channel = -1;
static int hf_nfapi_ri = -1;
static int hf_nfapi_number_of_cc_reported = -1;
static int hf_nfapi_cc = -1;
static int hf_nfapi_preamble = -1;
static int hf_nfapi_rach_resource_type = -1;
static int hf_nfapi_snr = -1;
static int hf_nfapi_doppler_estimation = -1;
static int hf_nfapi_rb_start = -1;
static int hf_nfapi_rbs = -1;
static int hf_nfapi_up_pts_symbol = -1;
static int hf_nfapi_number_prb_per_subband = -1;
static int hf_nfapi_number_antennas = -1;
static int hf_nfapi_subband_index = -1;
static int hf_nfapi_antennas = -1;
static int hf_nfapi_channel_coefficient = -1;
static int hf_nfapi_ul_rtoa = -1;
static int hf_nfapi_mp_cca = -1;
static int hf_nfapi_n_cca = -1;
static int hf_nfapi_offset = -1;
static int hf_nfapi_lte_txop_sf = -1;
static int hf_nfapi_txop_sfn_sf_end = -1;
static int hf_nfapi_lbt_mode = -1;
static int hf_nfapi_sfn_sf_end = -1;
static int hf_nfapi_result = -1;
static int hf_nfapi_txop_symbols = -1;
static int hf_nfapi_initial_partial_sf = -1;


static int hf_nfapi_frequency_band_indicator = -1;
static int hf_nfapi_measurement_period = -1;
static int hf_nfapi_bandwidth = -1;
static int hf_nfapi_timeout = -1;
static int hf_nfapi_number_of_earfcns = -1;
static int hf_nfapi_earfcn_list = -1;
static int hf_nfapi_uarfcn = -1;
static int hf_nfapi_number_of_uarfcns = -1;
static int hf_nfapi_uarfcn_list = -1;
static int hf_nfapi_arfcn = -1;
static int hf_nfapi_arfcn_direction = -1;
static int hf_nfapi_number_of_arfcns = -1;
static int hf_nfapi_arfcn_list = -1;
static int hf_nfapi_rssi = -1;
static int hf_nfapi_number_of_rssi = -1;
static int hf_nfapi_rssi_list = -1;
static int hf_nfapi_pci = -1;
static int hf_nfapi_measurement_bandwidth = -1;
static int hf_nfapi_exhaustive_search = -1;
static int hf_nfapi_number_of_pci = -1;
static int hf_nfapi_pci_list = -1;
static int hf_nfapi_psc = -1;
static int hf_nfapi_number_of_psc = -1;
static int hf_nfapi_psc_list = -1;
static int hf_nfapi_rsrp = -1;
static int hf_nfapi_rsrq = -1;
static int hf_nfapi_number_of_lte_cells_found = -1;
static int hf_nfapi_lte_cells_found_list = -1;
static int hf_nfapi_rscp = -1;
static int hf_nfapi_enco = -1;
static int hf_nfapi_number_of_utran_cells_found = -1;
static int hf_nfapi_utran_cells_found_list = -1;
static int hf_nfapi_bsic = -1;
static int hf_nfapi_rxlev = -1;
static int hf_nfapi_rxqual = -1;
static int hf_nfapi_sfn_offset = -1;
static int hf_nfapi_number_of_geran_cells_found = -1;
static int hf_nfapi_geran_cells_found_list = -1;
static int hf_nfapi_number_of_tx_antenna = -1;
static int hf_nfapi_mib_length = -1;
static int hf_nfapi_mib = -1;
static int hf_nfapi_phich_configuration = -1;
static int hf_nfapi_retry_count = -1;
static int hf_nfapi_sib1 = -1;
static int hf_nfapi_si_periodicity = -1;
static int hf_nfapi_si_index = -1;
static int hf_nfapi_number_of_si_periodicity = -1;
static int hf_nfapi_si_periodicity_list = -1;
static int hf_nfapi_si_window_length = -1;
static int hf_nfapi_sib_type = -1;
static int hf_nfapi_sib_len = -1;
static int hf_nfapi_sib = -1;
static int hf_nfapi_si_len = -1;
static int hf_nfapi_si = -1;

static int hf_nfapi_pnf_search_state = -1;
static int hf_nfapi_pnf_broadcast_state = -1;

static const value_string message_id_vals[]	= {	{ 0x80, "DL_CONFIG.request"},
												{ 0x81, "UL_CONFIG.request"},
												{ 0x82, "SUBFRAME_INDICATION"},
												{ 0x83, "HI_DCI0.request"},
												{ 0x84, "TX.request"},
												{ 0x85, "HARQ.indication"},
												{ 0x86, "CRC.indication"},
												{ 0x87, "RX_ULSCH.indication"},
												{ 0x88, "RACH.indication" },
												{ 0x89, "SRS.indication" },
												{ 0x8A, "RX_SR.indication" },
												{ 0x8B, "RX_CQI.indication" },
												{ 0x8C,	"LBT_DL_CONFIG.request" } ,
												{ 0x8D,	"LBT_DL.indication" } , 

												{ 0x0100, "PNF_PARAM.request" },
												{ 0x0101, "PNF_PARAM.response" },
												{ 0x0102, "PNF_CONFIG.request" },
												{ 0x0103, "PNF_CONFIG.response" },
												{ 0x0104, "PNF_START.request" },
												{ 0x0105, "PNF_START.response" },
												{ 0x0106, "PNF_STOP.request" },
												{ 0x0107, "PNF_STOP.response" },
												{ 0x0108, "PARAM.request" },
												{ 0x0109, "PARAM.response" },
												{ 0x010A, "CONFIG.request" },
												{ 0x010B, "CONFIG.response" },
												{ 0x010C, "START.request" },
												{ 0x010D, "START.response" },
												{ 0x010E, "STOP.request" },
												{ 0x010F, "STOP.response" },
												{ 0x0110, "MEASUREMENT.request" },
												{ 0x0111, "MEASUREMENT.response" },

												{ 0x0180, "DL_NODE_SYNC" },
												{ 0x0181, "UL_NODE_SYNC" },
												{ 0x0182, "TIMING_INFO" },

												{ 0x0200, "RSSI.request" },
												{ 0x0201, "RSSI.response" },
												{ 0x0202, "RSSI.indication" },
												{ 0x0203, "CELL_SEARCH.request" },
												{ 0x0204, "CELL_SEARCH.response" },
												{ 0x0205, "CELL_SEARCH.indication" },
												{ 0x0206, "BROADCAST_DETECT.request" },
												{ 0x0207, "BROADCAST_DETECT.response" },
												{ 0x0208, "BROADCAST_DETECT.indication" },
												{ 0x0209, "SYSTEM_INFORMATION_SCHEDULE.request" },
												{ 0x020A, "SYSTEM_INFORMATION_SCHEDULE.response" },
												{ 0x020B, "SYSTEM_INFORMATION_SCHEDULE.indication" },
												{ 0x020C, "SYSTEM_INFORMATION.request" },
												{ 0x020D, "SYSTEM_INFORMATION.response" },
												{ 0x020E, "SYSTEM_INFORMATION.indication" },
												{ 0x020F, "NMM_STOP.request" },
												{ 0x0210, "NMM_STOP.response" },

												{ 0 , NULL },	
};


typedef int(*tlv_decode)(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end);

typedef struct
{
	uint16_t tag_id;
	char* name;
	tlv_decode decode;
} tlv_t;

static int dissect_tlv_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint end);




static guint8 proto_tree_add_uint8(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, char* units)
{
	guint8 value = tvb_get_guint8(tvb, *offset);
	proto_item * item =  proto_tree_add_item(tree, hfindex, tvb, *offset, 1, ENC_NA);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 1;

	return value;
}

static guint8 proto_tree_add_uint8_with_range(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, packet_info *pinfo, guint8 min, guint8 max, char* units)
{
	guint8 value = tvb_get_guint8(tvb, *offset);
	proto_item * item = proto_tree_add_item(tree, hfindex, tvb, *offset, 1, ENC_NA);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 1;

	if (value < min || value > max)
	{
		expert_add_info(pinfo, tree, &ei_invalid_range);
	}


	return value;
}

static guint16 proto_tree_add_uint16(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, char* units)
{
	guint16 value = tvb_get_guint16(tvb, *offset, ENC_NA);
	proto_item * item =  proto_tree_add_item(tree, hfindex, tvb, *offset, 2, ENC_NA);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 2;

	return value;
}

static void proto_tree_add_int16(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, char* units)
{
	proto_item * item = proto_tree_add_item(tree, hfindex, tvb, *offset, 2, ENC_NA);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 2;
}

typedef int(*uint8_value_conversion)(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint8 value);

static guint8 proto_tree_add_uint8_with_conversion(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, uint8_value_conversion conversion)
{
	guint8 value = tvb_get_guint8(tvb, *offset);

	conversion(tree, hfindex, tvb, offset, value);

	*offset += 1;

	return value;
}

typedef int(*uint16_value_conversion)(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value);

static guint16 proto_tree_add_uint16_with_conversion(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, uint16_value_conversion conversion)
{
	guint16 value = tvb_get_guint16(tvb, *offset, ENC_NA);

	conversion(tree, hfindex, tvb, offset, value);

	*offset += 2;

	return value;
}

typedef int(*int16_value_conversion)(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, gint16 value);

static gint16 proto_tree_add_int16_with_conversion(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, int16_value_conversion conversion)
{
	gint16 value = (gint16)(tvb_get_guint16(tvb, *offset, ENC_NA));

	conversion(tree, hfindex, tvb, offset, value);

	*offset += 2;

	return value;
}


static void proto_tree_add_uint32(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint* offset, char* units)
{
	proto_item * item = proto_tree_add_item(tree, hfindex, tvb, *offset, 4, ENC_NA);

	if (units != NULL)
	{
		proto_item_append_text(item, " ");
		proto_item_append_text(item, units);
	}

	*offset += 4;
}

static void proto_tree_add_uint8_array(proto_tree *tree, int hfindex, guint len, tvbuff_t *tvb, guint* offset)
{
	proto_tree_add_item(tree, hfindex, tvb, *offset, len, ENC_NA);

	*offset += len;
}





int dissect_array_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end, const char* name, guint32 hf_idx, guint32 ett_idx, guint32 count, tlv_decode decode)
{
	guint16 i = 0;

	if (count > 0)
	{
		proto_item *list_ti = proto_tree_add_string_format(tree, hf_idx, tvb, *offset, 2, "", name);
		proto_tree *list_tree = proto_item_add_subtree(list_ti, ett_idx);

		gint start_of_list = *offset;

		for (i = 0; i < count; ++i)
		{
			proto_item *item_ti = proto_tree_add_string_format(list_tree, hf_idx, tvb, *offset, 2, "", "[%d]", i);
			proto_tree *item_tree = proto_item_add_subtree(item_ti, ett_idx);

			gint start_of_item = *offset;

			decode(tvb, pinfo, item_tree, data, offset, end);

			if (item_ti != NULL)
				item_ti->finfo->length = *offset - start_of_item;
		}

		if (list_ti != NULL)
			list_ti->finfo->length = *offset - start_of_list;
	}

	return 0;
}

int dissect_pnf_param_general_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_sync_mode, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_location_mode, tvb, offset, 0);
	guint16 len = proto_tree_add_uint16(tree, hf_nfapi_location_coordinates_length, tvb, offset, 0);
	if (len > 0)
		proto_tree_add_uint8_array(tree, hf_nfapi_location_coordinates, len, tvb, offset);
	proto_tree_add_uint32(tree, hf_nfapi_dl_config_timing, tvb, offset, "milliseconds");
	proto_tree_add_uint32(tree, hf_nfapi_tx_timing, tvb, offset, "milliseconds");
	proto_tree_add_uint32(tree, hf_nfapi_ul_config_timing, tvb, offset, "milliseconds");
	proto_tree_add_uint32(tree, hf_nfapi_hi_dci0_timing, tvb, offset, "milliseconds");
	proto_tree_add_uint16(tree, hf_nfapi_maximum_number_phys, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_maximum_total_bandwidth, tvb, offset, "(100 khz)");
	proto_tree_add_uint8(tree, hf_nfapi_maximum_total_number_dl_layers, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_maximum_total_number_ul_layers, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_shared_bands, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_shared_pa, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_maximum_total_power, tvb, offset, 0);
	proto_tree_add_uint8_array(tree, hf_nfapi_oui, 3, tvb, offset);
	
	return 0;
}

int dissect_pnf_rf_config_instance_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_rf_config_index, tvb, offset, 0);
	return 0;
}

int dissect_pnf_phy_instance_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_config_index, tvb, offset, 0);
	guint16 num_rf_configs = proto_tree_add_uint16(tree, hf_nfapi_number_of_rfs, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RF Config List", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy, num_rf_configs, dissect_pnf_rf_config_instance_value);
	guint16 num_rf_exclusions = proto_tree_add_uint16(tree, hf_nfapi_number_of_rf_exclusions, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RF Exclustion List", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy, num_rf_exclusions, dissect_pnf_rf_config_instance_value);
	proto_tree_add_uint16(tree, hf_nfapi_downlink_channel_bandwidth_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_uplink_channel_bandwidth_supported, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_dl_layers_supported, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_ul_layers_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_maximum_3gpp_release_supported, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_nmm_modes_supported, tvb, offset, 0);
	return 0;
}

int dissect_pnf_phy_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_phy = proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_number_phy, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PHY List", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy, num_phy, dissect_pnf_phy_instance_value);


	return 0;

}


int dissect_pnf_rf_config_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_rf_config_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_band, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_maximum_transmit_power, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_minimum_transmit_power, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_antennas_suppported, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_minimum_downlink_frequency, tvb, offset, "(100 khz)");
	proto_tree_add_uint32(tree, hf_nfapi_maximum_downlink_frequency, tvb, offset, "(100 khz)");
	proto_tree_add_uint32(tree, hf_nfapi_minimum_uplink_frequency, tvb, offset, "(100 khz)");
	proto_tree_add_uint32(tree, hf_nfapi_maximum_uplink_frequency, tvb, offset, "(100 khz)");

	return 0;
}


int dissect_pnf_rf_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_rf = proto_tree_add_uint16(tree, hf_nfapi_number_of_rfs, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RF List", hf_nfapi_pnf_phy_rf_config_array_phy_rf_config_info, ett_nfapi_pnf_phy_rf_config, num_rf, dissect_pnf_rf_config_value);

	return 0;

}

int dissect_pnf_phy_rel10_instance_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_config_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_transmission_mode7_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_transmission_mode8_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_two_antennas_ports_for_pucch, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_transmission_mode_9_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_simultaneous_pucch_pusch, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_for_layer_tx_with_tm3_and_tm4, tvb, offset, 0);

	return 0;
}

int dissect_pnf_phy_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_phy = proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_number_phy, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PHY Rel 10 List", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy_rel10, num_phy, dissect_pnf_phy_rel10_instance_value);

	return 0;
}

int dissect_pnf_phy_rel11_instance_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_config_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_epdcch_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_multi_ack_csi_reporting, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_pucch_tx_diversity_with_channel_selection, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_ul_comp_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_transmission_mode_5_supported, tvb, offset, 0);
	return 0;
}

int dissect_pnf_phy_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_phy = proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_number_phy, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PHY Rel 11 List", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy_rel11, num_phy, dissect_pnf_phy_rel11_instance_value);
	return 0;
}

int dissect_pnf_phy_rel12_instance_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_config_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_csi_subframe_set, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_enhanced_4tx_codebook, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_drs_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_ul_64qam_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_transmission_mode_10_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hi_nfapi_alternative_tbs_indices, tvb, offset, 0);
	return 0;
}

int dissect_pnf_phy_rel12_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_phy = proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_number_phy, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PHY Rel 12 List", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy_rel12, num_phy, dissect_pnf_phy_rel12_instance_value);
	return 0;
}

int dissect_pnf_phy_rel13_instance_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_config_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pucch_format_4_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pucch_format_5_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_more_than_5_ca_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_laa_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_laa_ending_in_dwpts_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_laa_starting_in_second_slot_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_beamforming_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_csi_rs_enhancements_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_drms_enhancements_supported, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_srs_enhancements_supported, tvb, offset, 0);
	return 0;
}

int dissect_pnf_phy_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_phy = proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_number_phy, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PHY Rel 13 List", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy_rel13, num_phy, dissect_pnf_phy_rel13_instance_value);
	return 0;
}

int dissect_pnf_phy_rf_config_instance_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_phy_rf_config_info_phy_id, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_config_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rf_config_index, tvb, offset, 0);
	return 0;
}


int dissect_pnf_phy_rf_config_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_configs = proto_tree_add_uint16(tree, hf_nfapi_pnf_phy_number_phy, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PHY RF Config List", hf_nfapi_pnf_phy_rf_config, ett_nfapi_pnf_phy_rf_config, num_configs, dissect_pnf_phy_rf_config_instance_value);
	return 0;
}

int bandwidth_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	/*
	guint8 comma = 0;

	proto_item_append_text(item, "(");

	if (value & 0x1)
	{
		proto_item_append_text(item, "6 Mhz");
		comma = 1;
	}

	if (comma)
		proto_item_append_text(item, ", ");

	if (value & 0x2)
	{
		proto_item_append_text(item, "15 Mhz");
		comma = 1;
	}

	if (comma)
		proto_item_append_text(item, ", ");

	if (value & 0x4)
	{
		proto_item_append_text(item, "25 Mhz");
		comma = 1;
	}

	if (comma)
		proto_item_append_text(item, ", ");

	if (value & 0x8)
	{
		proto_item_append_text(item, "50 Mhz");
		comma = 1;
	}

	if (comma)
		proto_item_append_text(item, ", ");

	if (value & 0x10)
	{
		proto_item_append_text(item, "75 Mhz");
		comma = 1;
	}

	if (comma)
		proto_item_append_text(item, ", ");

	if (value & 0x20)
	{
		proto_item_append_text(item, "100 Mhz");
		comma = 1;
	}

	proto_item_append_text(item, ")");
	*/
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "?? (%d)", value);
	return 0;

}

int sfn_sf_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "%d/%d (%d)", value >> 3, value & 0x0007, value);
	return 0;
}


int dissect_duplex_mode_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_duplex_mode, tvb, offset, 0);
	return 0;
}

int power_offset_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "%.2f dB (%d)", (((float)value * 0.001) - 6.0), value);
	return 0;
}

int dissect_pcfich_power_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 value = proto_tree_add_uint16_with_conversion(tree, hf_nfapi_pcfich_power_offset, tvb, offset, power_offset_conversion);

	if (value > 10000)
	{
		expert_add_info(pinfo, tree, &ei_power_invalid);
	}

	return 0;
}

int dissect_pb_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 value = proto_tree_add_uint16(tree, hf_nfapi_pb, tvb, offset, 0);

	if (value > 3)
	{
		expert_add_info(pinfo, tree, &ei_power_invalid);
	}
	return 0;
}

int dissect_dl_cyclic_prefix_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_dl_cyclic_prefix_type, tvb, offset, 0);
	return 0;
}
int dissect_ul_cyclic_prefix_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_ul_cyclic_prefix_type, tvb, offset, 0);
	return 0;
}
int dissect_dl_channel_bandwidth_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_downlink_channel_bandwidth, tvb, offset, bandwidth_conversion);
	return 0;
}
int dissect_ul_channel_bandwidth_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_uplink_channel_bandwidth, tvb, offset, bandwidth_conversion);
	return 0;
}


int reference_signal_power_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "%.2f dB (%d)", (((float)value * 0.25) - 63.75), value);
	return 0;
}

int dissect_reference_signal_power_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_reference_signal_power, tvb, offset, reference_signal_power_conversion);
	return 0;
}
int dissect_tx_antenna_ports_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_tx_antenna_ports, tvb, offset, 0);
	return 0;
}
int dissect_rx_antenna_ports_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_rx_antenna_ports, tvb, offset, 0);
	return 0;
}
int dissect_phich_resource_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_phich_resource, tvb, offset, 0);
	return 0;
}
int dissect_phich_duration_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_phich_duration, tvb, offset, 0);
	return 0;
}
int dissect_phich_power_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_phich_power_offset, tvb, offset, power_offset_conversion);
	return 0;
}
int dissect_psch_synch_signal_epre_eprers_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_primary_synchronization_signal_epre_eprers, tvb, offset, power_offset_conversion);
	return 0;
}
int dissect_physical_cell_id_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_physical_cell_id, tvb, offset, 0);
	return 0;
}
int dissect_ssch_synch_signal_epre_eprers_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_secondary_synchronization_signal_epre_eprers, tvb, offset, power_offset_conversion);
	return 0;
}
int dissect_prach_configuration_index_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_configuration_index, tvb, offset, 0);
	return 0;
}
int dissect_prach_root_sequence_index_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_root_sequence_index, tvb, offset, 0);
	return 0;
}
int dissect_prach_zero_correlation_zone_configuration_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_zero_correlation_zone_configuration, tvb, offset, 0);
	return 0;
}
int dissect_prach_high_speed_flag_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_high_speed_flag, tvb, offset, 0);
	return 0;
}
int dissect_prach_frequency_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_frequency_offset, tvb, offset, 0);
	return 0;
}
int dissect_pusch_hopping_mode_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_hopping_mode, tvb, offset, 0);
	return 0;
}
int dissect_pusch_hopping_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_hopping_offset, tvb, offset, 0);
	return 0;
}
int dissect_pusch_number_of_subbands_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_number_of_subbands, tvb, offset, 0);
	return 0;
}
int dissect_pucch_delta_pucch_shift_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_delta_pucch_shift, tvb, offset, 0);
	return 0;
}
int dissect_pucch_n_cqi_rb_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_n_cqi_rb, tvb, offset, 0);
	return 0;
}
int dissect_pucch_n_an_cs_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_n_an_cs, tvb, offset, 0);
	return 0;
}
int dissect_pucch_n1_pucch_an_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_n1_pucch_an, tvb, offset, 0);
	return 0;
}
int dissect_srs_bandwidth_configuration_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_bandwidth_configuration, tvb, offset, 0);
	return 0;
}
int dissect_srs_max_uppts_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_max_up_pts, tvb, offset, 0);
	return 0;
}
int dissect_srs_subframe_configuration_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_srs_subframe_configuration, tvb, offset, 0);
	return 0;
}
int dissect_srs_acknack_srs_sim_tx_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_srs_acknack_srs_simultaneous_transmission, tvb, offset, 0);
	return 0;
}
int dissect_uplink_rs_hopping_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_uplink_rs_hopping, tvb, offset, 0);
	return 0;
}
int dissect_group_assignment_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_group_assignment, tvb, offset, 0);
	return 0;
}
int dissect_cyclic_shift_1_for_drms_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_cyclic_shift_1_for_drms, tvb, offset, 0);
	return 0;
}
int dissect_tdd_subframe_assignement_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_subframe_assignment, tvb, offset, 0);
	return 0;
}
int dissect_tdd_subframe_patterns_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_special_subframe_patterns, tvb, offset, 0);
	return 0;
}

int laa_threshold_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "%.2f dB (%d)", (float)(value * -100.00), value);
	return 0;
}

int dissect_laa_ed_threashold_for_lbt_for_pdsch_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_ed_threshold_for_lbt_for_pdsch, tvb, offset, laa_threshold_conversion);
	return 0;
}
int dissect_laa_ed_threashold_for_lbt_for_drs_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_ed_threshold_for_lbt_for_drs, tvb, offset, laa_threshold_conversion);
	return 0;
}
int dissect_laa_pd_threshold_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_pd_threshold, tvb, offset, laa_threshold_conversion);
	return 0;
}
int dissect_laa_multi_carrier_type_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_multi_carrier_type, tvb, offset, 0);
	return 0;
}
int dissect_laa_multi_carrier_tx_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_multi_carrier_tx, tvb, offset, 0);
	return 0;
}
int dissect_laa_multi_carrier_freeze_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_multi_carrier_freeze, tvb, offset, 0);
	return 0;
}
int dissect_laa_tx_antenna_port_for_drs_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_tx_antenna_ports_for_drs, tvb, offset, 0);
	return 0;
}
int dissect_laa_transmission_power_for_drs_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power_for_drs, tvb, offset, power_offset_conversion);
	return 0;
}

int dissect_emtc_pbch_repeitions_enabled_r13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pbch_repetitions_enabled_r13, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_cat_m_root_sequence_index_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_cat_m_root_sequence_index, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_cat_m_zero_correlation_zone_configuration_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_cat_m_zero_correlation_zone_configuration, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_cat_m_high_speed_flag_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_cat_m_high_speed_flag, tvb, offset, 0);
	return 0;
}

int dissect_emtc_prach_ce_level_0_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_0_enable, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_0_configuration_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_0_configuration_index, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_0_frequency_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_0_frequency_offset, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_0_num_of_repeitions_per_attempt_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_0_number_of_repetitions_per_attempt, tvb, offset, 0);
	return 0;
}
int dissect_emtc_ce_level_0_starting_subframe_periodicity_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_0_starting_subframe_periodicity, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_0_hopping_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_0_hopping_enabled, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_0_hopping_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_0_hopping_offset, tvb, offset, 0);
	return 0;
}

int dissect_emtc_prach_ce_level_1_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_1_enable, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_1_configuration_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_1_configuration_index, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_1_frequency_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_1_frequency_offset, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_1_num_of_repeitions_per_attempt_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_1_number_of_repetitions_per_attempt, tvb, offset, 0);
	return 0;
}
int dissect_emtc_ce_level_1_starting_subframe_periodicity_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_1_starting_subframe_periodicity, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_1_hopping_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_1_hopping_enabled, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_1_hopping_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_1_hopping_offset, tvb, offset, 0);
	return 0;
}

int dissect_emtc_prach_ce_level_2_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_2_enable, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_2_configuration_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_2_configuration_index, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_2_frequency_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_2_frequency_offset, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_2_num_of_repeitions_per_attempt_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_2_number_of_repetitions_per_attempt, tvb, offset, 0);
	return 0;
}
int dissect_emtc_ce_level_2_starting_subframe_periodicity_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_2_starting_subframe_periodicity, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_2_hopping_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_2_hopping_enabled, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_2_hopping_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_2_hopping_offset, tvb, offset, 0);
	return 0;
}

int dissect_emtc_prach_ce_level_3_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_3_enable, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_3_configuration_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_3_configuration_index, tvb, offset, 0);
	return 0;
}
int dissect_emtc_prach_ce_level_3_frequency_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_3_frequency_offset, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_3_num_of_repeitions_per_attempt_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_3_number_of_repetitions_per_attempt, tvb, offset, 0);
	return 0;
}
int dissect_emtc_ce_level_3_starting_subframe_periodicity_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_3_starting_subframe_periodicity, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_3_hopping_enabled_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_3_hopping_enabled, tvb, offset, 0);
	return 0;
}
int dissect_emtc_preach_ce_level_3_hopping_offset_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_prach_ce_level_3_hopping_offset, tvb, offset, 0);
	return 0;
}

int dissect_emtc_pucch_interval_ul_hopping_config_common_mode_a_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pucch_internal_ul_hopping_config_common_mode_a, tvb, offset, 0);
	return 0;
}
int dissect_emtc_pucch_interval_ul_hopping_config_common_mode_b_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pucch_internal_ul_hopping_config_common_mode_b, tvb, offset, 0);
	return 0;
}


int dissect_dl_bandwidth_support_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_dl_bandwidth_support, tvb, offset, bandwidth_conversion);
	return 0;
}

int dissect_ul_bandwidth_support_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_ul_bandwidth_support, tvb, offset, bandwidth_conversion);
	return 0;
}

int dl_modulation_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "?? (%d)", value);
	return 0;
}

int dissect_dl_modulation_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_dl_modulation_support, tvb, offset, dl_modulation_conversion);
	return 0;
}

int ul_modulation_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "?? (%d)", value);
	return 0;
}
int dissect_ul_modulation_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_ul_modulation_support, tvb, offset, ul_modulation_conversion);
	return 0;
}
int dissect_phy_antenna_capability_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_phy_antenna_capability, tvb, offset, 0);
	return 0;
}

int release_capability_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint16 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 2, value, "?? (%d)", value);
	return 0;
}
int dissect_release_capability_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_release_capability, tvb, offset, release_capability_conversion);
	return 0;
}
int dissect_mbsfn_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_mbsfn_capability, tvb, offset, 0);
	return 0;
}

int dissect_laa_support_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_laa_capability, tvb, offset, 0);
	return 0;
}
int dissect_laa_pd_sensing_lbt_support_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pd_sensing_lbt_support, tvb, offset, 0);
	return 0;
}
int dissect_laa_multi_carrier_lbt_support_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_multi_carrier_lbt_support, tvb, offset, 0);
	return 0;
}
int dissect_laa_partial_sf_support_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_partial_sf_support, tvb, offset, 0);
	return 0;
}

int dissect_data_report_mode_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_data_report_mode, tvb, offset, 0);
	return 0;
}
int dissect_sfn_sf_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_sfnsf, tvb, offset, 0);
	return 0;
}
int dissect_phy_state_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_phy_state, tvb, offset, 0);
	return 0;
}



int dissect_p7_vnf_address_ipv4_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8_array(tree, hf_nfapi_vnf_address_ipv4, 4, tvb, offset);
	return 0;
}
int dissect_p7_vnf_address_ipv6_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8_array(tree, hf_nfapi_vnf_address_ipv4, 16, tvb, offset);
	return 0;
}
int dissect_p7_vnf_port_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_vnf_port, tvb, offset, 0);
	return 0;
}

int dissect_p7_pnf_address_ipv4_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8_array(tree, hf_nfapi_pnf_address_ipv4, 4, tvb, offset);
	return 0;
}
int dissect_p7_pnf_address_ipv6_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8_array(tree, hf_nfapi_pnf_address_ipv4, 16, tvb, offset);
	return 0;
}
int dissect_p7_pnf_port_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pnf_port, tvb, offset, 0);
	return 0;
}

int dissect_downlink_ues_per_subframe_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_dl_ue_per_sf, tvb, offset, 0);
	return 0;
}

int dissect_uplink_ues_per_subframe_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ul_ue_per_sf, tvb, offset, 0);
	return 0;
}

int dissect_rf_band_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_band, tvb, offset, 0);
	return 0;
}

int dissect_rf_bands_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 count = proto_tree_add_uint16(tree, hf_nfapi_number_of_rf_bands, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RF Band List", hf_nfapi_rf_bands, ett_nfapi_rf_bands, count, dissect_rf_band_value);
	return 0;
}

int dissect_timing_window_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_timing_window, tvb, offset, 0);
	return 0;
}
int dissect_timing_info_mode_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_timing_info_mode, tvb, offset, 0);
	return 0;
}
int dissect_timing_info_period_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_timing_info_period, tvb, offset, 0);
	return 0;
}

int dissect_maximum_transmit_power_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_maximum_transmit_power, tvb, offset, 0);
	return 0;
}
int dissect_earfcn_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_earfcn, tvb, offset, 0);
	return 0;
}

int dissect_nmm_gsm_frequency_bands_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 count = proto_tree_add_uint16(tree, hf_nfapi_number_of_rf_bands, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RF Band List", hf_nfapi_rf_bands, ett_nfapi_rf_bands, count, dissect_rf_band_value);
	return 0;
}
int dissect_nmm_umts_frequency_bands_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 count = proto_tree_add_uint16(tree, hf_nfapi_number_of_rf_bands, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RF Band List", hf_nfapi_rf_bands, ett_nfapi_rf_bands, count, dissect_rf_band_value);
	return 0;
}
int dissect_nmm_lte_frequency_bands_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 count = proto_tree_add_uint16(tree, hf_nfapi_number_of_rf_bands, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RF Band List", hf_nfapi_rf_bands, ett_nfapi_rf_bands, count, dissect_rf_band_value);
	return 0;
}
int dissect_nmm_uplink_rssi_supported_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_nmm_uplink_rssi_supported, tvb, offset, 0);
	return 0;
}

int dissect_dl_config_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_dl_config_pdu_type, tvb, offset, 0);
	guint8 size = proto_tree_add_uint8(tree, hf_nfapi_pdu_size, tvb, offset, 0);

	guint pdu_end = (*offset + size - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);

	return 0;
}


static int dissect_dl_config_request_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_number_pdcch_ofdm_symbols, tvb, offset, 0);
	guint16 num_pdu = proto_tree_add_uint8(tree, hf_nfapi_number_dci, tvb, offset, 0);
	num_pdu += proto_tree_add_uint16(tree, hf_nfapi_number_pdus, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_pdsch_rnti, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power_pcfich, tvb, offset, power_offset_conversion);

	dissect_array_value(tvb, pinfo, tree, data, offset, end, "DL Config PDU List", hf_nfapi_dl_config_request_pdu_list, ett_nfapi_dl_config_request_pdu_list, num_pdu, dissect_dl_config_pdu);


	return 0;
}

static int dissect_dl_config_request_bch_pdu_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_length, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pdu_index, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	return 0;
}

static int dissect_dl_config_request_dl_dci_pdu_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_dci_format, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cce_idx, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_aggregation_level, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_allocation_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_virtual_resource_block_assignment_flag, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_resource_block_coding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcs_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_redundancy_version_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_new_data_indicator_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transport_block_to_codeword_swap_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcs_2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_redundancy_version_2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_new_data_indicator_2, tvb, offset, 0);
	proto_tree_add_uint8_with_range(tree, hf_nfapi_harq_process, tvb, offset, pinfo, 0, 15, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpmi, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_precoding_information, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpc, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_downlink_assignment_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ngap, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transport_block_size_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_downlink_power_offset, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_allocate_prach_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_preamble_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_prach_mask_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rnti_type, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	return 0;
}
static int dissect_dl_config_request_dl_dci_pdu_rel9_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_mcch_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcch_change_notification, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_scrambling_identity, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_dl_dci_pdu_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_cross_carrier_scheduling_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_carrier_indicator, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_size_of_cqi_csi_feild, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_request, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_antenna_ports_scrambling_and_layers, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_total_dci_length_including_padding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_n_dl_rb, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_dl_dci_pdu_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_ack_resource_offset, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pdsch_re_mapping_and_quasi_co_location_indicator, tvb, offset, 0);
	return 0;
}

int dissect_ul_dl_configuration_index_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ul_dl_configuration_index, tvb, offset, 0);
	return 0;
}


static int dissect_dl_config_request_dl_dci_pdu_rel12_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_primary_cell_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_dl_configuration_flag, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_ul_dl_configurations, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "UL/DL Configurations", hf_nfapi_pnf_phy, ett_nfapi_pnf_phy, count, dissect_ul_dl_configuration_index_value);

	return 0;
}
static int dissect_dl_config_request_dl_dci_pdu_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_laa_end_partial_sf_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_laa_end_partial_sf_configuration, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_initial_lbt_sf, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_codebooksize_determination_r13, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rel13_drms_table_flag, tvb, offset, 0);
	return 0;
}

static int dissect_dl_config_request_mch_pdu_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_length, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pdu_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_allocation_type, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_resource_block_coding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_modulation, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	proto_tree_add_uint16(tree, hf_nfapi_mbsfn_area_id, tvb, offset, 0);

	return 0;
}

int dissect_codebook_index_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_codebook_index, tvb, offset, 0);
	return 0;
}

int dissect_bf_vector_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_bf_vector_bf_value, tvb, offset, 0);
	return 0;
}

int dissect_bf_vector_type_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_bf_vector_subband_index, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_bf_vector_num_antennas, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "Antennas", hf_nfapi_bf_vector_antennas, ett_nfapi_bf_vector_antennas, count, dissect_bf_vector_value);
	return 0;
}

static int dissect_dl_config_request_dlsch_pdu_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_length, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pdu_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);		
	proto_tree_add_uint8(tree, hf_nfapi_resource_allocation_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_virtual_resource_block_assignment_flag, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_resource_block_coding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_modulation, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_redundancy_version, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transport_blocks, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transport_block_to_codeword_swap_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transmission_scheme, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_layers, tvb, offset, 0);
	guint8 num_subbands = proto_tree_add_uint8(tree, hf_nfapi_number_of_subbands, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "Subbands", hf_nfapi_subbands, ett_nfapi_subbands, num_subbands, dissect_codebook_index_value);
	proto_tree_add_uint8(tree, hf_nfapi_ue_category_capacity, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pa, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_delta_power_offset_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ngap, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_nprb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transmission_mode, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_num_bf_prb_per_subband, tvb, offset, 0);
	guint8 num_vectors = proto_tree_add_uint8(tree, hf_nfapi_num_bf_vector, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "Beamforming Vectors", hf_nfapi_bf_vectors, ett_nfapi_bf_vectors, num_vectors, dissect_bf_vector_type_value);

	
	return 0;
}

int dissect_csi_rs_resource_config_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_csi_rs_resource_config, tvb, offset, 0);
	return 0;
}

static int dissect_dl_config_request_dlsch_pdu_rel9_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_nscid, tvb, offset, 0);

	return 0;
}
static int dissect_dl_config_request_dlsch_pdu_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_csi_rs_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_csi_rs_resource_config_r10, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_csi_rs_number_if_nzp_configurations, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "CSI-RS Resource Configs", hf_nfapi_csi_rs_resource_configs, ett_nfapi_csi_rs_resource_configs, count, dissect_csi_rs_resource_config_value);
	proto_tree_add_uint8(tree, hf_nfapi_pdsch_start, tvb, offset, 0);

	return 0;
}
static int dissect_dl_config_request_dlsch_pdu_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_drms_config_flag, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_drms_scrambling, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_csi_config_flag, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_csi_scrambling, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pdsch_re_mapping_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pdsch_re_mapping_antenna_ports, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pdsch_re_mapping_freq_shift, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_dlsch_pdu_rel12_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_alt_cqi_table_r12, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_max_layers, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_n_dl_harq, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_dlsch_pdu_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_dwpts_symbols, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_initial_lbt_sf, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ue_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pdsch_payload_type, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_initial_transmission_sf, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_req13_drms_table_flag, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_pch_pdu_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_length, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pdu_index, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_prnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_allocation_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_virtual_resource_block_assignment_flag, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_resource_block_coding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcs, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_redundancy_version, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_transport_blocks, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transport_block_to_codeword_swap_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transmission_scheme, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_layers, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_codebook_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ue_category_capacity, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pa, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	proto_tree_add_uint8(tree, hf_nfapi_nprb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ngap, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_pch_pdu_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ue_mode, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_initial_transmission_sf, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_prs_pdu_rel9_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	proto_tree_add_uint8(tree, hf_prs_bandwidth, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_prs_cyclic_prefix_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_prs_muting, tvb, offset, 0);
	return 0;
}
static int dissect_dl_config_request_csi_rs_pdu_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_csi_rs_antenna_port_count_r10, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_csi_rs_resource_config_r10, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	proto_tree_add_uint16(tree, hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_csi_rs_number_if_nzp_configurations, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "CSI-RS Resource Configs", hf_nfapi_csi_rs_resource_configs, ett_nfapi_csi_rs_resource_configs, count, dissect_csi_rs_resource_config_value);
	return 0;
}


int dissect_csi_rs_bf_vector_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_csi_rs_resource_index, tvb, offset, 0);
	//proto_tree_add_uint8(tree, hf_nfapi_csi_rs_resource_config, tvb, offset, 0);
	return 0;
}

static int dissect_dl_config_request_csi_rs_pdu_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_csi_rs_class, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cdm_type, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_num_bf_vector, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "Beamforming Vector", hf_nfapi_csi_rs_bf_vector, ett_nfapi_csi_rs_bf_vector, count, dissect_csi_rs_bf_vector_value);
	return 0;
}

int dissect_epdcch_prb_index_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_edpcch_prb_index, tvb, offset, 0);
	return 0;
}

static int dissect_dl_config_request_edpcch_params_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_epdcch_resource_assignment_flag, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_epdcch_id, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_epdcch_start_symbol, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_epdcch_num_prb, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PRBs", hf_nfapi_epdcch_prbs, ett_nfapi_epdcch_prbs, count, dissect_epdcch_prb_index_value);
	dissect_bf_vector_type_value(tvb, pinfo, tree, data, offset, end);

	return 0;
}
static int dissect_dl_config_request_edpcch_params_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_dwpts_symbols, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_initial_lbt_sf, tvb, offset, 0);
	return 0;
}

int dissect_precoding_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_precoding_value, tvb, offset, 0);
	return 0;
}

static int dissect_dl_config_request_mpdpcch_pdu_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_mpdcch_narrowband, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_prb_pairs, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_block_assignment, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_start_symbol, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ecce_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_aggregation_level, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rnti_type, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ce_mode, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_drms_scrabmling_init, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_initial_transmission_sf, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_transmission_power, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dci_format, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_resource_block_coding	, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcs, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pdsch_reception_levels , tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_redundancy_version, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_new_data_indicator, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_process, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpmi_length, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpmi, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pmi_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_resource_offset, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dci_subframe_repetition_number, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpc, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_downlink_assignment_index_length, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_downlink_assignment_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_allocate_prach_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_preamble_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_prach_mask_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_starting_ce_level, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_request, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_antenna_ports_and_scrambling_identity_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_antenna_ports_and_scrambling_identity, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_frequency_hopping_enabled_flag , tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_paging_direct_indication_differentiation_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_direct_indication, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_total_dci_length_including_padding, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_tx_antenna_ports, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "Precoding", hf_nfapi_precoding, ett_nfapi_precoding, count, dissect_precoding_value);
	
	return 0;
}

int dissect_ul_config_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ul_config_pdu_type, tvb, offset, 0);
	guint8 size = proto_tree_add_uint8(tree, hf_nfapi_pdu_size, tvb, offset, 0);

	guint pdu_end = (*offset + size - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);

	return 0;
}

static int  dissect_ul_config_request_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint8 num_pdu = proto_tree_add_uint8(tree, hf_nfapi_number_pdus, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rach_prach_frequency_resources, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_present, tvb, offset, 0);

	dissect_array_value(tvb, pinfo, tree, data, offset, end, "UL Config PDU List", hf_nfapi_ul_config_request_pdu_list, ett_nfapi_ul_config_request_pdu_list, num_pdu, dissect_ul_config_pdu);

	return 0;
}


int dissect_ul_config_ulsch_pdu_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_size, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_block_start, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_resource_blocks, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_modulation, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cyclic_shift_2_for_drms, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_frequency_hopping_enabled_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_frequency_hopping_bits, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_new_data_indication, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_redundancy_version, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_process_number, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_tx_mode, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_current_tx_nb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_n_srs, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_ulsch_pdu_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_resource_allocation_type, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_resource_block_coding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transport_blocks, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_transmission_scheme, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_layers, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_codebook_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_disable_sequence_hopping_flag, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_ulsch_pdu_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_virtual_cell_id_enabled_flag, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_npusch_identity, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_drms_config_flag, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_ndrms_csh_identity, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_ulsch_pdu_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ue_type, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_total_number_of_repetitions, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_repetition_number, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_initial_sf_io, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_empty_symbols_due_to_retunning, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_init_tx_params_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_n_srs_initial, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_initial_number_of_resource_blocks, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_cqi_ri_info_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_dl_cqi_pmi_size_rank_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dl_cqi_pmi_size_rank_greater_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ri_size, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_delta_offset_cqi, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_delta_offset_ri, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_cqi_ri_info_rel9_later_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint8 type = proto_tree_add_uint8(tree, hf_nfapi_report_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_delta_offset_cqi, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_delta_offset_ri, tvb, offset, 0);

	switch (type)
	{
		case 0:
		{
			proto_tree_add_uint8(tree, hf_nfapi_dl_cqi_ri_pmi_size, tvb, offset, 0);
			proto_tree_add_uint8(tree, hf_nfapi_control_type, tvb, offset, 0);
			break;
		}
		case 1:
		{
			/*guint8 num_cc = */proto_tree_add_uint8(tree, hf_nfapi_number_of_cc, tvb, offset, 0);

			// todo ...

			break;
		}
	}
	return 0;
}
int dissect_ul_config_cqi_ri_info_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_dl_cqi_ri_pmi_size_2, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_harq_info_ulsch_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_size, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_delta_offset_harq, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ack_nack_mode, tvb, offset, 0);

	return 0;
}
int dissect_ul_config_harq_info_ulsch_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_harq_size_2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_delta_offset_harq_2, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_ue_info_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_ue_info_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_virtual_cell_id_enabled_flag, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_npucch_identity, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_ue_info_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ue_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_empty_symbols, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_total_number_of_repetitions, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_repetition_number, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_cqi_info_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pucch_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dl_cqi_pmi_size, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_cqi_info_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_number_of_pucch_resource, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pucch_index_p1, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_cqi_info_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_csi_mode, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_dl_cqi_pmi_size_2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_statring_prb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_nprb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cdm_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_nsrs, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_sr_info_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_pucch_index, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_sr_info_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_number_of_pucch_resource, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pucch_index_p1, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_harq_info_uci_rel10_tdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_size, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ack_nack_mode, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_pucch_resource, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_0, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_1, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_2, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_3, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_harq_info_uci_rel8_fdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_0, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_size, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_harq_info_uci_rel9_later_fdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_size, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ack_nack_mode, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_pucch_resource, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_0, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_1, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_2, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_1_3, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_harq_info_uci_rel11_fdd_tdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_num_ant_ports, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_2_0, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_2_1, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_2_2, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_n_pucch_2_3, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_harq_info_uci_rel13_fdd_tdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_harq_size_2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_starting_prb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_nprb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cdm_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_nsrs, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_srs_info_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_size, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_bandwidth, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_frequency_domain_position, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_hopping_bandwidth, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_transmission_comb, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_i_srs, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_sounding_reference_cyclic_shift, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_srs_info_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_antenna_port, tvb, offset, 0);
	return 0;
}
int dissect_ul_config_srs_info_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_number_of_combs, tvb, offset, 0);
	return 0;
}

int dissect_hi_dci0_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_pdu_type, tvb, offset, 0);
	guint8 size = proto_tree_add_uint8(tree, hf_nfapi_pdu_size, tvb, offset, 0);

	guint pdu_end = (*offset + size - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);

	return 0;
}

static int dissect_hi_dci0_request_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_sfn_sf, tvb, offset, 0);
	guint8 num_pdu = proto_tree_add_uint8(tree, hf_nfapi_number_of_dci_pdus, tvb, offset, 0);
	num_pdu += proto_tree_add_uint8(tree, hf_nfapi_number_of_hi_pdus, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "HI DCI0 PDU List", hf_nfapi_hi_dci0_request_pdu_list, ett_nfapi_hi_dci0_request_pdu_list, num_pdu, dissect_hi_dci0_pdu);
	return 0;
}

static int dissect_hi_dci0_hi_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_resource_block_start, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cyclic_shift_2_for_drms, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_hi_value, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_i_phich, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	return 0;
}
static int dissect_hi_dci0_hi_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_flag_tb2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_hi_value_2, tvb, offset, 0);
	return 0;
}
static int dissect_hi_dci0_dci_ul_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_dci_format, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cce_idx, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_aggregation_level, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_block_start, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_resource_blocks, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcs_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cyclic_shift_2_for_drms, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_frequency_hopping_enabled_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_frequency_hopping_bits, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_new_data_indication, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ue_tx_antenna_selection, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpc, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_cqi_csi_request, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dl_assignment_index, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_tpc_bitmap, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	return 0;
}
static int dissect_hi_dci0_dci_ul_rel10_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_cross_carrier_scheduling_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_carrier_indicator, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_size_of_cqi_csi_feild, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_request, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_allocation_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_resource_allocation_type, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_resource_block_coding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcs_2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_new_data_indication_two, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_antenna_ports, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpmi, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_total_dci_length_including_padding, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_n_ul_rb, tvb, offset, 0);
	return 0;
}
static int dissect_hi_dci0_dci_ul_rel12_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_pscch_resource, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_time_resource_pattern, tvb, offset, 0);
	return 0;
}
static int dissect_hi_dci0_edpcch_dci_ul_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_epdcch_resource_assignment_flag, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_epdcch_id, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_epdcch_start_symbol, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_epdcch_num_prb, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PRBs", hf_nfapi_epdcch_prbs, ett_nfapi_epdcch_prbs, count, dissect_epdcch_prb_index_value);
	dissect_bf_vector_type_value(tvb, pinfo, tree, data, offset, end);
	return 0;
}

static int dissect_hi_dci0_mdpcch_dci_ul_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_mpdcch_narrowband, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_prb_pairs, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_resource_block_assignment, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mpdcch_transmission_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_start_symbol, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ecce_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_aggregation_level, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rnti_type, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ce_mode, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_drms_scrambling_init, tvb, offset, 0);
	proto_tree_add_uint16_with_conversion(tree, hf_nfapi_transmission_power, tvb, offset, power_offset_conversion);
	proto_tree_add_uint8(tree, hf_nfapi_dci_format, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_resource_blocks, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_mcs, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_pusch_repetition_levels, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_frequency_hopping_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_new_data_indication, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_process, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_redundancy_version, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_tpc, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_csi_request, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dai_presence_flag, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dl_assignment_index, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_srs_request, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_dci_subframe_repetition_number, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_tpc_bitmap, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_total_dci_length_include_padding, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_tx_antenna_ports, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "TX Antenna Ports", hf_nfapi_tx_antenna_ports, ett_nfapi_tx_antenna_ports, count, dissect_precoding_value);


	return 0;
}
static int dissect_rx_ue_info_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	return 0;
}
static int dissect_rx_indication_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_length, tvb, offset, 0);
	int data_offset = proto_tree_add_uint16(tree, hf_nfapi_data_offset, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_cqi, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance, tvb, offset, 0);
	return data_offset;
}
static int dissect_rx_indication_rel9_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance_r9, tvb, offset, 0);
	return 0;
}

static int dissect_harq_indication_data_bundling_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_0, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_1, tvb, offset, 0);
	return 0;
}

static int dissect_harq_indication_data_multplexing_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_0, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_2, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_3, tvb, offset, 0);
	return 0;
}

static int dissect_harq_indication_data_special_bundling_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_0, tvb, offset, 0);
	return 0;
}

static int dissect_harq_indication_data_channel_selection_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_0, tvb, offset, 0);
	return 0;
}

static int dissect_harq_indication_data_format_3_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_0, tvb, offset, 0);
	return 0;
}

static int dissect_harq_indication_data_format_4_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_0, tvb, offset, 0);
	return 0;
}


static int dissect_harq_indication_data_format_5_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_data_value_0, tvb, offset, 0);
	return 0;
}



static int dissect_harq_indication_rel8_tdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint8 mode = proto_tree_add_uint8(tree, hf_nfapi_harq_mode, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_ack_nack, tvb, offset, 0);

	switch (mode)
	{
		case 0:
		{
			dissect_harq_indication_data_bundling_value(tvb, pinfo, tree, data, offset, end);
			break;
		}
		case 1:
		{
			dissect_harq_indication_data_multplexing_value(tvb, pinfo, tree, data, offset, end);
			break;
		}
		case 2:
		{
			dissect_harq_indication_data_special_bundling_value(tvb, pinfo, tree, data, offset, end);
			break;
		}
	};

	return 0;
}
static int dissect_harq_indication_rel9_later_tdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint8 mode = proto_tree_add_uint8(tree, hf_nfapi_harq_mode, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_ack_nack, tvb, offset, 0);

	// Have to do this as the mode value is need to decode the value
	guint16 i = 0;

	proto_item *list_ti = proto_tree_add_string_format(tree, hf_nfapi_harq_ack_nack_data, tvb, *offset, 2, "", "ACK/NACK Data");
	proto_tree *list_tree = proto_item_add_subtree(list_ti, ett_nfapi_harq_ack_nack_data);

	for (i = 0; i < count; ++i)
	{

		proto_item *item_ti = proto_tree_add_string_format(list_tree, hf_nfapi_harq_ack_nack_data, tvb, *offset, 2, "", "[%d]", i);
		proto_tree *item_tree = proto_item_add_subtree(item_ti, ett_nfapi_harq_ack_nack_data);

		switch (mode)
		{
			case 0:
			{
				dissect_harq_indication_data_bundling_value(tvb, pinfo, item_tree, data, offset, end);
				break;
			}
			case 1:
			{
				dissect_harq_indication_data_multplexing_value(tvb, pinfo, item_tree, data, offset, end);
				break;
			}
			case 2:
			{
				dissect_harq_indication_data_special_bundling_value(tvb, pinfo, item_tree, data, offset, end);
				break;
			}
			case 3:
			{
				dissect_harq_indication_data_channel_selection_value(tvb, pinfo, item_tree, data, offset, end);
				break;
			}
			case 4:
			{
				dissect_harq_indication_data_format_3_value(tvb, pinfo, item_tree, data, offset, end);
				break;
			}
		};
	}

	return 0;
}
static int dissect_harq_indication_rel13_later_tdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint8 mode = proto_tree_add_uint8(tree, hf_nfapi_harq_mode, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_ack_nack, tvb, offset, 0);

	// Have to do this as the mode value is need to decode the value
	guint16 i = 0;

	proto_item *list_ti = proto_tree_add_string_format(tree, hf_nfapi_harq_ack_nack_data, tvb, *offset, 2, "", "ACK/NACK Data");
	proto_tree *list_tree = proto_item_add_subtree(list_ti, ett_nfapi_harq_ack_nack_data);

	for (i = 0; i < count; ++i)
	{
		proto_item *item_ti = proto_tree_add_string_format(list_tree, hf_nfapi_harq_ack_nack_data, tvb, *offset, 2, "", "[%d]", i);
		proto_tree *item_tree = proto_item_add_subtree(item_ti, ett_nfapi_harq_ack_nack_data);

		switch (mode)
		{
		case 0:
		{
			dissect_harq_indication_data_bundling_value(tvb, pinfo, item_tree, data, offset, end);
			break;
		}
		case 1:
		{
			dissect_harq_indication_data_multplexing_value(tvb, pinfo, item_tree, data, offset, end);
			break;
		}
		case 2:
		{
			dissect_harq_indication_data_special_bundling_value(tvb, pinfo, item_tree, data, offset, end);
			break;
		}
		case 3:
		{
			dissect_harq_indication_data_channel_selection_value(tvb, pinfo, item_tree, data, offset, end);
			break;
		}
		case 4:
		{
			dissect_harq_indication_data_format_3_value(tvb, pinfo, item_tree, data, offset, end);
			break;
		}
		case 5:
		{
			dissect_harq_indication_data_format_4_value(tvb, pinfo, item_tree, data, offset, end);
			break;
		}
		case 6:
		{
			dissect_harq_indication_data_format_5_value(tvb, pinfo, item_tree, data, offset, end);
			break;
		}
		};
	}

	return 0;
}
static int dissect_harq_indication_rel8_fdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_tb_1, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_harq_tb_2, tvb, offset, 0);
	return 0;
}

int dissect_harq_tb_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_harq_tb_n, tvb, offset, 0);
	return 0;
}


static int dissect_harq_indication_rel9_later_fdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_mode, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_ack_nack, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "HARQ TB List", hf_nfapi_harq_data, ett_nfapi_harq_data, count, dissect_harq_tb_value);
	return 0;
}
static int dissect_harq_indication_rel13_later_fdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_harq_mode, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_ack_nack, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "HARQ TB List", hf_nfapi_harq_data, ett_nfapi_harq_data, count, dissect_harq_tb_value);
	return 0;
}
static int dissect_ul_cqi_information_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ul_cqi, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_channel, tvb, offset, 0);
	return 0;
}
static int dissect_crc_indication_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_crc_flag, tvb, offset, 0);
	return 0;
}
static int dissect_rx_cqi_indication_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_length, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_data_offset, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_cqi, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ri, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance, tvb, offset, 0);
	return 0;
}

int dissect_ri_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_ri, tvb, offset, 0);
	return 0;
}
static int dissect_rx_cqi_indication_rel9_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_length, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_data_offset, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_ul_cqi, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_cc_reported, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "CC List", hf_nfapi_cc, ett_nfapi_cc, count, dissect_ri_value);
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance_r9, tvb, offset, 0);

	return 0;
}
static int dissect_rach_indication_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_rnti, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_preamble, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance, tvb, offset, 0);
	return 0;
}
static int dissect_rach_indication_rel9_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance_r9, tvb, offset, 0);
	return 0;
}
static int dissect_rach_indication_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_rach_resource_type, tvb, offset, 0);
	return 0;
}

int dissect_snr_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_snr, tvb, offset, 0);
	return 0;
}

static int dissect_srs_indication_rel8_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_doppler_estimation, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance, tvb, offset, 0);
	guint8 count = proto_tree_add_uint8(tree, hf_nfapi_number_of_resource_blocks, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rb_start, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "RB List", hf_nfapi_rbs, ett_nfapi_rbs, count, dissect_snr_value);


	return 0;
}
static int dissect_srs_indication_rel9_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_timing_advance_r9, tvb, offset, 0);
	return 0;
}
static int dissect_srs_indication_rel10_tdd_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_up_pts_symbol, tvb, offset, 0);
	return 0;
}
static int dissect_tdd_channel_measuerment_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_number_prb_per_subband, tvb, offset, 0);
	guint8 num_subbands = proto_tree_add_uint8(tree, hf_nfapi_number_of_subbands, tvb, offset, 0);
	guint8 num_phy_ant = proto_tree_add_uint8(tree, hf_nfapi_number_antennas, tvb, offset, 0);

	guint16 i = 0;
	guint16 j = 0;

	proto_item *sb_list_ti = proto_tree_add_string_format(tree, hf_nfapi_subbands, tvb, *offset, 2, "", "Subbands");
	proto_tree *sb_list_tree = proto_item_add_subtree(sb_list_ti, ett_nfapi_subbands);

	for (i = 0; i < num_subbands; ++i)
	{
		proto_item *sb_item_ti = proto_tree_add_string_format(sb_list_tree, hf_nfapi_subbands, tvb, *offset, 2, "", "[%d]", i);
		proto_tree *sb_item_tree = proto_item_add_subtree(sb_item_ti, ett_nfapi_subbands);

		proto_tree_add_uint8(sb_item_ti, hf_nfapi_subband_index, tvb, offset, 0);


		proto_item *ant_list_ti = proto_tree_add_string_format(sb_item_tree, hf_nfapi_antennas, tvb, *offset, 2, "", "Physical Antennas");
		proto_tree *ant_list_tree = proto_item_add_subtree(ant_list_ti, ett_nfapi_antennas);

		for (j = 0; j < num_phy_ant; ++j)
		{
			proto_item *ant_item_ti = proto_tree_add_string_format(ant_list_tree, hf_nfapi_antennas, tvb, *offset, 2, "", "[%d]", j);
			proto_tree *ant_item_tree = proto_item_add_subtree(ant_item_ti, ett_nfapi_antennas);

			proto_tree_add_uint16(ant_item_tree, hf_nfapi_channel_coefficient, tvb, offset, 0);
		}
	}

	return 0;
}

static int dissect_srs_indication_rel11_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_ul_rtoa, tvb, offset, 0);
	return 0;
}

static int dissect_lbt_dl_config_request_pdsch_req_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_mp_cca, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_n_cca, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_offset, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_lte_txop_sf, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_txop_sfn_sf_end, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_lbt_mode, tvb, offset, 0);
	return 0;
}
static int dissect_lbt_dl_config_request_drs_req_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_offset, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_sfn_sf_end, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_lbt_mode, tvb, offset, 0);
	return 0;
}
static int dissect_lbt_dl_config_request_pdsch_resp_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_result, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_txop_symbols, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_initial_partial_sf, tvb, offset, 0);
	return 0;
}
static int dissect_lbt_dl_config_request_drs_resp_rel13_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_handle, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_result, tvb, offset, 0);
	return 0;
}

int dissect_tx_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 len = proto_tree_add_uint16(tree, hf_nfapi_pdu_length, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pdu_index, tvb, offset, 0);

	proto_tree_add_uint8_array(tree, hf_nfapi_pdu, len, tvb, offset);

	return 0;
}

static int dissect_tx_request_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_pdu = proto_tree_add_uint16(tree, hf_nfapi_number_pdus, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "TX PDU List", hf_nfapi_tx_request_pdu_list, ett_nfapi_tx_request_pdu_list, num_pdu, dissect_tx_pdu);
	return 0;

}

int dissect_rx_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	//guint end = (*offset + size - 2);
	//dissect_tlv_list(tvb, pinfo, tree, data, offset, end);
	return 0;
}



int dissect_harq_indication_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 pdu_len = proto_tree_add_uint16(tree, hf_nfapi_instance_length, tvb, offset, 0);
	guint pdu_end = (*offset + pdu_len - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}

static int dissect_harq_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_pdu = proto_tree_add_uint16(tree, hf_nfapi_number_of_harqs, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "HARQ PDU List", hf_nfapi_harq_indication_pdu_list, ett_nfapi_harq_indication_pdu_list, num_pdu, dissect_harq_indication_pdu);
	return 0;
}

int dissect_crc_indication_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 pdu_len = proto_tree_add_uint16(tree, hf_nfapi_instance_length, tvb, offset, 0);
	guint pdu_end = (*offset + pdu_len - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}


static int dissect_crc_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_pdu = proto_tree_add_uint16(tree, hf_nfapi_number_of_crcs, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "CRC PDU List", hf_nfapi_crc_indication_pdu_list, ett_nfapi_crc_indication_pdu_list, num_pdu, dissect_crc_indication_pdu);
	return 0;
}
int dissect_sr_indication_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 pdu_len = proto_tree_add_uint16(tree, hf_nfapi_instance_length, tvb, offset, 0);
	guint pdu_end = (*offset + pdu_len - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}

static int dissect_rx_sr_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_pdu = proto_tree_add_uint16(tree, hf_nfapi_number_of_srs, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "SR PDU List", hf_nfapi_sr_indication_pdu_list, ett_nfapi_sr_indication_pdu_list, num_pdu, dissect_sr_indication_pdu);
	return 0;
}
int dissect_cqi_indication_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 pdu_len = proto_tree_add_uint16(tree, hf_nfapi_instance_length, tvb, offset, 0);
	guint pdu_end = (*offset + pdu_len - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}
static int dissect_rx_cqi_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_pdu = proto_tree_add_uint16(tree, hf_nfapi_number_of_cqi, tvb, offset, 0);

	guint16* lengths = malloc(num_pdu * 2);
	memset(lengths, 0, num_pdu * 2);

	guint8 tmp_offset = *offset;

	int i = 0;
	for (i = 0; i < num_pdu; ++i)
	{
		guint16 instance_len = tvb_get_guint16(tvb, tmp_offset, ENC_NA);
		tmp_offset += 2;
		guint8 pdu_end = tmp_offset + instance_len;

		while (tmp_offset < pdu_end)
		{
			guint16 tlv_id = tvb_get_guint16(tvb, tmp_offset, ENC_NA);
			tmp_offset += 2;
			guint16 tlv_len = tvb_get_guint16(tvb, tmp_offset, ENC_NA);
			tmp_offset += 2;

			if (tlv_id == 0x202F)
			{
				lengths[i] = tvb_get_guint16(tvb, tmp_offset, ENC_NA);
			}
			else if (tlv_id == 0x2030)
			{
				lengths[i] = tvb_get_guint16(tvb, tmp_offset, ENC_NA);
			}

			tmp_offset += tlv_len;
		}

	}


	dissect_array_value(tvb, pinfo, tree, data, offset, end, "CQI PDU List", hf_nfapi_cqi_indication_pdu_list, ett_nfapi_cqi_indication_pdu_list, num_pdu, dissect_cqi_indication_pdu);


	for (i = 0; i < num_pdu; ++i)
	{
		proto_tree_add_uint8_array(tree, hf_nfapi_pdu, lengths[i], tvb, offset);
	}

	free(lengths);

	return 0;
}
int dissect_preamble_indication_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 pdu_len = proto_tree_add_uint16(tree, hf_nfapi_instance_length, tvb, offset, 0);
	guint pdu_end = (*offset + pdu_len - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}
static int dissect_rach_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_pdu = proto_tree_add_uint16(tree, hf_nfapi_number_of_preambles, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "Preamble PDU List", hf_nfapi_preamble_indication_pdu_list, ett_nfapi_preamble_indication_pdu_list, num_pdu, dissect_preamble_indication_pdu);
	return 0;
}
int dissect_srs_indication_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 pdu_len = proto_tree_add_uint16(tree, hf_nfapi_instance_length, tvb, offset, 0);
	guint pdu_end = (*offset + pdu_len - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}
static int dissect_srs_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{

	guint8 num_pdu = proto_tree_add_uint8(tree, hf_nfapi_number_of_srss, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "SRS PDU List", hf_nfapi_srs_indication_pdu_list, ett_nfapi_srs_indication_pdu_list, num_pdu, dissect_srs_indication_pdu);
	return 0;
}
int dissect_lbt_dl_config_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_lbt_dl_req_pdu_type, tvb, offset, 0);
	guint8 size = proto_tree_add_uint8(tree, hf_nfapi_pdu_size, tvb, offset, 0);
	guint pdu_end = (*offset + size - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}
static int dissect_lbt_dl_config_request_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint8 num_pdu = proto_tree_add_uint8(tree, hf_nfapi_number_pdus, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "LBT DL PDU List", hf_nfapi_lbt_dl_config_pdu_list, ett_nfapi_lbt_dl_config_pdu_list, num_pdu, dissect_lbt_dl_config_pdu);

	return 0;
}
int dissect_lbt_dl_indication_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_lbt_dl_ind_pdu_type, tvb, offset, 0);
	guint8 size = proto_tree_add_uint8(tree, hf_nfapi_pdu_size, tvb, offset, 0);
	guint pdu_end = (*offset + size - 2);
	dissect_tlv_list(tvb, pinfo, tree, data, offset, pdu_end);
	return 0;
}
static int dissect_lbt_indication_message_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint8 num_pdu = proto_tree_add_uint8(tree, hf_nfapi_number_pdus, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "LBT DL PDU List", hf_nfapi_lbt_dl_indication_pdu_list, ett_nfapi_lbt_dl_indication_pdu_list, num_pdu, dissect_lbt_dl_indication_pdu);
	return 0;
}

static int dissect_lte_rssi_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_frequency_band_indicator, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_measurement_period, tvb, offset, "ms");
	proto_tree_add_uint8(tree, hf_nfapi_bandwidth, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	guint8 num_earfcns = proto_tree_add_uint8(tree, hf_nfapi_number_of_earfcns, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "EARFCNs", hf_nfapi_earfcn_list, ett_nfapi_earfcn_list, num_earfcns, dissect_earfcn_value);
	return 0;
}

int dissect_uarfcn_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_uarfcn, tvb, offset, 0);
	return 0;
}
static int dissect_utran_rssi_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_frequency_band_indicator, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_measurement_period, tvb, offset, "ms");
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	guint8 num_uarfcns = proto_tree_add_uint8(tree, hf_nfapi_number_of_uarfcns, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "UARFCNs", hf_nfapi_uarfcn_list, ett_nfapi_uarfcn_list, num_uarfcns, dissect_uarfcn_value);
	return 0;
}

int dissect_arfcn_dir_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_arfcn, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_arfcn_direction, tvb, offset, 0);
	return 0;
}
static int dissect_geran_rssi_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_frequency_band_indicator, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_measurement_period, tvb, offset, "ms");
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	guint8 num_arfcns = proto_tree_add_uint8(tree, hf_nfapi_number_of_arfcns, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "ARFCNs", hf_nfapi_arfcn_list, ett_nfapi_arfcn_list, num_arfcns, dissect_arfcn_dir_value);
	return 0;
}


int rssi_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, gint16 value)
{
	proto_tree_add_int_format_value(tree, hfindex, tvb, *offset, 2, value, "%.2f dB (%d)", ((float)value * 0.1), value);
	return 0;
}
int dissect_rssi_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_int16_with_conversion(tree, hf_nfapi_rssi, tvb, offset, rssi_conversion);
	return 0;
}
static int dissect_rssi_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_rssi = proto_tree_add_uint16(tree, hf_nfapi_number_of_rssi, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "ARFCNs", hf_nfapi_rssi_list, ett_nfapi_rssi_list, num_rssi, dissect_rssi_value);
	return 0;
}

int dissect_pci_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pci, tvb, offset, 0);
	return 0;
}
static int dissect_lte_cell_search_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_earfcn, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_measurement_bandwidth, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_exhaustive_search, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	guint8 num_pci = proto_tree_add_uint8(tree, hf_nfapi_number_of_pci, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PCIs", hf_nfapi_pci_list, ett_nfapi_pci_list, num_pci, dissect_pci_value);
	return 0;
}

int dissect_psc_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_psc, tvb, offset, 0);
	return 0;
}
static int dissect_utran_cell_search_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_uarfcn, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_exhaustive_search, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	guint8 num_psc = proto_tree_add_uint8(tree, hf_nfapi_number_of_psc, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "PSCs", hf_nfapi_psc_list, ett_nfapi_psc_list, num_psc, dissect_psc_value);
	return 0;
}

int dissect_arfcn_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_arfcn, tvb, offset, 0);
	return 0;
}

static int dissect_geran_cell_search_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	guint8 num_arfcn = proto_tree_add_uint8(tree, hf_nfapi_number_of_arfcns, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "ARFCNs", hf_nfapi_arfcn_list, ett_nfapi_arfcn_list, num_arfcn, dissect_arfcn_value);
	return 0;
}

int neg_pow_conversion(proto_item* tree, int hfindex, tvbuff_t *tvb, guint* offset, guint8 value)
{
	proto_tree_add_uint_format_value(tree, hfindex, tvb, *offset, 1, value, "%d dB (%d)", ((gint16)value * (-1)), value);
	return 0;
}

int dissect_lte_cell_found_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_pci, tvb, offset, 0);
	proto_tree_add_uint8_with_conversion(tree, hf_nfapi_rsrp, tvb, offset, neg_pow_conversion);
	proto_tree_add_uint8_with_conversion(tree, hf_nfapi_rsrq, tvb, offset, neg_pow_conversion);
	proto_tree_add_int16(tree, hf_nfapi_frequency_offset, tvb, offset, 0);
	return 0;
}
static int dissect_lte_cell_search_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_lte_cells = proto_tree_add_uint16(tree, hf_nfapi_number_of_lte_cells_found, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "LTE Cells Found", hf_nfapi_lte_cells_found_list, ett_nfapi_lte_cells_found_list, num_lte_cells, dissect_lte_cell_found_value);
	return 0;
}
int dissect_utran_cell_found_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_psc, tvb, offset, 0);
	proto_tree_add_uint8_with_conversion(tree, hf_nfapi_rscp, tvb, offset, neg_pow_conversion);
	proto_tree_add_uint8_with_conversion(tree, hf_nfapi_enco, tvb, offset, neg_pow_conversion);
	proto_tree_add_int16(tree, hf_nfapi_frequency_offset, tvb, offset, 0);
	return 0;
}
static int dissect_utran_cell_search_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_utran_cells = proto_tree_add_uint16(tree, hf_nfapi_number_of_utran_cells_found, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "UTRAN Cells Found", hf_nfapi_utran_cells_found_list, ett_nfapi_utran_cells_found_list, num_utran_cells, dissect_utran_cell_found_value);
	return 0;
}

int dissect_geran_cell_found_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_arfcn, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_bsic, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rxlev, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_rxqual, tvb, offset, 0);
	proto_tree_add_int16(tree, hf_nfapi_frequency_offset, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_sfn_offset, tvb, offset, 0);
	return 0;
}
static int dissect_geran_cell_search_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 num_geran_cells = proto_tree_add_uint16(tree, hf_nfapi_number_of_geran_cells_found, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "GERAN Cells Found", hf_nfapi_geran_cells_found_list, ett_nfapi_geran_cells_found_list, num_geran_cells, dissect_geran_cell_found_value);

	return 0;
}
static int dissect_pnf_cell_search_state_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8_array(tree, hf_nfapi_pnf_search_state, *end - *offset, tvb, offset);
	return 0;
}

static int dissect_pnf_cell_broadcast_state_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8_array(tree, hf_nfapi_pnf_broadcast_state, *end - *offset, tvb, offset);
	return 0;
}
static int dissect_lte_broadcast_detect_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_earfcn, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pci, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	return 0;
}
static int dissect_utran_broadcast_detect_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_uarfcn, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_psc, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, "ms");
	return 0;
}

static int dissect_lte_broadcast_detect_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_number_of_tx_antenna, tvb, offset, 0);
	guint16 mib_len = proto_tree_add_uint16(tree, hf_nfapi_mib_length, tvb, offset, 0);
	proto_tree_add_uint8_array(tree, hf_nfapi_mib, mib_len, tvb, offset);
	proto_tree_add_uint32(tree, hf_nfapi_sfn_offset, tvb, offset, 0);
	return 0;
}
static int dissect_utran_broadcast_detect_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 mib_len = proto_tree_add_uint16(tree, hf_nfapi_mib_length, tvb, offset, 0);
	proto_tree_add_uint8_array(tree, hf_nfapi_mib, mib_len, tvb, offset);
	proto_tree_add_uint32(tree, hf_nfapi_sfn_offset, tvb, offset, 0);
	return 0;
}

static int dissect_lte_system_information_schedule_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_earfcn, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pci, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_downlink_channel_bandwidth, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_phich_configuration, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_tx_antenna, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_retry_count, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, 0);
	return 0;
}
//static int dissect_pnf_cell_broadcast_state_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
//{
//	return 0;
//}
static int dissect_lte_system_information_schedule_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	// this needs to be SIB 1
	proto_tree_add_uint8_array(tree, hf_nfapi_sib1, (*end - *offset), tvb, offset);
	return 0;
}

int dissect_si_periodicity_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_si_periodicity, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_si_index, tvb, offset, 0);
	return 0;
}

static int dissect_lte_system_information_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_earfcn, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_pci, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_downlink_channel_bandwidth, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_phich_configuration, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_number_of_tx_antenna, tvb, offset, 0);
	guint8 si_priodicity = proto_tree_add_uint8(tree, hf_nfapi_number_of_si_periodicity, tvb, offset, 0);
	dissect_array_value(tvb, pinfo, tree, data, offset, end, "Number SI Periodicity", hf_nfapi_si_periodicity_list, ett_nfapi_si_periodicity_list, si_priodicity, dissect_si_periodicity_value);
	proto_tree_add_uint8(tree, hf_nfapi_si_window_length, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, 0);

	return 0;
}
static int dissect_utran_system_information_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_uarfcn, tvb, offset, 0);
	proto_tree_add_uint16(tree, hf_nfapi_psc, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, 0);
	return 0;
}
static int dissect_geran_system_information_request_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint16(tree, hf_nfapi_arfcn, tvb, offset, 0);
	proto_tree_add_uint8(tree, hf_nfapi_bsic, tvb, offset, 0);
	proto_tree_add_uint32(tree, hf_nfapi_timeout, tvb, offset, 0);
	return 0;
}
//static int dissect_pnf_cell_broadcast_state_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
//{
//	return 0;
//}
static int dissect_lte_system_information_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	proto_tree_add_uint8(tree, hf_nfapi_sib_type, tvb, offset, 0);
	guint16 sib_len = proto_tree_add_uint16(tree, hf_nfapi_sib_len, tvb, offset, 0);
	proto_tree_add_uint8_array(tree, hf_nfapi_sib, sib_len, tvb, offset);
	return 0;
}
static int dissect_utran_system_information_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 sib_len = proto_tree_add_uint16(tree, hf_nfapi_sib_len, tvb, offset, 0);
	proto_tree_add_uint8_array(tree, hf_nfapi_sib, sib_len, tvb, offset);
	return 0;
}
static int dissect_geran_system_information_indication_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint16 si_len = proto_tree_add_uint16(tree, hf_nfapi_si_len, tvb, offset, 0);
	proto_tree_add_uint8_array(tree, hf_nfapi_si, si_len, tvb, offset);
	return 0;
}

static int dissect_rx_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end);

const tlv_t tags[] =
{
	{ 0x1000, "PNF Param General", dissect_pnf_param_general_value },
	{ 0x1001, "PNF PHY", dissect_pnf_phy_value },
	{ 0x1002, "PNF RF", dissect_pnf_rf_value },
	{ 0x100A, "PNF PHY Rel 10", dissect_pnf_phy_rel10_value },
	{ 0x100B, "PNF PHY Rel 11", dissect_pnf_phy_rel11_value },
	{ 0x100C, "PNF PHY Rel 12", dissect_pnf_phy_rel12_value },
	{ 0x100D, "PNF PHY Rel 13", dissect_pnf_phy_rel13_value },
	{ 0x1003, "PNF PHY RF Config", dissect_pnf_phy_rf_config_value },

	{ 0x0001, "Subframe config - Duplex Mode", dissect_duplex_mode_value },
	{ 0x0002, "Subframe config - PCFICH power offset TLV", dissect_pcfich_power_offset_value },
	{ 0x0003, "Subframe config - P-B", dissect_pb_value },
	{ 0x0004, "Subframe config - DL cyclic prefix type", dissect_dl_cyclic_prefix_value },
	{ 0x0005, "Subframe config - UL cyclic prefix type", dissect_ul_cyclic_prefix_value },
	{ 0x000A, "RF config - Downlink channel bandwidth", dissect_dl_channel_bandwidth_value },
	{ 0x000B, "RF config - Uplink channel bandwidth", dissect_ul_channel_bandwidth_value },
	{ 0x000C, "RF config - Reference signal power", dissect_reference_signal_power_value },
	{ 0x000D, "RF config - Tx antenna ports", dissect_tx_antenna_ports_value },
	{ 0x000E, "RF config - Rx Antenna ports", dissect_rx_antenna_ports_value },
	{ 0x0014, "PHICH config - PHICH resource", dissect_phich_resource_value },
	{ 0x0015, "PHICH config - PHICH duration", dissect_phich_duration_value },
	{ 0x0016, "PHICH config - PHICH power offset", dissect_phich_power_offset_value },
	{ 0x001E, "SCH config - Primary synchronization signal EPRE/EPRERS", dissect_psch_synch_signal_epre_eprers_value },
	{ 0x001F, "SCH config - Secondary synchronization signal EPRE/EPRERS", dissect_ssch_synch_signal_epre_eprers_value },
	{ 0x0020, "SCH config - Physical Cell Id", dissect_physical_cell_id_value },
	{ 0x0028, "PRACH config - Configuration index", dissect_prach_configuration_index_value },
	{ 0x0029, "PRACH config - Root sequence index", dissect_prach_root_sequence_index_value },
	{ 0x002A, "PRACH config - Zero correlation zone configuration", dissect_prach_zero_correlation_zone_configuration_value },
	{ 0x002B, "PRACH config - High speed flag", dissect_prach_high_speed_flag_value },
	{ 0x002C, "PRACH config - Frequency offset", dissect_prach_frequency_offset_value },
	{ 0x0032, "PUSCH config - Hopping mode", dissect_pusch_hopping_mode_value },
	{ 0x0033, "PUSCH config - Hopping offset", dissect_pusch_hopping_offset_value },
	{ 0x0034, "PUSCH config - Number of sub-bands", dissect_pusch_number_of_subbands_value },
	{ 0x003C, "PUCCH config - Delta PUCCH Shift", dissect_pucch_delta_pucch_shift_value },
	{ 0x003D, "PUCCH config - N_CQI RB", dissect_pucch_n_cqi_rb_value },
	{ 0x003E, "PUCCH config - N_AN CS", dissect_pucch_n_an_cs_value },
	{ 0x003F, "PUCCH config - N1Pucch-AN", dissect_pucch_n1_pucch_an_value },
	{ 0x0046, "SRS config - Bandwidth configuration", dissect_srs_bandwidth_configuration_value },
	{ 0x0047, "SRS config - MaxUpPTS", dissect_srs_max_uppts_value },
	{ 0x0048, "SRS config - SRS subframe configuration", dissect_srs_subframe_configuration_value },
	{ 0x0049, "SRS config - SRS AckNack SRS simultaneous transmission", dissect_srs_acknack_srs_sim_tx_value },
	{ 0x0050, "Uplink reference signal config - Uplink RS hopping", dissect_uplink_rs_hopping_value },
	{ 0x0051, "Uplink reference signal config - Group assignment (delta sequence-shift pattern)", dissect_group_assignment_value },
	{ 0x0052, "Uplink reference signal config - Cyclic Shift 1 for DMRS", dissect_cyclic_shift_1_for_drms_value },
	{ 0x005A, "TDD frame structure config - Subframe assignment", dissect_tdd_subframe_assignement_value },
	{ 0x005B, "TDD frame structure config - Special sub-frame patterns", dissect_tdd_subframe_patterns_value },
	{ 0x0064, "LAA config - ED Threshold for LBT for PDSCH", dissect_laa_ed_threashold_for_lbt_for_pdsch_value },
	{ 0x0065, "LAA config - ED Threshold for LBT for DRS", dissect_laa_ed_threashold_for_lbt_for_drs_value },
	{ 0x0066, "LAA config - PD Threshold", dissect_laa_pd_threshold_value },
	{ 0x0067, "LAA config - Multi carrier type", dissect_laa_multi_carrier_type_value },
	{ 0x0068, "LAA config - Multi carrier TX", dissect_laa_multi_carrier_tx_value },
	{ 0x0069, "LAA config - Multi carrier freeze ", dissect_laa_multi_carrier_freeze_value },
	{ 0x006A, "LAA config - Tx antenna ports for DRS", dissect_laa_tx_antenna_port_for_drs_value },
	{ 0x006B, "LAA config - Transmission power for DRS", dissect_laa_transmission_power_for_drs_value },

	{ 0x0078, "eMTC config - PBCH Repetitions enable R13", dissect_emtc_pbch_repeitions_enabled_r13_value },
	{ 0x0079, "eMTC config - PRACH CAT-M Root sequence index", dissect_emtc_prach_cat_m_root_sequence_index_value },
	{ 0x007A, "eMTC config - PRACH CAT-M Zero correlation zone configuration", dissect_emtc_prach_cat_m_zero_correlation_zone_configuration_value },
	{ 0x007B, "eMTC config - PRACH CAT-M High speed flag", dissect_emtc_prach_cat_m_high_speed_flag_value },
	{ 0x007C, "eMTC config - PRACH CE level #0 Enable", dissect_emtc_prach_ce_level_0_enabled_value },
	{ 0x007D, "eMTC config - PRACH CE level #0 Configuration index", dissect_emtc_prach_ce_level_0_configuration_offset_value },
	{ 0x007E, "eMTC config - PRACH CE level #0 Frequency offset", dissect_emtc_prach_ce_level_0_frequency_offset_value },
	{ 0x007F, "eMTC config - PRACH CE level #0 Number of repetitions per attempt", dissect_emtc_preach_ce_level_0_num_of_repeitions_per_attempt_value },
	{ 0x0080, "eMTC config - CE level #0 Starting subframe periodicity", dissect_emtc_ce_level_0_starting_subframe_periodicity_value },
	{ 0x0081, "eMTC config - PRACH CE level #0 Hopping Enable", dissect_emtc_preach_ce_level_0_hopping_enabled_value },
	{ 0x0082, "eMTC config - PRACH CE level #0 Hopping Offset", dissect_emtc_preach_ce_level_0_hopping_offset_value },
	{ 0x0083, "eMTC config - PRACH CE level #1 Enable", dissect_emtc_prach_ce_level_1_enabled_value },
	{ 0x0084, "eMTC config - PRACH CE level #1 Configuration index", dissect_emtc_prach_ce_level_1_configuration_offset_value },
	{ 0x0085, "eMTC config - PRACH CE level #1 Frequency offset", dissect_emtc_prach_ce_level_1_frequency_offset_value },
	{ 0x0086, "eMTC config - PRACH CE level #1 Number of repetitions per attempt", dissect_emtc_preach_ce_level_1_num_of_repeitions_per_attempt_value },
	{ 0x0087, "eMTC config - CE level #1 Starting subframe periodicity", dissect_emtc_ce_level_1_starting_subframe_periodicity_value },
	{ 0x0088, "eMTC config - PRACH CE level #1 Hopping Enable", dissect_emtc_preach_ce_level_1_hopping_enabled_value },
	{ 0x0089, "eMTC config - PRACH CE level #1 Hopping Offset", dissect_emtc_preach_ce_level_1_hopping_offset_value },
	{ 0x008A, "eMTC config - PRACH CE level #2 Enable", dissect_emtc_prach_ce_level_2_enabled_value },
	{ 0x008B, "eMTC config - PRACH CE level #2 Configuration index", dissect_emtc_prach_ce_level_2_configuration_offset_value },
	{ 0x008C, "eMTC config - PRACH CE level #2 Frequency offset", dissect_emtc_prach_ce_level_2_frequency_offset_value },
	{ 0x008D, "eMTC config - PRACH CE level #2 Number of repetitions per attempt", dissect_emtc_preach_ce_level_2_num_of_repeitions_per_attempt_value },
	{ 0x008E, "eMTC config - CE level #2 Starting subframe periodicity", dissect_emtc_ce_level_2_starting_subframe_periodicity_value },
	{ 0x008F, "eMTC config - PRACH CE level #2 Hopping Enable", dissect_emtc_preach_ce_level_2_hopping_enabled_value },
	{ 0x0090, "eMTC config - PRACH CE level #2 Hopping Offset", dissect_emtc_preach_ce_level_2_hopping_offset_value },
	{ 0x0091, "eMTC config - PRACH CE level #3 Enable", dissect_emtc_prach_ce_level_3_enabled_value },
	{ 0x0092, "eMTC config - PRACH CE level #3 Configuration index", dissect_emtc_prach_ce_level_3_configuration_offset_value },
	{ 0x0093, "eMTC config - PRACH CE level #3 Frequency offset", dissect_emtc_prach_ce_level_3_frequency_offset_value },
	{ 0x0094, "eMTC config - PRACH CE level #3 Number of repetitions per attempt", dissect_emtc_preach_ce_level_3_num_of_repeitions_per_attempt_value },
	{ 0x0095, "eMTC config - CE level #3 Starting subframe periodicity", dissect_emtc_ce_level_3_starting_subframe_periodicity_value },
	{ 0x0096, "eMTC config - PRACH CE level #3 Hopping Enable", dissect_emtc_preach_ce_level_3_hopping_enabled_value },
	{ 0x0097, "eMTC config - PRACH CE level #3 Hopping Offset", dissect_emtc_preach_ce_level_3_hopping_offset_value },
	{ 0x0098, "eMTC config - PUCCH Interval - ULHoppingConfigCommonModeA", dissect_emtc_pucch_interval_ul_hopping_config_common_mode_a_value },
	{ 0x0099, "eMTC config - PUCCH Interval - ULHoppingConfigCommonModeB", dissect_emtc_pucch_interval_ul_hopping_config_common_mode_b_value },
	
	{ 0x00C8, "Layer 2/3 - Downlink Bandwidth Support", dissect_dl_bandwidth_support_value },
	{ 0x00C9, "Layer 2/3 - Uplink Bandwidth Support", dissect_ul_bandwidth_support_value },
	{ 0x00CA, "Layer 2/3 - Downlink modulation support", dissect_dl_modulation_value },
	{ 0x00CB, "Layer 2/3 - Uplink modulation support", dissect_ul_modulation_value },
	{ 0x00CC, "Layer 2/3 - PHY antenna capability", dissect_phy_antenna_capability_value },
	{ 0x00CD, "Layer 2/3 - Release capability", dissect_release_capability_value },
	{ 0x00CE, "Layer 2/3 - MBSFN capability", dissect_mbsfn_value },

	{ 0x00D1, "LAA Capability - LAA support", dissect_laa_support_value },
	{ 0x00D1, "LAA Capability - PD sensing LBT support", dissect_laa_pd_sensing_lbt_support_value },
	{ 0x00D1, "LAA Capability - Multi carrier LBT support", dissect_laa_multi_carrier_lbt_support_value },
	{ 0x00D1, "LAA Capability - Partial SF support", dissect_laa_partial_sf_support_value },

	{ 0x00F0, "Layer 2/3 - Data report mode", dissect_data_report_mode_value },
	{ 0x00F1, "Layer 2/3 - SFN/SF", dissect_sfn_sf_value },
	{ 0x00FA, "Layer 1 - PHY state", dissect_phy_state_value },

	{ 0x0100, "NFAPI - P7 VNF Address IPv4", dissect_p7_vnf_address_ipv4_value },
	{ 0x0101, "NFAPI - P7 VNF Address IPv4", dissect_p7_vnf_address_ipv6_value },
	{ 0x0102, "NFAPI - P7 Port", dissect_p7_vnf_port_value },
	{ 0x0103, "NFAPI - P7 PNF Address IPv4", dissect_p7_pnf_address_ipv4_value },
	{ 0x0104, "NFAPI - P7 PNF Address IPv4", dissect_p7_pnf_address_ipv6_value },
	{ 0x0105, "NFAPI - P7 Port", dissect_p7_pnf_port_value },
	{ 0x010A, "NFAPI - Downlink UEs per Subframe", dissect_downlink_ues_per_subframe_value },
	{ 0x010B, "NFAPI - Uplink UEs per Subframe", dissect_uplink_ues_per_subframe_value },

	{ 0x0114, "NFAPI - nFAPI RF Bands", dissect_rf_bands_value },

	{ 0x011E, "NFAPI - Timing window", dissect_timing_window_value },
	{ 0x011F, "NFAPI - Timing info mode", dissect_timing_info_mode_value },
	{ 0x0120, "NFAPI - Timing info period", dissect_timing_info_period_value },
	{ 0x0128, "NFAPI - Maximum Transmit Power", dissect_maximum_transmit_power_value },
	{ 0x0129, "NFAPI - EARFCN", dissect_earfcn_value },
	{ 0x0130, "NFAPI - NMM GSM Frequency Bands", dissect_nmm_gsm_frequency_bands_value },
	{ 0x0131, "NFAPI - NMM UMTS Frequency Bands", dissect_nmm_umts_frequency_bands_value },
	{ 0x0132, "NFAPI - NMM LTE Frequency Bands", dissect_nmm_lte_frequency_bands_value },
	{ 0x0133, "NFAPI - NMM Uplink RSSI supported", dissect_nmm_uplink_rssi_supported_value },

	{ 0x2000, "DL Config Request Body", dissect_dl_config_request_body_value },

	{ 0x2001, "DL DCI PDU Release 8", dissect_dl_config_request_dl_dci_pdu_rel8_value },
	{ 0x2002, "DL DCI PDU Release 9", dissect_dl_config_request_dl_dci_pdu_rel9_value },
	{ 0x2003, "DL DCI PDU Release 10", dissect_dl_config_request_dl_dci_pdu_rel10_value },
	{ 0x2039, "DL DCI PDU Release 11", dissect_dl_config_request_dl_dci_pdu_rel11_value },
	{ 0x203A, "DL DCI PDU Release 12", dissect_dl_config_request_dl_dci_pdu_rel12_value },
	{ 0x203B, "DL DCI PDU Release 13", dissect_dl_config_request_dl_dci_pdu_rel13_value },


	{ 0x2004, "BCH PDU Release 8", dissect_dl_config_request_bch_pdu_rel8_value },

	{ 0x2005, "MCH PDU Release 8", dissect_dl_config_request_mch_pdu_rel8_value },

	{ 0x2006, "DLSCH PDU Release 8", dissect_dl_config_request_dlsch_pdu_rel8_value },
	{ 0x2007, "DLSCH PDU Release 9", dissect_dl_config_request_dlsch_pdu_rel9_value },
	{ 0x2008, "DLSCH PDU Release 10", dissect_dl_config_request_dlsch_pdu_rel10_value },
	{ 0x203C, "DLSCH PDU Release 11", dissect_dl_config_request_dlsch_pdu_rel11_value },
	{ 0x203D, "DLSCH PDU Release 12", dissect_dl_config_request_dlsch_pdu_rel12_value },
	{ 0x203E, "DLSCH PDU Release 13", dissect_dl_config_request_dlsch_pdu_rel13_value },

	{ 0x2009, "PCH PDU Release 8", dissect_dl_config_request_pch_pdu_rel8_value },
	{ 0x203F, "PCH PDU Release 13", dissect_dl_config_request_pch_pdu_rel13_value },

	{ 0x200A, "PRS PDU Release 9", dissect_dl_config_request_prs_pdu_rel9_value },

	{ 0x200B, "CSI-RS PDU Release 10", dissect_dl_config_request_csi_rs_pdu_rel10_value },
	{ 0x2040, "CSI-RS PDU Release 13", dissect_dl_config_request_csi_rs_pdu_rel13_value },

	//{ 0x2001, "EDPCCH PDU Release 8", ?? },
	//{ 0x2002, "EDPCCH PDU Release 8", ?? },
	//{ 0x2003, "EDPCCH PDU Release 8", ?? },
	//{ 0x2039, "EDPCCH PDU Release 11", ?? },
	//{ 0x203A, "EDPCCH PDU Release 12", ?? },
	//{ 0x203B, "EDPCCH PDU Release 13", ?? },
	{ 0x2041, "EDPCCH PDU Release 11 Parameters", dissect_dl_config_request_edpcch_params_rel11_value },
	{ 0x2042, "EDPCCH PDU Release 13 Parameters", dissect_dl_config_request_edpcch_params_rel13_value },

	{ 0x205B, "MPDCCH PDU Release 13", dissect_dl_config_request_mpdpcch_pdu_rel13_value },


	{ 0x200C, "UL Config Request Body", dissect_ul_config_request_body_value },
	{ 0x200D, "ULSCH PDU Release 8", dissect_ul_config_ulsch_pdu_rel8_value },
	{ 0x200E, "ULSCH PDU Release 10", dissect_ul_config_ulsch_pdu_rel10_value },
	{ 0x2043, "ULSCH PDU Release 11", dissect_ul_config_ulsch_pdu_rel11_value },
	{ 0x2044, "ULSCH PDU Release 13", dissect_ul_config_ulsch_pdu_rel13_value },
	{ 0x200F, "Initial Transmission Paramters Release 8", dissect_ul_config_init_tx_params_rel8_value },
	{ 0x2010, "CQI RI Information Release 8", dissect_ul_config_cqi_ri_info_rel8_value },
	{ 0x2011, "CQI RI Information Release 9 or later", dissect_ul_config_cqi_ri_info_rel9_later_value },
	{ 0x2045, "CQI RI Information Release 13", dissect_ul_config_cqi_ri_info_rel13_value },
	{ 0x2012, "HARQ Information (ULSCH) Release 10", dissect_ul_config_harq_info_ulsch_rel10_value },
	{ 0x2046, "HARQ Information (ULSCH) Release 13", dissect_ul_config_harq_info_ulsch_rel13_value },
	{ 0x2013, "UE Information Release 8", dissect_ul_config_ue_info_rel8_value },
	{ 0x2047, "UE Information Release 11", dissect_ul_config_ue_info_rel11_value },
	{ 0x2048, "UE Information Release 13", dissect_ul_config_ue_info_rel13_value },
	{ 0x2014, "CQI Information Release 8", dissect_ul_config_cqi_info_rel8_value },
	{ 0x2015, "CQI Information Release 10", dissect_ul_config_cqi_info_rel10_value },
	{ 0x2049, "CQI Information Release 13", dissect_ul_config_cqi_info_rel13_value },
	{ 0x2016, "SR Information Release 8", dissect_ul_config_sr_info_rel8_value },
	{ 0x2017, "SR Information Release 10", dissect_ul_config_sr_info_rel10_value },
	{ 0x2018, "HARQ Information (UCI) Release 10 TDD", dissect_ul_config_harq_info_uci_rel10_tdd_value },
	{ 0x2019, "HARQ Information (UCI) Release 8 FDD", dissect_ul_config_harq_info_uci_rel8_fdd_value },
	{ 0x201A, "HARQ Information (UCI) Release 9 or later FDD", dissect_ul_config_harq_info_uci_rel9_later_fdd_value },
	{ 0x204A, "HARQ Information (UCI) Release 11 FDD/TDD", dissect_ul_config_harq_info_uci_rel11_fdd_tdd_value },
	{ 0x204B, "HARQ Information (UCI) Release 13 FDD/TDD", dissect_ul_config_harq_info_uci_rel13_fdd_tdd_value },
	{ 0x201B, "SRS Information Release 8", dissect_ul_config_srs_info_rel8_value },
	{ 0x201C, "SRS Information Release 10", dissect_ul_config_srs_info_rel10_value },
	{ 0x204C, "SRS Information Release 13", dissect_ul_config_srs_info_rel13_value },

	{ 0x201D, "HI DCI0 Request Body", dissect_hi_dci0_request_body_value },
	{ 0x201E, "HI PDU Release 8", dissect_hi_dci0_hi_rel8_value },
	{ 0x201F, "HI PDU Release 10", dissect_hi_dci0_hi_rel10_value },
	{ 0x2020, "DCI UL PDU Release 8", dissect_hi_dci0_dci_ul_rel8_value },
	{ 0x2021, "DCI UL PDU Release 10", dissect_hi_dci0_dci_ul_rel10_value },
	{ 0x204D, "DCI UL PDU Release 12", dissect_hi_dci0_dci_ul_rel12_value },
	//{ 0x2041, "EDPCCH DCI UL PDU Release 11", dissect_hi_dci0_edpcch_dci_ul_rel11_value },
	{ 0x204E, "MDPCCH DCI UL PDU Release 13", dissect_hi_dci0_mdpcch_dci_ul_rel13_value },

	{ 0x2022, "Tx Request Body", dissect_tx_request_body_value },

	{ 0x2038, "RX UE Information", dissect_rx_ue_info_value },

	{ 0x2023, "RX Indication Body", dissect_rx_indication_body_value },
	{ 0x2024, "RX PDU Release 8", dissect_rx_indication_rel8_value },
	{ 0x2025, "RX PDU Release 9", dissect_rx_indication_rel9_value },

	{ 0x2026, "HARQ Indication Body", dissect_harq_indication_body_value },
	{ 0x2027, "HARQ PDU Release 8 TDD", dissect_harq_indication_rel8_tdd_value },
	{ 0x2028, "HARQ PDU Release 9 or later TDD", dissect_harq_indication_rel9_later_tdd_value },
	{ 0x204F, "HARQ PDU Release 13 or later TDD", dissect_harq_indication_rel13_later_tdd_value },
	{ 0x2029, "HARQ PDU Release 8 FDD", dissect_harq_indication_rel8_fdd_value },
	{ 0x202A, "HARQ PDU Release 9 or later FDD", dissect_harq_indication_rel9_later_fdd_value },
	{ 0x2050, "HARQ PDU Release 13 or later FDD", dissect_harq_indication_rel13_later_fdd_value },
	{ 0x2052, "UL CQI Information", dissect_ul_cqi_information_value },

	{ 0x202B, "CRC Indication Body", dissect_crc_indication_body_value },
	{ 0x202C, "CRC PDU Release 8", dissect_crc_indication_rel8_value },

	{ 0x202D, "RX SR Indication Body", dissect_rx_sr_indication_body_value },

	{ 0x202E, "RX CQI Indication Body", dissect_rx_cqi_indication_body_value },
	{ 0x202F, "CQI PDU Release 8", dissect_rx_cqi_indication_rel8_value },
	{ 0x2030, "CQI PDU Release 9", dissect_rx_cqi_indication_rel9_value },

	{ 0x2031, "RACH Indication Body", dissect_rach_indication_body_value },
	{ 0x2032, "Preamable PDU Release 8", dissect_rach_indication_rel8_value },
	{ 0x2033, "Preamable PDU Release 9", dissect_rach_indication_rel9_value },
	{ 0x2051, "Preamable PDU Release 13", dissect_rach_indication_rel13_value },

	{ 0x2034, "SRS Indication Body", dissect_srs_indication_body_value },
	{ 0x2035, "SRS PDU Release 8", dissect_srs_indication_rel8_value },
	{ 0x2036, "SRS PDU Release 9", dissect_srs_indication_rel9_value },
	{ 0x2037, "SRS PDU Release 10 TDD", dissect_srs_indication_rel10_tdd_value },
	{ 0x2054, "TDD Channel Measurement", dissect_tdd_channel_measuerment_value },
	{ 0x2053, "SRS PDU Release 11", dissect_srs_indication_rel11_value },


	{ 0x2055, "LBT DL Config Request Body", dissect_lbt_dl_config_request_body_value },
	{ 0x2056, "LBT PDSCH Req PDU Release 13", dissect_lbt_dl_config_request_pdsch_req_rel13_value },
	{ 0x2057, "LBT DRS req PDU Release 13", dissect_lbt_dl_config_request_drs_req_rel13_value },

	{ 0x2058, "LBT DL Indication Message Body", dissect_lbt_indication_message_body_value },
	{ 0x2056, "LBT PDSCH Resp PDU Release 13", dissect_lbt_dl_config_request_pdsch_resp_rel13_value },
	{ 0x2057, "LBT DRS Resp PDU Release 13", dissect_lbt_dl_config_request_drs_resp_rel13_value },

	{ 0x3000, "LTE RSSI Request", dissect_lte_rssi_request_value },
	{ 0x3001, "UTRAN RSSI Request", dissect_utran_rssi_request_value },
	{ 0x3002, "GERAN RSSI Request", dissect_geran_rssi_request_value },
	{ 0x3003, "RSSI Indication", dissect_rssi_indication_value },
	{ 0x3004, "LTE CELL SEARCH Request", dissect_lte_cell_search_value },
	{ 0x3005, "UTRAN CELL SEARCH Request", dissect_utran_cell_search_value },
	{ 0x3006, "GERAN CELL SEARCH Request", dissect_geran_cell_search_value },
	{ 0x3007, "LTE CELL SEARCH Indication", dissect_lte_cell_search_indication_value },
	{ 0x3008, "UTRAN CELL SEARCH Indication", dissect_utran_cell_search_indication_value },
	{ 0x3009, "GERAN CELL SEARCH Indication", dissect_geran_cell_search_indication_value },
	{ 0x300a, "PNF CELL SEARCH STATE", dissect_pnf_cell_search_state_value },
	{ 0x300b, "LTE BROADCAST DETECT Request", dissect_lte_broadcast_detect_request_value },
	{ 0x300c, "UTRAN BROADCAST DETECT Request", dissect_utran_broadcast_detect_request_value },
	{ 0x300d, "PNF CELL SEARCH STATE", dissect_pnf_cell_search_state_value },
	{ 0x300e, "LTE BROADCAST DETECT Indication", dissect_lte_broadcast_detect_indication_value },
	{ 0x300f, "UTRAN BROADCAST DETECT Indication", dissect_utran_broadcast_detect_indication_value },
	{ 0x3010, "PNF CELL BROADCAST STATE", dissect_pnf_cell_broadcast_state_value },
	{ 0x3011, "LTE SYSTEM INFORMATION SCHEDULE Request", dissect_lte_system_information_schedule_request_value },
	{ 0x3012, "PNF CELL BROADCAST STATE", dissect_pnf_cell_broadcast_state_value },
	{ 0x3013, "LTE SYSTEM INFORMATION SCHEDULE Indication", dissect_lte_system_information_schedule_indication_value },
	{ 0x3014, "LTE SYSTEM INFORMATION Request", dissect_lte_system_information_request_value },
	{ 0x3015, "UTRAN SYSTEM INFORMATION Request", dissect_utran_system_information_request_value },
	{ 0x3016, "GERAN SYSTEM INFORMATION Request", dissect_geran_system_information_request_value },
	{ 0x3017, "PNF CELL BROADCAST STATE", dissect_pnf_cell_broadcast_state_value },
	{ 0x3018, "LTE SYSTEM INFORMATION Indication", dissect_lte_system_information_indication_value },
	{ 0x3019, "UTRAN SYSTEM INFORMATION Indication", dissect_utran_system_information_indication_value },
	{ 0x301a, "GERAN SYSTEM INFORMATION Indication", dissect_geran_system_information_indication_value },




};

int look_up_tlv(int tag_id)
{
	int i;
	int num_tags = sizeof(tags) / sizeof(tlv_t);

	for (i = 0; i < num_tags; i++)
	{
		if (tag_id == tags[i].tag_id)
			return i;
	}
	return -1;
}

static int dissect_tl_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset)
{
	proto_item *tl_ti = proto_tree_add_string_format(tree, hf_nfapi_tl, tvb, *offset, 4, "", "TL");
	proto_tree *tl_tree = proto_item_add_subtree(tl_ti, ett_nfapi_tl);

	proto_tree_add_uint16(tl_tree, hf_nfapi_tl_tag, tvb, offset, 0);
	proto_tree_add_uint16(tl_tree, hf_nfapi_tl_length, tvb, offset, "bytes");

	return 0;

}

static int dissect_tlv_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint len)
{	
	while (*offset < len)
	{
		guint16 tlv_id = tvb_get_guint16(tvb, *offset, ENC_NA);
		guint16 tlv_len = tvb_get_guint16(tvb, *offset + 2, ENC_NA);

		int tlv_index = look_up_tlv(tlv_id);

		char* tlv_name = tlv_index != -1 ? tags[tlv_index].name : "Unknown";

		proto_item *tlv_ti = proto_tree_add_string_format(tree, hf_nfapi_tlv_tree, tvb, *offset, tlv_len + 4, "", tlv_name);
		proto_tree *tlv_tree = proto_item_add_subtree(tlv_ti, ett_nfapi_tlv_tree);

		dissect_tl_header(tvb, pinfo, tlv_tree, data, offset);

		if (tags[tlv_index].decode != NULL)
		{
			guint tmp = *offset;
			guint end = *offset + tlv_len;
			tags[tlv_index].decode(tvb, pinfo, tlv_tree, data, &tmp, &end);
			*offset += tlv_len;
		}
		else
		{
			*offset += tlv_len;
		}
	}

	return 0;
}

static int dissect_rx_indication_body_value(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint* end)
{
	guint number_of_pdu_addr = *offset;
	guint16 count = proto_tree_add_uint16(tree, hf_nfapi_number_pdus, tvb, offset, 0);
	//dissect_array_value(tvb, pinfo, tree, data, offset, "RX PDU List", hf_nfapi_rx_indication_pdu_list, ett_nfapi_rx_indication_pdu_list, num_pdu, dissect_rx_pdu);

	guint16* lengths = malloc(count * 2);
	memset(lengths, 0, count * 2);

	guint16 i = 0;

	if (count > 0)
	{
		proto_item *list_ti = proto_tree_add_string_format(tree, hf_nfapi_rx_indication_pdu_list, tvb, *offset, 2, "", "RX PDU List");
		proto_tree *list_tree = proto_item_add_subtree(list_ti, ett_nfapi_rx_indication_pdu_list);

		//for (i = 0; i < count; ++i)
		proto_tree *item_tree = 0;

		guint pdu_end = *end;
		while (*offset < *end && *offset < pdu_end)
		{

			guint16 tlv_id = tvb_get_guint16(tvb, *offset, ENC_NA);
			guint16 tlv_len = tvb_get_guint16(tvb, *offset + 2, ENC_NA);

			if (tlv_id == 0x2038)
			{
				proto_item *item_ti = proto_tree_add_string_format(list_tree, hf_nfapi_rx_indication_pdu_list, tvb, *offset, 2, "", "[%d]", i);
				item_tree = proto_item_add_subtree(item_ti, ett_nfapi_rx_indication_pdu_list);

				i++;
			}

			int tlv_index = look_up_tlv(tlv_id);

			char* tlv_name = tlv_index != -1 ? tags[tlv_index].name : "Unknown";

			proto_item *tlv_ti = proto_tree_add_string_format(item_tree, hf_nfapi_tlv_tree, tvb, *offset, tlv_len + 4, "", tlv_name);
			proto_tree *tlv_tree = proto_item_add_subtree(tlv_ti, ett_nfapi_tlv_tree);


	

			dissect_tl_header(tvb, pinfo, tlv_tree, data, offset);

			guint tmp_offset = *offset;

			if (tlv_id == 0x2038)
			{
				dissect_rx_ue_info_value(tvb, pinfo, tlv_tree, data, &tmp_offset, end);
			}

			else if (tlv_id == 0x2024)
			{
				//int data_offset = dissect_rx_indication_rel8_value(tvb, pinfo, tlv_tree, data, &tmp_offset, end);

				lengths[i-1] = proto_tree_add_uint16(tlv_tree, hf_nfapi_length, tvb, &tmp_offset, 0);
				int data_offset = proto_tree_add_uint16(tlv_tree, hf_nfapi_data_offset, tvb, &tmp_offset, 0);
				proto_tree_add_uint8(tlv_tree, hf_nfapi_ul_cqi, tvb, &tmp_offset, 0);
				proto_tree_add_uint16(tlv_tree, hf_nfapi_timing_advance, tvb, &tmp_offset, 0);
				
				if ((data_offset > 0) && (pdu_end == *end))
				{
					pdu_end = number_of_pdu_addr + data_offset;
				}

			}
			else if (tlv_id == 0x2025)
			{
				dissect_rx_indication_rel9_value(tvb, pinfo, tlv_tree, data, &tmp_offset, end);
			}


			*offset += tlv_len;
		}

	}

	for (i = 0; i < count; ++i)
	{
		proto_tree_add_uint8_array(tree, hf_nfapi_pdu, lengths[i], tvb, offset);
	}

	free(lengths);

	// more to follow here ??
	return 0;

}


// ----------------------------------------------------------------------------|


static int dissect_p45_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset)
{
	proto_item *p4_p5_header_ti = proto_tree_add_string_format(tree, hf_nfapi_p4_p5_message_header, tvb, *offset, NFAPI_HEADER_LENGTH, "", "P4 P5 Header");
	proto_tree *p4_p5_header_tree = proto_item_add_subtree(p4_p5_header_ti, ett_nfapi_p4_p5_message_header);

	proto_tree_add_uint16(p4_p5_header_tree, hf_nfapi_p4_p5_message_header_phy_id, tvb, offset, 0);
	proto_tree_add_uint16(p4_p5_header_tree, hf_nfapi_p4_p5_message_header_message_id, tvb, offset, 0);
	proto_tree_add_uint16(p4_p5_header_tree, hf_nfapi_p4_p5_message_header_message_length, tvb, offset, 0);
	proto_tree_add_uint16(p4_p5_header_tree, hf_nfapi_p4_p5_message_header_spare, tvb, offset, 0);

	return 0;
}

static int dissect_p7_header_new(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset, guint8* m, guint8* seg, guint8* seq)
{
	proto_item *p7_header_ti = proto_tree_add_string_format(tree, hf_nfapi_p7_message_header, tvb, *offset, NFAPI_P7_HEADER_LENGTH, "", "P7 Header");
	proto_tree *p7_header_tree = proto_item_add_subtree(p7_header_ti, ett_nfapi_p7_message_header);

	proto_tree_add_uint16(p7_header_tree, hf_nfapi_p7_message_header_phy_id, tvb, offset, 0);
	proto_tree_add_uint16(p7_header_tree, hf_nfapi_p7_message_header_message_id, tvb, offset, 0);
	proto_tree_add_uint16(p7_header_tree, hf_nfapi_p7_message_header_message_length, tvb, offset, "bytes");

	// decoding bits for p7 header

	guint8 m_seg = tvb_get_guint8(tvb, *offset);
	*m = (m_seg & 0x80) >> 7;
	*seg = m_seg & 0x7F;


	proto_tree_add_bits_item(p7_header_tree, hf_nfapi_p7_message_header_m, tvb, (*offset) * 8, 1, ENC_NA);
	proto_tree_add_bits_item(p7_header_tree, hf_nfapi_p7_message_header_segment, tvb, ((*offset) * 8) + 1, 7, ENC_NA);
	*offset += 1;

	*seq = tvb_get_guint8(tvb, *offset);
	proto_tree_add_uint8(p7_header_tree, hf_nfapi_p7_message_header_sequence_number, tvb, offset, 0);


	proto_tree_add_uint32(p7_header_tree, hf_nfapi_p7_message_header_checksum, tvb, offset, 0);
	proto_tree_add_uint32(p7_header_tree, hf_nfapi_p7_message_header_transmit_timestamp, tvb, offset, "microseconds");

	return 0;

}




static int dissect_p7_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data, guint* offset)
{
	proto_item *p7_header_ti = proto_tree_add_string_format(tree, hf_nfapi_p7_message_header, tvb, *offset, NFAPI_P7_HEADER_LENGTH, "", "P7 Header");
	proto_tree *p7_header_tree = proto_item_add_subtree(p7_header_ti, ett_nfapi_p7_message_header);

	proto_tree_add_uint16(p7_header_tree, hf_nfapi_p7_message_header_phy_id, tvb, offset, 0);
	proto_tree_add_uint16(p7_header_tree, hf_nfapi_p7_message_header_message_id, tvb, offset, 0);
	proto_tree_add_uint16(p7_header_tree, hf_nfapi_p7_message_header_message_length, tvb, offset, "bytes");


	proto_tree_add_bits_item(p7_header_tree, hf_nfapi_p7_message_header_m, tvb, (*offset) * 8, 1, ENC_NA);
	proto_tree_add_bits_item(p7_header_tree, hf_nfapi_p7_message_header_segment, tvb, ((*offset) * 8) + 1, 7, ENC_NA);
	*offset += 1;

	proto_tree_add_uint8(p7_header_tree, hf_nfapi_p7_message_header_sequence_number, tvb, offset, 0);
	

	proto_tree_add_uint32(p7_header_tree, hf_nfapi_p7_message_header_checksum, tvb, offset, 0);
	proto_tree_add_uint32(p7_header_tree, hf_nfapi_p7_message_header_transmit_timestamp, tvb, offset, "microseconds");

	return 0;

}

static reassembly_table ul_p7_reassemble_table;
static reassembly_table dl_p7_reassemble_table;



static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;
static int hf_msg_reassembled_data = -1;
static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;

static const fragment_items msg_frag_items = {
	/* Fragment subtrees */
	&ett_msg_fragment,
	&ett_msg_fragments,
	/* Fragment fields */
	&hf_msg_fragments,
	&hf_msg_fragment,
	&hf_msg_fragment_overlap,
	&hf_msg_fragment_overlap_conflicts,
	&hf_msg_fragment_multiple_tails,
	&hf_msg_fragment_too_long_fragment,
	&hf_msg_fragment_error,
	&hf_msg_fragment_count,
	/* Reassembled in field */
	&hf_msg_reassembled_in,
	/* Reassembled length field */
	&hf_msg_reassembled_length,
	NULL,
	/* Tag */
	"Message fragments"
};

static int dissect_nfapi_ul_p7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	guint8 m;
	guint8 seg;
	guint8 seq;
	guint offset = 0;

	guint16 msg_id = tvb_get_guint16(tvb, 2, ENC_NA);
	guint16 msg_len	= tvb_get_guint16(tvb, 4, ENC_NA);

	dissect_p7_header_new(tvb, pinfo, tree, data, &offset, &m, &seg, &seq);
	
	guint8 save_fragmented = pinfo->fragmented;

	// not sure why I need to do this, but if I don't it does not reasses the protocol
	pinfo->fd->flags.visited = 0;

	if (m == 1 || (m == 0 && seg > 0))
	{
		pinfo->fragmented = TRUE;

		fragment_head *fd_head = fragment_add_seq_check(&ul_p7_reassemble_table, tvb, offset, pinfo, seq, NULL, seg, msg_len - offset, (m == 1));

		guint8 reassembled = 0;
		if (fd_head)
		{
			tvbuff_t * new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled UL P7", fd_head, &msg_frag_items, NULL, tree);

			if (new_tvb)
			{ 
				// set the tvb to the new reassembled buffer.
				tvb = new_tvb;
				reassembled = 1;
				col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Reassembled %d]", seg);

				// reset the offset for the new tvb
				offset = 0;
			}
			else
			{
				// Is this a failure to reassemble the data
				return 0;
			}
		}
		else
		{
			// this is a segement skip the body
			col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Segment %d]", seg);
			return 0;
		}
	}
		
	pinfo->fragmented = save_fragmented;
	
	{
		switch (msg_id)
		{
			//HARQ.indication
			case 0x85: 
			{
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
			}
			break;
			//CRC.indication
			case 0x86:
			{
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
			}
			break;
			//RX_ULSCH.indication
			case 0x87:
			{
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
			}
			break;
			//RACH.indication
			case 0x88:
			{
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
			}
			break;
			//SRS.indication
			case 0x89:
			{
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
			}
			break;
			//RX_SR.indication
			case 0x8A:
			{
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
			}
			break;
			//RX_CQI.indication
			case 0x8B:
			{
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
			}
			break;
		};
	}
	
	return 0;
}

static int dissect_nfapi_dl_p7(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	guint8 m;
	guint8 seg;
	guint8 seq;
	guint offset = 0;

	guint16 msg_id = tvb_get_guint16(tvb, 2, ENC_NA);
	guint16 msg_len = tvb_get_guint16(tvb, 4, ENC_NA);

	dissect_p7_header_new(tvb, pinfo, tree, data, &offset, &m, &seg, &seq);

	guint8 save_fragmented = pinfo->fragmented;

	// not sure why I need to do this, but if I don't it does not reasses the protocol
	pinfo->fd->flags.visited = 0;

	if (m == 1 || (m == 0 && seg > 0))
	{
		pinfo->fragmented = TRUE;

		fragment_head *fd_head = fragment_add_seq_check(&dl_p7_reassemble_table, tvb, offset, pinfo, seq, NULL, seg, msg_len - offset, (m == 1));

		guint8 reassembled = 0;
		if (fd_head)
		{
			tvbuff_t * new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled DL P7", fd_head, &msg_frag_items, NULL, tree);

			if (new_tvb)
			{
				// set the tvb to the new reassembled buffer.
				tvb = new_tvb;
				reassembled = 1;
				col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Reassembled %d]", seg);

				// reset the offset for the new tvb
				offset = 0;
			}
			else
			{
				// Is this a failure to reassemble the data
				return 0;
			}
		}
		else
		{
			// this is a segement skip the body
			col_append_fstr(pinfo->cinfo, COL_INFO, "[NFAPI P7 Segment %d]", seg);
			return 0;
		}
	}

	pinfo->fragmented = save_fragmented;

	{
		switch (msg_id)
		{
			// DL_CONFIG.request
			case 0x80:
			{
				//dissect_p7_header(tvb, pinfo, tree, data, &offset);
				proto_tree_add_uint16_with_conversion(tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
				dissect_tlv_list(tvb, pinfo, tree, data, &offset, tvb_reported_length(tvb));
				break;
			}
	
		};
	}

	return 0;
}


static int dissect_nfapi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NFAPI");

	guint16 msg_id = tvb_get_guint16(tvb, 2, ENC_NA);
	guint16 msg_len = tvb_get_guint16(tvb, 4, ENC_NA);

	const gchar* message_str = val_to_str_const(msg_id, message_id_vals, "Unknown");

	col_clear(pinfo->cinfo,COL_INFO);
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", message_str);

	proto_item *msg_tree_ti = proto_tree_add_string_format(tree, hf_nfapi_message_tree,
															tvb, 0, msg_len,
															"", message_str);

	proto_tree *msg_tree = proto_item_add_subtree(msg_tree_ti, ett_nfapi_message_tree);

	guint offset = 0;


	switch (msg_id)
	{
		// HARQ.indication
		case 0x85:
		// CRC.indication
		case 0x86:
		// RX_ULSCH.indicatoin
		case 0x87:
		// RACH.indication
		case 0x88:
		// SRS.indication
		case 0x89:
		// RX_SR.indication
		case 0x8A:
		// RX_CQI.indication
		case 0x8B:
		{
			dissect_nfapi_ul_p7(tvb, pinfo, msg_tree, data);
		}
		break;

		// DL_CONFIG.request
		case 0x80:
		{
			dissect_nfapi_dl_p7(tvb, pinfo, msg_tree, data);
			//dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			//proto_tree_add_uint16_with_conversion(msg_tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
			//dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
	
		// UL_CONFIG.request
		case 0x81:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint16_with_conversion(msg_tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
		}
		break;
		// HI_DCI0.request
		case 0x83:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint16_with_conversion(msg_tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
		}
		break;
		// TX.request
		case 0x84:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint16_with_conversion(msg_tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
		}
		break;

		// LBT_DL_CONFIG.request
		case 0x8C:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint16_with_conversion(msg_tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
		}
		break;
		// LBT_DL.indication
		case 0x8D:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint16_with_conversion(msg_tree, hf_nfapi_sfn_sf, tvb, &offset, sfn_sf_conversion);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// PNF_PARAM.request
		case 0x100:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// PNF_PARAM.response
		case 0x101:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// PNF_CONFIG.request
		case 0x102:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// PNF_CONFIG.response
		case 0x103:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			break;
		}
		// PNF_START.request
		case 0x104:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			break;
		}
		// PNF_START.response
		case 0x105:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			break;
		}
		// PNF_STOP.response
		case 0x106:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			break;
		}
		// PNF_STOP.request
		case 0x107:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			break;
		}
		// PARAM.request
		case 0x108:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			break;
		}
		// PARAM.response
		case 0x109:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// CONFIG.request
		case 0x10A:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint8(msg_tree, hf_nfapi_num_tlv, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// CONFIG.response
		case 0x10B:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			break;
		}
		// START.request
		case 0x10C:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			break;
		}
		// START.response
		case 0x10D:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			break;
		}
		// STOP.request
		case 0x10E:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			break;
		}
		// STOP.response
		case 0x10F:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			break;
		}
		// MEASUREMENT.request
		case 0x110:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// MEASUREMENT.response
		case 0x111:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}

		// P4
		// RSSI.request
		case 0x200:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint8(msg_tree, hf_nfapi_rat_type, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// RSSI.response
		case 0x201:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			break;
		}
		// RSSI.indication
		case 0x202:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// CELL_SEARCH.request
		case 0x203:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint8(msg_tree, hf_nfapi_rat_type, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// CELL_SEARCH.response
		case 0x204:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			break;
		}
		// CELL_SEARCH.indication
		case 0x205:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// BROADCAST_DETECT.request
		case 0x206:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint8(msg_tree, hf_nfapi_rat_type, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// BROADCAST_DETECT.response
		case 0x207:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			break;
		}
		// BROADCAST_DETECT.indication
		case 0x208:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// SYSTEM_INFORMATION_SCHEDULE.request
		case 0x209:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint8(msg_tree, hf_nfapi_rat_type, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// SYSTEM_INFORMATOIN_SCHEDULE.response
		case 0x20A:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			break;
		}
		// SYSTEM_INFORMATION_SCHEDULE.indication
		case 0x20B:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// SYSTEM_INFORMATION.request
		case 0x20C:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint8(msg_tree, hf_nfapi_rat_type, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// SYSTEM_INFORMATION.response
		case 0x20D:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			break;
		}
		// SYSTEM_INFORMATION.indication
		case 0x20E:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			dissect_tlv_list(tvb, pinfo, msg_tree, data, &offset, tvb_reported_length(tvb));
			break;
		}
		// NMM_STOP.request
		case 0x20F:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			break;
		}
		// NMM_STOP_response
		case 0x210:
		{
			dissect_p45_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_p4_error_code, tvb, &offset, 0);
			break;
		}

		// DL_NODE.sync
		case 0x0180:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_dl_node_sync_t1, tvb, &offset, "microseconds");
			proto_tree_add_uint32(msg_tree, hf_nfapi_dl_node_sync_delta_sfn_sf, tvb, &offset, 0);
			break;
		}
		// UL_NODE.sync
		case 0x0181:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_ul_node_sync_t1, tvb, &offset, "microseconds");
			proto_tree_add_uint32(msg_tree, hf_nfapi_ul_node_sync_t2, tvb, &offset, "microseconds");
			proto_tree_add_uint32(msg_tree, hf_nfapi_ul_node_sync_t3, tvb, &offset, "microseconds");
			break;
		}
		// TIMING_INFO
		case 0x0182:
		{
			dissect_p7_header(tvb, pinfo, msg_tree, data, &offset);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_last_sfn_sf, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_time_since_last_timing_info, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_dl_config_jitter, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_tx_request_jitter, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_ul_config_jitter, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_hi_dci0_jitter, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_dl_config_latest_delay, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_tx_request_latest_delay, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_ul_config_latest_delay, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_hi_dci0_latest_delay, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_dl_config_earliest_arrival, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_tx_request_earliest_arrival, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_ul_config_earliest_arrival, tvb, &offset, 0);
			proto_tree_add_uint32(msg_tree, hf_nfapi_timing_info_hi_dci0_earliest_arrival, tvb, &offset, 0);
			break;
		}
		default:
		{
			// todo : is this vendor extention?
			break;
		}
	};

	return tvb_captured_length(tvb);
}

static void nfapi_tag_vals_fn(gchar* s, guint32 v)
{
	int index = look_up_tlv(v);
	if (v >= 0)
	{
		g_snprintf(s, ITEM_LABEL_LENGTH, "%s (0x%x)", tags[index].name, v);
	}
	else
	{
		g_snprintf(s, ITEM_LABEL_LENGTH, "%s (0x%x)", "Unknown", v);
	}
}

// ----------------------------------------------------------------------------|

void proto_register_nfapi(void)
{

	static hf_register_info hf[] =
	{
		{ &hf_msg_fragments, { "Message fragments", "afs.fragments", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_fragment, { "Message fragment", "afs.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_fragment_overlap, { "Message fragment overlap", "afs.fragment.overlap", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_fragment_overlap_conflicts, { "Message fragment overlapping with conflicting data", "afs.fragment.overlap.conflicts", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_fragment_multiple_tails, { "Message has multiple tail fragments", "afs.fragment.multiple_tails", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_fragment_too_long_fragment, { "Message fragment too long", "afs.fragment.too_long_fragment", FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_fragment_error, { "Message defragmentation error", "afs.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_fragment_count, { "Message fragment count", "afs.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_reassembled_in, { "Reassembled in", "afs.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_reassembled_length, { "Reassembled length", "afs.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
		{ &hf_msg_reassembled_data, { "Reassembled data", "afs.reassembled.data", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
		{ &hf_nfapi_message_tree, { "Message tree", "nfapi.message_tree", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p4_p5_message_header, { "P4 P5 Header", "nfapi.p4_p5_message_header",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p4_p5_message_header_phy_id, { "PHY ID", "nfapi.p4_p5_message_header.phy_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p4_p5_message_header_message_id, { "Message ID", "nfapi.p4_p5_message_header.message_id", FT_UINT16, BASE_HEX_DEC, VALS(message_id_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_p4_p5_message_header_message_length, { "Message Length", "nfapi.p4_p5_message_header.message_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p4_p5_message_header_spare,	{ "Spare", "nfapi.p4_p5_message_header.spare", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header, { "P7 Header", "nfapi.p7_message_header", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_phy_id, { "Phy ID", "nfapi.p7_message_header.phy_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_message_id, { "Message ID", "nfapi.p7.message_header.message_id", FT_UINT16, BASE_HEX_DEC, VALS(message_id_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_message_length, { "Message Length", "nfapi.p7_message_header.message_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_m, { "M", "nfapi.p7_message_header.m_segment_sequence", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_segment, { "Segment Number", "nfapi.p7_message_header.m_segment_sequence", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_sequence_number, { "Sequence Number", "nfapi.p7_message_header.m_segment_sequence", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_checksum, { "Checksum", "nfapi.p7_message_header.checksum", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_p7_message_header_transmit_timestamp, { "Transmit Timestamp", "nfapi.p7_message_header.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tlv_tree, { "TAG", "nfapi.tlv.tree", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tl, { "TL", "nfapi.tl", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tl_tag, { "TL Tag", "nfapi.tl_tag", FT_UINT16, BASE_CUSTOM, CF_FUNC(nfapi_tag_vals_fn), 0x0, NULL, HFILL } },
		{ &hf_nfapi_tl_length, { "TL Length", "nfapi.tl_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tag_uint8_value, { "Value", "nfapi.tag.uint8.value", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tag_uint16_value, { "Value", "nfapi.tag.uint16.value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_param_response, { "Param Request", "nfapi.param.request", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_error_code, { "Error Code", "nfapi.error.code", FT_UINT8, BASE_DEC, VALS(nfapi_error_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_p4_error_code, { "Error Code", "nfapi.p4_error.code", FT_UINT8, BASE_DEC, VALS(nfapi_p4_error_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_rat_type, { "RAT Type", "nfapi.rat_type", FT_UINT8, BASE_DEC, VALS(nfapi_rat_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_num_tlv, { "Number of TLV", "nfapi.param.response.num_tlv", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_phy_state, { "Phy state value", "nfapi.phy.state", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_modulation_support,	{ "Modulation value", "nfapi.modulation.support", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_ue_per_sf, { "Downlink UEs per Subframe", "nfapi.dl.ue.per.sf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_ue_per_sf, { "Uplink UEs per Subframe", "nfapi.ul.ue.per.sf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_duplex_mode, { "Duplex Mode", "nfapi.duplex.mode", FT_UINT16, BASE_DEC, VALS(nfapi_duplex_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_bandwidth_support, { "Downlink bandwidth support", "nfapi.dl.bandwidth.support", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_bandwidth_support, { "Uplink bandwidth support", "nfapi.ul.bandwidth.support", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_modulation_support, { "Downlink modulation support", "nfapi.dl.modulation.support", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_modulation_support, { "Uplink modulation support", "nfapi.ul.modulation.support", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_phy_antenna_capability, { "Phy Antenna capability", "nfapi.phy.antenna.capability", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_release_capability, { "Release capability", "nfapi.release.capability", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mbsfn_capability, { "MBSFN capability", "nfapi.mbsfn.capability", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_laa_capability, { "LAA Support", "nfapi.laa.support", FT_BOOLEAN, 8, TFS(&support_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_pd_sensing_lbt_support, { "PD sensing LBT support", "nfapi.pd.sensing.lbt.support", FT_BOOLEAN, 8, TFS(&support_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_multi_carrier_lbt_support, { "Multi carrier LBT support", "nfapi.multi.carrier.lbt.support", FT_UINT16, BASE_DEC, VALS(nfapi_mutli_carrier_lbt_support_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_partial_sf_support, { "Partial SF support", "nfapi.partial.sf.support", FT_BOOLEAN, 8, TFS(&partial_sf_support_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_reference_signal_power, { "Reference signal power", "nfapi.ref_sig_power", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_primary_synchronization_signal_epre_eprers, { "Primary synchronization signal EPRE/EPRERS", "nfapi.primary.sync.signal", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_secondary_synchronization_signal_epre_eprers, { "Secondary synchronization signal EPRE/EPRERS", "nfapi.secondary.sync.signal", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_physical_cell_id, { "Physical Cell ID", "nfapi.physical.cell.id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_phich_resource, { "PHICH Resource", "nfapi.phich.resource", FT_UINT16, BASE_DEC, VALS(nfapi_phich_resource_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_phich_duration, { "PHICH Duration", "nfapi.phich.duration", FT_BOOLEAN, 8, TFS(&phich_duration_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_phich_power_offset, { "PHICH Power Offset", "nfapi.phich.power.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_configuration_index, { "Configuration Index", "nfapi.configuration.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_root_sequence_index, { "Root sequence Index", "nfapi.root.sequence.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_zero_correlation_zone_configuration, { "Zero correlation zone configuration", "nfapi.zero.correlation.zone.configuration", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_high_speed_flag, { "High Speed Flag", "nfapi.high.speed.flag", FT_BOOLEAN, 8, TFS(&high_speed_flag_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_frequency_offset, { "Frequency offset", "nfapi.frequency.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_hopping_mode, { "Hopping Mode", "nfapi.hopping.mode", FT_BOOLEAN, 8, TFS(&hopping_mode_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_hopping_offset, { "Hopping offset", "nfapi.hopping.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_delta_pucch_shift, { "Delta PUCCH Shift", "nfapi.delta.pucch.shift", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_cqi_rb, { "N CQI RB", "nfapi.n.cqi.rb", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_an_cs, { "N AN CS", "nfapi.n.an.cs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n1_pucch_an, { "N1 PUCCH AN", "nfapi.n1.pucch.an", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bandwidth_configuration, { "Bandwidth configuration", "nfapi.bw.configuration", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_subframe_configuration, { "SRS subframe configuration", "nfapi.srs.subframe.configuration", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_uplink_rs_hopping, { "Uplink RS hopping", "nfapi.uplink.rs.hopping", FT_UINT16, BASE_DEC, VALS(nfapi_uplink_rs_hopping_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_group_assignment, { "Group assigment", "nfapi.group.assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_cyclic_shift_1_for_drms, { "Cyclic Shift 1 for DRMS", "nfapi.cyclic.shift.1.for.drms", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_subframe_assignment, { "Subframe_assignment", "nfapi.subframe.assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_special_subframe_patterns, { "Special Subframe patterns", "nfapi.special.subframe.patterns", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ed_threshold_for_lbt_for_pdsch, { "ED Threshold for LBT for PDSCH", "nfapi.subframe.assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ed_threshold_for_lbt_for_drs, { "ED Threshold for LBT for DRS", "nfapi.subframe.assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pd_threshold, { "PD Threshold", "nfapi.subframe.assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_multi_carrier_type, { "Multi carrier type", "nfapi.subframe.assignment", FT_UINT16, BASE_DEC, VALS(nfapi_laa_carrier_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_multi_carrier_tx, { "Multi carrier TX", "nfapi.subframe.assignment", FT_BOOLEAN, 8, TFS(&nfapi_multi_carrier_tx_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_multi_carrier_freeze, { "Multi carrier freeze ", "nfapi.subframe.assignment", FT_BOOLEAN, 8, TFS(&nfapi_multi_carrier_freeze_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_tx_antenna_ports_for_drs, { "Tx antenna ports for DRS", "nfapi.subframe.assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transmission_power_for_drs, { "Transmission power for DRS", "nfapi.subframe.assignment", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pbch_repetitions_enabled_r13, { "PBCH Repetitions enable R13", "nfapi.pbch.repetitions.enabled_r13", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_cat_m_root_sequence_index, { "PRACH CAT-M Root sequence index", "nfapi.prach.cat_m.root.squence.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_cat_m_zero_correlation_zone_configuration, { "PRACH CAT-M Zero correlation zone configuration", "nfapi.prach.cat_m.zero.correlation.zone.configuration", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_cat_m_high_speed_flag, { "PRACH CAT-M High speed flag", "nfapi.prach.cat_m.high.speed.flag", FT_BOOLEAN, 8, TFS(&high_speed_flag_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_0_enable, { "PRACH CE level #0 Enable", "nfapi.prach.ce.level.0.enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_0_configuration_index, { "PRACH CE level #0 Configuration index", "nfapi.prach.ce.level.0.configuration.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_0_frequency_offset, { "PRACH CE level #0 Frequency offset", "nfapi.prach.ce.level.0.frequency_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_0_number_of_repetitions_per_attempt, { "PRACH CE level #0 Number of repetitions per attempt", "nfapi.prach.ce.level.0.number.of.repetitions.per_attempt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_0_starting_subframe_periodicity, { "CE level #0 Starting subframe periodicity", "nfapi.prach.ce.level.0.starting.subframe_periodicity", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_0_hopping_enabled, { "PRACH CE level #0 Hopping Enable", "nfapi.prach.ce.level.0.hopping_enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_0_hopping_offset, { "PRACH CE level #0 Hopping Offset", "nfapi.prach.ce.level.0.hopping.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_1_enable, { "PRACH CE level #1 Enable", "nfapi.prach.ce.level.0.enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_1_configuration_index, { "PRACH CE level #1 Configuration index", "nfapi.prach.ce.level.0.configuration.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_1_frequency_offset, { "PRACH CE level #1 Frequency offset", "nfapi.prach.ce.level.0.frequency_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_1_number_of_repetitions_per_attempt, { "PRACH CE level #1 Number of repetitions per attempt", "nfapi.prach.ce.level.0.number.of.repetitions.per_attempt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_1_starting_subframe_periodicity, { "CE level #1 Starting subframe periodicity", "nfapi.prach.ce.level.0.starting.subframe_periodicity", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_1_hopping_enabled, { "PRACH CE level #1 Hopping Enable", "nfapi.prach.ce.level.0.hopping_enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_1_hopping_offset, { "PRACH CE level #1 Hopping Offset", "nfapi.prach.ce.level.0.hopping.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_2_enable, { "PRACH CE level #2 Enable", "nfapi.prach.ce.level.0.enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_2_configuration_index, { "PRACH CE level #2 Configuration index", "nfapi.prach.ce.level.0.configuration.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_2_frequency_offset, { "PRACH CE level #2 Frequency offset", "nfapi.prach.ce.level.0.frequency_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_2_number_of_repetitions_per_attempt, { "PRACH CE level #2 Number of repetitions per attempt", "nfapi.prach.ce.level.0.number.of.repetitions.per_attempt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_2_starting_subframe_periodicity, { "CE level #2 Starting subframe periodicity", "nfapi.prach.ce.level.0.starting.subframe_periodicity", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_2_hopping_enabled, { "PRACH CE level #2 Hopping Enable", "nfapi.prach.ce.level.0.hopping_enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_2_hopping_offset, { "PRACH CE level #2 Hopping Offset", "nfapi.prach.ce.level.0.hopping.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_3_enable, { "PRACH CE level #3 Enable", "nfapi.prach.ce.level.0.enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_3_configuration_index, { "PRACH CE level #3 Configuration index", "nfapi.prach.ce.level.0.configuration.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_3_frequency_offset, { "PRACH CE level #3 Frequency offset", "nfapi.prach.ce.level.0.frequency_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_3_number_of_repetitions_per_attempt, { "PRACH CE level #3 Number of repetitions per attempt", "nfapi.prach.ce.level.0.number.of.repetitions.per_attempt", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_3_starting_subframe_periodicity, { "CE level #3 Starting subframe periodicity", "nfapi.prach.ce.level.0.starting.subframe_periodicity", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_3_hopping_enabled, { "PRACH CE level #3 Hopping Enable", "nfapi.prach.ce.level.0.hopping_enable", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_ce_level_3_hopping_offset, { "PRACH CE level #3 Hopping Offset", "nfapi.prach.ce.level.0.hopping.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pucch_internal_ul_hopping_config_common_mode_a, { "PUCCH Interval-ULHoppingConfigCommonModeA", "nfapi.pucch.interval.ulhopping.config.common.mode.a", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pucch_internal_ul_hopping_config_common_mode_b, { "PUCCH Interval-ULHoppingConfigCommonModeB", "nfapi.pucch.interval.ulhopping.config.common.mode.b", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_data_report_mode, { "Data Report Mode", "nfapi.data.report.mode", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sfnsf, { "SFN/SF", "nfapi.sfn.sf", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_max_up_pts, { "Max UpPTS frames", "nfapi.max.uppts.frame", FT_BOOLEAN, 8, TFS(&enabled_disabled_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_acknack_srs_simultaneous_transmission, { "SRS AckNack Simultaneous transmission", "nfapi.srs.acknack.simult.tx", FT_BOOLEAN, 8, TFS(&srs_simult_tx_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_address, { "PNF address", "nfapi.p7.pnf.address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_address_ipv4, { "PNF IPV4", "nfapi.pnf.address.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_address_ipv6, { "PNF IPV6", "nfapi.pnf.address.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_vnf_address, { "VNF address", "nfapi.vnf.address", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_vnf_address_ipv4, { "VNF IPV4 Address", "nfapi.vnf.address.ipv4", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_vnf_address_ipv6, { "VNF IPV6 Address", "nfapi.vnf.address.ipv6", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_port, { "PNF PORT value", "nfapi.config.pnf.port.value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_vnf_port, { "VNF PORT value", "nfapi.config.vnf.port.value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rf_bands, { "RF Bands", "nfapi.rf.bands", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rf_bands_count,	{ "Number of RF Bands", "nfapi.rf.bands.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rf_bands_value, { "Band value", "nfapi.rf.bands.value",	FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_param_request, { "PNF Param Request", "nfapi.pnf.param.request", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_param_response, { "PNF Param Response", "nfapi.pnf.param.response",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_config_request,	{ "PNF Config Request", "nfapi.pnf.config.request",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_config_response, { "PNF Config Response", "nfapi.pnf.config.response", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_start_request, { "PNF Start Request", "nfapi.pnf.start.request", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_start_response, { "PNF Start Response", "nfapi.pnf.start.response", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_start_request, { "PNF Start Request", "nfapi.start.request", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_start_response, { "PNF Start Response", "nfapi.start.response", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_param_general, { "PNF Param General ", "nfapi.pnf.param.general", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sync_mode, { "Sync Mode", "nfapi.sync.mode", FT_UINT8, BASE_DEC, VALS(nfapi_sync_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_location_mode, { "Location Mode", "nfapi.location.mode", FT_UINT8, BASE_DEC, VALS(location_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_location_coordinates_length, { "Location Coordinates Length", "nfapi.location.coordinates.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_location_coordinates, { "Location Coordinates", "nfapi.location.coordinates", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdu, { "PDU", "nfapi.pdu", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_timing, { "DL config Timing", "nfapi.dl.config.timing", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tx_timing, { "Tx Timing", "nfapi.general.tx.timing", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_timing, { "UL Config Timing", "nfapi.ul.config.timing", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_hi_dci0_timing, { "HI DCi0 Timing", "nfapi.hi.dci0.timing", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_number_phys, { "Maximum number of Phys", "nfapi.maximum.number.phys", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_total_bandwidth, { "Maximum Total Bandwidth", "nfapi.maximum.total.bandwidth", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_total_number_dl_layers,	{ "Maximum Total Number DL Layers", "nfapi.maximum.total.number.dl.layers", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_total_number_ul_layers,	{ "Maximum Total Number UL Layers", "nfapi.maximum.total.number.ul.layers",	FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_shared_bands, { "Shared bands", "nfapi.shared.bands", FT_BOOLEAN, 8, TFS(&true_false_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_shared_pa, { "Shared pa", "nfapi.shared.pa", FT_BOOLEAN, 8, TFS(&true_false_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_total_power, { "Maximum total power", "nfapi.maximum.total.power", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_oui, { "OUI", "nfapi.oui", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_phy, { "PNF Phy", "nfapi.pnf.phy", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_phy_number_phy, { "PNF Phy Number of Phy", "nfapi.pnf.phy.number.phy", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_phy_config_index, { "PNF Phy Config Index", "nfapi.pnf.phy.config.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_rf,	{ "PNF Phy RF", "nfapi.pnf.rf",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_rfs, { "Number of RFs", "nfapi.pnf.rf.number.rf",	FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_phy_rf_config_info,	{ "Phy RF Config Info", "nfapi.phy.rf.config.info",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_phy_rf_config_info_phy_id, { "Phy ID", "nfapi.pnf.phy.rf.config.phy.id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_phy_rf_config_info_band, { "RF Band", "nfapi.pnf.phy.rf.config.phy.id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_phy_rf_config, { "PNF Phy RF Config", "nfapi.pnf.phy.rf.config", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_phy_rf_config_number_phy_rf_config_info, { "Number of RF Config Info(s)", "nfapi.pnf.phy.rf.config.number.phy.rf.config.info", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_phy_rf_config_array_phy_rf_config_info,	{ "PNF Phy RF Config array phy rf config info ", "nfapi.pnf.phy.rf.config.array.phy.rf.config.info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rf_config_index, { "RF Config Index", "nfapi.rf_config_index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_rf_exclusions, { "Number of RF exclusions", "nfapi.hf_nfapi_number_of_rf_exclusions",	FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_3gpp_release_supported,	{ "Maximum 3gpp Release Supported", "nfapi.maximum_3gpp_release_supported",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_downlink_channel_bandwidth_supported, { "Maximum Channel Downlink Bandwidth Supported", "nfapi.downlink_channel_bandwidth_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_uplink_channel_bandwidth_supported, { "Maximum Channel Uplink Bandwidth Supported", "nfapi.uplink_channel_bandwidth_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_dl_layers_supported, { "Number of DL Layers Supported", "nfapi.number_of_dl_layer_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_ul_layers_supported, { "Number of UL Layers Supported", "nfapi.number_of_ul_layer_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_nmm_modes_supported, { "NMM modes supported", "nfapi.nmm_modes_supported", FT_UINT8, BASE_DEC, VALS(nmm_modes_supported_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_band, { "Band", "nfapi.band", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_transmit_power, { "Maximum transmit power", "nfapi.maximum_transmit_power", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_earfcn, { "EARFCN", "nfapi.earfcn", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_rf_bands, { "Number of RF Bands", "nfapi.num.rf_bands", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_nmm_uplink_rssi_supported, { "NMM Uplink RSSI supported", "nfapi.nmm.uplink.rssi.supported", FT_UINT16, BASE_DEC, VALS(ul_rssi_supported_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_minimum_transmit_power, { "Minimum transmit power", "nfapi.minimum_transmit_power", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_antennas_suppported, { "Number of Supported Antennas", "nfapi.number_of_antennas_suppported", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_minimum_downlink_frequency, { "Minimum downlink frequency", "nfapi.minimum_downlink_frequency", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_downlink_frequency, { "Maximum downlink frequency", "nfapi.maximum_downlink_frequency", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_minimum_uplink_frequency, { "Minimum uplink frequency", "nfapi.minimum_downlink_frequency", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_maximum_uplink_frequency, { "Maximum uplink frequency", "nfapi.maximum_downlink_frequency", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transmission_mode7_supported, { "Transmission Mode 7 Supported", "nfapi.pnf.phy_rel10.tx_mode7_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_transmission_mode8_supported, { "Transmission Mode 8 Supported", "nfapi.pnf.phy_rel10.tx_mode8_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_two_antennas_ports_for_pucch, { "Two antennas ports for PUCCH", "nfapi.pnf.phy_rel10.two_antennas_ports_for_pucch", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_transmission_mode_9_supported, { "Transmission Mode 9 Supported", "nfapi.pnf.phy_rel10.tx_mode9_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_simultaneous_pucch_pusch, { "Simultaneous PUCCH PUSCH", "nfapi.pnf.simultaneous_pucch_pusch", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_for_layer_tx_with_tm3_and_tm4, { "Four layer Tx with TM3 and TM4", "nfapi.pnf.phy_rel10.layer_tx_with_tm3_and_tm4", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_epdcch_supported, { "ePDCCH supported", "nfapi.pnf.phy_rel11.epdcch_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_multi_ack_csi_reporting, { "Multi ACK CSI reporting", "nfapi.pnf.phy_rel11.mutli_ack_csi_reporting", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_pucch_tx_diversity_with_channel_selection, { "PUCCH Tx diversity with channel selection", "nfapi.pnf.phy_rel11.tx_div_with_channel_selection", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_ul_comp_supported, { "UL CoMP supported", "nfapi.pnf.phy_rel11.ul_comp_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_transmission_mode_5_supported, { "Transmission mode 5 supported", "nfapi.pnf.phy_rel11.tx_mode5_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_subframe_set, { "CSI subframe set", "nfapi.pnf.phy_rel12.csi_subframe_set", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_enhanced_4tx_codebook, { "Enhanced 4TX codebook", "nfapi.pnf.phy_rel12.exhanced_t4x_codebook", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_drs_supported, { "DRS supported", "nfapi.pnf.phy_rel12.drs_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_ul_64qam_supported, { "UL 64QAM supported", "nfapi.pnf.phy_rel12.ul_64qam_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_transmission_mode_10_supported, { "Transmission mode 10 supported", "nfapi.pnf.phy_rel12.tx_mode10_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hi_nfapi_alternative_tbs_indices, { "Alternative TBS indices", "nfapi.pnf.phy_rel12.alternative_tbs_indices", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pucch_format_4_supported, { "PUCCH format 4 supported", "nfapi.pnf.phy_rel13.pucch_format4_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pucch_format_5_supported, { "PUCCH format 5 supported", "nfapi.pnf.phy_rel13.pucch_format5_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_more_than_5_ca_supported, { "More than 5 CA support", "nfapi.pnf.phy_rel13.mode_than_5_ca_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_laa_supported, { "LAA supported", "nfapi.pnf.phy_rel13.laa_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_laa_ending_in_dwpts_supported, { "LAA ending in DwPTS supported", "nfapi.pnf.phy_rel13.laa_ending_in_dwpts_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_laa_starting_in_second_slot_supported, { "LAA starting in second slot Supported", "nfapi.pnf.phy_rel13.laa_starting_in_second_slot_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_beamforming_supported, { "Beamforming Supported", "nfapi.pnf.phy_rel13.beamingforming_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_enhancements_supported, { "CSI-RS enhancements supported", "nfapi.pnf.phy_rel13.csi_rs_enchancements_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_drms_enhancements_supported, { "DMRS enhancements supported", "nfapi.pnf.phy_rel13.drms_enhancements_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_enhancements_supported, { "SRS enhancements supported", "nfapi.pnf.phy_rel13.srs_enhancements_supported", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sfn_sf, { "SFN_SF", "nfapi.sfn_sf", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_request_body, { "DL Config Request body", "nfapi.dl.config.request.body", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_pdcch_ofdm_symbols, { "Number of PDCCH OFDM Symbols", "nfapi.number_pdcch_ofdm_symbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_dci, { "Number of DCI", "nfapi.number_dci", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_pdus, { "Number of PDUs", "nfapi.number_pdu", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_harqs, { "Number of HARQs", "nfapi.number_harqs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_crcs, { "Number of CRCs", "nfapi.number_crcs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_srs, { "Number of SRs", "nfapi.number_srs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_cqi, { "Number of CQIs", "nfapi.number_cqi", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_preambles, { "Number of Preambles", "nfapi.number_preambles", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_srss, { "Number of SRSs", "nfapi.number_srss", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_lbt_dl_req_pdu_type, { "LBT DL Request PDU Type", "nfapi.number_srss", FT_UINT16, BASE_DEC, VALS(nfapi_lbt_dl_req_pdu_type), 0x0, NULL, HFILL } },
		{ &hf_nfapi_lbt_dl_ind_pdu_type, { "LBT DL Indication PDU Type", "nfapi.number_srss", FT_UINT16, BASE_DEC, VALS(nfapi_lbt_dl_ind_pdu_type), 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_pdsch_rnti, { "Number of PDSCH RNTI", "nfapi.number_pdsch_rnti", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transmission_power_pcfich, { "Transmission Power PCFICH", "nfapi.transmission_power_pcfich", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_request_pdu_list,	{ "DL Config Request body", "nfapi.dl.config.request.pdu_list",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_request_pdu_list,	{ "UL Config Request body", "nfapi.ul.config.request.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_hi_dci0_request_pdu_list, { "HI DCI0 Request body", "nfapi.hi.dci0.config.request.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tx_request_pdu_list, { "Tx Request body", "nfapi.tx.request.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rx_indication_pdu_list, { "Rx Indication body", "nfapi.rx.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_indication_pdu_list, { "Harq Indication body", "nfapi.harq.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_crc_indication_pdu_list, { "CRC Indication body", "nfapi.crc.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sr_indication_pdu_list, { "SR Indication body", "nfapi.sr.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_cqi_indication_pdu_list, { "CQI Indication body", "nfapi.cqi.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_preamble_indication_pdu_list, { "Preamble Indication body", "nfapi.preamble.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_indication_pdu_list, { "SRS Indication body", "nfapi.srs.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_lbt_dl_config_pdu_list, { "LBT DL Config Request body", "nfapi.lbt.dl.request.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_lbt_dl_indication_pdu_list, { "LBT DL Indicatoin body", "nfapi.lbt.dl.indication.pdu_list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_pdu_type, { "PDU Type", "nfapi.pdu.type",	FT_UINT8, BASE_DEC, VALS(nfapi_dl_config_pdu_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdu_size, { "PDU size", "nfapi.pdu.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_instance_length, { "Instance length", "nfapi.instance.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_dlsch_pdu_rel8, { "DL CONFIG DLSCH PDU REL8", "nfapi.dl.config.dlsch.pdu.rel8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_length, { "PDU length", "nfapi.pdu.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdu_index, { "PDU Index", "nfapi.pdu.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rnti, { "RNTI", "nfapi.rnti", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_resource_allocation_type, { "Resource Allocation Type", "nfapi.resource.allocation.type", FT_UINT8, BASE_DEC, VALS(resource_allocation_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_virtual_resource_block_assignment_flag, { "Virtual resource block assignment flag", "nfapi.resource.block.assignment.flag", FT_UINT8, BASE_DEC, VALS(local_distributed_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_resource_block_coding, { "Resource block coding", "nfapi.resource.block.coding", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_modulation, { "Modulation", "nfapi.modulation", FT_UINT8, BASE_DEC, VALS(modulation_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_redundancy_version, { "Redundancy version", "nfapi.redundancy.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transport_blocks, { "Transport blocks", "nfapi.transport.blocks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transport_block_to_codeword_swap_flag, { "Transport block to codeword swap flag", "nfapi.transport.block.to.codeword.swap.flag", FT_UINT8, BASE_DEC, VALS(transport_block_to_codeword_swap_flag_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_transmission_scheme, { "Transmission scheme", "nfapi.transmission.scheme", FT_UINT8, BASE_DEC, VALS(transmission_scheme_vals), 0x0, "The MIMO mode used in the PDU", HFILL } },
		{ &hf_nfapi_ul_transmission_scheme, { "Transmission scheme", "nfapi.transmission.scheme", FT_UINT8, BASE_DEC, VALS(ul_transmission_scheme_vals), 0x0, "The MIMO mode used in the PDU", HFILL } },
		{ &hf_nfapi_number_of_layers, { "Number of layers", "nfapi.number.of.layers", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_subbands, { "Number of subbands", "nfapi.number.of.subbands", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_codebook_index, { "Codebook index", "nfapi.number.of.codebook.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ue_category_capacity, { "UE category capacity", "nfapi.ue.category.capacity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pa, { "P-A", "nfapi.pa", FT_UINT8, BASE_DEC, VALS(pa_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_delta_power_offset_index, { "Delta Power offset index", "nfapi.delta.power.offset.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_nprb, { "Nprb", "nfapi.nprb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transmission_mode, { "Transmission Mode", "nfapi.transmission_nprb", FT_UINT8, BASE_DEC, VALS(transmission_mode_vals), 0x0, "Transmission mode associated with the UE", HFILL } },
		{ &hf_nfapi_prnti, { "P-RNTI", "nfapi.prnti", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mcs, { "MCS", "nfapi.mcs", FT_UINT8, BASE_DEC, VALS(pch_modulation_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_transport_blocks, { "Number of transport blocks", "nfapi.number_of_transport_blocks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ue_mode, { "UE Mode", "nfapi.ue.mode", FT_UINT8, BASE_DEC, VALS(ue_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_prs_bandwidth, { "PRS bandwidth", "nfapi.prs.bandwidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_prs_cyclic_prefix_type, { "PRS cyclic prefix type", "nfapi.prs.cyclic.prefix.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_prs_muting, { "PRS muting", "nfapi.prs.muting", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_num_bf_prb_per_subband, { "Num of BF PRB per Subband", "nfapi.num.bf.prb.per.subband", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_num_bf_vector, { "Num of BF Vector", "nfapi.num.bf.vector", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_resource_config, { "CSI-RS resource config", "nfapi.csi.rs.resource.config", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bf_vector_subband_index, { "BF Subband Index", "nfapi.num.bf.vector.subband.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bf_vector_num_antennas, { "BF Num of Antennas", "nfapi.num.bf.vector.bf.value", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bf_vector_bf_value, { "BF Value per Antenna", "nfapi.num.bf.vector.bf.value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_dlsch_pdu_rel9, { "DL CONFIG DLSCH PDU REL9", "nfapi.dl.config.dlsch.pdu.rel9", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_nscid, { "NSC id", "nfapi.nscid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_dlsch_pdu_rel10, { "DL CONFIG DLSCH PDU REL10", "nfapi.dl.config.dlsch.pdu.rel10", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_flag, { "CSI RS Flag", "nfapi.csi.rs.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_subbands, { "Subbands", "nfapi.subbands", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bf_vectors, { "BF Vectors", "nfapi.bf.vectors", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bf_vector_antennas, { "Antennas", "nfapi.antennas", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_resource_config_r10, { "CSI RS resource config R10", "nfapi.csi.rs.resource_config_r10", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_zero_tx_power_resource_config_bitmap_r10, { "CSI-RS Number of NZP configuration", "nfapi.csi.rs.num.of.nzp.configurations",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_number_if_nzp_configurations, { "CSI RS zero Tx Power Resource config bitmap R10", "nfapi.csi.rs.zero.tx.power.resource.config.bitmap.r10", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_resource_configs, { "CSR/RS Resource Configs", "nfapi.csi.rs.resource.configs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdsch_start, { "PDSCH_start", "nfapi.pdsch.start", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_drms_config_flag, { "DMRS Config flag", "nfapi.drms.config.flag", FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_drms_scrambling, { "DMRS Scrambling", "nfapi.drms.scrambling", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_config_flag, { "CSI Config flag", "nfapi.csi.config.flag", FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_scrambling, { "CSI Scrambling", "nfapi.csi.scrambling", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdsch_re_mapping_flag, { "PDSCH RE mapping flag", "nfapi.pdsch.remapping.flag", FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdsch_re_mapping_antenna_ports, { "PDSCH RE mapping antenna ports", "nfapi.pdsch.remapping.antenna.ports", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdsch_re_mapping_freq_shift, { "PDSCH RE mapping freq shift", "nfapi.pdsch.remapping.freq.shift", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_alt_cqi_table_r12, { "altCQI-Table-r12", "nfapi.alt.cqi.table.r12", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_max_layers, { "MaxLayers", "nfapi.max.layers", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_dl_harq, { "N_DL_HARQ", "nfapi.n.dl.harq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dwpts_symbols, { "DwPTS Symbols", "nfapi.dwpts.symbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_initial_lbt_sf, { "Initial LBT SF", "nfapi.initial.lbt.sf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ue_type, { "UE Type", "nfapi.ue.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdsch_payload_type, { "PDSCH Payload Type", "nfapi.pdsch.payload.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_initial_transmission_sf, { "Initial transmission SF (io) ", "nfapi.init.tx.sf.io", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_req13_drms_table_flag, { "Rel-13-DMRS-tabe flag", "nfapi.r13.drms.table.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_resource_index, { "CSI-RS resource index", "nfapi.csi.rs.resource.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_class, { "Class", "nfapi.csi.rs.class", FT_UINT8, BASE_DEC, VALS(csi_rs_class_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_cdm_type, { "CDM Type", "nfapi.cdm.type", FT_UINT8, BASE_DEC, VALS(csi_rs_cdm_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_bf_vector, { "BF Vector", "nfapi.bf.vector", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_edpcch_prb_index, { "EPDCCH PRB index", "nfapi.edpcch.prb.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_epdcch_resource_assignment_flag, { "EPDCCH Resource assignment flag", "nfapi.epdcch.resource.assignment.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_epdcch_id, { "EPDCCH ID", "nfapi.epdcch.id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_epdcch_start_symbol, { "EPDCCH Start Symbol", "nfapi.epdcch.start.symbol", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_epdcch_num_prb, { "EPDCCH NumPRB", "nfapi.epdcch.num.prb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_epdcch_prbs, { "EPDCCH PRBs", "nfapi.epdcch.prbs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_precoding_value, { "Precoding value", "nfapi.precoding.value", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mpdcch_narrowband, { "MPDCCH Narrowband", "nfapi.mpdcch.narrowband", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_prb_pairs, { "Number of PRB pairs", "nfapi.number.prb.pairs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_resource_block_assignment, { "Resource Block Assignment", "nfapi.resource.block.assignement", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_start_symbol, { "Start symbol", "nfapi.start.symbol", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ecce_index, { "ECCE index", "nfapi.ecce.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ce_mode, { "Rel-13-DMRS-tabe flag", "nfapi.r13.drms.table.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_drms_scrabmling_init, { "DMRS scrambling init", "nfapi.drms.scrambling.init", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdsch_reception_levels, { "PDSCH repetition levels", "nfapi.pdsch.repetition.levels", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_new_data_indicator, { "New data indicator", "nfapi.new.data.indicator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tpmi_length, { "TPMI length", "nfapi.tpmi.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pmi_flag, { "PMI flag", "nfapi.pmi.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_resource_offset, { "HARQ resource offset", "nfapi.harq.resource.offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dci_subframe_repetition_number, { "DCI subframe repetition number", "nfapi.dci.subframe.repetition.number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_downlink_assignment_index_length, { "Downlink assignment index Length", "nfapi.dl.assignement.index.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_starting_ce_level, { "Starting CE Level", "nfapi.starting.ce.level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_antenna_ports_and_scrambling_identity_flag, { "Antenna ports and scrambling identity flag", "nfapi.antenna.ports.and.scrambling.identity.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_antenna_ports_and_scrambling_identity, { "Antenna ports and scrambling identity", "nfapi.antenna.ports.and.scrambling.identit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_paging_direct_indication_differentiation_flag, { "Paging/Direct indication differentiation flag", "nfapi.paging.direct.indictation.differentiation.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_direct_indication, { "Direct indication", "nfapi.direct.indication", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_tx_antenna_ports, { "Number of TX Antenna ports", "nfapi.num.of.tx.antenna.ports.", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_precoding, { "Precoding", "nfapi.precodiing", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_bch_pdu_rel8, { "DL CONFIG BCH PDU Rel8", "nfapi.dl.config.bch.pdu.rel8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_value_float, { "Value", "nfapi.value.float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transmission_power, { "Transmission Power", "nfapi.transmission_power", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_mch_pdu_rel8, { "DL CONFIG MCH PDU Rel8", "nfapi.dl.config.mch.pdu.rel8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mbsfn_area_id, { "MBSFN Area id", "nfapi.mbsfn.area.id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_pch_pdu_rel8, { "DL CONFIG MCH PDU Rel8", "nfapi.dl.config.mch.pdu.rel8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_dci_dl_pdu_rel8, { "DL CONFIG DCI DL PDU Rel8", "nfapi.dl.config.mch.pdu.rel8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dci_format, { "DCI format", "nfapi.dci.format", FT_UINT8, BASE_DEC, VALS(dci_format_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_cce_idx, { "CCE index", "nfapi.cce.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_aggregation_level, { "Aggregation level", "nfapi.aggregation.level", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mcs_1, { "MCS_1", "nfapi.mcs_1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mcs_2, { "MCS_2", "nfapi.mcs_2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_redundancy_version_1, { "Redundancy version_1", "nfapi.redundancy.version.1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_redundancy_version_2, { "Redundancy version_2", "nfapi.redundancy.version.2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_new_data_indicator_1, { "New data indicator_1", "nfapi.new.data.indicator.1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_new_data_indicator_2 ,{ "New data indicator_2", "nfapi.new.data.indicator.2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_process, { "HARQ process", "nfapi.harq.process", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tpmi, { "TPMI", "nfapi.tpmi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pmi, { "PMI", "nfapi.pmi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_precoding_information, { "Precoding information", "nfapi.precoding.information", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tpc, { "TPC", "nfapi.tpc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_downlink_assignment_index, { "Downlink assignment index", "nfapi.downlink.assignment.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ngap, { "Ngap", "nfapi.ngap", FT_UINT8, BASE_DEC, VALS(ngap_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_transport_block_size_index, { "Transport block size index", "nfapi.transport.block.size.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_downlink_power_offset, { "Downlink power offset", "nfapi.downlink.power.offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_allocate_prach_flag, { "Allocation PRACH flag", "nfapi.allocation.prach.flag", FT_UINT8, BASE_DEC, VALS(true_false_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_preamble_index, { "Preamble index", "nfapi.preamable.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prach_mask_index, { "PRACH mask index", "nfapi.prach.mask.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rnti_type, { "RNTI type", "nfapi.rnti.type", FT_UINT8, BASE_DEC, VALS(rnti_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_dci_dl_pdu_rel9, { "DL CONFIG DCI DL PDU Rel9", "nfapi.dl.config.mch.pdu.rel9", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mcch_flag, { "MCCH flag", "nfapi.mcch.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mcch_change_notification, { "MCCH change notification", "nfapi.mcch.change.notification", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_scrambling_identity, { "Scrambling identity", "nfapi.scrambling.identity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_dci_dl_pdu_rel10, { "DL CONFIG DCI DL PDU Rel10", "nfapi.dl.config.mch.pdu.rel10", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_cross_carrier_scheduling_flag, { "Cross Carrier scheduling flag", "nfapi.cross.carrier.scheduling.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_carrier_indicator, { "Carrier Indicator", "nfapi.carrier.indicator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_flag, { "SRS flag", "nfapi.srs.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_request, { "SRS request", "nfapi.srs.request", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_antenna_ports_scrambling_and_layers, { "Antenna ports scrambling and layers", "nfapi.antenna.ports.scrambling.and.layers", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_total_dci_length_including_padding, { "Total DCI length including padding", "nfapi.total.dci.length.including.padding", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_dl_rb, { "N_DL_RB", "nfapi.n.dl.rb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_ul_rb, { "N_UL_RB", "nfapi.n.dl.rb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_ack_resource_offset, { "HARQ-ACK resource offset", "nfapi.harq.ack.resource.offset", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdsch_re_mapping_and_quasi_co_location_indicator, { "PDSCH RE Mapping and Quasi-Co-Location Indicator", "nfapi.pdsch.re.mapping", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_primary_cell_type, { "Primary cell type", "nfapi.primary.cell.type", FT_UINT8, BASE_DEC, VALS(primary_cells_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_dl_configuration_flag, { "UL/DL configuration flag", "nfapi.ul.dl.configuration.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_ul_dl_configurations, { "Number of UL/DL configurations", "nfapi.number.ul.dl.configurations", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_dl_configuration_index, { "UL/DL configuration indication", "nfapi.ul.dl.configuration.indication", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_laa_end_partial_sf_flag, { "LAA end partial SF flag", "nfapi.laa.end.partial.sf.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_laa_end_partial_sf_configuration, { "LAA end partial SF configuration", "nfapi.laa.end.partial.sf.configuration", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_codebooksize_determination_r13, { "Codebook Size Determination R13", "nfapi.codebook.size.determination.r13", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rel13_drms_table_flag, { "Rel-13-DMRS-tabe flag", "nfapi.drms.table.flag.r13", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pscch_resource, { "PSCCH Resource", "nfapi.pscch.resource", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_time_resource_pattern, { "Time resource pattern", "nfapi.time.resource.pattern", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mpdcch_transmission_type, { "MPDCCH transmission type", "nfapi.mpdcch.transmission.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_drms_scrambling_init, { "DMRS scrambling init", "nfapi.drms.scrambling.init", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pusch_repetition_levels, { "PUSCH repetition levels", "nfapi.pusch.repetition.levels", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_frequency_hopping_flag, { "Frequency hopping flag", "nfapi.frequency.hopping.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_request, { "CSI request", "nfapi.csi.request", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dai_presence_flag, { "DAI presence flag", "nfapi.dia.presence.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_total_dci_length_include_padding, { "Total DCI length including padding", "nfapi.total.dci.length.including.padding", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_prs_pdu_rel9, { "DL CONFIG PRS PDU Rel9", "nfapi.dl.config.prs.pdu.rel9", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prs_bandwidth, { "PRS Bandwidth", "nfapi.prs.bandwidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_prs_cyclic_prefix_type, { "PRS cyclic prefix type", "nfapi.prs.cyclic.prefix.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_config_csi_rs_pdu_rel10, { "DL CONFIG CSI RS PDU Rel10", "nfapi.dl.config.csi.rs.pdu.rel10", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_rs_antenna_port_count_r10, { "Antenna port count r10", "nfapi.csi.rs.antenna.port.count.r10", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_request_body, { "UL Config Request body", "nfapi.ul.config.request.body", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_pdu_type,	{ "UL Config PDU Type", "nfapi.ul.config.pdu.type", FT_UINT8, BASE_DEC, VALS(nfapi_ul_config_pdu_type_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_rach_prach_frequency_resources,	{ "RACH PRACH Frequency resources", "nfapi.rach.prach.frequency.resources",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_present, { "SRS present", "nfapi.srs.present", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_harq_buffer_pdu, { "HARQ Buffer PDU", "nfapi.ul.config.harq.buffer.pdu", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_ue_information_rel8, { "UE Information Rel 8", "nfapi.ul.config.ue.information.pdu.rel8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_handle,	{ "Handle", "nfapi.handle",	FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_sr_information_pdu_rel8, { "SR Information Rel 8", "nfapi.ul.config.sr.information.pdu.rel8",	FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pucch_index, { "PUCCH Index", "nfapi.pucch.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_size, { "Size", "nfapi.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_resource_block_start, { "Resource block start", "nfapi.resource.block.start", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_resource_blocks, { "Number of resource blocks", "nfapi.resource.blocks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_cyclic_shift_2_for_drms, { "Cyclic Shift 2 for DRMS", "nfapi.cyclic.shift.2.for.drms", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_frequency_hopping_enabled_flag, { "Frequency hopping enabled flag", "nfapi.frequency.hopping.enabled.flag", FT_UINT8, BASE_DEC, VALS(hopping_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_frequency_hopping_bits, { "Frequency hopping bits", "nfapi.frequency.hopping.bits", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_new_data_indication, { "New Data inidication", "nfapi.new.data.indication", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_process_number, { "HARQ Process number", "nfapi.harq.process.number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_tx_mode, { "UL Tx Mode", "nfapi.ul.tx.mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_current_tx_nb, { "Current Tx nb", "nfapi.current.tx.nb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_srs, { "N SRS", "nfapi.n.srs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_disable_sequence_hopping_flag, { "Disable seqeunce hopping flag", "nfapi.disable.sequence.hopping.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_virtual_cell_id_enabled_flag, { "Virtual cell ID enabled flag", "nfapi.virtual.cell.id.enabled.flag", FT_UINT8, BASE_DEC, VALS(not_used_enabled_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_npusch_identity, { "nPUSCH Identity", "nfapi.npusch.identity", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ndrms_csh_identity, { "nDMRS-CSH Identity", "nfapi.ndrms.csh.identity", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_total_number_of_repetitions, { "Total Number of repetitions", "nfapi.total.number.of.repetitions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_repetition_number, { "Repetition Number", "nfapi.repetition.number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_initial_sf_io, { "Initial transmission SF (io) ", "nfapi.initial.sf.io", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_empty_symbols_due_to_retunning, { "Empy symbols due to re-tunning", "nfapi.empty.symbols.due.to.retunning", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_cqi_ri_pmi_size_2, { "DL CQI/PMI/RI size 2", "nfapi.dl.cqi.ri.pmi.size.2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_size_2, { "HARQ Size 2", "nfapi.harq.size2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_delta_offset_harq_2, { "Delta Offset HARQ 2", "nfapi.delta.offset.harq.2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_starting_prb, { "Starting PRB", "nfapi.starting.prb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_antenna_port, { "Antenna Port", "nfapi.antenna.port", FT_UINT8, BASE_DEC, VALS(antenna_ports_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_combs, { "Number of Combs", "nfapi.num.of.combs", FT_UINT8, BASE_DEC, VALS(combs_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_npucch_identity, { "nPUCCH Identity", "nfapi.npucch.identity", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_empty_symbols, { "Empty symbols", "nfapi.empty.symbols", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_csi_mode, { "CSI_mode", "nfapi.csi.mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_cqi_pmi_size_2, { "DL CQI/PMI Size 2", "nfapi.dl.cqi.pmi.size.2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_statring_prb, { "Starting PRB", "nfapi.starting.prb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_cdm_index, { "cdm_Index", "nfapi.cdm.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_nsrs, { "N srs", "nfapi.n.srs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_num_ant_ports, { "Num_ant_ports", "nfapi.num.ant.port", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_2_0, { "n_PUCCH_2_0", "nfapi.n.pucch.2.0", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_2_1, { "n_PUCCH_2_1", "nfapi.n.pucch.2.1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_2_2, { "n_PUCCH_2_2", "nfapi.n.pucch.2.2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_2_3, { "n_PUCCH_2_3", "nfapi.n.pucch.2.3", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_cqi_pmi_size_rank_1, { "DL CQI PMI size rank 1", "nfapi.dl.cqi.pmi.size.rank.1",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_cqi_pmi_size_rank_greater_1,	{ "DL CQI PMI size rank greater 1", "nfapi.dl.cqi.pmi.size.rank.1",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ri_size, { "RI size", "nfapi.ri.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_delta_offset_cqi, { "Delta offset cqi", "nfapi.delta.offset.cqi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_delta_offset_ri, { "Delta offset ri", "nfapi.delta.offset.ri", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_size, { "HARQ size", "nfapi.harq_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_delta_offset_harq, { "Delta offset HARQ", "nfapi.delta.offset.harq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ack_nack_mode, { "ACK NACK mode", "nfapi.ack.nack.mode", FT_UINT8, BASE_DEC, VALS(nfapi_ack_nack_mode_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_srs_initial, { "N srs initial", "nfapi.n.srs.initial", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_initial_number_of_resource_blocks, { "Initial number of resource blocks", "nfapi.initial.number.of.resource.blocks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_cqi_pmi_size, { "DL cqi pmi size", "nfapi.dl.cqi.pmi.size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_report_type, { "Report type", "nfapi.report.type", FT_BOOLEAN, 8, TFS(&nfapi_csi_report_type_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_cqi_ri_pmi_size,	{ "DL CQI RI PMI size", "nfapi.dl.cqi.ri.pmi.size",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_control_type, { "Control type", "nfapi.control.type", FT_BOOLEAN, 8, TFS(&nfapi_control_type_string_name), 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_cc, { "Number of cc", "nfapi.number.of.cc",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_pucch_resource, { "Number of PUCCH Resource", "nfapi.number.of.pucch.resource", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pucch_index_p1, { "PUCCH Index P1", "nfapi.pucch.index.p1", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_1_0, { "N PUCCH 1 0", "nfapi.n.pucch.1.0", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_1_1, { "N PUCCH 1 1", "nfapi.n.pucch.1.1", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_1_2, { "N PUCCH 1 2", "nfapi.n.pucch.1.2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_n_pucch_1_3, { "N PUCCH 1 3", "nfapi.n.pucch.1.3", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_bandwidth, { "SRS Bandwidth", "nfapi.srs.bandwidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_frequency_domain_position, { "Frequency Domain position", "nfapi.frequency.domain.position", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_srs_hopping_bandwidth, { "SRS hopping bandwidth", "nfapi.srs.hopping.bandwidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_transmission_comb, { "Transmission comb", "nfapi.transmission.comb", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_i_srs, { "I SRS", "nfapi.i.srs", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sounding_reference_cyclic_shift, { "Sounding reference cyclic shift", "nfapi.sounding.reference.cyclic.shift", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_antenna_ports, { "Antenna port(s)", "nfapi.antenna.port", FT_UINT8, BASE_DEC, VALS(nfapi_antenna_port_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_srs_pdu_rel10, { "SRS PDU Rel 10", "nfapi.srs.pdu.rel.10", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_srs_pdu_rel8, { "SRS PDU Rel 8", "nfapi.srs.pdu.rel.8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_harq_information_rel9_fdd, { "HARQ information Rel 9 FDD", "nfapi.harq.information.rel.9.fdd", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_harq_information_rel8_fdd, { "HARQ information Rel 8 FDD", "nfapi.harq.information.rel.8.fdd", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_harq_information_rel10_tdd, { "HARQ information Rel 10 TDD", "nfapi.harq.information.rel.10.tdd", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_sr_information_rel10, { "SR information Rel 10", "nfapi.sr.information.rel.10", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_sr_information_rel8, { "SR information Rel 8", "nfapi.sr.information.rel.8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_cqi_information_rel10, { "CQI information Rel 10", "nfapi.cqi.information.rel.10", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_cqi_information_rel8, { "CQI information Rel 8", "nfapi.cqi.information.rel.8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_initial_transmission_parameters_rel8, { "Initial transmission parameters Rel 8", "nfapi.initial.transmission.parameters.rel.8", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_config_ulsch_harq_information_rel10, { "HARQ Information Rel 10", "nfapi.harq.information.rel.10", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdu_length, { "PDU length", "nfapi.pdu.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_num_segments, { "Num segments", "nfapi.num.segments", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_segment_length, { "Segment length", "nfapi.segment.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_segment_data, { "Segment data", "nfapi.segment.data", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_crc_indication_body, { "CRC Indication Body", "nfapi.crc_indication_body", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_crc_flag, { "CRC flag", "nfapi.crc.flag", FT_BOOLEAN, 8, TFS(&crc_flag_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_hi_pdus, { "Number of HI Pdu's", "nfapi.number_of_hi_pdus", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_dci_pdus, { "Number of DCI Pdu's", "nfapi.number_of_dci_pdus", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pdu_type, { "PDU Type", "nfapi.pdu_type",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_hi_value, { "HI Value", "nfapi.hi_value", FT_BOOLEAN, 8, TFS(&hi_value_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_i_phich, { "i phich", "nfapi.i_phich", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_flag_tb2, { "Flag TB2", "nfapi.flag_tb2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_hi_value_2, { "HI Value 2", "nfapi.hi_value_2", FT_BOOLEAN, BASE_NONE, TFS(&hi_value_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_ue_tx_antenna_selection, { "UE Tx Antenna selection", "nfapi.ue_tx_antenna_selection", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_cqi_csi_request, { "cqi csi request", "nfapi.cqi_csi_request", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_index, { "UL index", "nfapi.ul_index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_assignment_index, { "DL Assignment index", "nfapi.dl_assignment_index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tpc_bitmap, { "TPC bitmap", "nfapi.tpc_bitmap", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_antenna_ports, { "Number of antenna ports", "nfapi.number.of.antenna.ports", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_size_of_cqi_csi_feild, { "Size of cqi csi feild", "nfapi.size.of.cqi.csi.feild", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_new_data_indication_two, { "New data indicatipon 2", "nfapi.new.data.indication.two", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_resource_allocation_flag, { "Resource allocation flag", "nfapi.resource.allocation.flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_node_sync, { "DL Node Sync", "nfapi.dl.node.sync", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_node_sync_t1, { "DL Node Sync t1", "nfapi.dl.node.sync.t1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_node_sync_delta_sfn_sf, { "DL Node Sync Delta SFN SF", "nfapi.dl.node.sync.delta_sfn_sf", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_dl_cyclic_prefix_type, { "DL Cyclic Prefix type", "nfapi.dl.cyclic.prefix.type", FT_BOOLEAN, 8, TFS(&cyclic_prefix_type_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_cyclic_prefix_type, { "UL Cyclic Prefix type", "nfapi.ul.cyclic.prefix.type", FT_BOOLEAN, 8, TFS(&cyclic_prefix_type_strname), 0x0, NULL, HFILL } },
		{ &hf_nfapi_downlink_channel_bandwidth, { "Downlink Channel Bandwidth", "nfapi.dl.channel.bandwidth", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_uplink_channel_bandwidth, { "Uplink Channel Bandwidth", "nfapi.ul.channel_bandwidth", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_tx_antenna_ports, { "Tx Antenna Ports", "nfapi.tx.antenna.ports", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rx_antenna_ports, { "Tx Antenna Ports", "nfapi.rx.antenna.ports", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_node_sync, { "UL Node Sync", "nfapi.ul.node.sync", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_node_sync_t1, { "UL Node Sync t1", "nfapi.ul.node.sync.t1", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_node_sync_t2, { "UL Node Sync t2", "nfapi.ul.node.sync.t2", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_node_sync_t3, { "UL Node Sync t3", "nfapi.ul.node.sync.t3", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pb, { "P-B", "nfapi.pb.allocation", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_last_sfn_sf, { "Last SFN/SF", "nfapi.timing.info.last.sfn.sf", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_time_since_last_timing_info, { "Time since last Timing Info", "nfapi.timing.info.time.since.last.timing.info", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_dl_config_jitter, { "DL Config Jitter", "nfapi.timing.info.dl.config.jitter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_tx_request_jitter, { "Tx Request Jitter", "nfapi.timing.info.tx.req.jitter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_ul_config_jitter, { "UL Config Jitter", "nfapi.timing.info.ul.config.jitter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_hi_dci0_jitter, { "HI_DCI0 Jitter", "nfapi.timing.info.hi.dci0.jitter", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_dl_config_latest_delay, { "DL Config Latest Delay", "nfapi.timing.info.dl.config.latest.delay", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_tx_request_latest_delay, { "Tx Request Latest Delay", "nfapi.timing.info.tx.request.latest.delay", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_ul_config_latest_delay, { "UL Config Latest Delay", "nfapi.timing.info.ul.config.latest.delay", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_hi_dci0_latest_delay, { "HI_DCI0 Latest Delay", "nfapi.timing.info.hi.dci0.latest.delay", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_dl_config_earliest_arrival, { "DL Config Earliest Arrival", "nfapi.timing.info.dl.config.earliest.arrival", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_tx_request_earliest_arrival, { "Tx Request Earliest Arrival", "nfapi.timing.info.tx.request.earliest.arrival", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_ul_config_earliest_arrival, { "UL Config Earliest Arrival", "nfapi.timing.info.ul.config.earliest.arrival", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_hi_dci0_earliest_arrival, { "HI_DCI0 Earliest Arrival", "nfapi.timing.info.hi.dci0.earliest.arrival", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pcfich_power_offset, { "PCFICH Power Offset", "nfapi.pcfich.power.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_window, { "NFAPI Timing window", "nfapi.timing.window", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_mode, { "Timing Info mode", "nfapi.timing.info.mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_info_period, { "Timing info period", "nfapi.timing.info.period", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_max_transmit_power, { "Max transmit power", "nfapi.max.transmit.power", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_uint8_tag, { "uint8 tag", "nfapi.uint8.tag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_uint16_tag, { "uint16 tag", "nfapi.uint16.tag", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_mode, { "Mode", "nfapi.harq.mode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_ack_nack,	{ "Number of ACK/NACK", "nfapi.uint16.tag",	FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_data_value_0,	{ "Value 0", "nfapi.harq.value.0",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_data_value_1,	{ "Value 1", "nfapi.harq.value.1",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_data_value_2,	{ "Value 2", "nfapi.harq.value.2",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_data_value_3,	{ "Value 3", "nfapi.harq.value.3",	FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_tb_1, { "HARQ TB1", "nfapi.harq.tb.", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_tb_2, { "HARQ TB2", "nfapi.harq.tb.2", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_tb_n, { "HARQ TB_N", "nfapi.harq.tb.n", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_cqi, { "UL_CQI", "nfapi.ul.cqi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_channel, { "Channel", "nfapi.channel", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_data_offset, { "Data Offset", "nfapi.data.offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },		
		{ &hf_nfapi_ri, { "RI", "nfapi.ri", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_ack_nack_data, { "HARQ Ack/Nack Data", "nfapi.harq.ack.nack.data", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_harq_data, { "HARQ TB Data", "nfapi.harq.tb.data", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_cc, { "CC", "nfapi.cc", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rbs, { "RBs", "nfapi.rbs", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_antennas, { "Physical Antennas", "nfapi.physical.antennas", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_advance, { "Timing Advance", "nfapi.timing.advance", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timing_advance_r9, { "Timing Advance R9", "nfapi.timing.advance.r9", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_cc_reported, { "Number of CC reported", "nfapi.number.of.cc.reported", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_preamble, { "Preamble", "nfapi.preamble", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rach_resource_type, { "RACH resource type", "nfapi.rach.resource.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_doppler_estimation, { "Doppler estimation", "nfapi.doppler.estimation", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rb_start, { "RB Start", "nfapi.rb.start", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_snr, { "SNR", "nfapi.snr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_up_pts_symbol, { "UpPTS Symbol", "nfapi.uppts.symbol", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_prb_per_subband, { "numPRBperSubband", "nfapi.num.prb.per.subband", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_antennas, { "numAntennas", "nfapi.num.antennas", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_subband_index, { "subbandIndex", "nfapi.subband.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_channel_coefficient, { "Channel", "nfapi.channel.coefficient", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_ul_rtoa, { "UL_RTOA", "nfapi.ul.rtoa", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_frequency_band_indicator, { "Frequency Band Indicator", "nfapi.frequency.band.indicator", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_measurement_period, { "Measurement Period", "nfapi.measurement.period", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bandwidth, { "Bandwidth", "nfapi.bandwidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_timeout, { "Timeout", "nfapi.timeout", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_earfcns, { "Number of EARFCNs", "nfapi.number.of.earfcns", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_earfcn_list, { "EARFCN List", "nfapi.earfcn.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_uarfcn, { "UARFCN", "nfapi.uarfcn", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_uarfcns, { "Number of UARFCNs", "nfapi.number.of.uarfcn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_uarfcn_list, { "UARFCN List", "nfapi.uarfcn.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_arfcn, { "ARFCN", "nfapi.arfcn", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_arfcn_direction, { "Direction", "nfapi.arfcn.direction", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_arfcns, { "Number of ARFCNs", "nfapi.number.of.arfcn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_arfcn_list, { "ARFCN List", "nfapi.arfcn.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rssi, { "RSSI", "nfapi.rssi", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_rssi, { "Number of RSSI", "nfapi.number.of.rssi", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rssi_list, { "RSSI List", "nfapi.rssi.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pci, { "PCI", "nfapi.pci", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_measurement_bandwidth, { "Measurement Bandwidth", "nfapi.measurement.bandwidth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_exhaustive_search, { "Exhaustive Search", "nfapi.exhaustive.search", FT_UINT8, BASE_DEC, VALS(exhustive_search_vals), 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_pci, { "Number of PCI", "nfapi.number.of.pci", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pci_list, { "PCI List", "nfapi.pci.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_psc, { "PSC", "nfapi.psc", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_psc, { "Number of PSC", "nfapi.number.of.psc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_psc_list, { "PCS List", "nfapi.psc.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rsrp, { "RSRP", "nfapi.rsrp", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rsrq, { "RSRQ", "nfapi.rsrq", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_lte_cells_found, { "Number of LTE Cells Found", "nfapi.number.of.lte.cells.found", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_lte_cells_found_list, { "LTE Cells Found List", "nfapi.lte.cells.found.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rscp, { "RSCP", "nfapi.rscp", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_enco, { "EcNo", "nfapi.ecno", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_utran_cells_found, { "Number of UTRAN Cells Found", "nfapi.number.of.utran.cells.found", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_utran_cells_found_list, { "UTRAN Cells Found List", "nfapi.utran.cells.found.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_bsic, { "BSIC", "nfapi.bsic", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rxlev, { "RxLev", "nfapi.rxlev", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_rxqual, { "RxQual", "nfapi.rxqual", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sfn_offset, { "SFN Offset", "nfapi.sfn.offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_geran_cells_found, { "Number of GSM Cells Found", "nfapi.number.of.geran.cells.found", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_geran_cells_found_list, { "GERAN Cells Found List", "nfapi.geran.cells.found.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_tx_antenna, { "Number of Tx Antenna", "nfapi.number.of.tx.antenna", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mib_length, { "MIB Length", "nfapi.mib.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_mib, { "MIB", "nfapi.mib", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_phich_configuration, { "PHICH Configuration", "nfapi.phich.configuration", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_retry_count, { "retryCount", "nfapi.retry.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sib1, { "SIB1", "nfapi.sib1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_si_periodicity, { "SI Periodicity", "nfapi.si.periodicity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_si_index, { "SI Index", "nfapi.si.index", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_number_of_si_periodicity, { "Number of SI Periodicity", "nfapi.number.of.si.periodicity", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_si_periodicity_list, { "SI Periodicity List", "nfapi.si.periodicity.list", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_si_window_length, { "SI Window Length", "nfapi.si.window.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sib_type, { "SIB Type", "nfapi.sib.type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sib_len, { "SIB Length", "nfapi.sib.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_sib, { "SIB", "nfapi.sib", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_si_len, { "SI Length", "nfapi.si.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_si, { "SI", "nfapi.si", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_search_state, { "State", "nfapi.state", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
		{ &hf_nfapi_pnf_broadcast_state, { "State", "nfapi.state", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

	};

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_nfapi_message_tree,
		&ett_nfapi_p4_p5_message_header,
		&ett_nfapi_p7_message_header,
		&ett_nfapi_tlv_tree,
		&ett_nfapi_tl,
		&ett_nfapi_pnf_param_response,
		&ett_nfapi_pnf_phy_rf_config,
		&ett_nfapi_pnf_phy_rf_config_instance,
		&ett_nfapi_pnf_phy,
		&ett_nfapi_pnf_phy_rel10,
		&ett_nfapi_pnf_phy_rel11,
		&ett_nfapi_pnf_phy_rel12,
		&ett_nfapi_pnf_phy_rel13,
		&ett_nfapi_pnf_rf,
		&ett_nfapi_phy_state,
		&ett_nfapi_rf_bands,
		&ett_nfapi_bf_vectors,
		&ett_nfapi_csi_rs_bf_vector,
		&ett_nfapi_csi_rs_resource_configs,
		&ett_nfapi_tx_antenna_ports,
		&ett_nfapi_harq_ack_nack_data,
		&ett_nfapi_harq_data,
		&ett_nfapi_cc,
		&ett_nfapi_rbs,
		&ett_nfapi_antennas,
		&ett_nfapi_epdcch_prbs,
		&ett_nfapi_dl_config_request_body,
		&ett_nfapi_dl_config_request_pdu_list,
		&ett_nfapi_ul_config_request_pdu_list,
		&ett_nfapi_hi_dci0_request_pdu_list,
		&ett_nfapi_tx_request_pdu_list,
		&ett_nfapi_rx_indication_pdu_list,
		&ett_nfapi_harq_indication_pdu_list,
		&ett_nfapi_crc_indication_pdu_list,
		&ett_nfapi_sr_indication_pdu_list,
		&ett_nfapi_cqi_indication_pdu_list,
		&ett_nfapi_preamble_indication_pdu_list,
		&ett_nfapi_srs_indication_pdu_list,
		&ett_nfapi_lbt_dl_config_pdu_list,
		&ett_nfapi_lbt_dl_indication_pdu_list,
		&ett_nfapi_dl_config_request_dlsch_pdu_rel8,
		&ett_nfapi_dl_config_request_dlsch_pdu_rel9,
		&ett_nfapi_dl_config_request_dlsch_pdu_rel10,
		&ett_nfapi_dl_config_bch_pdu_rel8,
		&ett_nfapi_dl_config_mch_pdu_rel8,
		&ett_nfapi_dl_config_pch_pdu_rel8,
		&ett_nfapi_dl_config_dci_dl_pdu_rel8,
		&ett_nfapi_dl_config_dci_dl_pdu_rel9,
		&ett_nfapi_dl_config_dci_dl_pdu_rel10,
		&ett_nfapi_dl_config_prs_pdu_rel9,
		&ett_nfapi_dl_config_csi_rs_pdu_rel10,
		&ett_nfapi_subbands,
		&ett_nfapi_precoding,
		&ett_nfapi_bf_vector_antennas,
		&ett_nfapi_ul_config_request_body,
		&ett_nfapi_ul_config_harq_buffer_pdu,
		&ett_nfapi_ul_config_ue_information_rel8,
		&ett_nfapi_ul_config_sr_information_pdu_rel8,
		&ett_nfapi_ul_config_ulsch_pdu_rel8,
		&ett_nfapi_ul_config_ulsch_pdu_rel10,
		&ett_nfapi_ul_config_cqi_ri_information_rel8,
		&ett_nfapi_ul_config_cqi_ri_information_rel9,
		&ett_nfapi_ul_config_ulsch_harq_information_rel10,
		&ett_nfapi_ul_config_initial_transmission_parameters_rel8,
		&ett_nfapi_ul_config_cqi_information_rel8,
		&ett_nfapi_ul_config_cqi_information_rel10,
		&ett_nfapi_ul_config_sr_information_rel8,
		&ett_nfapi_ul_config_sr_information_rel10,
		&ett_nfapi_ul_config_harq_information_rel10_tdd,
		&ett_nfapi_ul_config_harq_information_rel8_fdd,
		&ett_nfapi_ul_config_harq_information_rel9_fdd,
		&ett_nfapi_ul_config_srs_pdu_rel8,
		&ett_nfapi_ul_config_srs_pdu_rel10,
		&ett_nfapi_crc_indication_body,

		&ett_nfapi_earfcn_list,
		&ett_nfapi_uarfcn_list,
		&ett_nfapi_arfcn_list,
		&ett_nfapi_rssi_list,
		&ett_nfapi_pci_list,
		&ett_nfapi_psc_list,
		&ett_nfapi_lte_cells_found_list,
		&ett_nfapi_utran_cells_found_list,
		&ett_nfapi_geran_cells_found_list,
		&ett_nfapi_si_periodicity_list,

		/* for fragmentation support*/
		&ett_msg_fragment,
		&ett_msg_fragments
    };

    static ei_register_info ei[] = 
	{
		{ &ei_power_invalid, { "nfapi.power.invalid", PI_PROTOCOL, PI_ERROR, "Tx Power range invalid [0 - 10000]", EXPFILL } },
		{ &ei_ref_sig_power_invalid, { "nfapi.ref_sig_power.invalid", PI_PROTOCOL, PI_ERROR, "Ref Sig Power range invalid [0 - 255]", EXPFILL }},
		{ &ei_invalid_range, { "nfapi.invalid.range", PI_PROTOCOL, PI_ERROR, "Out of valid range. Todo create more specific error", EXPFILL } },
    };
	


    expert_module_t* expert_nfapi;

	/* Register protocol */
	proto_nfapi = proto_register_protocol("Nfapi", "NFAPI", "nfapi");

    expert_nfapi = expert_register_protocol(proto_nfapi);

    expert_register_field_array(expert_nfapi, ei, array_length(ei));

    proto_register_field_array(proto_nfapi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
	
	reassembly_table_register(&ul_p7_reassemble_table, &addresses_ports_reassembly_table_functions);
	reassembly_table_register(&dl_p7_reassemble_table, &addresses_ports_reassembly_table_functions);

	register_dissector("nfapi", dissect_nfapi, proto_nfapi);

}

// ----------------------------------------------------------------------------|

void proto_reg_handoff_nfapi(void)
{
	static dissector_handle_t nfapi_handle;

	nfapi_handle = create_dissector_handle(dissect_nfapi, proto_nfapi);

	dissector_add_for_decode_as("sctp.port", nfapi_handle);

	dissector_add_uint("udp.port", 41700, nfapi_handle);

}
