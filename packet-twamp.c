/* packet-twamp.c
 * Routines for TWAMP packet dissection
 *
 * Murat Demirten <murat@debian.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-bootp.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Documentation:
 * RFC 5357: A Two-Way Active Measurement Protocol (TWAMP)
 * RFC 5618: Mixed Security Mode for the TWAMP
 *           (not yet implemented)
 * RFC 5938: Individual Session Control Feature for the TWAMP
 *           (not yet implemented)
 * RFC 6038: TWAMP Reflect Octets and Symmetrical Size Features
 *           (not yet implemented)
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <inttypes.h>
#include <glib.h>

#define TWAMP_CONTROL_PORT 862
#define TWAMP_CONTROL_SERVER_GREETING_LEN 64
#define TWAMP_SESSION_ACCEPT_OK 0
/* Twamp times start from year 1900 */
#define TWAMP_BASE_TIME_OFFSET 2208988800u
#define TWAMP_FLOAT_DENOM 4294.967296

#define TWAMP_MODE_UNAUTHENTICATED	0x1
#define TWAMP_MODE_AUTHENTICATED	0x2
#define TWAMP_MODE_ENCRYPTED		0x4

enum twamp_control_state {
	CONTROL_STATE_UNKNOWN = 0,
	CONTROL_STATE_GREETING,
	CONTROL_STATE_SETUP_RESPONSE,
	CONTROL_STATE_SERVER_START,
	CONTROL_STATE_REQUEST_SESSION,
	CONTROL_STATE_ACCEPT_SESSION,
	CONTROL_STATE_START_SESSIONS,
	CONTROL_STATE_START_SESSIONS_ACK,
	CONTROL_STATE_TEST_RUNNING,
	CONTROL_STATE_STOP_SESSIONS,
	CONTROL_STATE_REQUEST_TW_SESSION
};
typedef struct _twamp_session {
	uint8_t accepted;
	int padding;
	uint16_t sender_port;
	uint16_t receiver_port;
	uint32_t sender_address[4];
	uint32_t receiver_address[4];
	uint8_t ipvn;
} twamp_session_t;

typedef struct twamp_control_packet {
	guint32 fd;
	enum twamp_control_state state;
	conversation_t *conversation;
} twamp_control_packet_t;

typedef struct twamp_control_transaction {
	enum twamp_control_state last_state;
	guint32 first_data_frame;
	GSList *sessions;
	proto_tree *tree;
} twamp_control_transaction_t;

static dissector_handle_t twamp_test_handle;
static dissector_handle_t twamp_control_handle;

/* Protocol enabled flags */
static int proto_twamp_test = -1;
static int proto_twamp_control = -1;
static gint ett_twamp_test = -1;
static gint ett_twamp_control = -1;

/* Twamp test fields */
static int twamp_seq_number = -1;
static int twamp_sender_timestamp = -1;
static int twamp_error_estimate = -1;
static int twamp_mbz1 = -1;
static int twamp_receive_timestamp = -1;
static int twamp_sender_seq_number = -1;
static int twamp_timestamp = -1;
static int twamp_sender_error_estimate = -1;
static int twamp_mbz2 = -1;
static int twamp_sender_ttl = -1;
static int twamp_padding = -1;

/* Twamp control fields */
static int twamp_control_unused		= -1;
static int twamp_control_command	= -1;
static int twamp_control_modes		= -1;
static int twamp_control_mode		= -1;
static int twamp_control_challenge	= -1;
static int twamp_control_salt		= -1;
static int twamp_control_count		= -1;
static int twamp_control_keyid		= -1;
static int twamp_control_sessionid	= -1;
static int twamp_control_iv			= -1;
static int twamp_control_ipvn		= -1;
static int twamp_control_start_time	= -1;
static int twamp_control_accept		= -1;
static int twamp_control_timeout	= -1;
static int twamp_control_type_p		= -1;
static int twamp_control_mbz1		= -1;
static int twamp_control_mbz2		= -1;
static int twamp_control_hmac		= -1;
static int twamp_control_num_sessions	= -1;
static int twamp_control_sender_port	= -1;
static int twamp_control_server_uptime	= -1;
static int twamp_control_receiver_port	= -1;
static int twamp_control_padding_length	= -1;
static int twamp_control_sender_ipv4	= -1;
static int twamp_control_sender_ipv6	= -1;
static int twamp_control_receiver_ipv4	= -1;
static int twamp_control_receiver_ipv6	= -1;

static int d1 = 0;
static int d2 = 0;

static const value_string twamp_control_accept_vals[] = {
	{ 0, "OK" },
	{ 1, "Failure, reason unspecified (catch-all)" },
	{ 2, "Internal error" },
	{ 3, "Some aspect of request is not supported" },
	{ 4, "Cannot perform request due to permanent resource limitations" },
	{ 5, "Cannot perform request due to temporary resource limitations" }
};

static const value_string twamp_control_command_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Forbidden" },
	{ 2, "Start-Sessions" },
	{ 3, "Stop-Sessions" },
	{ 4, "Reserved" },
	{ 5, "Request-TW-Session" },
	{ 6, "Experimentation" }
};

static gint find_twamp_session_by_sender_port (gconstpointer element, gconstpointer compared)
{
	uint16_t *sender_port = (uint16_t*) compared;
	twamp_session_t *session = (twamp_session_t*) element;
	return !(session->sender_port == *sender_port);
}

static gint find_twamp_session_by_first_accept_waiting (gconstpointer element)
{
	twamp_session_t *session = (twamp_session_t*) element;
	if (session->accepted == 0) return 0; else return 1;
}

static int get_twamp_time_from_packet (tvbuff_t *tvb, const gint offset, nstime_t *ts)
{
	ts->secs = tvb_get_ntohl(tvb, offset) - TWAMP_BASE_TIME_OFFSET;
	ts->nsecs = (tvb_get_ntohl(tvb, offset + 4) / TWAMP_FLOAT_DENOM) * 1000;
	return 0;
}

static int dissect_twamp_control (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	gboolean is_request;
	proto_item *ti = NULL;
	proto_item *twamp_tree = NULL;
	conversation_t *conversation = NULL;
	twamp_control_transaction_t *ct = NULL;
	twamp_control_packet_t *cp = NULL;
	twamp_session_t *session = NULL;
	uint8_t accept;
	uint16_t sender_port;
	uint16_t receiver_port;
	GSList *list;
	guint32 fd;
	int captured_length;

	offset = 0;
	captured_length = tvb_captured_length(tvb);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TWAMP-Control");

	if (pinfo->destport == TWAMP_CONTROL_PORT) {
		is_request = TRUE;
	} else {
		is_request = FALSE;
	}

	fd = PINFO_FD_NUM(pinfo);

	if (!pinfo->fd->flags.visited) {
		conversation = find_or_create_conversation(pinfo);
		ct = (twamp_control_transaction_t *) conversation_get_proto_data(conversation, proto_twamp_control);
		if (ct == NULL && is_request == FALSE && captured_length == TWAMP_CONTROL_SERVER_GREETING_LEN) {
			/* We got server greeting */
			if ((ct = wmem_new0(wmem_file_scope(), twamp_control_transaction_t)) == NULL) {
				return 0;
			}
			conversation_add_proto_data(conversation, proto_twamp_control, ct);
			ct->last_state = CONTROL_STATE_UNKNOWN;
			ct->first_data_frame = fd;
		}
		if ((cp = p_get_proto_data(wmem_file_scope(), pinfo, proto_twamp_control, 0)) == NULL) {
			cp = wmem_new0(wmem_file_scope(), twamp_control_packet_t);
			p_add_proto_data(wmem_file_scope(), pinfo, proto_twamp_control, 0, cp);
		}
		/* detect state */
		if (fd == ct->first_data_frame) {
			ct->last_state = CONTROL_STATE_GREETING;
		} else if (ct->last_state == CONTROL_STATE_GREETING) {
			ct->last_state = CONTROL_STATE_SETUP_RESPONSE;
		} else if (ct->last_state == CONTROL_STATE_SETUP_RESPONSE) {
			ct->last_state = CONTROL_STATE_SERVER_START;
		} else if (ct->last_state == CONTROL_STATE_SERVER_START) {
			ct->last_state = CONTROL_STATE_REQUEST_SESSION;
			sender_port = tvb_get_ntohs(tvb, 12);
			receiver_port = tvb_get_ntohs(tvb, 14);
			/* try to find session from past visits */
			if ((list = g_slist_find_custom(ct->sessions, &sender_port,
					(GCompareFunc) find_twamp_session_by_sender_port)) == NULL) {
				session = (twamp_session_t *) g_malloc0(sizeof(twamp_session_t));
				session->sender_port = sender_port;
				session->receiver_port = receiver_port;
				session->accepted = 0;
				uint8_t ipvn = tvb_get_guint8(tvb, 1) & 0x0F;
				if (ipvn == 6) {
					tvb_get_ipv6(tvb, 16, (struct e_in6_addr*) &session->sender_address);
					tvb_get_ipv6(tvb, 32, (struct e_in6_addr*) &session->receiver_address);

				} else {
					session->sender_address[0] = tvb_get_ipv4(tvb, 16);
					session->receiver_address[0] = tvb_get_ipv4(tvb, 32);
				}
				/*
				 * If ip addresses not specified in control protocol, we have to choose from IP header.
				 * It is a design decision by TWAMP and we need that ports for identifying future UDP conversations
				 */
				if (session->sender_address[0] == 0) {
					memcpy(&session->sender_address[0], pinfo->src.data, pinfo->src.len);
				}
				if (session->receiver_address[0] == 0) {
					memcpy(&session->receiver_address[0], pinfo->dst.data, pinfo->dst.len);
				}
				session->padding = tvb_get_ntohl(tvb, 64);
				ct->sessions = g_slist_append(ct->sessions, session);
			}
		} else if (ct->last_state == CONTROL_STATE_REQUEST_SESSION) {
			ct->last_state = CONTROL_STATE_ACCEPT_SESSION;
			accept = tvb_get_guint8(tvb, 0);
			if (accept == TWAMP_SESSION_ACCEPT_OK) {
				receiver_port = tvb_get_ntohs(tvb, 2);

				if ((list = g_slist_find_custom(ct->sessions, NULL,
						(GCompareFunc) find_twamp_session_by_first_accept_waiting)) == NULL) {
					return 0;
				}
				session = (twamp_session_t*) list->data;
				session->receiver_port = receiver_port;

				cp->conversation = find_conversation(pinfo->fd->num, &pinfo->dst, &pinfo->src, PT_UDP,
						session->sender_port, session->receiver_port, 0);
				if (cp->conversation == NULL || cp->conversation->dissector_handle != twamp_test_handle) {
					cp->conversation = conversation_new(pinfo->fd->num, &pinfo->dst, &pinfo->src, PT_UDP,
							session->sender_port, session->receiver_port, 0);
					if (cp->conversation) {
						/* create conversation specific data for test sessions */
						conversation_add_proto_data(cp->conversation, proto_twamp_test, session);
						conversation_set_dissector(cp->conversation, twamp_test_handle);
					}
				}
			}
		} else if (ct->last_state == CONTROL_STATE_ACCEPT_SESSION) {
			ct->last_state = CONTROL_STATE_START_SESSIONS;
		} else if (ct->last_state == CONTROL_STATE_START_SESSIONS) {
			ct->last_state = CONTROL_STATE_START_SESSIONS_ACK;
		} else if (ct->last_state == CONTROL_STATE_START_SESSIONS_ACK) {
			ct->last_state = CONTROL_STATE_STOP_SESSIONS;
		} else {
			/* response */
		}
		cp->state = ct->last_state;
		return captured_length;
	}

	if (tree) {
		proto_tree *it = proto_tree_add_item(tree, proto_twamp_control, tvb, 0, -1, ENC_NA);
		if ((cp = p_get_proto_data(wmem_file_scope(), pinfo, proto_twamp_control, 0)) == NULL) {
			return 0;
		}
		nstime_t ts;
		proto_item *time_item;
		proto_tree *item;
		uint32_t modes;
		switch (cp->state) {
		case CONTROL_STATE_GREETING:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Server Greeting");
			proto_tree_add_item(twamp_tree, twamp_control_unused, tvb, offset, 12, ENC_NA);
			offset += 12;
			modes = tvb_get_ntohl(tvb, offset) & 0x00000007;
			item = proto_tree_add_item(twamp_tree, twamp_control_modes, tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_item_append_text(item, " (%s%s%s)",
					(modes & TWAMP_MODE_UNAUTHENTICATED) ? " Unauthenticated " : "",
					(modes & TWAMP_MODE_AUTHENTICATED) ? "Authenticated " : "",
					(modes & TWAMP_MODE_ENCRYPTED) ? "Encrypted " : "");
			offset += 4;
			proto_tree_add_item(twamp_tree, twamp_control_challenge, tvb, offset, 16, ENC_NA);
			offset += 16;
			proto_tree_add_item(twamp_tree, twamp_control_salt, tvb, offset, 16, ENC_NA);
			offset += 16;
			proto_tree_add_item(twamp_tree, twamp_control_count, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(twamp_tree, twamp_control_mbz1, tvb, offset, 12, ENC_NA);
			offset += 12;
			break;

		case CONTROL_STATE_SETUP_RESPONSE:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Setup Response");
			proto_tree_add_item(twamp_tree, twamp_control_mode, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(twamp_tree, twamp_control_keyid, tvb, offset, 40, ENC_NA);
			offset += 40;
			break;
		case CONTROL_STATE_SERVER_START:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Server Start");
			proto_tree_add_item(twamp_tree, twamp_control_mbz1, tvb, offset, 15, ENC_NA);
			offset += 15;
			accept = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(twamp_tree, twamp_control_accept, tvb, offset, 1, accept);
			col_append_fstr(pinfo->cinfo, COL_INFO, ", (%s%s)",
					(accept == 0) ? "" : "Error: ", val_to_str(accept, twamp_control_accept_vals, "%u"));
			offset += 1;
			proto_tree_add_item(twamp_tree, twamp_control_iv, tvb, offset, 16, ENC_NA);
			offset += 16;

			get_twamp_time_from_packet(tvb, offset, &ts);
			time_item = proto_tree_add_time(twamp_tree, twamp_control_server_uptime, tvb, offset, 8, &ts);
			offset += 8;
			proto_tree_add_item(twamp_tree, twamp_control_mbz2, tvb, offset, 8, ENC_NA);

			break;
		case CONTROL_STATE_REQUEST_SESSION:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Request Session");
			proto_tree_add_item(twamp_tree, twamp_control_command, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			uint8_t ipvn = tvb_get_guint8(tvb, offset) & 0x0F;
			proto_tree_add_uint(twamp_tree, twamp_control_ipvn, tvb, offset, 1, ipvn);

			offset = 12;
			sender_port = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(twamp_tree, twamp_control_sender_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			receiver_port = tvb_get_ntohs(tvb, offset);
			proto_tree_add_item(twamp_tree, twamp_control_receiver_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			if (ipvn == 6) {
				proto_tree_add_item(twamp_tree, twamp_control_sender_ipv6, tvb, offset, 16, ENC_NA);
			} else {
				proto_tree_add_item(twamp_tree, twamp_control_sender_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			offset += 16;
			if (ipvn == 6) {
				proto_tree_add_item(twamp_tree, twamp_control_receiver_ipv6, tvb, offset, 16, ENC_NA);
			} else {
				proto_tree_add_item(twamp_tree, twamp_control_receiver_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
			}
			offset += 16;
			proto_tree_add_item(twamp_tree, twamp_control_sessionid, tvb, offset, 16, ENC_NA);
			offset += 16;

			proto_tree_add_item(twamp_tree, twamp_control_padding_length, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			get_twamp_time_from_packet(tvb, offset, &ts);
			time_item = proto_tree_add_time(twamp_tree, twamp_control_start_time, tvb, offset, 8, &ts);
			offset += 8;

			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = (tvb_get_ntohl(tvb, offset + 4) / TWAMP_FLOAT_DENOM);
			proto_tree_add_none_format(twamp_tree, twamp_control_timeout, tvb, offset, 8,
					"Timeout: %li.%06li Seconds", ts.secs, ts.nsecs);
			offset += 8;
			uint32_t type_p = tvb_get_ntohl(tvb, offset);
			item = proto_tree_add_item(twamp_tree, twamp_control_type_p, tvb, offset, 4, ENC_BIG_ENDIAN);
			proto_item_append_text(item, " (DSCP: %d)", type_p);
			offset += 4;
			break;
		case CONTROL_STATE_ACCEPT_SESSION:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Accept Session");
			accept = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(twamp_tree, twamp_control_accept, tvb, offset, 1, accept);
			col_append_fstr(pinfo->cinfo, COL_INFO, ", (%s%s)",
					(accept == 0) ? "" : "Error: ", val_to_str(accept, twamp_control_accept_vals, "%u"));
			offset = 2;
			proto_tree_add_item(twamp_tree, twamp_control_receiver_port, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(twamp_tree, twamp_control_sessionid, tvb, offset, 16, ENC_NA);
			offset += 16;
			proto_tree_add_item(twamp_tree, twamp_control_mbz1, tvb, offset, 12, ENC_NA);
			offset += 12;
			proto_tree_add_item(twamp_tree, twamp_control_hmac, tvb, offset, 16, ENC_NA);
			break;
		case CONTROL_STATE_START_SESSIONS:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Start Sessions");
			proto_tree_add_item(twamp_tree, twamp_control_command, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			proto_tree_add_item(twamp_tree, twamp_control_mbz1, tvb, offset, 15, ENC_NA);
			offset += 15;
			proto_tree_add_item(twamp_tree, twamp_control_hmac, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;
		case CONTROL_STATE_START_SESSIONS_ACK:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Start Sessions ACK");
			accept = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(twamp_tree, twamp_control_accept, tvb, offset, 1, accept);
			col_append_fstr(pinfo->cinfo, COL_INFO, ", (%s%s)",
					(accept == 0) ? "" : "Error: ", val_to_str(accept, twamp_control_accept_vals, "%u"));
			offset += 1;
			proto_tree_add_item(twamp_tree, twamp_control_mbz1, tvb, offset, 15, ENC_NA);
			offset += 15;
			proto_tree_add_item(twamp_tree, twamp_control_hmac, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;
		case CONTROL_STATE_STOP_SESSIONS:
			twamp_tree = proto_item_add_subtree(it, ett_twamp_control);
			col_set_str(pinfo->cinfo, COL_INFO, "Stop Session");
			proto_tree_add_item(twamp_tree, twamp_control_command, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(twamp_tree, twamp_control_accept, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(twamp_tree, twamp_control_mbz1, tvb, offset, 2, ENC_NA);
			offset += 2;
			proto_tree_add_item(twamp_tree, twamp_control_num_sessions, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(twamp_tree, twamp_control_mbz2, tvb, offset, 8, ENC_NA);
			offset += 8;
			proto_tree_add_item(twamp_tree, twamp_control_hmac, tvb, offset, 16, ENC_NA);
			offset += 16;
			break;
		default:
			break;
		}
		return offset;
	}
	return captured_length;
}

static int dissect_twamp_test (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	proto_item *ti = NULL;
	proto_item *twamp_tree = NULL;

	col_set_str(pinfo-> cinfo, COL_PROTOCOL, "TWAMP-Test");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		nstime_t ts;
		uint8_t is_response;
		int padding;
		proto_item *time_item;
		conversation_t *conv;
		twamp_session_t *session;
		ti = proto_tree_add_item (tree, proto_twamp_test, tvb, 0, -1, ENC_NA);
		twamp_tree = proto_item_add_subtree (ti, ett_twamp_test);

		col_append_str(pinfo->cinfo, COL_INFO, "Measurement packet");
		
		conv = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
			    PT_UDP, pinfo->srcport, pinfo->destport, 0);
		if (conv == NULL) {
			/* we should set a warning here */
			return tvb_length(tvb);
		}
		if ((session = conversation_get_proto_data(conv, proto_twamp_test)) == NULL) {
			/* we should set a warning here */
			return tvb_length(tvb);
		}

		if ((pinfo->destport == session->sender_port) &&
				memcmp(pinfo->src.data, &session->receiver_address, pinfo->src.len) == 0) {
			is_response = TRUE;
		} else {
			is_response = FALSE;
		}

		proto_tree_add_item (twamp_tree, twamp_seq_number, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		get_twamp_time_from_packet(tvb, offset, &ts);
	    time_item = proto_tree_add_time(twamp_tree, twamp_timestamp, tvb, offset, 8, &ts);
	    offset += 8;

		proto_tree_add_item (twamp_tree, twamp_error_estimate, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		if (!is_response) {
			padding = tvb_length(tvb) - offset;
			if (padding > 0) {
				proto_tree_add_item (twamp_tree, twamp_padding, tvb, offset, padding, ENC_NA);
				offset += padding;
			}
			return offset;
		}
		proto_tree_add_item (twamp_tree, twamp_mbz1, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		get_twamp_time_from_packet(tvb, offset, &ts);
	    time_item = proto_tree_add_time(twamp_tree, twamp_receive_timestamp, tvb, offset, 8, &ts);
	    offset += 8;

		proto_tree_add_item (twamp_tree, twamp_sender_seq_number, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;

		get_twamp_time_from_packet(tvb, offset, &ts);
	    time_item = proto_tree_add_time(twamp_tree, twamp_sender_timestamp, tvb, offset, 8, &ts);
	    offset += 8;

		proto_tree_add_item (twamp_tree, twamp_sender_error_estimate, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item (twamp_tree, twamp_mbz2, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item (twamp_tree, twamp_sender_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		if (padding > 0) {
			proto_tree_add_item (twamp_tree, twamp_padding, tvb, offset, padding, ENC_BIG_ENDIAN);
			offset += padding;
		}

		/* Return the number of bytes we have dissected */
		return offset;
	}

	/* Return the total length */
	return tvb_length(tvb);
}

void proto_register_twamp(void)
{
	static hf_register_info hf_twamp_test[] = {
		{&twamp_seq_number,
		 {"Sequence Number", "twamp.test.seq_number", FT_UINT32,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&twamp_timestamp,
		 {"Timestamp", "twamp.test.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		  NULL, 0x0, NULL, HFILL}},
		{&twamp_error_estimate,
		 {"Error Estimate", "twamp.test.error_estimate", FT_UINT16,
		  BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_mbz1,
		 {"MBZ", "twamp-test.mbz1", FT_UINT8, BASE_DEC_HEX,
		  NULL, 0x0, NULL, HFILL}},
		{&twamp_receive_timestamp,
		 {"Receive Timestamp", "twamp.test.receive_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}},
		{&twamp_sender_seq_number,
		 {"Sender Sequence Number", "twamp.test.sender_seq_number",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
		{&twamp_sender_timestamp,
		 {"Sender Timestamp", "twamp.test.sender_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}},
		{&twamp_sender_error_estimate,
		 {"Sender Error Estimate", "twamp.test.sender_error_estimate",
		  FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
		{&twamp_mbz2,
		 {"MBZ", "twamp.test.mbz2", FT_UINT8, BASE_DEC_HEX,
		  NULL, 0x0, NULL, HFILL}},
		{&twamp_sender_ttl,
		 {"Sender TTL", "twamp.test.sender_ttl", FT_UINT8, BASE_DEC,
		  NULL, 0x0, NULL, HFILL}},
		{&twamp_padding,
		 {"Packet Padding", "twamp.test.padding", FT_BYTES, BASE_NONE,
		  NULL, 0x0, NULL, HFILL}},
	};

	static gint *ett_twamp_test_arr[] = {
		&ett_twamp_test
	};

	static hf_register_info hf_twamp_control[] = {
		{&twamp_control_unused,
			{"Unused", "twamp.control.unused", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_command,
			{"Control Command", "twamp.control.command", FT_UINT8, BASE_DEC,
					VALS(twamp_control_command_vals), 0x0, NULL, HFILL}
		},
		{&twamp_control_modes,
			{"Supported Modes", "twamp.control.modes", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_mode,
			{"Mode", "twamp.control.mode", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_keyid,
			{"Key ID", "twamp.control.keyid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_challenge,
			{"Challenge", "twamp.control.challenge", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_salt,
			{"Salt", "twamp.control.salt", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_count,
			{"Count", "twamp.control.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_iv,
			{"Key ID", "twamp.control.iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_sessionid,
			{"Session Id", "twamp.control.session_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_mbz1,
			{"MBZ", "twamp.control.mbz1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_mbz2,
			{"MBZ", "twamp.control.mbz2", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_hmac,
			{"HMAC", "twamp.control.hmac", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_padding_length,
			{"Padding Length", "twamp.control.padding_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_start_time,
			{"Start Time", "twamp.control.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_timeout,
			{"Timeout", "twamp.control.timeout", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_type_p,
			{"Type-P Descriptor", "twamp.control.type-p", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_num_sessions,
			{"Number of Sessions", "twamp.control.numsessions", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_server_uptime,
			{"Server Start Time", "twamp.control.server_uptime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_accept,
			{"Accept", "twamp.control.accept", FT_UINT8, BASE_DEC, VALS(twamp_control_accept_vals), 0x0,
				"Message acceptence by the other side", HFILL}
		},
		{&twamp_control_sender_port,
			{"Sender Port", "twamp.control.sender_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_receiver_port,
			{"Receiver Port", "twamp.control.receiver_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_ipvn,
			{"IP Version", "twamp.control.ipvn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
		},
		{&twamp_control_sender_ipv4,
			{"Sender Address", "twamp.control.sender_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
				"IPv4 sender address want to use in test packets", HFILL}
		},
		{&twamp_control_sender_ipv6,
			{"Sender Address", "twamp.control.sender_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
				"IPv6 sender address want to use in test packets", HFILL}
		},
		{&twamp_control_receiver_ipv4,
			{"Receiver Address", "twamp.control.receiver_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
				"IPv4 sender address want to use in test packets", HFILL}
		},
		{&twamp_control_receiver_ipv6,
			{"Receiver Address", "twamp.control.receiver_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
				"IPv6 receiver address want to use in test packets", HFILL}
		}
	};

	static gint *ett_twamp_control_arr[] = {
		&ett_twamp_control
	};


	/* Register the protocol */
	proto_twamp_test = proto_register_protocol(
		"TwoWay Active Measurement Test Protocol",
		"TWAMP-Test",
		"twamp.test");

	/* Register the field array */
	proto_register_field_array (proto_twamp_test, hf_twamp_test,
				    array_length(hf_twamp_test));

	/* Register the subtree array */
	proto_register_subtree_array (ett_twamp_test_arr,
				      array_length(ett_twamp_test_arr));

	/* Register the protocol */
	proto_twamp_control = proto_register_protocol(
		"TwoWay Active Measurement Control Protocol",
		"TWAMP-Control",
		"twamp.control");

	/* Register the field array */
	proto_register_field_array (proto_twamp_control, hf_twamp_control,
				    array_length(hf_twamp_control));

	/* Register the subtree array */
	proto_register_subtree_array (ett_twamp_control_arr,
				      array_length(ett_twamp_control_arr));
}

void proto_reg_handoff_twamp(void)
{
	twamp_test_handle = create_dissector_handle((dissector_t)dissect_twamp_test, proto_twamp_test);

	twamp_control_handle = create_dissector_handle((dissector_t)dissect_twamp_control, proto_twamp_control);
	dissector_add_uint("tcp.port", TWAMP_CONTROL_PORT, twamp_control_handle);
}
