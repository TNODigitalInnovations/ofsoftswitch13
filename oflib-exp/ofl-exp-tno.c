/*
 * ofl-exp-tno.c
 *
 *  Created on: Feb 21, 2016
 *      Author: Borgert van der Kluit
 */


#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

#include "openflow/openflow.h"
#include "openflow/tno-ext.h"
#include "ofl-exp-tno.h"
#include "../oflib/ofl-print.h"
#include "../oflib/ofl-log.h"

#define LOG_MODULE ofl_exp_tno
OFL_LOG_INIT(LOG_MODULE)


int
ofl_exp_tno_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len) {
    (void) buf;
    (void) buf_len;

    if (msg->experimenter_id == TNO_VENDOR_ID) {

        struct ofl_exp_tno_msg_header *exp = (struct ofl_exp_tno_msg_header *)msg;

        switch (exp->type) {
            case (TNO_PUT_BPF): {
				OFL_LOG_WARN(LOG_MODULE, "Trying to pack TNO Experimenter message.");
            	return -1; }
            case (TNO_DEL_BPF): {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack TNO Experimenter message.");
            	return -1; }
            case (TNO_GET_BPF): {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack TNO Experimenter message.");
            	return -1; }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack TNO Experimenter message.");
                return -1;
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to pack non-TNO Experimenter message.");
        return -1;
    }
}

// Given the OpenFlow wire format in converts to an experimenter structure
ofl_err
ofl_exp_tno_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg)
{
    struct tno_header *exp;
    struct ofl_tno_bpf_put_header *src;
    struct ofl_exp_tno_msg_bpf *dst;

    if (*len < sizeof(struct ofl_exp_tno_msg_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct tno_header *)oh;

    if (ntohl(exp->vendor) == TNO_VENDOR_ID) {

        switch (ntohl(exp->subtype)) {
			case (TNO_PUT_BPF): {
				OFL_LOG_WARN(LOG_MODULE, "Trying to TNO SET BPF");



				if (*len < sizeof(struct ofl_tno_bpf_put_header)) {
					OFL_LOG_WARN(LOG_MODULE,
							"Received TNO_PUT_BPF message has invalid length (%zu).",
							*len);
					OFL_LOG_WARN(LOG_MODULE,
												"Expected (%zu).",
												sizeof(struct ofl_tno_bpf_put_header));

					return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
				}
				*len -= sizeof(struct ofl_tno_bpf_put_header);

				src = (struct ofl_tno_bpf_put_header *) exp;


				// Malloc here needs to freed somewhere.
				dst = (struct ofl_exp_tno_msg_bpf *) malloc(sizeof(struct ofl_exp_tno_msg_bpf));

                dst->header.header.experimenter_id = ntohl(exp->vendor);
                dst->header.type                   = ntohl(exp->subtype);
				dst->prog_id = ntohl(src->prog_id);
				dst->prog_len = ntohl(src->prog_len);


				OFL_LOG_WARN(LOG_MODULE,"Received TNO_PUT_BPF message prog_id: (%u).",dst->prog_id);
				OFL_LOG_WARN(LOG_MODULE,"Received TNO_PUT_BPF message prog_len: (%u).",dst->prog_len);

				if (dst->prog_len != *len)
				{
					OFL_LOG_WARN(LOG_MODULE, "Received TNO_PUT_BPF message has invalid payload length left: (%zu). msg: (%u).",
							*len, dst->prog_len );
					return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
				}

				*len -= dst->prog_len * sizeof(uint8_t);

				dst->program = (uint8_t * ) malloc(dst->prog_len * sizeof(uint8_t));

				memcpy(dst->program,src->program,dst->prog_len * sizeof(uint8_t));

				(*msg) = (struct ofl_msg_experimenter *) dst;
				OFL_LOG_WARN(LOG_MODULE, "Success");
				return 0;

			}
        	case (TNO_DEL_BPF): {
        		OFL_LOG_WARN(LOG_MODULE, "Trying to TNO DEL BPF");
        		return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        	}
        	case (TNO_GET_BPF): {
        		OFL_LOG_WARN(LOG_MODULE, "Trying to TNO GET BPF");
        		return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        	}
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown TNO Experimenter message.");
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to unpack non-TNO Experimenter message.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
    }
    free(msg);
    return 0;
}


// This function is called from the datapath.c after the program is saved in the
// dp program list..
int
ofl_exp_tno_msg_free(struct ofl_msg_experimenter *msg)
{
    if (msg->experimenter_id == TNO_VENDOR_ID) {

        struct ofl_exp_tno_msg_header *exp = (struct ofl_exp_tno_msg_header *)msg;
        switch (exp->type) {
            case (TNO_PUT_BPF): {
                struct ofl_exp_tno_msg_bpf * put_bpf_msg = (struct ofl_exp_tno_msg_bpf *)msg;
                free(put_bpf_msg->program);
                OFL_LOG_WARN(LOG_MODULE, "Correct freeing TNO Experimenter message :)");
                break;
            }
            case (TNO_DEL_BPF):
            case (TNO_GET_BPF):
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown TNO Experimenter message.");
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to free non-TNO Experimenter message.");
    }
    free(msg);
    return 0;
}

char *
ofl_exp_tno_msg_to_string(struct ofl_msg_experimenter *msg) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    if (msg->experimenter_id == TNO_VENDOR_ID) {
        struct ofl_exp_tno_msg_header *exp = (struct ofl_exp_tno_msg_header *)msg;
        switch (exp->type) {
			case (TNO_PUT_BPF):
			case (TNO_DEL_BPF):
			case (TNO_GET_BPF):
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown TNO Experimenter message.");
                fprintf(stream, "ofexp{type=\"%u\"}", exp->type);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-TNO Experimenter message.");
        fprintf(stream, "exp{exp_id=\"%u\"}", msg->experimenter_id);
    }

    fclose(stream);
    return str;
}



