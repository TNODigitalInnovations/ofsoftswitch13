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

        struct ofl_msg_exp_tno_header *exp = (struct ofl_msg_exp_tno_header *)msg;

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

// Given the OpenFlow wire format (OFP) in converts to an experimenter structure (OFL)
/**
 * struct ofp_header *oh is the incomming structure.
 * len is the size of the incomming structure.
 * struct ofl_msg_experimenter **msg is the outputted structure. (experimenter structure message) OFL
 * The bytes that are used need to be substracted from parameter len.
 */
ofl_err
ofl_exp_tno_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg)
{
    // First convert incoming ofp_header to large tno struct that contains all information.
    struct ofp_tno_header_bpf *ofp_src = (struct ofp_tno_header_bpf *) oh;
    struct ofl_msg_exp_tno_header_bpf *ofl_dst = NULL;

    OFL_LOG_WARN(LOG_MODULE, "Received OFP header parameter len : (%zu).", *len);
    OFL_LOG_WARN(LOG_MODULE, "Size of ofp_tno_header_bpf struct: (%zu).", sizeof(struct ofp_tno_header_bpf));
    // Should be something like 40 bytes.

    // If the len(gth) of the incoming structure ofp_header is smaller then a OFP tno structure something is wrong.
    if (*len < sizeof(struct ofp_tno_header_bpf)) {
        OFL_LOG_WARN(LOG_MODULE, "Received OFP EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ntohl(ofp_src->header.vendor) == TNO_VENDOR_ID) {
        switch (ntohl(ofp_src->header.subtype)) {
            case (TNO_PUT_BPF): {
                OFL_LOG_WARN(LOG_MODULE, "Trying to TNO PUT(SET) BPF");

                // Malloc here needs to freed somewhere.
                ofl_dst = (struct ofl_msg_exp_tno_header_bpf *)malloc(sizeof(struct ofl_msg_exp_tno_header_bpf));

                // Fill the empty structure.
                ofl_dst->header.header.experimenter_id  = ntohl(ofp_src->header.vendor);
                ofl_dst->header.type                    = ntohl(ofp_src->header.subtype);
                ofl_dst->prog_id                        = ntohl(ofp_src->prog_id);
                ofl_dst->prog_len                       = ntohl(ofp_src->prog_len);

                OFL_LOG_WARN(LOG_MODULE,"Received TNO_PUT_BPF message prog_id: (%u).",ofl_dst->prog_id);
                OFL_LOG_WARN(LOG_MODULE,"Received TNO_PUT_BPF message prog_len: (%u).",ofl_dst->prog_len);

                // Subtract here the total size of the complete OFP structure. Only the real program length should be left.
                *len -= sizeof(struct ofp_tno_header_bpf);  // -40 bytes

                // By now the value of 'len' should be the same as the program length!
                if (ofl_dst->prog_len != *len) {
                    OFL_LOG_WARN(LOG_MODULE, "Received TNO_PUT_BPF message invalid payload length len:(%zu) prog_len: (%u)", *len, ofl_dst->prog_len );
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }

                // Subtract all the bytes from len.
                *len -= ofl_dst->prog_len * sizeof(uint8_t);
                // By now len should be zero.

                // malloc stuff and let it program point to it
                ofl_dst->program = (uint8_t *) malloc( ofl_dst->prog_len * sizeof(uint8_t) );

                // Copy the program.
                memcpy(ofl_dst->program, ofp_src->program, ofl_dst->prog_len * sizeof(uint8_t) );

                // set the msg pointer to the correct location.
                (*msg) = (struct ofl_msg_experimenter *) ofl_dst;
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
int ofl_exp_tno_msg_free(struct ofl_msg_experimenter *msg)
{
    if (msg->experimenter_id == TNO_VENDOR_ID)
    {
        struct ofl_msg_exp_tno_header *ofl_msg = (struct ofl_msg_exp_tno_header *)msg;

        // Switch for each (sub)type.
        switch (ofl_msg->type)
        {
            case (TNO_PUT_BPF): {
                struct ofl_msg_exp_tno_header_bpf * ofl_msg_tno = (struct ofl_msg_exp_tno_header_bpf *)msg;
                free(ofl_msg_tno->program);
                OFL_LOG_WARN(LOG_MODULE, "Correct freeing TNO Experimenter message :)");
                break;
            }
            case (TNO_DEL_BPF): {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free DEL TNO Experimenter message.");
                break;
            }
            case (TNO_GET_BPF): {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free GET TNO Experimenter message.");
                break;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown TNO Experimenter message.");
                break;
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to free non-TNO Experimenter message.");
    }

    // Always free the msg.
    free(msg);

    return 0;
}


char *
ofl_exp_tno_msg_to_string(struct ofl_msg_experimenter *msg) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    if (msg->experimenter_id == TNO_VENDOR_ID) {
        struct ofl_msg_exp_tno_header *exp = (struct ofl_msg_exp_tno_header *)msg;
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



