/*
 * ofl-exp-tno.h
 *
 *  Created on: Feb 21, 2016
 *      Author: Borgert van der Kluit
 */

#ifndef OFL_EXP_DEF_TNO_H_
#define OFL_EXP_DEF_TNO_H_ 1

#include "../oflib/ofl-structs.h"
#include "../oflib/ofl-messages.h"

/**
 * OFP headers and structs
 */
struct ofp_tno_header {
    struct ofp_header header;  //  8 bytes
    uint32_t vendor;            /* NX_VENDOR_ID. */
    uint32_t subtype;           /* Action, PUT, DEL or something*/
};
OFP_ASSERT(sizeof(struct ofp_tno_header) == 16);

struct ofp_tno_header_bpf {
    struct ofp_tno_header header; // 16 bytes
    uint32_t prog_id;
    uint32_t prog_len;            // +8 bytes = 24 bytes
    uint8_t program[0];           // +0 bytes = 24 bytes.
}; //  24 bytes.
OFP_ASSERT(sizeof(struct ofp_tno_header_bpf) == 24);

/**
 * OFL headers headers and structs
 */
struct ofl_msg_exp_tno_header {
    struct ofl_msg_experimenter header; // enum , 32 bits
    uint32_t   type;                    // 32 bits
}; // x + 8 bytes
//OFP_ASSERT(sizeof(struct ofp_tno_header_bpf) == 24);

struct ofl_msg_exp_tno_header_bpf {
    struct ofl_msg_exp_tno_header   header; //enum ,+8 bytes
    uint32_t prog_id;
    uint32_t prog_len;                      // + 8 bytes = 16 bytes
    uint8_t *program;
}; // 17 bytes



struct ofl_exp_tno_msg_del_bpf {
    struct ofl_msg_exp_tno_header   header;
    uint32_t                  		prog_id;
};

/**
 * This function packs a TNO experimenter structure to a Openflow wireformat.
 */
int
ofl_exp_tno_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len);

/**
 * This function unpacks the OpenFow wireformat to OUR own defined (TNO) experimenter structure.
 */
ofl_err
ofl_exp_tno_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg);

/**
 * The free function only frees the TNO experimenter structure
 */
int
ofl_exp_tno_msg_free(struct ofl_msg_experimenter *msg);

char *
ofl_exp_tno_msg_to_string(struct ofl_msg_experimenter *msg);



#endif /* OFL_EXP_DEF_TNO_H_ */
