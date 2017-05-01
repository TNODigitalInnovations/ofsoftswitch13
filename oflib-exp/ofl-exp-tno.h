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
 * struct ofl_msg_experimenter {
 *   struct ofl_msg_header  header;             // OFPT_EXPERIMENTER
 *   uint32_t               experimenter_id;
 * };
 */
struct ofl_exp_tno_msg_header {
    struct ofl_msg_experimenter header; /* NX_VENDOR_ID */
    uint32_t   type;
};

struct tno_header {
    struct ofp_header header;
    uint32_t vendor;            /* NX_VENDOR_ID. */
    uint32_t subtype;           /* One of NXT_* above. */
};

struct ofl_exp_tno_msg_bpf {
    struct ofl_exp_tno_msg_header   header;
    uint32_t                  		prog_id;
    uint32_t						prog_len;
    uint8_t * 						program;
};

struct ofl_tno_bpf_put_header {
    struct tno_header header;
    uint32_t prog_id;
    uint32_t prog_len;
    uint8_t program[0];
};

struct ofl_exp_tno_msg_del_bpf {
    struct ofl_exp_tno_msg_header   header;
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
