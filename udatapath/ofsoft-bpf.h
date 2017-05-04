/*
 * ofsoft-bpf.h
 *
 *  Created on: Apr 19, 2016
 *      Author: Borgert van der Kluit
 */

#ifndef OFSOFT_BPF_H_
#define OFSOFT_BPF_H_

#include <stdint.h>

struct ofsoft_bpf {
    // Ofsoftswitch13 metadata
    uint8_t     table_id;
    uint32_t    in_port;
    uint8_t     param_len;  // length of parameter for example: tno1/ of tno3/
    size_t      packet_len; // length of incoming packet ip packet with tlv (NDN payload)
    uint8_t *   param;
    uint8_t *   packet;
};


#endif /* OFSOFT_BPF_H_ */
