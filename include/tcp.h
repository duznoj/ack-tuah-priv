#ifndef TCP_H
#define TCP_H

#include "uthash.h"
#include <stdbool.h>

struct tcp_header {
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t seq_number;
	uint32_t ack_number;
	uint16_t dataOffset_reserved_flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_pointer;
	// ignore options
}__attribute__((packed));

typedef struct {
	uint32_t local_ip;
	uint32_t remote_ip;
	uint16_t local_port;
	uint16_t remote_port;
} TCP_Quad;

typedef enum {
	CLOSED,
	LISTEN,
	SYN_RECVD,
	ESTABLISHED
} TCP_State;

struct send_seq_space {
	uint32_t unack; // Sent but unacknowledged by remote
	uint32_t next; // Next seq_number from which can be sent by local
	uint16_t window; // size of window which can be sent without waiting for acknowledges from remote
	bool urgent_pointer;
	uint16_t wl1; // For dynamic window resizing
	uint16_t wl2; // For dynamic window resizing
	uint32_t iss; // initial send sequence number
};

struct recv_seq_space {
	uint32_t next; // Next sequence number expected from remote
	uint16_t window; // Remote's Window Size
	bool urgent_pointer;
	uint32_t irs; // initial recv sequence number
};

typedef struct {
	TCP_Quad connection_quad; // key


	TCP_State connection_state; // values
	struct send_seq_space send;
	struct recv_seq_space recv;
	UT_hash_handle hh;
} TCP_Connection;


// FLAGS

#define FIN 0x01
#define SYN 0x02
#define RST 0x04
#define PSH 0x08
#define ACK 0x10
#define URG 0x20

void add_connection(TCP_Connection **table, TCP_Quad, TCP_State);

TCP_Connection*  find_connection(TCP_Connection *table, TCP_Quad key);

void match_state(int, TCP_Connection *, uint8_t *);


#endif
