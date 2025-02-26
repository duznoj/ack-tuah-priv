#include "../include/tcp.h"
#include "../include/ipv4.h"
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

struct pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t zero;
	uint8_t protocol;
	uint16_t tcp_length;
}__attribute__((packed));



void add_connection(TCP_Connection **table, TCP_Quad quad, TCP_State state) {
	TCP_Connection *connection = malloc(sizeof(TCP_Connection));

	if(!connection) {
		assert(0 && "Malloc Failed");
		return;
	}

	connection->connection_quad = quad;
	connection->connection_state = state;

	HASH_ADD(hh, *table, connection_quad, sizeof(TCP_Quad), connection);
}

TCP_Connection*  find_connection(TCP_Connection *table, TCP_Quad key) {
	TCP_Connection *result = NULL;
	HASH_FIND(hh, table, &key, sizeof(TCP_Quad), result);
	return result;
}

uint8_t get_tcp_flags(uint16_t dataOffset_reserved_flags) {
	return (uint8_t)(ntohs(dataOffset_reserved_flags) & 0x3F);
}
  

uint16_t calculate_ip_checksum(const void *buf, int length) {
	uint32_t sum = 0;
	uint16_t *data = (uint16_t *)buf;
	size_t num_words = length / 2;

	// Add 16-bit words
	for (size_t i = 0; i < num_words; i++) {
		sum += ntohs(data[i]);  // Use ntohs to ensure the data is in host byte order
	}

	// Handle odd byte length (if any)
	if (length % 2 != 0) {
		sum += ntohs(((uint8_t *)data)[length - 1] << 8);
	}

	// Add carry bits
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	// Return the ones' complement of the sum
	return htons(~sum);
}

//int verify_checksum(struct ipv4_header header) {
//	// Calculate checksum on the entire header
//	uint16_t checksum = ~calculate_ip_checksum(&header, sizeof(struct ipv4_header));
//
//	printf("inside verify %04X\n", checksum);
//
//	// If checksum is correct, it should be all 1s (0xFFFF)
//	return (checksum == 0xFFFF);
//}


//uint16_t calculate_tcp_checksum(struct pseudo_header p, void *tcp_segment_void, int tcp_segment_len) {
//	uint32_t sum = 0;
//
//	sum += (p.source_address) & 0xFFFF;
//	sum += (p.source_address >> 16) & 0xFFFF;
//	sum += (p.dest_address) & 0xFFFF;
//	sum += (p.dest_address >> 16) & 0xFFFF;
//
//	sum += htons(0x06);
//
//	uint16_t *tcp_segment = tcp_segment_void;
//	while(tcp_segment_len > 1) {
//		sum += *tcp_segment++;
//		tcp_segment_len -= 2;
//	}
//
//	if(tcp_segment_len > 0) {
//		sum += ((*tcp_segment)&htons(0xFF00));
//	}
//
//	while(sum >> 16) {
//		sum = (sum & 0xFFFF) + (sum >> 16);
//	}
//
//	return ~sum;
//
//}


void match_state(int tun_fd, TCP_Connection *connection, uint8_t *packet) {
	if(connection->connection_state == CLOSED) {
		return;
	}
	struct ipv4_header in_ip_header = *(struct ipv4_header *)packet;
	int ip_header_length = (in_ip_header.ver_and_header_len & 0x0F) * 4;

	uint8_t *tcp_segment = packet + ip_header_length;
	//int tcp_segment_len = ntohs(in_ip_header.total_length) - ip_header_length;
	struct tcp_header in_tcp_header = *(struct tcp_header *)tcp_segment;


	
	if(connection->connection_state == LISTEN) {
		printf("IS IN LISTEN\n");
		// Should only receive a SYN packet
		uint8_t flags = get_tcp_flags(in_tcp_header.dataOffset_reserved_flags);

		if(flags != SYN){
			printf("SYN Expected\n");
			return;
		}

		printf("GOT SYN\n");
		connection->connection_state = SYN_RECVD;

		// Initialize our own sequence space, and set the remote's sequence space

		connection->recv.irs = ntohl(in_tcp_header.seq_number);
		connection->recv.next = ntohl(in_tcp_header.seq_number) + 1;
		connection->recv.window = ntohs(in_tcp_header.window_size);
		connection->recv.urgent_pointer = false;

		// Send Sequence Stuff
		connection->send.iss = 0;
		connection->send.unack = 0;
		connection->send.next = connection->send.unack + 1;
		connection->send.window = 10;
		connection->send.wl1 = 0;
		connection->send.wl2 = 0;
		connection->send.urgent_pointer = false;

		struct ipv4_header out_ip_header = {
			.ver_and_header_len = 0x45,
			.tos = 0,
			.total_length = htons(sizeof(struct ipv4_header) + sizeof(struct tcp_header)),
			.identification = 0,
			.fragment_offset = htons(0x4000),
			.ttl = 100,
			.protocol = 0x06,
			.header_check_sum = 0,
			.source_ip = in_ip_header.dest_ip,
			.dest_ip = in_ip_header.source_ip,
		};

		for(int i=0; i<ip_header_length; i++) {
			printf("%02X ", packet[i]);
		}

		out_ip_header.header_check_sum = calculate_ip_checksum(&out_ip_header, ip_header_length);


		printf("Caluclated: %04X\n", out_ip_header.header_check_sum);
		//printf("Verified: %04X\n", verify_checksum(out_ip_header));

		struct tcp_header out_tcp_header = {
			.source_port = in_tcp_header.dest_port,
			.dest_port = in_tcp_header.source_port,
			.seq_number = htonl(connection->send.iss), // Should be random
			.ack_number = htonl(connection->recv.next),
			.dataOffset_reserved_flags = htons((((uint32_t)sizeof(struct tcp_header)/4) << 12) | SYN | ACK),
			.window_size = htons(connection->send.window),
			.checksum = 0,
			.urgent_pointer = 0
		};


		struct pseudo_header pseudo = {
			.source_address = in_ip_header.dest_ip,
			.dest_address = in_ip_header.source_ip,
			.zero = 0,
			.protocol = 0x06, // TCP protocol
			.tcp_length = htons(sizeof(struct tcp_header))
        	};


		uint32_t tcp_checksum = ntohs(~calculate_ip_checksum((uint16_t *)&pseudo, sizeof(struct pseudo_header)));

		tcp_checksum += ntohs(~calculate_ip_checksum((uint16_t *)&out_tcp_header, sizeof(struct tcp_header)));

		while(tcp_checksum >> 16) {
			tcp_checksum = (tcp_checksum & 0xFFFF) + (tcp_checksum >> 16);
		}

		out_tcp_header.checksum = htons(~tcp_checksum);
		uint8_t *response_packet = malloc(1500);
		memcpy(response_packet, &out_ip_header, sizeof(struct ipv4_header));
		memcpy(response_packet + sizeof(struct ipv4_header), &out_tcp_header, sizeof(struct tcp_header));

		write(tun_fd, response_packet, sizeof(struct ipv4_header) + sizeof(struct tcp_header));
		free(response_packet);

		//return response_packet;
	}

}
