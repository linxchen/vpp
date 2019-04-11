#ifndef included_vnet_ip4_inwt_packet_h
#define included_vnet_ip4_inwt_packet_h

#include <vnet/ip/ip.h>

typedef struct
{
	/* No option (0000 0001), a padding character*/
	u8 nop;
	/* Option code (ssr is 137) */
	u8 code;
	/* Total length of option header */
	u8 length;
	/* Pointer is next available slot */
	u8 pointer;

	/* The DIP elts */
	ip4_address_t dip_array[0];
} __attribute__ ((packed)) ip4_option_sr_header_t;

typedef struct
{
	u8 type;
	u8 shim_header_reserved;
	u8 length;
	u8 next_protocol;

	u16 flags;
	u8 metadata_length_of_per_hop;
	u8 remaining_number_of_hops;

	u16 instruction_bitmap;
	u16 metadata_header_reserved;

	u32 metadata_stack[0];
} __attribute__ ((packed)) ip4_int_header_t;

typedef struct
{
	/* ip4 option header (strict source routing) */
	ip4_option_sr_header_t option_sr_header;

	/* int shim header, int metadata header and metadata stack */
	ip4_int_header_t int_header;
	
} __attribute__ ((packed)) ip4_inwt_header_t;

#endif /* included_vnet_inwt_packet_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */