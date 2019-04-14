#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sample-inwt/inwt.h>
#include <vnet/sample-inwt/inwt_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>

/*********************** SR rewrite string computation ************************/
/**
 * @brief SR rewrite string computation for SR header insertion
 */
static inline u8 *
compute_rewrite_sr(ip4_address_t * segments)
{
	u8 *result = NULL;
	ip4_inwt_ip4option_sr_header_t *inwt_srh;
	u8 header_length = 0;

	ip4_address_t *addrp, *this_address;

	header_length += sizeof(ip4_inwt_ip4option_sr_header_t);
	header_length += vec_len(segments) * sizeof(ip4_address_t);

	vec_validate(result, header_length-1);

	inwt_srh = (ip4_inwt_ip4option_sr_header_t *) result;
	inwt_srh->nop = 1;    //NOP 00000001
	inwt_srh->code = 137; //strict source routing
	inwt_srh->length = header_length;
	inwt_srh->pointer = 4;
	addrp = inwt_srh->dip_array;
	vec_foreach(this_address, segments)
	{
		clib_memcpy_fast(addrp->data, this_address->data, sizeof(ip4_address_t));
		addrp++;
	}
	return result;
}

/**
 * @brief INT rewrite string computation for INT header insertion
 */
static inline u8 *
compute_rewrite_int(u8 max_hop, u16 ins_map)
{
	u8 *result = NULL;
	ip4_inwt_int_header_t *inwt_inth;
	u8 header_length = 0;

	u8 *p_metadata_stack;

	header_length += sizeof(ip4_inwt_int_header_t);  //12byte
	u8 length_metadata_stack = max_hop * 32;
	// u8 length_metadata_stack = find_length_via_ins_map(ins_map) * max_hop;
	header_length += length_metadata_stack;  //Currently, length of int_metadata per hop is 32 byte

	vec_validate(result, header_length-1);

	inwt_inth = (ip4_inwt_int_header_t *) result;
	inwt_inth->type = 1;   //hop-by-hop type
	inwt_inth->shim_header_reserved = 0;
	inwt_inth->length = header_length;
	inwt_inth->next_protocol = 0;
	inwt_inth->flags = 0x1000;
	inwt_inth->metadata_length_of_per_hop = 0x20;  //32byte
	inwt_inth->pointer_to_hops = 0x0c;  // =12
	inwt_inth->instruction_bitmap = ins_map;
	inwt_inth->metadata_header_reserved = 0;
	p_metadata_stack = inwt_inth->metadata_stack;
	for(u8 i=0; i<length_metadata_stack; ++i)
		clib_memset(p_metadata_stack + i, 0, sizeof(*p_metadata_stack));
	return result;
}

/**
 * @brief Add SR header and INT header to an INWT policy
 */
static inline void
create_inwt_policy(ip4_inwt_policy_t * inwt_policy, ip4_address_t * segments, u8 max_hop, u16 ins_map)
{
	inwt_policy->rewrite_sr = compute_rewrite_sr(segments);
	inwt_policy->rewrite_int = compute_rewrite_int(max_hop, ins_map);
}

/******************************* INWT rewrite API *******************************/
/**
 * @brief Create a new INWT header
 *
 * @param segments is a vector of IPv4 address composing the source routing path
 * @param max_hop is the max hop number of INT path
 * @param ins_map is an instruction map of INT metadata
 *
 * @return 0 if correct, else error
 */
int
inwt_header_add(ip4_address_t * segments, u8 max_hop, u16 ins_map)
{
	ip4_inwt_main_t *iim = &ip4_inwt_main;
	ip4_inwt_policy_t *inwt_policy = 0;

	/* Add an INWT policy object */
	pool_get(iim->inwt_policies, inwt_policy);
	clib_memset(inwt_policy, 0, sizeof(*inwt_policy));
	create_inwt_policy(inwt_policy, segments, max_hop, ins_map);
	return 0;
}

/**
 * @brief CLI for 'inwt header' command family
 */
static clib_error_t *
inwt_header_rewrite_command_fn (vlib_main_t * vm, unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
	int rv = -1;
	char is_add = 0;
	u8 max_hop = (u8) ~ 0;
	u16 ins_map = (u16) ~ 0;
	ip4_address_t next_address;
	ip4_address_t *segments = 0, *this_seg;

	while(unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
	{
		if(!is_add && unformat(input, "add"))
			is_add = 1;
		else if(unformat(input, "next %U", unformat_ip4_address, &next_address))
		{
			vec_add2(segments, this_seg, 1);
			clib_memcpy_fast(this_seg->data, next_address.data, sizeof(*this_seg));
		}
		else if(unformat(input, "maxhop %u", &max_hop));
		else if(unformat(input, "insmap 0x%x", &ins_map));
		else
			break;
	}

	if(!is_add)
		return clib_error_return(0, "Incorrect CLI");
	if(is_add)
	{
		if(vec_len(segments) == 0)
			return clib_error_return(0, "No Source Routing Path specified");
		rv = inwt_header_add(segments, max_hop, ins_map);
		vec_free(segments);
	}

	switch(rv)
	{
		case 0:
			break;
		case 1:
			break;
		default:
			return clib_error_return(0, "BUG: inwt header rewrite returns %d", rv);
	}
	return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (inwt_header_rewrite_command, static) = {
	.path = "inwt header",
	.short_help = "inwt header add "
	  "next 10.0.1.0 next 10.0.2.0 next 10.0.3.0 "
	  "maxhop 3 insmap 0xffff",
	.function = inwt_header_rewrite_command_fn,
};
/* *INDENT-ON* */

/*************************** INWT rewrite graph node ****************************/
/**
 * @brief Graph node for applying an INWT policy into a packet.
 *        Generate INWT probe packet and insert INWT header.
 */
static uword
inwt_probe_packet_generation(vlib_main_t * vm, vlib_node_runtime_t * node,
			vlib_frame_t * from_frame)
{

	return from_frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (inwt_probe_packet_generation_node) = {
  .function = inwt_probe_packet_generation,
  .name = "inwt-probe-packet-generation",
  .vector_size = sizeof (u32),
  // .format_trace = format_inwt_probe_packet_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = INWT_PROBE_PACKET_N_ERROR,
  .error_strings = inwt_probe_packet_error_strings,
  .n_next_nodes = INWT_PROBE_PACKET_N_NEXT,
  .next_nodes = {
#define _(s,n) [INWT_PROBE_PACKET_NEXT_##s] = n,
    foreach_inwt_probe_packet_next
#undef _
  },
};
/* *INDENT-ON* */

/********************* INWT Header Rewrite initialization ***********************/
/**
 * @brief INWT Header Rewrite Initialization
 */
clib_error_t *
inwt_header_rewrite_init(vlib_main_t * vm)
{
	ip4_inwt_main_t *iim = &ip4_inwt_main;

	/* Registrations */

	return 0;
}

VLIB_INIT_FUNCTION (inwt_header_rewrite_init);

/*
* fd.io coding-style-patch-verification: ON
*
* Local Variables:
* eval: (c-set-style "gnu")
* End:
*/
