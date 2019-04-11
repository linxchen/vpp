#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/sample-inwt/inwt.h>
#include <vnet/sample-inwt/inwt_packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>

#include <vppinfra/error.h>
#include <vppinfra/elog.h>




/******************************* INWT rewrite API *******************************/
/**
 * @brief Create a new INWT header
 *
 * @param 
 *
 * @return 0 if correct, else error
 */
int
inwt_header_add()
{
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
	char is_encap = 0;
	u32 max_hop = (u32) ~ 0;
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
			clib_memcpy_fast(this_seg->data, next_address->data, sizeof(*this_seg));
		}
		else if(unformat(input, "encap"))
			is_encap = 1;
		else if(unformat(input, "maxhop %d", &max_hop));
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
		rv = inwt_header_add();
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
	  "next 10.0.1.0 next 10.0.2.0 next 10.0.3.0 encap "
	  "maxhop 3 insmap 0xffff",
	.function = inwt_header_rewrite_command_fn,
};
/* *INDENT-ON* */

/*************************** INWT rewrite graph node ****************************/



/********************* INWT Header Rewrite initialization ***********************/
/**
 * @brief INWT Header Rewrite Initialization
 */
clib_error_t *
inwt_header_rewrite_init(vlib_main_t * vm)
{
	ip4_inwt_main_t *im = &ip4_inwt_main;

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
