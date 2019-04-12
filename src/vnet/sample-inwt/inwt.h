#ifndef included_vnet_ip4_inwt_h
#define included_vnet_ip4_inwt_h

#include <vnet/vnet.h>
#include <vnet/sample-inwt/inwt_packet.h>

typedef struct
{
	u8 *rewrite_sr;
	u8 *rewrite_int;
} ip4_inwt_policy_t;

typedef struct
{
	ip4_inwt_policy_t *inwt_policies;
	
	/* convenience */
	vlib_main_t *vlib_main;
	vnet_main_t *vnet_main;
} ip4_inwt_main_t;

extern ip4_inwt_main_t ip4_inwt_main;

#endif /* included_vnet_ip4_inwt_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
