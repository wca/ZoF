#ifndef _OFFSET_INC_
#define _OFFSET_INC_
#if !defined(GENOFFSET) && (!defined(KLD_MODULE) || defined(KLD_TIED))
struct thread_lite {
	u_char	pad_td_epochnest[0xf9 - 0];
	u_char	td_epochnest;
	u_char	pad_td_owepreempt[0x120 - (0xf9 + sizeof(u_char))];
	u_char	td_owepreempt;
	u_char	pad_td_pinned[0x154 - (0x120 + sizeof(u_char))];
	int	td_pinned;
	u_char	pad_td_priority[0x392 - (0x154 + sizeof(int))];
	u_char	td_priority;
	u_char	pad_td_pre_epoch_prio[0x396 - (0x392 + sizeof(u_char))];
	u_char	td_pre_epoch_prio;
	u_char	pad_td_critnest[0x48c - (0x396 + sizeof(u_char))];
	u_int	td_critnest;
};
#endif
#endif
