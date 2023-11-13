#include "asm/cache.h"
#include "asm/fpu/api.h"
#include "linux/hrtimer.h"
#include "linux/kern_levels.h"
#include "linux/ktime.h"
#include "linux/limits.h"
#include "linux/printk.h"
#include "linux/slab.h"
#include "linux/stddef.h"
#include "linux/tcp.h"
#include "linux/timekeeping.h"
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <linux/jhash.h>
#include <net/tcp.h>
#include <trace/events/tcp.h>


#define TBTCP_BETA_SCALE 1024 	/* Scale factor beta calculation */

static int beta __read_mostly = 512;	/* = 512/1024 (TBTCP_BETA_SCALE) */
module_param(beta, int, 0644);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");

static int ssthresh_cwnd_based __read_mostly = false;
module_param(ssthresh_cwnd_based, int, 0644);
MODULE_PARM_DESC(ssthresh_cwnd_based, "ssthresh based on cwnd instead of inflight");


struct tcp_tb {
	u64 Ttx;
	u32 Ntx;
	u32 ssthresh_Ntx;
	u32 NlastAck;
	u32 Nak;
	u64 Tak;
	u32 HighData;
	u64 rtt;
	bool postRecovery;	       // true if we are in post-recovery
	enum tcp_ca_state state;
	struct list_head lostPackets; // linked list of packets in flight
	bool stalled;
};

struct tb_packet {
	u32 Ntx;
	u32 Nak;
	u32 seq;
	u64 time;
	struct list_head list;
};

inline bool tcp_tb_in_slow_start(struct tcp_tb *ca);

/* function that does the same as remove_packets but returns how many were removed */
static int remove_packets(struct tcp_tb *ca, u32 seq) {
	struct tb_packet *packet;
	struct list_head *pos, *q;
	int i = 0;

	if (ca->lostPackets.next == NULL || ca->lostPackets.prev == NULL) {
		return -1;
	}
	list_for_each_safe(pos, q, &ca->lostPackets) {
		packet = list_entry(pos, struct tb_packet, list);
		if (before(packet->seq, seq)) {
			list_del(pos);
			kfree(packet);
			i++;
		}
	}

	return i;
}

static int add_packet(struct tcp_tb *ca, u32 seq, u32 Ntx, u32 Nak, u64 time) {
	struct tb_packet *packet;
	if (ca->lostPackets.next == NULL || ca->lostPackets.prev == NULL) {
		return -1;
	}
	packet = kmalloc(sizeof(struct tb_packet), GFP_ATOMIC);
	if (!packet) {
		return -1;
	}

	packet->Ntx = Ntx;
	packet->Nak = Nak;
	packet->seq = seq;
	packet->time = time;

	list_add_tail(&packet->list, &ca->lostPackets);

	return 0;
}

__attribute__((target("sse2"))) double sqrt_double(double x) {
	double guess = x / 2; // Initial guess
  	double epsilon = 0.000001; // Tolerance for convergence
  	int i;

	for (i = 0; i < 12; i++) { // Maximum of 10 iterations
		double diff = guess * guess - x; // Calculate the difference
		if (diff < 0) {
			diff = -diff; // Take the absolute value if diff is negative
		}
		if (diff < epsilon) { // Check for convergence
			break;
	}
		guess = (guess + x / guess) / 2; // Update guess using Babylonian method
	}

  	return guess;
}

/*
 * From the fastapprox library: https://github.com/romeric/fastapprox/blob/ccc534400ec3e0f67de4eafb53377334962d9db6/fastapprox/src/fastlog.h#L48
 */
__attribute__((target("sse2"))) float log2_of_number(float x) {
    union {
        float f;
        uint32_t i;
    } vx = {x};
    union {
        uint32_t i;
        float f;
    } mx = {(vx.i & 0x007FFFFF) | 0x3f000000};
    float y = vx.i;
    y *= 1.1920928955078125e-7f;
    return y - 124.22551499f
           - 1.498030302f * mx.f
           - 1.72587999f / (0.3520887068f + mx.f);
}


__attribute__((target("sse2"))) inline u64 delta_time_mult_rtt(struct tcp_tb *ca, u32 seq_num, u32 k, u64 rtt)
{
	double res, div;
	if (tcp_tb_in_slow_start(ca)) {
		div = (float)((float) k / (float) seq_num);
		res = log2_of_number(1 + div);
		return res * rtt;
	} else {
		res = (double)(sqrt_double((8*(seq_num + k)-7)) / (double)2) - (double)(sqrt_double((double)(8*seq_num - 7)) / (double)2);
		return res * rtt;
	}

	return 1;
}

int start_event_timer(struct sock *sk, struct hrtimer *timer, u64 time_ns) {
	if (!hrtimer_is_queued(timer)) {
		hrtimer_start(timer,
				ns_to_ktime(time_ns),
				HRTIMER_MODE_ABS_PINNED_SOFT);
		sock_hold(sk);
		return 1;
	} else {
		return 0;
	}
}

int cancel_event_timer(struct hrtimer *timer) {
	if (hrtimer_is_queued(timer)) {
		hrtimer_try_to_cancel(timer);
		return 1;
	} else {
		return 0;
	}
}

int cancel_and_start_new_timer(struct sock *sk, struct hrtimer *timer, u64 time_ns) {
	if (hrtimer_is_queued(timer)) {
		if (hrtimer_try_to_cancel(timer) != -1) {
			hrtimer_start(timer,
					ns_to_ktime(time_ns),
					HRTIMER_MODE_ABS_PINNED_SOFT);
			sock_hold(sk);
			return 1;
		} else {
			return 0;
		}
	} else {
		hrtimer_start(timer,
				ns_to_ktime(time_ns),
				HRTIMER_MODE_ABS_PINNED_SOFT);
		sock_hold(sk);
		return 1;
	}
}

inline bool tcp_tb_in_slow_start(struct tcp_tb *ca) {
	return ca->Ntx < ca->ssthresh_Ntx;
}

/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_tb_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_tb *ca = inet_csk_ca(sk);

	/* In "safe" area, increase. */
	if (tcp_tb_in_slow_start(ca)) {
		acked = tcp_slow_start(tp, acked);
		if (!acked)
			return;
	}
	/* In dangerous area, increase slowly. */
	tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
}
EXPORT_SYMBOL_GPL(tcp_tb_cong_avoid);

/* Slow start threshold is half the congestion window (min 2) */
u32 tcp_tb_ssthresh(struct sock *sk)
{
	struct tcp_tb *ca = inet_csk_ca(sk);
	struct tb_packet *lostPacketsFront = list_first_entry(&ca->lostPackets, struct tb_packet, list);
	u32 ssthresh;

	if (ssthresh_cwnd_based) {
		ssthresh = max((tcp_sk(sk)->snd_cwnd * beta) / TBTCP_BETA_SCALE, 2U);
	} else {
		ssthresh = max(((lostPacketsFront->Ntx - lostPacketsFront->Nak) * beta) / TBTCP_BETA_SCALE, 2U);
	}

	ca->ssthresh_Ntx = ssthresh;
	return ssthresh;
}
EXPORT_SYMBOL_GPL(tcp_tb_ssthresh);

u32 tcp_tb_undo_cwnd(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return max(tp->snd_cwnd, tp->prior_cwnd);
}
EXPORT_SYMBOL_GPL(tcp_tb_undo_cwnd);


static void tcp_tb_init(struct sock *sk)
{
	struct tcp_tb *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct hrtimer *timer = (struct hrtimer*) &tp->event_timer;
	u64 now = ktime_get_ns();
	u32 IW = tp->snd_cwnd;

	ca->postRecovery = false;
	ca->rtt = max(tp->srtt_us >> 3, 1U) * 1000;

	ca->HighData = 1;
	ca->ssthresh_Ntx = U32_MAX;
	tp->snd_ssthresh = TCP_INFINITE_SSTHRESH;
	ca->NlastAck = tp->snd_una;

	ca->Ttx = now;
	ca->Ntx = IW; // initial window size
	ca->Nak = ca->Ntx;
	ca->Tak = now + ca->rtt;
	ca->stalled = false;
	INIT_LIST_HEAD(&ca->lostPackets);


	/* start initial timer */
	start_event_timer(sk, timer, ca->Ttx);
}

static void tcp_tb_release(struct sock *sk) {
	struct tcp_sock *tp = tcp_sk(sk);
	struct hrtimer *timer = (struct hrtimer*) &tp->event_timer;

	cancel_event_timer(timer);
	printk(KERN_DEBUG "Releasing timer\n");
}

static u32 tcp_tb_min_tso_segs(struct sock *sk)
{
	return 1;
}

void tcp_tb_pace(struct hrtimer *timer, u64 now) {
	struct tcp_sock *tp = container_of(timer, struct tcp_sock, event_timer);
	struct sock *sk = (struct sock *)tp;
	struct tcp_tb *ca = inet_csk_ca(sk);
	u64 pacingTime;
	u32 snd_nxt;

	snd_nxt = tp->snd_nxt;
	if (!sock_owned_by_user(sk)) {
		tcp_write_xmit(sk, tcp_current_mss(sk), TCP_NAGLE_OFF, 2, sk_gfp_mask(sk, GFP_ATOMIC));
	} else {
		start_event_timer(sk, timer, ktime_get_ns());
		return;
	}

	/* start a new initial timer if nothing was sent */
	if (tp->bytes_sent == 0) {
		ca->Ttx = ktime_get_ns();
		ca->Tak = ktime_get_ns() + ca->rtt;

		start_event_timer(sk, timer, ca->Ttx);
		return;

	}

	add_packet(ca, snd_nxt, ca->Ntx, ca->Nak, now);
	ca->HighData = ca->HighData + 1;

	kernel_fpu_begin();
	pacingTime = delta_time_mult_rtt(ca, ca->Ntx, 1, ca->rtt);
	kernel_fpu_end();

	ca->Ntx = ca->Ntx + 1;
	ca->Ttx = now + pacingTime;

	/* queue next event */
	start_event_timer(sk, timer, ca->Ttx);
}

enum hrtimer_restart tcp_tb_event_handler(struct hrtimer *timer) {
	struct tcp_sock *tp = container_of(timer, struct tcp_sock, event_timer);
	struct sock *sk = (struct sock *)tp;
	struct tcp_tb *ca = inet_csk_ca(sk);
	ca->stalled = false;

	/* pace if we are still anticipating an ACK */
	if (ca->Ttx < ca->Tak && ca->state < TCP_CA_Recovery) {
		tcp_tb_pace(timer, ca->Ttx);
	} else {
		ca->stalled = true;
	}

	return HRTIMER_NORESTART;
}

EXPORT_SYMBOL_GPL(tcp_tb_event_handler);

void tcp_tb_set_state (struct sock *sk, u8 new_state) {
	struct tcp_tb *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);

	if (ca->state == TCP_CA_Loss && new_state == TCP_CA_Open) {
		/* coming back to OPEN from LOSS */
		ca->Ntx = 1;
		ca->Nak = 1;

		/* choose min RTT as ACK sampled RTT is affected by loss */
		ca->rtt = tcp_min_rtt(tp) * 1000;
		ca->Ttx = ktime_get_ns();
		ca->Tak = ca->Ttx + ca->rtt;

		/* restart timer */
		start_event_timer(sk,&tp->event_timer, ca->Ttx);
	}

	ca->state = new_state;
}

void tcp_tb_cwnd_reduction(struct sock *sk, const struct rate_sample *rs) {
	struct tcp_sock *tp = tcp_sk(sk);
	int sndcnt = 0;
	int delta = tp->snd_ssthresh - tcp_packets_in_flight(tp);
	int acked = rs->acked_sacked;

	if (acked <= 0 || WARN_ON_ONCE(!tp->prior_cwnd))
		return;

	tp->prr_delivered += acked;
	if (delta < 0) {
		u64 dividend = (u64)tp->snd_ssthresh * tp->prr_delivered +
			       tp->prior_cwnd - 1;
		sndcnt = div_u64(dividend, tp->prior_cwnd) - tp->prr_out;
	} else if (rs->is_retrans) {
		sndcnt = min_t(int, delta,
			       max_t(int, tp->prr_delivered - tp->prr_out,
				     acked) + 1);
	} else {
		sndcnt = min(delta, acked);
	}
	/* Force a fast retransmit upon entering fast recovery */
	sndcnt = max(sndcnt, (tp->prr_out ? 0 : 1));
	tp->snd_cwnd = tcp_packets_in_flight(tp) + sndcnt;
}


void tcp_tb_update_cwnd(struct sock *sk, const struct rate_sample *rs) {
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_tb *ca = inet_csk_ca(sk);
	int acked = rs->acked_sacked;

	if (tcp_in_cwnd_reduction(sk)) {
		/* Reduce cwnd if state mandates */
		tcp_tb_cwnd_reduction(sk, rs);
	} else {
		if (tcp_tb_in_slow_start(ca)) {
			acked = tcp_slow_start(tp, acked);
			if (!acked)
				return;
			}
		/* In dangerous area, increase slowly. */
		tcp_cong_avoid_ai(tp, tp->snd_cwnd, acked);
	}
}

static void tcp_tb_pkts_acked(struct sock *sk, const struct ack_sample *sample) {
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_tb *ca = inet_csk_ca(sk);
	u64 now = ktime_get_ns();
	u64 rtt_ns = sample->rtt_us * 1000;
	int removed;
	u64 delta;

	if (sample->rtt_us > 0)
		ca->rtt = rtt_ns;

	if (before(tp->snd_una, ca->NlastAck) || tp->snd_una == ca->NlastAck) {
		return;	// ignore duplicate acks
	}

	ca->NlastAck = tp->snd_una;
	removed = remove_packets(ca, tp->snd_una);

	if (ca->state == TCP_CA_Loss) {
		return;
	}

	if (ca->state == TCP_CA_Recovery) {
		ca->postRecovery = true;
		return;
	}


	if (ca->postRecovery) {
		ca->Ntx = tp->snd_ssthresh * (tp->snd_ssthresh - 1) / 2 + 1;
	 	ca->Nak = ca->Ntx;
	 	ca->Ttx = now;
		ca->Tak = now + ca->rtt;
		ca->postRecovery = false;
	} else if (removed > 0) {
		ca->Tak = now;
		kernel_fpu_begin();
		delta = delta_time_mult_rtt(ca, ca->Nak, sample->pkts_acked, ca->rtt);
		kernel_fpu_end();
		ca->Tak = ca->Tak + delta;
		ca->Nak = ca->Nak + sample->pkts_acked;
	}

	if (ca->stalled) {
		ca->stalled = false;
		tcp_tb_pace(&tp->event_timer, now);
	}
}


static void tcp_tb_main(struct sock *sk, const struct rate_sample *rs) {

	tcp_tb_update_cwnd(sk, rs);
}

struct tcp_congestion_ops tcp_tb_ops = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "timer_based",
	.init		= tcp_tb_init,
	.release	= tcp_tb_release,
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_tb_ssthresh,
	.cong_control	= tcp_tb_main,
	.undo_cwnd	= tcp_tb_undo_cwnd,
	.min_tso_segs	= tcp_tb_min_tso_segs,
	.event_handler  = tcp_tb_event_handler,
	.set_state	= tcp_tb_set_state,
	.pkts_acked     = tcp_tb_pkts_acked,
};

static int __init tb_register(void)
{
	printk(KERN_DEBUG "Registering timer based congestion control\n");
	tcp_register_congestion_control(&tcp_tb_ops);
	return 0;
}

static void __exit tb_unregister(void)
{
	printk(KERN_DEBUG "Unregistering timer based congestion control\n");
	tcp_unregister_congestion_control(&tcp_tb_ops);
}

module_init(tb_register);
module_exit(tb_unregister);
