package tcpip

import "errors"
import "container/list"

func tcp_select_initial_window(rwnd *uint32) {
	*rwnd = 44477
}

func tcp_connect(sk *sock) error {
	if sk == nil {
		return errors.New("sock is nil")
	}
	if sk.tsk == nil {
		sk.tsk = new(tcp_sock)
	}
	if sk.write_queue == nil {
		sk.write_queue = list.New()
	}
	if sk.receive_queue == nil {
		sk.receive_queue = list.New()
	}

	tsk := sk.tsk
	tcb := &tsk.tcb
	tsk.sk = sk

	tsk.smss = 1460
	tsk.rmss = 1460

	tcb.iss = generate_iss()
	tcb.snd_wnd = 0
	tcb.snd_wl1 = 0

	tcb.snd_una = tcb.iss
	tcb.snd_up = tcb.iss
	tcb.snd_nxt = tcb.iss
	tcb.rcv_nxt = 0

	tcp_select_initial_window(&tsk.tcb.rcv_wnd)

	err := tcp_send_syn(sk)
	tcb.snd_nxt++
	return err
}

func tcp_send_syn(sk *sock) error {
	if sk.state != TCP_SYN_SENT && sk.state != TCP_CLOSE && sk.state != TCP_LISTEN {
		return errors.New("Socket was not in correct state (closed or listen)")
	}

	// struct sk_buff *skb;
	// struct tcphdr *th;
	// struct tcp_options opts = { 0 };
	// int tcp_options_len = 0;

	// tcp_options_len = tcp_syn_options(sk, &opts);
	// skb = tcp_alloc_skb(tcp_options_len, 0);
	// th = tcp_hdr(skb);

	// tcp_write_options(th, &opts, tcp_options_len)
	// sk.state = TCP_SYN_SENT
	// th.syn = 1

	skb := tcp_alloc_skb(0, 0)
	skb.head = skb.head[ETH_HDR_LEN+IP_HDR_LEN:]
	th := &tcphdr{
		flags: TCP_SYN,
	}
	sk.state = TCP_SYN_SENT
	tcphdr_encode(skb, th)

	return tcp_queue_transmit_skb(sk, skb)
}

func tcp_write_options(skb *sk_buff, opts *tcp_options) {

}

func tcp_syn_options(sk *sock) *tcp_options {
	// struct tcp_sock *tsk = tcp_sk(sk);
	// int optlen = 0;

	// opts->mss = tsk->rmss;
	// optlen += TCP_OPTLEN_MSS;
	return &tcp_options{
		mss: sk.tsk.rmss,
	}
}

func tcp_queue_transmit_skb(sk *sock, skb *sk_buff) error {
	// struct tcp_sock *tsk = tcp_sk(sk);
	// struct tcb *tcb = &tsk->tcb;
	// int rc = 0;

	// pthread_mutex_lock(&sk->write_queue.lock);

	// if (skb_queue_empty(&sk->write_queue)) {
	//     tcp_rearm_rto_timer(tsk);
	// }

	tsk := sk.tsk
	tcb := tsk.tcb
	// if tsk.inflight < 3 {
	/* Store sequence information into the socket buffer */

	err := tcp_transmit_skb(sk, skb, tcb.snd_nxt)
	if err != nil {
		return err
	}
	// tsk.inflight++
	// }

	// skb.seq = tcb.snd_nxt
	// tcb.snd_nxt += skb.dlen
	// skb.end_seq = tcb.snd_nxt

	// sk.write_queue.PushBack(skb)

	return nil
}

func tcp_transmit_skb(sk *sock, skb *sk_buff, seq uint32) error {
	// struct tcp_sock *tsk = tcp_sk(sk);
	// struct tcb *tcb = &tsk->tcb;
	// struct tcphdr *thdr = tcp_hdr(skb);

	// /* No options were previously set */
	// if (thdr->hl == 0) thdr->hl = TCP_DOFFSET;

	// skb_push(skb, thdr->hl * 4);

	// thdr->sport = sk->sport;
	// thdr->dport = sk->dport;
	// thdr->seq = seq;
	// thdr->ack_seq = tcb->rcv_nxt;
	// thdr->rsvd = 0;
	// thdr->win = tcb->rcv_wnd;
	// thdr->csum = 0;
	// thdr->urp = 0;

	tcb := sk.tsk.tcb
	th := tcphdr_decode(skb)
	th.sport = sk.sport
	th.dport = sk.dport
	th.seq = seq
	th.ack_seq = tcb.rcv_nxt
	th.rsvd = 0
	th.win = uint16(tcb.rcv_wnd)
	th.csum = 0
	th.urp = 0
	tcphdr_encode(skb, th)

	// tcp_out_dbg(thdr, sk, skb);

	// thdr->sport = htons(thdr->sport);
	// thdr->dport = htons(thdr->dport);
	// thdr->seq = htonl(thdr->seq);
	// thdr->ack_seq = htonl(thdr->ack_seq);
	// thdr->win = htons(thdr->win);
	// thdr->csum = htons(thdr->csum);
	// thdr->urp = htons(thdr->urp);
	// thdr->csum = tcp_v4_checksum(skb, htonl(sk->saddr), htonl(sk->daddr));

	return ip_output(sk, skb)
}
