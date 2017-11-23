package tcpip

import (
	"errors"
	"log"
)

func tcp_init_segment(tcph *tcphdr, skb *sk_buff) {
	// th->sport = ntohs(th->sport);
	// th->dport = ntohs(th->dport);
	// th->seq = ntohl(th->seq);
	// th->ack_seq = ntohl(th->ack_seq);
	// th->win = ntohs(th->win);
	// th->csum = ntohs(th->csum);
	// th->urp = ntohs(th->urp);

	// skb->seq = th->seq;
	// skb->dlen = ip_len(ih) - tcp_hlen(th);
	// skb->len = skb->dlen + th->syn + th->fin;
	// skb->end_seq = skb->seq + skb->dlen;
	// skb->payload = th->data;

	skb.seq = tcph.seq
	skb.end_seq = tcph.seq + uint32(len(skb.end))
	skb.payload = tcph.data
}

func tcp_in(skb *sk_buff) error {
	iph := ipv4_decode(skb)
	th := tcphdr_decode(skb)

	tcp_init_segment(th, skb)

	// sk = inet_lookup(skb, th->sport, th->dport);

	// if (sk == NULL) {
	//     print_err("No TCP socket for sport %d dport %d\n",
	//               th->sport, th->dport);
	//     free_skb(skb);
	//     return;
	// }
	// pthread_rwlock_wrlock(&sk->sock->lock);

	// tcp_in_dbg(th, sk, skb);
	// /* if (tcp_checksum(iph, th) != 0) { */
	// /*     goto discard; */
	// /* } */

	var sk *sock
	tcp_input_state(sk, th, skb)

	// pthread_rwlock_unlock(&sk->sock->lock);
	return nil
}

func tcp_input_state(sk *sock, th *tcphdr, skb *sk_buff) error {
	// struct tcp_sock *tsk = tcp_sk(sk);
	// struct tcb *tcb = &tsk->tcb;

	tsk := sk.tsk
	tcb := tsk.tcb

	log.Println("input state", sk)

	switch sk.state {
	case TCP_CLOSE:
		return tcp_closed(tsk, skb, th)
	case TCP_LISTEN:
		return tcp_listen(tsk, skb, th)
	case TCP_SYN_SENT:
		return tcp_synsent(tsk, skb, th)
	}

	//     /* "Otherwise" section in RFC793 */

	//     /* first check sequence number */
	//     if (!tcp_verify_segment(tsk, th, skb)) {
	//         /* RFC793: If an incoming segment is not acceptable, an acknowledgment
	//          * should be sent in reply (unless the RST bit is set, if so drop
	//          *  the segment and return): */
	//         if (!th.rst) {
	//             tcp_send_ack(sk);
	//         }
	//         return tcp_drop(tsk, skb);
	//     }

	//     /* second check the RST bit */
	//     if (th.rst) {
	//         free_skb(skb);
	//         tcp_enter_time_wait(sk);
	//         tsk.sk.ops.recv_notify(&tsk.sk);
	//         return 0;
	//     }

	//     /* third check security and precedence */
	//     // Not implemented

	//     /* fourth check the SYN bit */
	//     if (th.syn) {
	//         /* RFC 5961 Section 4.2 */
	//         tcp_send_challenge_ack(sk, skb);
	//         return tcp_drop(tsk, skb);
	//     }

	//     /* fifth check the ACK field */
	//     if (!th.ack) {
	//         return tcp_drop(tsk, skb);
	//     }

	//     // ACK bit is on
	//     switch (sk.state) {
	//     case TCP_SYN_RECEIVED:
	//         if (tcb.snd_una <= th.ack_seq && th.ack_seq < tcb.snd_nxt) {
	//             tcp_set_state(sk, TCP_ESTABLISHED);
	//         } else {
	//             return tcp_drop(tsk, skb);
	//         }
	//     case TCP_ESTABLISHED:
	//     case TCP_FIN_WAIT_1:
	//     case TCP_FIN_WAIT_2:
	//     case TCP_CLOSE_WAIT:
	//     case TCP_CLOSING:
	//     case TCP_LAST_ACK:
	//         if (tcb.snd_una < th.ack_seq && th.ack_seq <= tcb.snd_nxt) {
	//             tcb.snd_una = th.ack_seq;
	//             /* Any segments on the retransmission queue which are thereby
	//                entirely acknowledged are removed. */
	//             tcp_rtt(tsk);
	//             tcp_clean_rto_queue(sk, tcb.snd_una);
	//         }

	//         if (th.ack_seq < tcb.snd_una) {
	//             // If the ACK is a duplicate, it can be ignored
	//             return tcp_drop(tsk, skb);
	//         }

	//         if (th.ack_seq > tcb.snd_nxt) {
	//             // If the ACK acks something not yet sent, then send an ACK, drop segment
	//             // and return
	//             // TODO: Dropping the seg here, why would I respond with an ACK? Linux
	//             // does not respond either
	//             //tcp_send_ack(&tsk.sk);
	//             return tcp_drop(tsk, skb);
	//         }

	//         if (tcb.snd_una < th.ack_seq && th.ack_seq <= tcb.snd_nxt) {
	//             // TODO: Send window should be updated
	//         }

	//         break;
	//     }

	//     /* If the write queue is empty, it means our FIN was acked */
	//     if (skb_queue_empty(&sk.write_queue)) {
	//         switch (sk.state) {
	//         case TCP_FIN_WAIT_1:
	//             tcp_set_state(sk, TCP_FIN_WAIT_2);
	//         case TCP_FIN_WAIT_2:
	//             break;
	//         case TCP_CLOSING:
	//             /* In addition to the processing for the ESTABLISHED state, if
	//              * the ACK acknowledges our FIN then enter the TIME-WAIT state,
	//                otherwise ignore the segment. */
	//             tcp_set_state(sk, TCP_TIME_WAIT);
	//             break;
	//         case TCP_LAST_ACK:
	//             /* The only thing that can arrive in this state is an acknowledgment of our FIN.
	//              * If our FIN is now acknowledged, delete the TCB, enter the CLOSED state, and return. */
	//             free_skb(skb);
	//             return tcp_done(sk);
	//         case TCP_TIME_WAIT:
	//             /* TODO: The only thing that can arrive in this state is a
	//                retransmission of the remote FIN.  Acknowledge it, and restart
	//                the 2 MSL timeout. */
	//             if (tcb.rcv_nxt == th.seq) {
	//                 tcpsock_dbg("Remote FIN retransmitted?", sk);
	// //                tcb.rcv_nxt += 1;
	//                 tsk.flags |= TCP_FIN;
	//                 tcp_send_ack(sk);
	//             }
	//             break;
	//         }
	//     }

	//     /* sixth, check the URG bit */
	//     if (th.urg) {

	//     }

	//      expected := skb.seq == tcb.rcv_nxt;

	//     pthread_mutex_lock(&sk.receive_queue.lock);
	//     /* seventh, process the segment txt */
	//     switch (sk.state) {
	//     case TCP_ESTABLISHED:
	//     case TCP_FIN_WAIT_1:
	//     case TCP_FIN_WAIT_2:
	//         if (th.psh || skb.dlen > 0) {
	//             tcp_data_queue(tsk, th, skb);
	//             tsk.sk.ops.recv_notify(&tsk.sk);
	//         }

	//         break;
	//     case TCP_CLOSE_WAIT:
	//     case TCP_CLOSING:
	//     case TCP_LAST_ACK:
	//     case TCP_TIME_WAIT:
	//         /* This should not occur, since a FIN has been received from the
	//            remote side.  Ignore the segment text. */
	//         break;
	//     }

	//     /* eighth, check the FIN bit */
	//     if (th.fin && expected) {
	//         tcpsock_dbg("Received in-sequence FIN", sk);

	//         switch (sk.state) {
	//         case TCP_CLOSE:
	//         case TCP_LISTEN:
	//         case TCP_SYN_SENT:
	//             // Do not process, since SEG.SEQ cannot be validated
	//             goto drop_and_unlock;
	//         }

	//         tcb.rcv_nxt += 1;
	//         tsk.flags |= TCP_FIN;
	//         sk.poll_events |= (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND);

	//         tcp_send_ack(sk);
	//         tsk.sk.ops.recv_notify(&tsk.sk);

	//         switch (sk.state) {
	//         case TCP_SYN_RECEIVED:
	//         case TCP_ESTABLISHED:
	//             tcp_set_state(sk, TCP_CLOSE_WAIT);
	//             break;
	//         case TCP_FIN_WAIT_1:
	//             /* If our FIN has been ACKed (perhaps in this segment), then
	//                enter TIME-WAIT, start the time-wait timer, turn off the other
	//                timers; otherwise enter the CLOSING state. */
	//             if (skb_queue_empty(&sk.write_queue)) {
	//                 tcp_enter_time_wait(sk);
	//             } else {
	//                 tcp_set_state(sk, TCP_CLOSING);
	//             }

	//             break;
	//         case TCP_FIN_WAIT_2:
	//             /* Enter the TIME-WAIT state.  Start the time-wait timer, turn
	//                off the other timers. */
	//             tcp_enter_time_wait(sk);
	//             break;
	//         case TCP_CLOSE_WAIT:
	//         case TCP_CLOSING:
	//         case TCP_LAST_ACK:
	//             /* Remain in the state */
	//             break;
	//         case TCP_TIME_WAIT:
	//             /* TODO: Remain in the TIME-WAIT state.  Restart the 2 MSL time-wait
	//                timeout. */
	//             break;
	//         }
	//     }

	//     /* Congestion control and delacks */
	//     switch (sk.state) {
	//     case TCP_ESTABLISHED:
	//     case TCP_FIN_WAIT_1:
	//     case TCP_FIN_WAIT_2:
	//         if (expected) {
	//             tcp_stop_delack_timer(tsk);

	//              pending := min(skb_queue_len(&sk.write_queue), 3);
	//             /* RFC1122:  A TCP SHOULD implement a delayed ACK, but an ACK should not
	//              * be excessively delayed; in particular, the delay MUST be less than
	//              * 0.5 seconds, and in a stream of full-sized segments there SHOULD
	//              * be an ACK for at least every second segment. */
	//             if (tsk.inflight == 0 && pending > 0) {
	//                 tcp_send_next(sk, pending);
	//                 tsk.inflight += pending;
	//                 tcp_rearm_rto_timer(tsk);
	//             } else if (th.psh || (skb.dlen > 1000 && (tsk.delacks++) > 1)) {
	//                 tsk.delacks = 0;
	//                 tcp_send_ack(sk);
	//             } else if (skb.dlen > 0) {
	//                 tsk.delack = timer_add(200, &tcp_send_delack, &tsk.sk);
	//             }
	//         }
	//     }

	// free_skb(skb);

	// unlock:
	//     pthread_mutex_unlock(&sk.receive_queue.lock);
	//     return 0;
	// drop_and_unlock:
	//     tcp_drop(tsk, skb);
	//     goto unlock;
	return nil
}

func tcp_closed(tsk *tcp_sock, skb *sk_buff, th *tcphdr) error {
	/*
	   All data in the incoming segment is discarded.  An incoming
	   segment containing a RST is discarded.  An incoming segment not
	   containing a RST causes a RST to be sent in response.  The
	   acknowledgment and sequence field values are selected to make the
	   reset sequence acceptable to the TCP that sent the offending
	   segment.

	   If the ACK bit is off, sequence number zero is used,

	     <SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>

	   If the ACK bit is on,

	     <SEQ=SEG.ACK><CTL=RST>

	   Return.
	*/

	// int rc = -1;

	// 	tcpsock_dbg("state is closed", (&tsk->sk));

	if th.flags == TCP_RST {
		// tcp_discard(tsk, skb, th)
		// rc = 0
		// goto out
	}

	if th.flags == TCP_ACK {

	} else {

	}

	// rc = tcp_send_reset(tsk)
	// free_skb(skb)

	return tcp_send_reset(tsk)
	// out:
	// 	return rc;
}

func tcp_send_reset(tsk *tcp_sock) error {
	// struct sk_buff *skb;
	// struct tcphdr *th;
	// struct tcb *tcb;
	// int rc = 0;

	// skb = tcp_alloc_skb(0, 0);
	// th = tcp_hdr(skb);
	// tcb = &tsk->tcb;

	// th->rst = 1;
	// tcb->snd_una = tcb->snd_nxt;

	// rc = tcp_transmit_skb(&tsk->sk, skb, tcb->snd_nxt);
	// free_skb(skb);

	return nil
}

func tcp_listen(tsk *tcp_sock, skb *sk_buff, th *tcphdr) error {
	// free_skb(skb);
	// return 0;
	return nil
}

func tcp_synsent(tsk *tcp_sock, skb *sk_buff, th *tcphdr) error {
	//     struct tcb *tcb = &tsk->tcb;
	//     struct sock *sk = &tsk->sk;

	//     tcpsock_dbg("state is synsent", sk);

	//     if (th->ack) {
	//         if (th->ack_seq <= tcb->iss || th->ack_seq > tcb->snd_nxt) {
	//             tcpsock_dbg("ACK is unacceptable", sk);

	//             if (th->rst) goto discard;
	//             goto reset_and_discard;
	//         }

	//         if (th->ack_seq < tcb->snd_una || th->ack_seq > tcb->snd_nxt) {
	//             tcpsock_dbg("ACK is unacceptable", sk);
	//             goto reset_and_discard;
	//         }
	//     }

	sk := tsk.sk
	tcb := tsk.tcb
	if th.flags&TCP_ACK == TCP_ACK {
		if th.ack_seq <= tcb.iss || th.ack_seq > tcb.snd_nxt {
			return errors.New("ACK is unacceptable")
		}
		if th.ack_seq < tcb.snd_una || th.ack_seq > tcb.snd_nxt {
			return errors.New("ACK is unacceptable")
		}
	}

	//     /* ACK is acceptable */

	//     if (th->rst) {
	//         tcp_reset(&tsk->sk);
	//         goto discard;
	//     }

	if th.flags&TCP_RST == TCP_RST {
		return errors.New("tcp rst")
	}

	//     /* third check the security and precedence -> ignored */

	//     /* fourth check the SYN bit */
	//     if (!th->syn) {
	//         goto discard;
	//     }

	if th.flags&TCP_SYN != TCP_SYN {
		return errors.New("tcp is't syn")
	}

	//     tcb->rcv_nxt = th->seq + 1;
	//     tcb->irs = th->seq;
	//     if (th->ack) {
	//         tcb->snd_una = th->ack_seq;
	//         /* Any packets in RTO queue that are acknowledged here should be removed */
	//         tcp_clean_rto_queue(sk, tcb->snd_una);
	//     }

	//     if (tcb->snd_una > tcb->iss) {
	//         tcp_set_state(sk, TCP_ESTABLISHED);
	//         tcb->snd_una = tcb->snd_nxt;
	//         tsk->backoff = 0;
	//         /* RFC 6298: Sender SHOULD set RTO <- 1 second */
	//         tsk->rto = 1000;
	//         tcp_send_ack(&tsk->sk);
	//         tcp_rearm_user_timeout(&tsk->sk);
	//         sock_connected(sk);
	//     } else {
	//         tcp_set_state(sk, TCP_SYN_RECEIVED);
	//         tcb->snd_una = tcb->iss;
	//         tcp_send_synack(&tsk->sk);
	//     }

	tcb.rcv_nxt = th.seq + 1
	tcb.irs = th.seq

	tcp_set_state(sk, TCP_SYN_RECEIVED)
	tcb.snd_una = tcb.iss

	err := tcp_send_synack(sk)

	// discard:
	//     tcp_drop(tsk, skb);
	//     return 0;
	// reset_and_discard:
	//     //TODO reset
	//     tcp_drop(tsk, skb);
	//     return 0;
	return err
}

func tcp_send_synack(sk *sock) error {
	if sk.state == TCP_CLOSE {
		return errors.New("tcp closed")
	}

	// struct sk_buff *skb;
	// struct tcphdr *th;
	// struct tcb *tcb = &tcp_sk(sk).tcb;
	// int rc = 0;

	// skb = tcp_alloc_skb(0, 0);

	// th = tcp_hdr(skb);
	// th.ack = 1;

	// rc = tcp_transmit_skb(sk, skb, tcb.snd_nxt);
	// free_skb(skb);

	// return rc;

	skb := tcp_alloc_skb(0, 0)
	th := &tcphdr{
		flags: TCP_ACK,
	}
	tcphdr_encode(skb, th)
	tcb := sk.tsk.tcb

	return tcp_transmit_skb(sk, skb, tcb.snd_nxt)

}
