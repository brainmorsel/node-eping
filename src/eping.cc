#define BUILDING_NODE_EXTENSION
#include <v8.h>
#include <node.h>


#include <uv.h>
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

// sleep, getpid
#include <unistd.h>

#include <vector>

using namespace v8;

//#define DEBUG

namespace {

#ifdef DEBUG
#define DEBUG_MSG(format, ...) fprintf(stderr, "%s:%d " format "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define DEBUG_EXP(format, exp) fprintf(stderr, "%s:%d " #exp " = " format "\n", __FILE__, __LINE__, (exp))
#else
#define DEBUG_MSG(format, ...)
#define DEBUG_EXP(format, exp)
#endif


#define PACKETSIZE	64
typedef struct {
	struct icmphdr hdr;
	uint8_t payload[PACKETSIZE - sizeof(struct icmphdr)];
} icmp_packet_t;

typedef union packet_u {
	uint8_t raw[PACKETSIZE];
	icmp_packet_t icmp_req;
	struct {
		struct ip iphdr;
		icmp_packet_t pckt;
	} icmp_res;
} packet_t;

/* standard 1s complement checksum */
static uint16_t checksum (void *b, int len)
{	unsigned short *buf = (unsigned short *) b;
	unsigned int sum=0;
	unsigned short result;

	for ( sum = 0; len > 1; len -= 2 )
		sum += *buf++;
	if ( len == 1 )
		sum += *(unsigned char*)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

static void dump_packet (icmp_packet_t *icmp) {
	uint8_t *raw = (uint8_t *) icmp;

	printf("type: %d code: %d checksum: %d/%d id: %d seq: %d\n",
			icmp->hdr.type, icmp->hdr.code,
			icmp->hdr.checksum, checksum(icmp, sizeof(*icmp)),
			icmp->hdr.un.echo.id, icmp->hdr.un.echo.sequence);
	unsigned int i;
	for (i = 0; i < sizeof(*icmp); i++) {
		if (i % 16 == 0) printf("\n");
		printf("%02X ", raw[i]);
	}
	printf("\n------------------------------------\n");
}


typedef struct {
	struct sockaddr sa;
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint8_t responded;
} HostItem;

/* *******************************************************************
 * Pinger object
 * *******************************************************************/
class Eping: public node::ObjectWrap {
  public:
	static void Init (Handle<Object> target);

  private:
	uv_timer_t t_timeout;
	uv_timer_t t_towrite;
	uv_poll_t poll_socket;

	// options
	std::vector<HostItem> hosts;
	int max_packets_to_send;
	int packets_send_period;
	int timeout_time;
	// runtime data
	unsigned int packets_sent_on_cur_iteration;
	unsigned int hosts_responded;
	uint16_t sequence_id;
	uint16_t packets_id;

	Eping(const Arguments&);
	~Eping();
	void start ();
	void stop ();
	void emit_one (HostItem*);
	void emit_all ();
	void emit_error (const char*);
	void emit_perror (const char*);
	static void on_timeout (uv_timer_t*, int);
	static void on_towrite (uv_timer_t*, int);
	static void on_socket_ready (uv_poll_t*, int, int);

	// JS public interface:
	static Handle<Value> Constructor (const Arguments&);
	static Handle<Value> Start (const Arguments&);
	static Handle<Value> Stop (const Arguments&);
};

Eping::Eping (const Arguments& args) {
	HandleScope scope;

	packets_id = getpid();
	uv_timer_init(uv_default_loop(), &t_timeout);
	t_timeout.data = this;
	uv_timer_init(uv_default_loop(), &t_towrite);
	t_towrite.data = this;

	// init options
	Local<Array> host_arr = Local<Array>::Cast(args[0]);
	hosts = std::vector<HostItem>(host_arr->Length());

	unsigned int idx;
	for (idx = 0; idx < hosts.size(); idx++) {
		HandleScope forScope;

		Local<Value> arr_itm = host_arr->Get(Integer::New(idx));
		if (!arr_itm->IsString()) {
			ThrowException(Exception::TypeError(String::New("Array must contain strings")));
			return;
		}
		// convert to c-string
		String::Utf8Value str(arr_itm);
		const char *host_ip = *str;

		struct sockaddr *sa = &hosts[idx].sa;
		sa->sa_family = AF_INET;
		inet_pton(sa->sa_family, host_ip, &((sockaddr_in *) sa)->sin_addr);

		// mark all targets as timed out by dafault
		hosts[idx].icmp_type = ICMP_TIME_EXCEEDED;
		hosts[idx].icmp_code = 255;
	}

	max_packets_to_send = 3;
	packets_send_period = 10;
	timeout_time = 3000;
}
Eping::~Eping () {
}

void
Eping::start () {
	// reset runtime data
	packets_sent_on_cur_iteration = 0;
	sequence_id = 0;
	hosts_responded = 0;

	// init raw socket
	int ttl_val = 64;
	int sd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
	if ( sd < 0 )
	{
		emit_perror("open raw socket");
		return;
	}
	if ( setsockopt(sd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
		emit_perror("set TTL option");
		return;
	}
	if ( fcntl(sd, F_SETFL, O_NONBLOCK) != 0 ) {
		emit_perror("sequest nonblocking I/O");
		return;
	}

	uv_poll_init(uv_default_loop(), &poll_socket, sd);
	poll_socket.data = this;

	uv_timer_start(&t_towrite, (uv_timer_cb) on_towrite, 0, packets_send_period);
}

void
Eping::stop () {
	// stop and close everything
	uv_timer_stop(&t_timeout);
	uv_timer_stop(&t_towrite);
	uv_poll_stop(&poll_socket);
	close(poll_socket.fd);
}

void
Eping::emit_one (HostItem* hi) {
	HandleScope scope;
	char addr_str[INET_ADDRSTRLEN];
	struct sockaddr_in* sa = (struct sockaddr_in*) &hi->sa;

	inet_ntop(AF_INET, &sa->sin_addr, addr_str, INET_ADDRSTRLEN);

	Handle<Value> argv[] = {
		String::New("one"), // event name
		String::New(addr_str),
		Boolean::New(hi->icmp_type == 0)
	};
	node::MakeCallback(handle_, "emit", 3, argv);
}

void
Eping::emit_all () {
	HandleScope scope;

	Local<Array> result = Array::New(hosts.size());
	unsigned int idx;
	for (idx = 0; idx < hosts.size(); idx++) {
		HostItem *hi = &hosts[idx];
		result->Set(Integer::New(idx), Boolean::New(hi->icmp_type == ICMP_ECHOREPLY));
	}

	Handle<Value> argv[] = {
		String::New("all"), // event name
		result
	};
	node::MakeCallback(handle_, "emit", 2, argv);
}

void
Eping::emit_error (const char* errstr) {
	HandleScope scope;

	Handle<Value> argv[] = {
		String::New("error"), // event name
		Exception::Error(String::New(errstr))
	};
	node::MakeCallback(handle_, "emit", 2, argv);
}

void
Eping::emit_perror (const char* s) {
	char buf[1024];

	snprintf(buf, sizeof(buf), "%s: %s", s, strerror(errno));
	emit_error(buf);
}

void
Eping::on_timeout (uv_timer_t *req, int t) {
	Eping *self = (Eping *) req->data;

	self->stop();
	self->emit_all();
}

void
Eping::on_towrite (uv_timer_t *req, int t) {
	Eping *self = (Eping *) req->data;

	// it's time to send next packet, siwtch to r/w mode
	uv_poll_start(&self->poll_socket, UV_READABLE | UV_WRITABLE, on_socket_ready);
}

void
Eping::on_socket_ready (uv_poll_t *req, int status, int events) {
	Eping *self = (Eping *) req->data;
	packet_t pckt;
	icmp_packet_t *i_p;

	if (events & UV_WRITABLE) {
		struct sockaddr *sa = &self->hosts[self->packets_sent_on_cur_iteration].sa;
		i_p = &pckt.icmp_req;

		// prepare icmp packet
		bzero(i_p, sizeof(*i_p));
		i_p->hdr.type = ICMP_ECHO;
		i_p->hdr.un.echo.id = self->packets_id;
		i_p->hdr.un.echo.sequence = self->sequence_id;
		i_p->hdr.checksum = checksum(i_p, sizeof(*i_p));

#ifdef DEBUG
		dump_packet(i_p);
#endif
		if ( sendto(req->fd, i_p, sizeof(*i_p), 0, sa, sizeof(*sa)) <= 0 ) {
			self->stop();
			self->emit_perror("sendto");
			return;
		}

		self->packets_sent_on_cur_iteration++;

		if (self->packets_sent_on_cur_iteration == self->hosts.size()) {
			if (0 == self->sequence_id) {
				uv_timer_start(&self->t_timeout, (uv_timer_cb) on_timeout, self->timeout_time, 0);
			}
			self->sequence_id++;
			self->packets_sent_on_cur_iteration = 0;

			if (self->sequence_id == self->max_packets_to_send) {
				// stop send anything
				uv_timer_stop(&self->t_towrite);
			}
		}

		// we need wait a little before send next packet, switch to read-only mode
		uv_poll_start(&self->poll_socket, UV_READABLE, on_socket_ready);
	}
	
	if (events & UV_READABLE) {
		struct sockaddr r_addr;
		struct sockaddr_in *sa1, *sa2;
		socklen_t len = sizeof(r_addr);
		size_t size;

		if ((size = recvfrom(req->fd, &pckt, sizeof(pckt), 0, &r_addr, &len)) > 0 ) {
			i_p = &pckt.icmp_res.pckt;
			sa1 = (struct sockaddr_in *) &r_addr;
#ifdef DEBUG
			dump_packet(i_p);
#endif
			if (i_p->hdr.un.echo.id == self->packets_id && i_p->hdr.type != ICMP_ECHO) {
				// it's our packets, lets see what within
				unsigned int idx;
				for (idx = 0; idx < self->hosts.size(); idx++) {
					HostItem *hi = &self->hosts[idx];
					sa2 = (struct sockaddr_in *) &hi->sa;
					if ( sa1->sin_addr.s_addr == sa2->sin_addr.s_addr ) {
						if (!hi->responded) {
							hi->icmp_type = i_p->hdr.type;
							hi->icmp_code = i_p->hdr.code;
							hi->responded = 1;

							self->emit_one(hi);

							self->hosts_responded++;

							if (self->hosts_responded == self->hosts.size()) {
								self->stop();
								self->emit_all();
							}
						}
					}
				}
			}
		}
	}
}


/* *******************************************************************
 * JS Interface
 * *******************************************************************/
Handle<Value>
Eping::Constructor (const Arguments& args) {
	HandleScope scope;

	assert(args.IsConstructCall());
	if (args.Length() < 1) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
		return scope.Close(Undefined());
	}
	if (!args[0]->IsArray()) {
		ThrowException(Exception::TypeError(String::New("Wrong arguments")));
		return scope.Close(Undefined());
	}

	Eping* self = new Eping(args);
	self->Wrap(args.This());

	return scope.Close(args.This());
}

Handle<Value>
Eping::Start (const Arguments& args) {
	HandleScope scope;
	Eping* self = node::ObjectWrap::Unwrap<Eping>(args.This());

	self->start();

	return scope.Close(args.This());
}

void
Eping::Init (Handle<Object> target) {
	HandleScope scope;

	Local<FunctionTemplate> t = FunctionTemplate::New(Eping::Constructor);
	t->InstanceTemplate()->SetInternalFieldCount(1);
	t->SetClassName(String::New("Eping"));
	NODE_SET_PROTOTYPE_METHOD(t, "start", Eping::Start);

	target->Set(String::NewSymbol("Eping"), t->GetFunction());
}


extern "C" void init (Handle<Object> target) {
	Eping::Init(target);
}

} // anonymous namespace
