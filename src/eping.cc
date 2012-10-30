#define BUILDING_NODE_EXTENSION
#include <v8.h>
#include <node.h>

#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <inttypes.h>

#include <vector>

using namespace v8;

namespace {

//#define DEBUG

#ifdef DEBUG
#define DEBUG_MSG(format, ...) fprintf(stderr, "%s:%d " format "\n", __FILE__, __LINE__, ## __VA_ARGS__)
#define DEBUG_EXP(format, exp) fprintf(stderr, "%s:%d " #exp " = " format "\n", __FILE__, __LINE__, (exp))
#else
#define DEBUG_MSG(format, ...)
#define DEBUG_EXP(format, exp)
#endif

#define MAX(a, b) (a > b ? a : b)

#define PACKETSIZE	64
typedef struct {
	struct icmphdr hdr;
	uint32_t ts;
	uint8_t payload[PACKETSIZE - sizeof(struct icmphdr) - sizeof(ts)];
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
static uint16_t
checksum (void *b, int len)
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

static uint32_t
get_monotonic_time () {
	timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (ts.tv_sec / 1000 + ts.tv_nsec / 1000000);
}

static uint32_t
get_monotonic_time_diff (uint32_t start, uint32_t end) {
	return end - start;
}

#ifdef DEBUG
static void
dump_packet (icmp_packet_t *icmp) {
	uint8_t *raw = (uint8_t *) icmp;
	uint32_t te = get_monotonic_time();

	printf("type: %d code: %d checksum: %d/%d id: %d seq: %d time diff: %d ms\n",
			icmp->hdr.type, icmp->hdr.code,
			icmp->hdr.checksum, checksum(icmp, sizeof(*icmp)),
			icmp->hdr.un.echo.id, icmp->hdr.un.echo.sequence,
			get_monotonic_time_diff(icmp->ts, te)
			);
	unsigned int i;
	for (i = 0; i < sizeof(*icmp); i++) {
		if (i % 16 == 0) printf("\n");
		printf("%02X ", raw[i]);
	}
	printf("\n------------------------------------\n");
}
#endif // DEBUG

typedef struct {
	struct sockaddr sa;
	uint8_t responded;
	uint8_t is_up;
} HostItem;

/* *******************************************************************
 * Pinger object
 * *******************************************************************/
#define MY_UV_TIMER_CB_DEF(classname, methodname) \
	static void methodname##_wrapper (uv_timer_t *handle, int status) {\
		classname *self = (classname *) handle->data;\
		self->methodname(handle, status);\
	};\
	void methodname (uv_timer_t*, int);

#define MY_UV_POLL_CB_DEF(classname, methodname) \
	static void methodname##_wrapper (uv_poll_t *handle, int status, int events) {\
		classname *self = (classname *) handle->data;\
		self->methodname(handle, status, events);\
	};\
	void methodname (uv_poll_t*, int, int);

#define MY_UV_TIMER_CB(classname, methodname) \
	((uv_timer_cb) &classname::methodname##_wrapper)

#define MY_UV_POLL_CB(classname, methodname) \
	((uv_poll_cb) &classname::methodname##_wrapper)

#define MY_UV_TIMER_INIT(timer) \
	uv_timer_init(uv_default_loop(), (timer));\
	(timer)->data = this;

#define MY_UV_POLL_INIT(handle, fd) \
	uv_poll_init(uv_default_loop(), (handle), fd);\
	(handle)->data = this;


class Eping: public node::ObjectWrap {
  public:
	static void Init (Handle<Object> target);

  private:
	uv_timer_t t_timeout;
	uv_timer_t t_towrite;
	uv_timer_t t_seq_timer;
	uv_poll_t poll_socket;

	// options
	std::vector<HostItem> hosts;
	int sequence_size;
	int packets_send_period;
	int timeout_time;
	int sequence_time;
	// runtime data
	unsigned int cur_host;
	unsigned int hosts_responded;
	uint16_t sequence_id;
	uint16_t packets_id;

	Eping(const Arguments&);
	~Eping();
	void start ();
	void stop ();
	void emit_one (HostItem*, icmp_packet_t*);
	void emit_all ();
	void emit_error (const char*);
	void emit_perror (const char*);
	void socket_write_mode (bool);

	MY_UV_POLL_CB_DEF(Eping, on_socket_ready)
	MY_UV_TIMER_CB_DEF(Eping, on_timeout)
	MY_UV_TIMER_CB_DEF(Eping, on_towrite)
	MY_UV_TIMER_CB_DEF(Eping, on_seq_timer)

	// JS public interface:
	static Handle<Value> Constructor (const Arguments&);
	static Handle<Value> Start (const Arguments&);
	static Handle<Value> Stop (const Arguments&);
};

Eping::Eping (const Arguments& args) {
	HandleScope scope;

	packets_id = getpid();

	MY_UV_TIMER_INIT(&t_timeout)
	MY_UV_TIMER_INIT(&t_towrite)
	MY_UV_TIMER_INIT(&t_seq_timer)

	// init options
	Local<Array> host_arr;
	// defaults:
	sequence_size = 1;
	packets_send_period = 1; // ms
	timeout_time = 1000;     // ms
	sequence_time = 1000;    // ms
	
	if (args[0]->IsObject()) {
		Local<Object> obj = Local<Object>::Cast(args[0]);
		if (obj->Has(String::NewSymbol("hosts"))) {
			host_arr = Local<Array>::Cast(obj->Get(String::NewSymbol("hosts")));
		}
		if 	(obj->Has(String::NewSymbol("timeout"))) {
			timeout_time = MAX(1, Local<Integer>::Cast(obj->Get(String::NewSymbol("timeout")))->Value());
		}
		if 	(obj->Has(String::NewSymbol("wait"))) {
			sequence_time = MAX(1, Local<Integer>::Cast(obj->Get(String::NewSymbol("wait")))->Value());
		}
		if 	(obj->Has(String::NewSymbol("period"))) {
			packets_send_period = MAX(1, Local<Integer>::Cast(obj->Get(String::NewSymbol("period")))->Value());
		}
		if 	(obj->Has(String::NewSymbol("tryouts"))) {
			sequence_size = MAX(1, Local<Integer>::Cast(obj->Get(String::NewSymbol("tryouts")))->Value());
		}
	} else {
		host_arr = Local<Array>::Cast(args[0]);
	}

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
	}
}
Eping::~Eping () {
}

void
Eping::start () {
	// reset runtime data
	cur_host = 0;
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

	MY_UV_POLL_INIT(&poll_socket, sd)

	uv_timer_start(&t_towrite, MY_UV_TIMER_CB(Eping, on_towrite), 0, packets_send_period);
}

void
Eping::stop () {
	// stop and close everything
	uv_timer_stop(&t_timeout);
	uv_timer_stop(&t_towrite);
	uv_timer_stop(&t_seq_timer);
	uv_poll_stop(&poll_socket);
	close(poll_socket.fd);
}

void
Eping::emit_one (HostItem* hi, icmp_packet_t* icmp) {
	HandleScope scope;
	char addr_str[INET_ADDRSTRLEN];
	struct sockaddr_in* sa = (struct sockaddr_in*) &hi->sa;

	inet_ntop(AF_INET, &sa->sin_addr, addr_str, INET_ADDRSTRLEN);
	hi->is_up = icmp->hdr.type == ICMP_ECHOREPLY;

	Local<Object> details = Object::New();
	details->Set(String::NewSymbol("icmp_type_id"), Integer::New(icmp->hdr.type));
	details->Set(String::NewSymbol("icmp_code_id"), Integer::New(icmp->hdr.code));
	details->Set(String::NewSymbol("responce_time"), Integer::New(
				get_monotonic_time_diff(icmp->ts, get_monotonic_time())));

	Handle<Value> argv[] = {
		String::New("one"), // event name
		String::New(addr_str),
		Boolean::New(hi->is_up),
		details
	};
	node::MakeCallback(handle_, "emit", sizeof(argv)/sizeof(argv[0]), argv);

	if (!hi->responded) {
		hi->responded = 1;
		hosts_responded++;

		if (hosts_responded == hosts.size()) {
			stop();
			emit_all();
		}
	}
}

void
Eping::emit_all () {
	HandleScope scope;

	Local<Array> result = Array::New(hosts.size());
	unsigned int idx;
	for (idx = 0; idx < hosts.size(); idx++) {
		HostItem *hi = &hosts[idx];
		result->Set(Integer::New(idx), Boolean::New(hi->is_up));
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
Eping::socket_write_mode (bool isOn) {
	if (isOn) {
		uv_poll_start(&poll_socket, UV_READABLE | UV_WRITABLE, MY_UV_POLL_CB(Eping, on_socket_ready));
	} else {
		uv_poll_start(&poll_socket, UV_READABLE, MY_UV_POLL_CB(Eping, on_socket_ready));
	}
}

void
Eping::on_timeout (uv_timer_t *handle, int status) {
	stop();
	emit_all();
}

void
Eping::on_towrite (uv_timer_t *handle, int status) {
	// it's time to send next packet, switch to r/w mode
	socket_write_mode(true);
}

void
Eping::on_seq_timer (uv_timer_t *handle, int status) {
	socket_write_mode(true);
	uv_timer_start(&t_towrite, MY_UV_TIMER_CB(Eping, on_towrite), 0, packets_send_period);
}
void
Eping::on_socket_ready (uv_poll_t *req, int status, int events) {
	packet_t pckt;
	icmp_packet_t *i_p;

	if (events & UV_WRITABLE) {
		// we need wait a little before send next packet, switch to read-only mode
		socket_write_mode(false);

		// skip responded hosts
		while ( hosts[cur_host].responded && cur_host < hosts.size() )
			cur_host++;

		if (cur_host < hosts.size()) {
			struct sockaddr *sa = &hosts[cur_host].sa;
			i_p = &pckt.icmp_req;

			// prepare icmp packet
			bzero(i_p, sizeof(*i_p));
			i_p->hdr.type = ICMP_ECHO;
			i_p->hdr.un.echo.id = packets_id;
			i_p->hdr.un.echo.sequence = sequence_id;
			i_p->ts = get_monotonic_time();
			i_p->hdr.checksum = checksum(i_p, sizeof(*i_p));

			if ( sendto(req->fd, i_p, sizeof(*i_p), 0, sa, sizeof(*sa)) <= 0 ) {
				stop();
				emit_perror("sendto");
				return;
			}

			cur_host++;
		}
		if (cur_host == hosts.size()) {
			sequence_id++;
			cur_host = 0;

			// disable write loop
			uv_timer_stop(&t_towrite);

			if (sequence_id < sequence_size) {
				// wait before turn on write mode
				uv_timer_start(&t_seq_timer, MY_UV_TIMER_CB(Eping, on_seq_timer), sequence_time, 0);
			} else {
				// no more packets to send, just wait
				uv_timer_start(&t_timeout, MY_UV_TIMER_CB(Eping, on_timeout), timeout_time, 0);
			}
		}
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
			if (i_p->hdr.un.echo.id == packets_id && i_p->hdr.type != ICMP_ECHO) {
				// it's our packets, lets see what within
				unsigned int idx;
				for (idx = 0; idx < hosts.size(); idx++) {
					HostItem *hi = &hosts[idx];
					sa2 = (struct sockaddr_in *) &hi->sa;
					if ( sa1->sin_addr.s_addr == sa2->sin_addr.s_addr ) {
						emit_one(hi, i_p);
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
	if (args.Length() != 1) {
		ThrowException(Exception::TypeError(String::New("Wrong number of arguments")));
		return scope.Close(Undefined());
	}
	if (!(args[0]->IsArray() || args[0]->IsObject())) {
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
