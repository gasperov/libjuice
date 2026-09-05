/**
 * Standalone throughput benchmark comparing TURN relay transports (UDP, TCP, TLS).
 *
 * Not part of the ctest suite: run manually against a real TURN/TURNS deployment.
 *
 * Required environment variables:
 *   TURN_HOST, TURN_PORT, TURN_USERNAME, TURN_PASSWORD   (for UDP and TCP transports)
 *   TURNS_HOST, TURNS_PORT, TURNS_USERNAME, TURNS_PASSWORD (for the TLS transport)
 * Either group may be omitted; the corresponding transport(s) are skipped.
 *
 * Optional:
 *   BENCH_DURATION_MS (default 5000)
 */

#include "juice/juice.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
static void sleep_ms(int ms) { Sleep(ms); }
static uint64_t now_ms(void) { return GetTickCount64(); }
#else
#include <time.h>
#include <unistd.h>
static void sleep_ms(int ms) { usleep(ms * 1000); }
static uint64_t now_ms(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
#endif

#define PAYLOAD_SIZE 1024
#define DEFAULT_DURATION_MS 5000
#define DRAIN_IDLE_MS 500
#define DRAIN_TIMEOUT_MS 5000
#define POLL_MS 5
#define TIMEOUT_GATHER_MS 10000
#define TIMEOUT_CONNECT_MS 30000

typedef struct {
	juice_agent_t *agent1;
	juice_agent_t *agent2;
	volatile int gathering_done1;
	volatile int gathering_done2;
	volatile juice_state_t state1;
	volatile juice_state_t state2;
	volatile uint64_t recv_count2;
	volatile uint64_t recv_bytes2;
	volatile uint64_t first_recv_ms;
	volatile uint64_t last_recv_ms;
} bench_ctx_t;

typedef struct {
	char name[32];
	bool connected;
	uint64_t sent_count;
	uint64_t sent_bytes;
	uint64_t again_count; // send attempts rejected because the transport buffer was still full
	uint64_t recv_count;
	uint64_t recv_bytes;
	double elapsed_s;
	double throughput_mbps;
} bench_result_t;

static void on_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
	bench_ctx_t *ctx = (bench_ctx_t *)user_ptr;
	if (agent == ctx->agent1)
		ctx->state1 = state;
	else
		ctx->state2 = state;
}

static void on_candidate1(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	bench_ctx_t *ctx = (bench_ctx_t *)user_ptr;
	if (!strstr(sdp, "typ relay"))
		return;
	juice_add_remote_candidate(ctx->agent2, sdp);
}

static void on_candidate2(juice_agent_t *agent, const char *sdp, void *user_ptr) {
	(void)agent;
	bench_ctx_t *ctx = (bench_ctx_t *)user_ptr;
	if (!strstr(sdp, "typ relay"))
		return;
	juice_add_remote_candidate(ctx->agent1, sdp);
}

static void on_gathering_done1(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	bench_ctx_t *ctx = (bench_ctx_t *)user_ptr;
	ctx->gathering_done1 = 1;
	juice_set_remote_gathering_done(ctx->agent2);
}

static void on_gathering_done2(juice_agent_t *agent, void *user_ptr) {
	(void)agent;
	bench_ctx_t *ctx = (bench_ctx_t *)user_ptr;
	ctx->gathering_done2 = 1;
	juice_set_remote_gathering_done(ctx->agent1);
}

static void on_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
	(void)data;
	bench_ctx_t *ctx = (bench_ctx_t *)user_ptr;
	if (agent != ctx->agent2)
		return; // only agent1 -> agent2 traffic is measured
	uint64_t t = now_ms();
	if (ctx->recv_count2 == 0)
		ctx->first_recv_ms = t;
	ctx->last_recv_ms = t;
	ctx->recv_bytes2 += size;
	++ctx->recv_count2;
}

// Set to skip TLS certificate validation, e.g. against a self-signed test relay
static bool turns_insecure(void) {
	const char *v = getenv("TURNS_INSECURE");
	return v && *v && strcmp(v, "0") != 0;
}

static int add_turn_server(juice_agent_t *agent, const juice_turn_server_t *server,
                           juice_turn_transport_t transport) {
	switch (transport) {
	case JUICE_TURN_TRANSPORT_TCP: return juice_add_turn_server_tcp(agent, server);
	case JUICE_TURN_TRANSPORT_TLS: return juice_add_turn_server_tls(agent, server, turns_insecure());
	default:                       return juice_add_turn_server(agent, server);
	}
}

static bool run_benchmark(const char *name, const juice_turn_server_t *server,
                          juice_turn_transport_t transport, int duration_ms,
                          bench_result_t *result) {
	printf("\n=== %s ===\n", name);
	memset(result, 0, sizeof(*result));
	snprintf(result->name, sizeof(result->name), "%s", name);

	bench_ctx_t ctx;
	memset(&ctx, 0, sizeof(ctx));

	juice_config_t config1, config2;
	memset(&config1, 0, sizeof(config1));
	memset(&config2, 0, sizeof(config2));
	config1.concurrency_mode = config2.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;
	config1.cb_state_changed = config2.cb_state_changed = on_state_changed;
	config1.cb_candidate = on_candidate1;
	config2.cb_candidate = on_candidate2;
	config1.cb_gathering_done = on_gathering_done1;
	config2.cb_gathering_done = on_gathering_done2;
	config1.cb_recv = config2.cb_recv = on_recv;
	config1.user_ptr = config2.user_ptr = &ctx;

	ctx.agent1 = juice_create(&config1);
	ctx.agent2 = juice_create(&config2);

	if (add_turn_server(ctx.agent1, server, transport) != JUICE_ERR_SUCCESS ||
	    add_turn_server(ctx.agent2, server, transport) != JUICE_ERR_SUCCESS) {
		printf("%s: transport not available in this build, skipping\n", name);
		juice_destroy(ctx.agent1);
		juice_destroy(ctx.agent2);
		return false;
	}

	char sdp1[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(ctx.agent1, sdp1, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(ctx.agent2, sdp1);

	char sdp2[JUICE_MAX_SDP_STRING_LEN];
	juice_get_local_description(ctx.agent2, sdp2, JUICE_MAX_SDP_STRING_LEN);
	juice_set_remote_description(ctx.agent1, sdp2);

	juice_gather_candidates(ctx.agent1);
	for (int t = 0; t < TIMEOUT_GATHER_MS && !ctx.gathering_done1; t += POLL_MS)
		sleep_ms(POLL_MS);

	juice_gather_candidates(ctx.agent2);
	for (int t = 0; t < TIMEOUT_GATHER_MS && !ctx.gathering_done2; t += POLL_MS)
		sleep_ms(POLL_MS);

	for (int t = 0; t < TIMEOUT_CONNECT_MS; t += POLL_MS) {
		juice_state_t s1 = ctx.state1, s2 = ctx.state2;
		if ((s1 == JUICE_STATE_COMPLETED || s1 == JUICE_STATE_CONNECTED) &&
		    (s2 == JUICE_STATE_COMPLETED || s2 == JUICE_STATE_CONNECTED))
			break;
		if (s1 == JUICE_STATE_FAILED || s2 == JUICE_STATE_FAILED)
			break;
		sleep_ms(POLL_MS);
	}

	result->connected =
	    (ctx.state1 == JUICE_STATE_COMPLETED || ctx.state1 == JUICE_STATE_CONNECTED) &&
	    (ctx.state2 == JUICE_STATE_COMPLETED || ctx.state2 == JUICE_STATE_CONNECTED);

	if (!result->connected) {
		printf("%s: failed to establish relayed connection (state1=%s, state2=%s)\n", name,
		       juice_state_to_string(ctx.state1), juice_state_to_string(ctx.state2));
		juice_destroy(ctx.agent1);
		juice_destroy(ctx.agent2);
		return false;
	}

	printf("%s: connected, sending for %d ms...\n", name, duration_ms);

	char payload[PAYLOAD_SIZE];
	memset(payload, 'X', sizeof(payload));

	// Spin-retry rather than sleep on JUICE_ERR_AGAIN: there's no writable-again callback to
	// wait on, and a fixed sleep would mask the real drain latency (on Windows, Sleep(1) can
	// round up to the ~15ms scheduler tick, dwarfing the time an outbound buffer actually takes
	// to drain). The AGAIN rate itself is the saturation signal: attempts that fail because the
	// transport's buffer is still full mean the line is running at capacity.
	uint64_t deadline = now_ms() + (uint64_t)duration_ms;
	while (now_ms() < deadline) {
		int ret = juice_send(ctx.agent1, payload, PAYLOAD_SIZE);
		if (ret == JUICE_ERR_SUCCESS) {
			++result->sent_count;
			result->sent_bytes += PAYLOAD_SIZE;
		} else {
			++result->again_count;
		}
	}

	// Drain in-flight messages: wait until no new bytes arrive for DRAIN_IDLE_MS, or give up
	// after DRAIN_TIMEOUT_MS.
	uint64_t drain_deadline = now_ms() + DRAIN_TIMEOUT_MS;
	uint64_t last_seen = ctx.recv_count2;
	uint64_t idle_since = now_ms();
	while (now_ms() < drain_deadline) {
		sleep_ms(POLL_MS);
		if (ctx.recv_count2 != last_seen) {
			last_seen = ctx.recv_count2;
			idle_since = now_ms();
		} else if (now_ms() - idle_since >= DRAIN_IDLE_MS) {
			break;
		}
	}

	result->recv_count = ctx.recv_count2;
	result->recv_bytes = ctx.recv_bytes2;
	if (ctx.recv_count2 > 0) {
		double elapsed_ms = (double)(ctx.last_recv_ms - ctx.first_recv_ms);
		if (elapsed_ms < 1.0)
			elapsed_ms = 1.0;
		result->elapsed_s = elapsed_ms / 1000.0;
		result->throughput_mbps =
		    ((double)result->recv_bytes * 8.0 / 1000000.0) / result->elapsed_s;
	}

	uint64_t attempts = result->sent_count + result->again_count;
	double saturation_pct = attempts ? 100.0 * (double)result->again_count / (double)attempts : 0.0;

	printf("%s: sent %llu msg (%llu bytes), received %llu msg (%llu bytes) over %.2f s "
	       "-> %.2f Mbps (%.1f%% delivered, %.1f%% of send attempts blocked on a full buffer)\n",
	       name, (unsigned long long)result->sent_count, (unsigned long long)result->sent_bytes,
	       (unsigned long long)result->recv_count, (unsigned long long)result->recv_bytes,
	       result->elapsed_s, result->throughput_mbps,
	       result->sent_count ? 100.0 * (double)result->recv_count / (double)result->sent_count
	                          : 0.0,
	       saturation_pct);
	if (saturation_pct < 1.0)
		printf("%s: send buffer was almost never full - throughput reflects the benchmark's "
		       "send-loop rate, not necessarily the transport's ceiling\n",
		       name);

	juice_destroy(ctx.agent1);
	juice_destroy(ctx.agent2);
	return true;
}

int main(void) {
	const char *turn_host = getenv("TURN_HOST");
	const char *turn_port_str = getenv("TURN_PORT");
	const char *turn_username = getenv("TURN_USERNAME");
	const char *turn_password = getenv("TURN_PASSWORD");
	bool have_turn = turn_host && turn_port_str && turn_username && turn_password;

	const char *turns_host = getenv("TURNS_HOST");
	const char *turns_port_str = getenv("TURNS_PORT");
	const char *turns_username = getenv("TURNS_USERNAME");
	const char *turns_password = getenv("TURNS_PASSWORD");
	bool have_turns = turns_host && turns_port_str && turns_username && turns_password;

	if (!have_turn && !have_turns) {
		printf("Set TURN_HOST/TURN_PORT/TURN_USERNAME/TURN_PASSWORD and/or "
		       "TURNS_HOST/TURNS_PORT/TURNS_USERNAME/TURNS_PASSWORD to run the benchmark\n");
		return 1;
	}

	int duration_ms = DEFAULT_DURATION_MS;
	const char *duration_str = getenv("BENCH_DURATION_MS");
	if (duration_str)
		duration_ms = atoi(duration_str);

	// Per-transport override, e.g. to give TCP more time to leave slow-start while
	// leaving UDP/TLS on the shared duration above.
	int tcp_duration_ms = duration_ms;
	const char *tcp_duration_str = getenv("BENCH_TCP_DURATION_MS");
	if (tcp_duration_str)
		tcp_duration_ms = atoi(tcp_duration_str);

	juice_set_log_level(JUICE_LOG_LEVEL_WARN);

	bench_result_t results[3];
	int results_count = 0;

	if (have_turn) {
		juice_turn_server_t server;
		memset(&server, 0, sizeof(server));
		server.host = turn_host;
		server.port = (uint16_t)atoi(turn_port_str);
		server.username = turn_username;
		server.password = turn_password;

		if (run_benchmark("UDP", &server, JUICE_TURN_TRANSPORT_UDP, duration_ms,
		                  &results[results_count]))
			++results_count;
		if (run_benchmark("TCP", &server, JUICE_TURN_TRANSPORT_TCP, tcp_duration_ms,
		                  &results[results_count]))
			++results_count;
	} else {
		printf("TURN_HOST not set; skipping UDP and TCP transports\n");
	}

	if (have_turns) {
		juice_turn_server_t server;
		memset(&server, 0, sizeof(server));
		server.host = turns_host;
		server.port = (uint16_t)atoi(turns_port_str);
		server.username = turns_username;
		server.password = turns_password;

		if (run_benchmark("TLS", &server, JUICE_TURN_TRANSPORT_TLS, duration_ms,
		                  &results[results_count]))
			++results_count;
	} else {
		printf("TURNS_HOST not set; skipping TLS transport\n");
	}

	printf("\n=== Summary ===\n");
	printf("%-6s %10s %10s %12s %12s\n", "Name", "Sent", "Received", "Throughput", "Saturation");
	for (int i = 0; i < results_count; ++i) {
		bench_result_t *r = &results[i];
		uint64_t attempts = r->sent_count + r->again_count;
		double saturation_pct = attempts ? 100.0 * (double)r->again_count / (double)attempts : 0.0;
		printf("%-6s %10llu %10llu %10.2f Mbps %10.1f%%\n", r->name,
		       (unsigned long long)r->sent_count, (unsigned long long)r->recv_count,
		       r->throughput_mbps, saturation_pct);
	}

	return 0;
}
