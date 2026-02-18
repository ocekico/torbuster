#ifndef H_TOR_CLIENT
#define H_TOR_CLIENT

#include "utility.hpp"
#include "tor_controller.hpp"
#include <cstdint>

struct retry_config
{
    unsigned int max_retries = 3;
    unsigned int base_delay_ms = 2000;
    double backoff_factor = 2.0;
    bool rotate_circuit = true;
};

class tor_client
{
    asio::io_context          &_ioctx;
    ssl::context              &_ctx;
    asio::ip::tcp::socket     _sock;
    ssl::stream<tcp::socket>  _sslsock;
    tor_controller            _ctrl;
    bool                      _ssl_mode;
    retry_config              _retry_cfg;

    // Stored for reconnection
    std::string               _last_domain;
    uint16_t                  _last_port{0};
    bool                      _last_use_ssl{false};

    friend class              endpoint_scanner;

public:

    tor_client(asio::io_context &ioc, ssl::context &sslctx, const std::string &auth_cookie, bool ssl_mode = false) :
        _ioctx(ioc),
        _ctx(sslctx),
        _sslsock(ioc, _ctx),
        _sock(ioc),
        _ctrl(std::string("AUTHENTICATE " + auth_cookie + "\r\n")),
        _ssl_mode(ssl_mode)
    {
    }

    void start_connect(const std::string &domain, uint16_t port, bool use_ssl);
    void reconnect(void);
    void set_retry_config(const retry_config &cfg) { _retry_cfg = cfg; }
    void send_auth_cookie(const std::string &ac);

    template <typename Request>
    void write_request(const Request &req);

    template <typename Response>
    void read_response(beast::flat_buffer &buf, Response &res);

    static bool is_recoverable_error(const std::exception &e);

    void send_command(const std::string &cmd);
    bool is_ssl_enabled(void);
    bool rotate_circuit(void) { return _ctrl.rotate_circuit(); }
    bool rotate_circuit_wait(void) { return _ctrl.rotate_circuit_wait(); }
    std::string get_port_number(void);

private:
    void connect_ssl(const std::string &domain, uint16_t port);
    void connect_plain(const std::string &domain, uint16_t port);
};

#endif