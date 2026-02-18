#ifndef H_ENDPOINT_SCANNER
#define H_ENDPOINT_SCANNER

#include "utility.hpp"
#include "tor_client.hpp"
#include "tor_controller.hpp"
#include "progress_bar.hpp"

class endpoint_scanner
{
    std::string                             _domain;
    std::vector<std::string>                _words;
    std::map<std::string, unsigned>         _res;
    std::vector<uint16_t>                   _excl, _incl;
    std::mutex                              _rate_mtx;
    std::mutex                              _output_mtx;
    std::chrono::steady_clock::time_point   _last_req_time;
    int                                     _rate_limit_ms;
    unsigned                                _threads_max;
    friend class                            tor_client;
    std::unique_ptr<progress_bar>           _pbar;
    retry_config                            _retry_cfg;
    std::atomic<size_t>                     _errors{0};
    std::atomic<size_t>                     _redirects_followed{0};
    bool                                    _follow_redirects{false};
    unsigned int                            _max_redirects{5};
    std::atomic<size_t>                     _reconnects{0};

    // Shared contexts for thread spawning
    asio::io_context                        _ioc;
    ssl::context                            _ssl_ctx;

public:

    endpoint_scanner(const std::string &domain, unsigned int rate_limit = 0, uint16_t threads = 1) :
        _domain(domain),
        _rate_limit_ms(rate_limit),
        _threads_max(threads),
        _ssl_ctx(ssl::context::tlsv12_client)
    {
        // .onion SSL certificates are self-signed so we don't verify the certificate
        _ssl_ctx.set_verify_mode(ssl::verify_none);
        _ssl_ctx.set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2 |
            ssl::context::no_sslv3 |
            ssl::context::no_tlsv1 |
            ssl::context::no_tlsv1_1
        );
    }

    ssl::context &get_ssl_ctx(void) { return _ssl_ctx; }

    void set_retry_config(const retry_config &cfg) { _retry_cfg = cfg; }
    void set_follow_redirects(bool enable, unsigned int max_hops = 5)
    {
        _follow_redirects = enable;
        _max_redirects = max_hops;
    }

    void load_wordlist(const std::string &filename, const std::vector<std::string> &ext = {});
    void send_request(tor_client &t, enum http::verb v, const std::string &ep);
    void send_request_with_rate_limit(tor_client &t, enum http::verb v, const std::string &ep);
    void add_exclude_code(const std::vector<uint16_t> &v);
    void add_include_code(const std::vector<uint16_t> &v);
    void start_scan(tor_client &t);
    void thread_func(int nb_threads, unsigned short port, bool ssl_mode);
    std::string get_url(void);
    void print_summary(void) const;

private:
    std::string extract_redirect_path(const std::string &location) const;
    void color_output(const std::string &ep, unsigned int http_code, const std::string &redirect_info);
    bool should_display(unsigned int http_code) const;
};

#endif // H_ENDPOINT_SCANNER