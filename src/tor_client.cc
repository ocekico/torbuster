#include "../includes/utility.hpp"
#include "../includes/tor_client.hpp"
#include "../includes/tor_controller.hpp"
#include "../includes/endpoint_scanner.hpp"

/**
 * Connect to a .onion domain through Tor's SOCKS5 proxy
 * On failure, automatically:
 *  1. Wait with exponential backoff
 *  2. Rotate Tor circuit (SIGNAL NEWNYM)
 *  3. Retry the connection
 */

void
tor_client::start_connect(const std::string &domain, uint16_t port, bool use_ssl)
{
    unsigned int attempt = 0;
    unsigned int delay_ms = _retry_cfg.base_delay_ms;

    while (attempt <= _retry_cfg.max_retries)
    {
        if (attempt > 0)
        {
            std::cerr << BOLD_YELLOW << "[~] " << RESET_COLOR
                      << "Retry " << attempt << "/" << _retry_cfg.max_retries
                      << " in " << delay_ms << "ms..." << std::endl;

            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
            if (_retry_cfg.rotate_circuit && _ctrl.is_connected())
            {
                std::cout << BOLD_CYAN << "[*] " << RESET_COLOR
                          << "Requesting new Tor circuit..." << std::endl;
                _ctrl.rotate_circuit();

                // Wait a bit for the circuit to establish
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }

            // Exponential backoff for next attempt
            delay_ms = static_cast<unsigned int>(delay_ms * _retry_cfg.backoff_factor);
        
            // Reopen the socket since the old one may be in a bad state
            boost::system::error_code ignored;
            
            if (use_ssl)
            {
                auto &underlying = _sslsock.next_layer();
                if (underlying.is_open())
                    underlying.close(ignored);
                
                // Recreate SSL stream
                _sslsock = ssl::stream<tcp::socket>(_ioctx, _ctx);
                if (_sock.is_open())
                    _sock.close(ignored);
                _sock = tcp::socket(_ioctx);
            }
            else
            {
                if (_sock.is_open())
                    _sock.close(ignored);
                _sock = tcp::socket(_ioctx);
            }
        }

        try
        {
            if (use_ssl)
                connect_ssl(domain, port);
            else
                connect_plain(domain, port);

            _last_domain = domain;
            _last_port = port;
            _last_use_ssl = use_ssl;
            
            //std::cout << BOLD_GREEN << "[*] " << RESET_COLOR
            //        << "Connected to " << domain << ":" << port;
            //if (attempt > 0)
            //    std::cout << " (after " << attempt << " retries)";
            //std::cout << std::endl;
            return;
        }
        catch (boost::system::system_error const &e)
        {
            std::cout << "Error: " << e.what() << std::endl;
        }
        catch (std::exception const &e)
        {
            std::cout << "Error: " << e.what() << std::endl;
        }

        attempt++;
    }

    // If al lretries are exhausted
    throw std::runtime_error(
        "Failed to connect to " + domain + " after "
        + std::to_string(_retry_cfg.max_retries) + " retries"
    );
}

bool
tor_client::is_recoverable_error(const std::exception &e)
{
    if (auto *se = dynamic_cast<const boost::system::system_error *>(&e))
    {
        auto ec = se->code();

        int val = ec.value();
        if (val == EPIPE)       return true;
        if (val == ECONNRESET)  return true;
        if (val == EBADF)       return true;
        if (val == ENOTCONN)    return true;
        if (val == ETIMEDOUT)   return true;

        if (ec == boost::asio::error::eof)              return true;
        if (ec == boost::asio::error::connection_reset) return true;
        if (ec == boost::asio::error::not_connected)    return true;
        if (ec == beast::http::error::end_of_stream)    return true;
        if (ec == beast::http::error::partial_message)  return true;

        if (ec.category() == boost::asio::error::get_ssl_category())
            return true;
    }

    std::string msg = e.what();

    if (msg.find("Broken pipe")         != std::string::npos) return true;
    if (msg.find("system:32")           != std::string::npos) return true;
    if (msg.find("Connection reset")    != std::string::npos) return true;
    if (msg.find("system:104")          != std::string::npos) return true;
    if (msg.find("Bad file descriptor") != std::string::npos) return true;
    if (msg.find("system:9")            != std::string::npos) return true;
    if (msg.find("end of stream")       != std::string::npos) return true;
    if (msg.find("stream truncated")    != std::string::npos) return true;
    if (msg.find("short read")          != std::string::npos) return true;
    if (msg.find("asio.misc:2")         != std::string::npos) return true;

    return false;
}

void
tor_client::reconnect(void)
{
    if (_last_domain.empty())
        throw std::runtime_error("reconnect() called before any successful connection");

    boost::system::error_code ignored;
    if (_last_use_ssl)
    {
        auto &underlying = _sslsock.next_layer();
        if (underlying.is_open())
            underlying.close(ignored);
        _sslsock = ssl::stream<tcp::socket>(_ioctx, _ctx);
    }

    if (_sock.is_open())
        _sock.close(ignored);
    _sock = tcp::socket(_ioctx);

    // Reconnect with stored parameters
    start_connect(_last_domain, _last_port, _last_use_ssl);
}

void
tor_client::connect_ssl(const std::string &domain, uint16_t port)
{
    _ssl_mode = true;
    socks5::TargetSpec target{domain, port};
    auto &socket = _sslsock.next_layer();

    std::future<void> conn_result = socks5::async_proxy_connect(
        _sock, target, tcp::endpoint{{}, 9050}, boost::asio::use_future
    );

    _ioctx.restart();
    _ioctx.run();

    if (conn_result.wait_for(20s) == std::future_status::timeout)
    {
        _sock.cancel();
        throw std::runtime_error("SOCKS5 connection timed out (20s)");
    }

    conn_result.get();
    //std::cout << BOLD_GREEN << "[+] " << RESET_COLOR
    //          << "SOCKS5 tunnel established" << std::endl;

    //socket.set_option(tcp::no_delay(true));
    auto native_fd = _sock.release();
    _sslsock.next_layer().assign(tcp::v4(), native_fd);
    _sslsock.next_layer().set_option(tcp::no_delay(true));

    if (!SSL_set_tlsext_host_name(_sslsock.native_handle(), domain.c_str()))
    {
        std::cerr << BOLD_YELLOW << "[~] " << RESET_COLOR
            << "Warning: could not set SNI hostname" << std::endl;
    }

    _sslsock.handshake(ssl::stream_base::handshake_type::client);

    //std::cout << BOLD_GREEN << "[*] " << RESET_COLOR
    //          << "SSL handshake completed";
}

void
tor_client::connect_plain(const std::string &domain, uint16_t port)
{
    _ssl_mode = false;
    socks5::TargetSpec target{domain, port};

    std::future<void> conn_result = socks5::async_proxy_connect(
        _sock, target, tcp::endpoint{{}, 9050}, boost::asio::use_future
    );

    _ioctx.restart();
    _ioctx.run();

    if (conn_result.wait_for(20s) == std::future_status::timeout)
    {
        _sock.cancel();
        throw std::runtime_error("SOCKS5 connection timed out (20s)");
    }

    conn_result.get();
    //std::cout << BOLD_GREEN << "[+] " << RESET_COLOR
    //          << "SOCKS5 tunnel established (plaintext)" << std::endl;

    _sock.set_option(tcp::no_delay(true));
}

template <typename Request>
void
tor_client::write_request(const Request &req)
{
    if (_ssl_mode)
        http::write(_sslsock, req);
    else
        http::write(_sock, req);
}

template <typename Response>
void
tor_client::read_response(beast::flat_buffer &buf, Response &res)
{
    if (_ssl_mode)
        http::read(_sslsock, buf, res);
    else
        http::read(_sock, buf, res);
}

template void tor_client::read_response<http::response<http::string_body>>(
    beast::flat_buffer&, http::response<http::string_body>&
);

template void tor_client::write_request<http::request<http::empty_body>>(
    http::request<http::empty_body> const&
);

void
tor_client::send_command(const std::string &cmd)
{
    _ctrl._sock.send(asio::buffer(cmd));

    char buf[256];
    boost::system::error_code error;
    size_t len = _ctrl._sock.read_some(asio::buffer(buf), error);
    if (error == asio::error::eof)
        std::cout << "[!] Connection closed by server" << std::endl;
    else if (error)
        throw boost::system::system_error(error);

    // Output received data
    std::cout.write(buf, len);
    std::cout << std::endl;
}

bool
tor_client::is_ssl_enabled(void)
{
    return _ssl_mode == true;
}