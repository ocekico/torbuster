#include "../includes/endpoint_scanner.hpp"

void
endpoint_scanner::load_wordlist(const std::string &filename, const std::vector<std::string> &ext)
{
    std::ifstream ifs(filename);
    if (!ifs.is_open())
    {
        if (ifs.failbit || ifs.badbit)
            throw std::runtime_error("Stream failure reading the wordlist");
        throw std::runtime_error("Error reading the file");
    }

    std::string line;
    while (getline(ifs, line))
    {
        if (line.empty() || line[0] == '#')
            continue;
        
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        if (!line.empty())
        {
            if (!ext.empty())
            {
                for (const auto &e : ext)
                    _words.push_back(line + e.c_str());
            }
            else
                _words.push_back(line);
        }
    }

    ifs.close();
    if (_words.empty())
        throw std::runtime_error("Empty wordlist after filtering comments");
    _pbar = std::make_unique<progress_bar>(_words.size(), 30);
}

void
endpoint_scanner::add_exclude_code(const std::vector<uint16_t> &v)
{
    for (auto &e : v)
        _excl.push_back(e);
}

void
endpoint_scanner::add_include_code(const std::vector<uint16_t> &v)
{
    for (auto &i : v)
        _incl.push_back(i);
}

bool
endpoint_scanner::should_display(unsigned int http_code) const
{
    if (!_incl.empty())
    {
        for (auto c : _incl)
            if (c == http_code)
                return true;
        return false;
    }

    if (!_excl.empty())
    {
        for (auto c : _excl)
            if (c == http_code)
                return false;
    }

    return true;
}

std::string
endpoint_scanner::extract_redirect_path(const std::string &location) const
{
    std::string path = location;
    auto scheme_pos = path.find("://");

    // Strip absolute URL prefix: http(s)://domain...
    if (scheme_pos != std::string::npos)
    {
        auto slash_pos = path.find('/', scheme_pos + 3);
        if (slash_pos != std::string::npos)
            path = path.substr(slash_pos);
        else
            path = "/";
    }

    // Strip leading slash(es) to get a clean relative path
    while (!path.empty() && path[0] == '/')
        path.erase(0, 1);

    return path;
}

void
endpoint_scanner::send_request(tor_client &t, enum http::verb v, const std::string &ep)
{
    for (int attempt = 0; attempt < 2; attempt++)
    {
        try
        {
            std::string current_path = ep;
            std::string original_ep = ep;
            unsigned int hops = 0;
            unsigned int status_code = 0;

            while (true)
            {
                http::request<http::empty_body> req(http::verb::get, "/" + ep, 11);
                req.set(http::field::host, _domain);
                req.set(http::field::user_agent, "torbuster/1.1");
                req.set(http::field::connection, "keep-alive");
                req.prepare_payload();

                t.write_request(req);

                http::response<http::string_body> res;
                beast::flat_buffer buf;

                t.read_response(buf, res);

                status_code = res.result_int();
                bool is_redirect = (status_code >= 300 && status_code < 400);

                if (_follow_redirects && is_redirect && hops < _max_redirects)
                {
                    auto it = res.find(http::field::location);
                    if (it == res.end())
                        break;

                    std::string location = std::string(it->value());
                    std::string new_path = extract_redirect_path(location);
                    if (new_path == current_path)
                        break;

                    _redirects_followed.fetch_add(1, std::memory_order_relaxed);
                    hops++;
                    current_path = new_path;
                    continue;
                }

                break;
            }

            // Store final result (thread-safe)
            {
                std::lock_guard<std::mutex> lg(_output_mtx);
                _res.insert_or_assign(original_ep, status_code);
            }

            // Build redirect info string if we followed any
            std::string redir_info;
            if (hops > 0 && current_path != original_ep)
            {
                redir_info = " → /" + current_path;
                if (hops > 1)
                    redir_info += " (" + std::to_string(hops) + " hops)";
            }

            if (should_display(status_code))
                color_output(original_ep, status_code, redir_info);
            
            break;
        }
        catch (const std::exception &e)
        {
            if (attempt == 0 && tor_client::is_recoverable_error(e))
            {
                try
                {
                    t.reconnect();
                    _reconnects.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    continue;
                }
                catch (const std::exception &re)
                {
                    if (_pbar)
                    {
                        _pbar->print_above(
                            BOLD_RED "[!] " RESET_COLOR
                            "Reconnect failed for /%s: %s\n",
                            ep.c_str(), re.what()
                        );
                    }
                    else
                    {
                        std::lock_guard<std::mutex> lg(_output_mtx);
                        std::cerr << BOLD_RED << "[!] " << RESET_COLOR
                            << "Reconnect failed for /" << ep << ": " << re.what()
                            << std::endl;
                    }
                }

                _errors.fetch_add(1, std::memory_order_relaxed);
                if (_pbar)
                {
                    _pbar->print_above(
                        BOLD_RED "[!] " RESET_COLOR "Request failed for /%s: %s\n",
                        ep.c_str(), e.what()
                    );
                }
                else
                {
                    std::lock_guard<std::mutex> lg(_output_mtx);
                    std::cerr << BOLD_RED << "[!] " << RESET_COLOR
                          << "Request failed for /" << ep << ": " << e.what()
                          << std::endl;
                }

                break;
            }
        }
    }

    if (_pbar)
        _pbar->tick();
}

void
endpoint_scanner::send_request_with_rate_limit(tor_client &t, http::verb v, const std::string &ep)
{
    if (_rate_limit_ms > 0)
    {
        std::unique_lock<std::mutex> lock(_rate_mtx);
        auto now = std::chrono::steady_clock::now();
        auto wait_time = _last_req_time + std::chrono::milliseconds(_rate_limit_ms);

        if (now < wait_time)
            std::this_thread::sleep_until(wait_time);

        _last_req_time = std::chrono::steady_clock::now();
        lock.unlock();
    }

    send_request(t, v, ep);
}

void
endpoint_scanner::start_scan(tor_client &t)
{
    if (_pbar)
        _pbar->reset(_words.size());
    
    for (auto it = _words.begin(); it != _words.end(); it++)
    {
        if (_rate_limit_ms > 0)
            send_request_with_rate_limit(t, http::verb::get, *it);
        else
            send_request(t, http::verb::get, *it);
    }

    if (_pbar)
        _pbar->finish();
}

void
endpoint_scanner::thread_func(int nb_threads, unsigned short port, bool ssl_mode)
{
    const char *cookie_env = std::getenv("COOKIE_AUTH");
    if (!cookie_env || *cookie_env == '\0')
        return;

    static unsigned count = 0;
    asio::io_context thread_ioc;
    tor_client tc(thread_ioc, _ssl_ctx, cookie_env, ssl_mode);
    tc.set_retry_config(_retry_cfg);

    try
    {
        tc.start_connect(_domain, port, ssl_mode);
    }
    catch (const std::exception &e)
    {
        if (_pbar)
        {
            if (count == 0)
            {
                _pbar->print_above(
                    BOLD_RED "[!] Thread %d failed to connect: %s" RESET_COLOR "\n",
                    nb_threads, e.what()
                );
                count++;
            }
        }
        else
        {
            if (count == 0)
            {
                std::lock_guard<std::mutex> lg(_output_mtx);
                std::cerr << BOLD_RED << "[!] Thread " << nb_threads << " failed to connect: " << e.what()
                    << RESET_COLOR << std::endl;
                count++;
            }
        }

        return;
    }

    if (_threads_max > 1)
    {
        size_t split_sz = _words.size() / _threads_max;
        size_t factor = nb_threads;
        size_t start_pos = factor * split_sz;
        size_t end_pos = (nb_threads ==  _threads_max - 1) ? _words.size() : start_pos + split_sz;

        for (int ind = start_pos; ind < end_pos; ind++) {
            if (_rate_limit_ms > 0)
                send_request_with_rate_limit(tc, http::verb::get, _words[ind]);
            else
                send_request(tc, http::verb::get, _words[ind]);
        }

        return;
    }

    for (int ind = 0; ind < _words.size(); ind++)
    {
        if (_rate_limit_ms > 0)
            send_request_with_rate_limit(tc, http::verb::get, _words[ind]);
        else
            send_request(tc, http::verb::get, _words[ind]);
    }
}

void
endpoint_scanner::color_output(const std::string &ep, unsigned int http_code, const std::string &redirect_info)
{
    const char *color;

    if (http_code >= 200 && http_code < 300) color = BOLD_GREEN;
    else if (http_code >= 300 && http_code < 400) color = BOLD_BLUE;
    else if (http_code >= 400 && http_code < 500) color = BOLD_RED;
    else if (http_code >= 500 && http_code < 600) color = BOLD_MAGENTA;
    else color = NORMAL_WHITE;

    //std::cout << "DEBUG: " << http_code << std::endl;
    if (_pbar)
    {
        if (redirect_info.empty())
        {
            _pbar->print_above(
                "%s[%3u]" RESET_COLOR " /%s\n",
                color, http_code, ep.c_str()
            );
        }
        else
        {
            _pbar->print_above(
                "%s[%3u]" RESET_COLOR " /%s" BOLD_YELLOW "%s" RESET_COLOR "\n",
                color, http_code, ep.c_str(), redirect_info.c_str()
            );
        }
    }
    else
    {
        std::lock_guard<std::mutex> lg(_output_mtx);
        std::printf("%s[%3u]%s /%s%s%s%s\n",
            color, http_code, RESET_COLOR,
            ep.c_str(),
            redirect_info.empty() ? "" : BOLD_YELLOW,
            redirect_info.c_str(),
            redirect_info.empty() ? "" : RESET_COLOR
        );
        std::fflush(stdout);
    }
}

void
endpoint_scanner::print_summary(void) const
{
    std::cout << "\n" << BOLD_WHITE
              << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << RESET_COLOR << "\n";
    std::cout << BOLD_CYAN << " SCAN SUMMARY" << RESET_COLOR << "\n";
    std::cout << BOLD_WHITE
              << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << RESET_COLOR << "\n";

    unsigned c2xx = 0, c3xx = 0, c4xx = 0, c5xx = 0;
    for (const auto &[ep, code] : _res)
    {
        if (code >= 200 && code < 300) c2xx++;
        else if (code >= 300 && code < 400) c3xx++;
        else if (code >= 400 && code < 500) c4xx++;
        else if (code >= 500 && code < 600) c5xx++;
    }

    std::cout << BOLD_GREEN   << "  2xx (Success):      " << c2xx << RESET_COLOR << "\n";
    std::cout << BOLD_BLUE    << "  3xx (Redirect):     " << c3xx << RESET_COLOR << "\n";
    std::cout << BOLD_RED     << "  4xx (Client Error): " << c4xx << RESET_COLOR << "\n";
    std::cout << BOLD_MAGENTA << "  5xx (Server Error): " << c5xx << RESET_COLOR << "\n";
    std::cout << BOLD_YELLOW  << "  Errors/Timeouts:    " << _errors.load() << RESET_COLOR << "\n";
    std::cout << BOLD_WHITE   << "  Total endpoints:    " << _words.size() << RESET_COLOR << "\n";
    std::cout << BOLD_WHITE
              << "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" << RESET_COLOR << "\n";

    // List found endpoints (2xx and 3xx)
    if (c2xx + c3xx > 0)
    {
        std::cout << "\n" << BOLD_GREEN << " Found endpoints: " << RESET_COLOR << "\n";
        for (const auto &[ep, code] : _res)
        {
            if (code >= 200 && code < 400)
                std::printf("    /%s -> %u\n", ep.c_str(), code);
        }
    }

    std::cout << std::endl;
}
