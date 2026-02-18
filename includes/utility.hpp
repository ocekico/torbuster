#ifndef H_UTILITY
#define H_UTILITY

// Bold ANSI colors
#define BOLD_RED        "\033[31m\033[1m"
#define BOLD_GREEN      "\033[32m\033[1m"
#define BOLD_YELLOW     "\033[33m\033[1m"
#define BOLD_BLUE       "\033[34m\033[1m"
#define BOLD_MAGENTA    "\033[35m\033[1m"
#define BOLD_CYAN       "\033[36m\033[1m"
#define BOLD_WHITE      "\033[37m\033[1m"

// Standard ANSI colors
#define NORMAL_RED        "\033[31m\033[0m"
#define NORMAL_GREEN      "\033[32m\033[0m"
#define NORMAL_YELLOW     "\033[33m\033[0m"
#define NORMAL_BLUE       "\033[34m\033[0m"
#define NORMAL_MAGENTA    "\033[35m\033[0m"
#define NORMAL_CYAN       "\033[36m\033[0m"
#define NORMAL_WHITE      "\033[37m\033[0m"

// Special ANSI codes
#define RESET_COLOR       "\033[0m\033[0m"

// Utility headers
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <future>
#include <chrono>

#include <sstream>
#include <fstream>
#include <map>
#include <iomanip>
#include <algorithm>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <getopt.h>
#include "../vendor/asio-socks45-client-main/socks5.hpp"

namespace ssl = boost::asio::ssl;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

using namespace std::chrono_literals;
static std::mutex mtx;
static asio::io_context _ioc;
static ssl::context _ssl_ctx(ssl::context::tlsv12_client);

#endif