#ifndef H_TOR_CONTROLLER
#define H_TOR_CONTROLLER

#include "../includes/utility.hpp"

namespace ssl = boost::asio::ssl;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

/* TODO:
 *  - To enumerate endpoints of a tor .onion site, we can use a wordlist and fetch the HTTP code.
 *    if HTTP code is not 404 then the endpoint exists, otherwise we don't output it.
 *  - Create a class "endpoint_scanner" to be part of "tor_client" class.
 */

 /**
  * Tor Controller codes:
  * - 250 OK
  * - 552 Unrecognized option
  * - 513 Syntax error
  * - 553 Impossible configuration setting
  */

class tor_controller
{
    asio::io_context          _ctx;
    tcp::socket               _sock;
    tcp::resolver             _rslv;
    bool                      _connected;

public:

    tor_controller(const std::string &cmd) :
        _ctx(),
        _sock(_ctx),
        _rslv(_ctx),
        _connected(false)
    {
        try {
            auto endpoints = _rslv.resolve("127.0.0.1", "9051");
            asio::connect(_sock, endpoints);
            std::string response = send_and_recv(cmd);

            if (response.find("250") != std::string::npos)
            {
                _connected = true;
                //std::cout << BOLD_GREEN << "[+] " << RESET_COLOR <<
                //    "Tor Controller authenticated on port 9051" << std::endl;
            }
            else
            {
                std::cerr << BOLD_RED << "[!] " << RESET_COLOR
                    << "Tor Controller auth failed: " << response << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::cerr << BOLD_RED << "[!] " << RESET_COLOR
                << "Cannot connect to Tor Controller: " << e.what() << std::endl;
        }
    }

    bool rotate_circuit(void)
    {
        if (!_connected)
        {
            std::cerr << BOLD_YELLOW << "[!] " << RESET_COLOR
                << "Controller not connected, cannot rotate circuit" << std::endl;
            return false;
        }
    
        std::string response = send_and_recv("SIGNAL NEWNYM\r\n");
        if (response.find("250") != std::string::npos)
        {
            std::cout << BOLD_CYAN << "[*] " << RESET_COLOR
                << "Circuit rotated (NEWNYM)" << std::endl;
            return true;
        }

        std::cerr << BOLD_YELLOW << "[!] " << RESET_COLOR
            << "NEWNYM failed: " << response << std::endl;
        return false;
    }

    bool rotate_circuit_wait(void)
    {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return rotate_circuit();
    }

    bool is_connected(void) const { return _connected; }

private:
    friend class tor_client;

    std::string send_and_recv(const std::string &cmd)
    {
        boost::system::error_code ec;
        _sock.send(asio::buffer(cmd));

        char buf[512];
        size_t len = _sock.read_some(asio::buffer(buf), ec);

        if (ec == asio::error::eof)
            return "[EOF]";
        else if (ec)
            return "[ERROR: " + ec.message() + "]";

        return std::string(buf, len);
    }
};

#endif