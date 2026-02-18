#include "../includes/utility.hpp"
#include "../includes/tor_client.hpp"
#include "../includes/tor_controller.hpp"
#include "../includes/endpoint_scanner.hpp"

using namespace std::chrono_literals;

static int threads_max = 1;
std::vector<std::thread> threads;

void
show_help(const char *progname)
{
    std::cerr << BOLD_YELLOW << progname << 
        RESET_COLOR << BOLD_WHITE << ": [-u:w:a:sVvt:he:i:p:r:R:Lx:]\n"
        << RESET_COLOR;
    std::cerr << BOLD_WHITE << "Required:\n" << RESET_COLOR;
    std::cerr << "\t-u, --url <onion_url>:\t\t\tA .onion URL\n";
    std::cerr << "\t-w, --wordlist <file>:\t\t\tPath to the wordlist to be used\t\n";
    std::cerr << BOLD_WHITE << "Connection:\n" << RESET_COLOR;
    std::cerr << "\t-p, --port <port_number>:\t\tSpecify a port number between 1 and 65535\t\n";
    std::cerr << "\t-a, --auth-cookie <cookie>:\t\tThe password/cookie to connect to Tor controller\t\n";
    std::cerr << "\t-s, --ssl-on-tor:\t\t\tActivates SSL-On-Tor (compatible with HTTPS .onion domains)\t\n";
    std::cerr << "\t-R, --max-retries <number_of_tries>:\tDefine the maximum number of retries\t\n";
    std::cerr << BOLD_WHITE << "Performance:\n" << RESET_COLOR;
    std::cerr << "\t-t, --threads-max <number_of_threads>:\tSet the number of threads\t\n";
    std::cerr << "\t-r, --rate-limit-max <req/s>:\t\tSet a rate-limit (in req/s)\t\n";
    std::cerr << BOLD_WHITE << "Filtering:\n" << RESET_COLOR;
    std::cerr << "\t-e, --exclude-http-code <list>:\t\tA comma-separated list of HTTP codes to exclude from results\t\n";
    std::cerr << "\t-i, --include-http-code <list>:\t\tA comma-separated list of HTTP codes to include in results\t\n";
    std::cerr << BOLD_WHITE << "Miscellanous:\n" << RESET_COLOR;
    std::cerr << "\t-L, --follow-redirects:\t\t\tFollow HTTP redirections\t\n";
    std::cerr << "\t-x, --extensions:\t\t\tAdd a comma-separated list of extensions to each item in the wordlist\t\n";
    std::cerr << "\t-V, --version:\t\t\t\tShow the version of TorBuster\t\n";
    std::cerr << "\t-v, --verbose:\t\t\t\tShow verbose output\t\n";
    std::cerr << "\t-h, --help:\t\t\t\tShow this help menu\t\n";
    std::cerr << BOLD_WHITE << "Example:\n" << RESET_COLOR;
    std::cerr << " " << progname << " -u abcdef12345.onion -w wordlist.txt -t 4 -s -e 404,403\n\n";
}

static const int FONT[9][7][5] = {
    /* ── T ─────────────────────────────────── */
    {
        { 1, 1, 1, 1, 1 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
    },
    /* ── O ─────────────────────────────────── */
    {
        { 0, 1, 1, 1, 0 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 0, 1, 1, 1, 0 },
    },
    /* ── R ─────────────────────────────────── */
    {
        { 1, 1, 1, 1, 0 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 1, 1, 1, 0 },
        { 1, 0, 1, 0, 0 },
        { 1, 0, 0, 1, 0 },
        { 1, 0, 0, 0, 1 },
    },
    /* ── B ─────────────────────────────────── */
    {
        { 1, 1, 1, 1, 0 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 1, 1, 1, 0 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 1, 1, 1, 0 },
    },
    /* ── U ─────────────────────────────────── */
    {
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 0, 1, 1, 1, 0 },
    },
    /* ── S ─────────────────────────────────── */
    {
        { 0, 1, 1, 1, 1 },
        { 1, 0, 0, 0, 0 },
        { 1, 0, 0, 0, 0 },
        { 0, 1, 1, 1, 0 },
        { 0, 0, 0, 0, 1 },
        { 0, 0, 0, 0, 1 },
        { 1, 1, 1, 1, 0 },
    },
    /* ── T ─────────────────────────────────── */
    {
        { 1, 1, 1, 1, 1 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
        { 0, 0, 1, 0, 0 },
    },
    /* ── E ─────────────────────────────────── */
    {
        { 1, 1, 1, 1, 1 },
        { 1, 0, 0, 0, 0 },
        { 1, 0, 0, 0, 0 },
        { 1, 1, 1, 1, 0 },
        { 1, 0, 0, 0, 0 },
        { 1, 0, 0, 0, 0 },
        { 1, 1, 1, 1, 1 },
    },
    /* ── R ─────────────────────────────────── */
    {
        { 1, 1, 1, 1, 0 },
        { 1, 0, 0, 0, 1 },
        { 1, 0, 0, 0, 1 },
        { 1, 1, 1, 1, 0 },
        { 1, 0, 1, 0, 0 },
        { 1, 0, 0, 1, 0 },
        { 1, 0, 0, 0, 1 },
    },
};

void
show_banner(void)
{
    static constexpr int NUM_LETTERS = 9;
    static constexpr int PIXEL_W     = 5;
    static constexpr int PIXEL_H     = 7;
    static constexpr int LETTER_GAP  = 1;

    /* Magenta — RGB(255, 0, 255) */
    static const char *MAGENTA = "\033[38;2;255;0;255m";
    static const char *RESET   = "\033[0m";

    std::putchar('\n');

    for (int row = 0; row < PIXEL_H; row++)
    {
        for (int letter = 0; letter < NUM_LETTERS; letter++)
        {
            for (int px = 0; px < PIXEL_W; px++)
            {
                if (FONT[letter][row][px])
                    std::printf("%s\xe2\x96\x88\xe2\x96\x88", MAGENTA);
                else
                    std::printf("  ");
            }

            if (letter < NUM_LETTERS - 1)
                std::printf(" ");
        }

        std::printf("%s\n", RESET);
    }

    std::putchar('\n');
    std::printf("A CLI tool to enumerate Tor website endpoints\n");
    std::printf("by ocekico\n\n");
}

std::vector<uint16_t>
parse_http_codes_from_cmdline(const std::string &arg)
{
    std::vector<uint16_t> codes;
    std::stringstream ss(arg);
    std::string token;

    while (std::getline(ss, token, ','))
    {
        try
        {
            int val = std::stoi(token);
            if (val < 100 || val > 599)
                throw std::out_of_range("HTTP code out of range");
            codes.push_back(static_cast<uint16_t>(val));
        }
        catch (const std::exception &e)
        {
            std::cerr << BOLD_YELLOW << "[!] " << RESET_COLOR
                << "Invalid HTTP code: '" << token << "' - " << e.what() << "\n";
        }
    }

    return codes;
}

std::vector<std::string>
parse_extensions_from_cmdline(const std::string &arg)
{
    std::vector<std::string> ext;
    std::stringstream ss(arg);
    std::string token;

    while (std::getline(ss, token, ','))
    {
        try
        {
            if (!token.empty())
                ext.push_back(token);
        }
        catch (const std::exception &e)
        {
            std::cerr << BOLD_YELLOW << "[!] " << RESET_COLOR
                << "Invalid HTTP code: '" << token << "' - " << e.what() << "\n";
        }
    }

    return ext;
}

int main(int argc, char **argv) try
{
    std::string url, wordlist, auth_cookie;
    std::vector<uint16_t> incl, excl;
    std::vector<std::string> extensions;
    bool ssl_on_tor = false, verbose = false;
    bool is_cookie_enabled = false;
    int port = 80, rate_limit = 0;
    int max_retries = 3;
    bool redirects = false;

    const char *short_opts = "u:w:a:sVvt:he:i:p:r:R:L:x:";

    const struct option long_opts[] = {
        {"url",                 required_argument, nullptr, 'u'},
        {"wordlist",            required_argument, nullptr, 'w'},
        {"auth-cookie",         required_argument, nullptr, 'a'},
        {"ssl-on-tor",          no_argument,       nullptr, 's'},
        {"version",             no_argument,       nullptr, 'V'},
        {"verbose",             no_argument,       nullptr, 'v'},
        {"threads-max",         required_argument, nullptr, 't'},
        {"help",                no_argument,       nullptr, 'h'},
        {"exclude-http-code",   required_argument, nullptr, 'e'},
        {"include-http-code",   required_argument, nullptr, 'i'},
        {"port",                required_argument, nullptr, 'p'},
        {"rate-limit-max",      required_argument, nullptr, 'r'},
        {"max-retries",         required_argument, nullptr, 'R'},
        {"follow-redirects",    no_argument,       nullptr, 'L'},
        {"extensions",          required_argument, nullptr, 'x'},
        {nullptr, 0, nullptr, 0}
    };

    int opt, long_index = 0;
    while ((opt = getopt_long(argc, argv, short_opts, long_opts, &long_index)) != -1)
    {
        switch (opt)
        {
            case 'u':
                url = optarg;
                break;
            case 'w':
                wordlist = optarg;
                break;
            case 'a':
                auth_cookie = optarg;
                setenv("COOKIE_AUTH", optarg, true);
                break;
            case 's':
                ssl_on_tor = true;
                port = 443;
                break;
            case 'V':
                std::cout << "TorBuster v1.1\n";
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                show_banner();
                show_help(basename(argv[0]));
                return 0;
            case 't':
                threads_max = std::atoi(optarg);
                break;
            case 'e':
                excl = parse_http_codes_from_cmdline(optarg);
                break;
            case 'i':
                incl = parse_http_codes_from_cmdline(optarg);
                break;
            case 'p':
                port = std::atoi(optarg);
                break;
            case 'r':
                rate_limit = std::atoi(optarg);
                break;
            case 'R':
                max_retries = std::atoi(optarg);
                break;
            case 'L':
                redirects = true;
                break;
            case 'x':
                extensions = parse_extensions_from_cmdline(optarg);
                break;
            case '?':
            default:
                show_help(argv[0]);
                return -1;
        }
    }

    show_banner();

    if (verbose)
    {
        std::cout << "[DEBUG] URL: " << url << "\n";
        std::cout << "[DEBUG] Wordlist: " << wordlist << "\n";
        std::cout << "[DEBUG] Threads: " << threads_max << "\n";
        std::cout << "[DEBUG] Port: " << port << "\n";
        std::cout << "[DEBUG] Rate Limit: " << rate_limit << " req/ms\n";
        std::cout << "[DEBUG] SSL on Tor: " << (ssl_on_tor ? "YES" : "NO") << "\n";
    }

    endpoint_scanner e(url, rate_limit, threads_max);
    e.set_follow_redirects(redirects, 5);

    if (!incl.empty()) e.add_include_code(incl);
    if (!excl.empty()) e.add_exclude_code(excl);

    if (!wordlist.empty() && !url.empty())
    {
        if (!extensions.empty())
            e.load_wordlist(wordlist, extensions);
        else
            e.load_wordlist(wordlist);

        for (int i = 0; i < threads_max; i++) {
            threads.emplace_back(&endpoint_scanner::thread_func, &e, i, port, ssl_on_tor);
        }

        for (int i = 0; i < threads_max; i++) {
            if (threads[i].joinable())
                threads[i].join();
        }
    }
    e.print_summary();
}
catch (boost::system::system_error const &e)
{
    std::cerr << "Error: " << e.what() << std::endl;
}
catch (std::exception const &e)
{
    std::cerr << "Error: " << e.what() << std::endl;
}