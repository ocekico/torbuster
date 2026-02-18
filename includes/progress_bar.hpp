#ifndef H_PROGRESS_BAR
#define H_PROGRESS_BAR

#include <iostream>
#include <string>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cmath>

/**
 * Thread-safe progress bar for TorBuster
 * Display format: [####.....]: 42% (125/300) [12.3 req/s] [ETA: 00:23])
 */
class progress_bar
{
    std::atomic<size_t> _current{0};
    size_t _total;
    size_t _bar_width;
    std::mutex _draw_mtx;
    std::chrono::steady_clock::time_point _start_time;
    bool _finished{false};

    // Characters for the bar
    static constexpr char FILL_CHAR = '#';
    static constexpr char EMPTY_CHAR = '.';
    static constexpr char TIP_CHAR = '>';

public:

    progress_bar(size_t total, size_t bar_width = 30) :
        _total(total),
        _bar_width(bar_width),
        _start_time(std::chrono::steady_clock::now())
    {}

    void print_above(const char *fmt, ...)
    {
        std::lock_guard<std::mutex> lg(_draw_mtx);
        if (_finished) return;

        std::fprintf(stderr, "\r\033[2K");
        std::fflush(stderr);

        // 2. Print the result line to stdout (ends with \n so it scrolls up)
        va_list args;
        va_start(args, fmt);
        std::vfprintf(stdout, fmt, args);
        va_end(args);
        std::fflush(stdout);

        // 3. Redraw bar on the new current line
        draw_bar_unlocked(_current.load(std::memory_order_relaxed));
    }

    void print_line_above(const std::string &line)
    {
        std::lock_guard<std::mutex> lg(_draw_mtx);
        if (_finished) return;

        std::fprintf(stderr, "\r\033[2K");
        std::fflush(stderr);

        std::fprintf(stdout, "%s", line.c_str());
        std::fflush(stdout);

        draw_bar_unlocked(_current.load(std::memory_order_relaxed));
    }

    /**
     * Increment progress by 1 and redraw.
     * Safe to call from multiple threads.
     */
    void tick(void)
    {
        size_t cur = _current.fetch_add(1, std::memory_order_relaxed) + 1;
        redraw(cur);
    }

    /**
     * Increment progress by 'n' and return
     */
    void advance(size_t n)
    {
        size_t cur = _current.fetch_add(n, std::memory_order_relaxed) + n;
        redraw(cur);
    }

    /**
     * Get current progress count
     */
    size_t current(void) const
    {
        return _current.load(std::memory_order_relaxed);
    }

    /**
     * Get total count
     */
    size_t total(void) const
    {
        return _total;
    }

    /**
     * Update total (useful if wordlist size changes)
     */
    void set_total(size_t t)
    {
        _total = t;
    }

    /**
     * Force a final redraw and print a newline
     */
    void finish(void)
    {
        std::lock_guard<std::mutex> lg(_draw_mtx);
        _finished = true;
        draw_bar_unlocked(_total);
        std::fprintf(stderr, "\n");
        std::fflush(stderr);
    }

    /**
     * Reset the bar for reuse
     */
    void reset(size_t new_total = 0)
    {
        std::lock_guard<std::mutex> lg(_draw_mtx);
        _current.store(0, std::memory_order_relaxed);
        _finished = false;
        if (new_total > 0)
            _total = new_total;
        _start_time = std::chrono::steady_clock::now();
    }

private:

    void redraw(size_t cur)
    {
        std::lock_guard<std::mutex> lg(_draw_mtx);
        if (_finished) return;
        draw_bar_unlocked(cur);
    }

    void draw_bar_unlocked(size_t cur)
    {
        if (_total == 0)
            return;

        // Clamp
        if (cur > _total)
            cur = _total;

        double ratio = static_cast<double>(cur) / static_cast<double>(_total);
        int percent = static_cast<int>(ratio * 100.0);

        // Calculate req/s and ETA
        auto now = std::chrono::steady_clock::now();
        double elapsed = std::chrono::duration<double>(now - _start_time).count();
        double rps = (elapsed > 0.05) ? (static_cast<double>(cur) / elapsed) : 0.0;
    
        int eta_s = 0;
        if (rps > 0.01 && cur < _total)
            eta_s = static_cast<int>(static_cast<double>(_total - cur) / rps);
        
        int eta_min = eta_s / 60;
        int eta_sec = eta_s % 60;
        int term_w = get_term_width();
        int fixed_len = 55;
        int avail = term_w - fixed_len;
        size_t bw = (avail > 10) ? static_cast<size_t>(avail) : _bar_width;

        size_t filled = static_cast<size_t>(ratio * bw);
        if (filled > bw) filled = bw;

        std::string bar(bw, EMPTY_CHAR);
        for (size_t i = 0; i < filled; i++)
            bar[i] = FILL_CHAR;
        if (filled < bw)
            bar[filled] = TIP_CHAR;

        // \r  = return to start of line
        // \033[2K = erase entire line
        // Then draw the bar on stderr so it doesn't mix with piped stdout
        std::fprintf(stderr,
            "\r\033[2K"
            "\033[1;36mTasks:\033[0m %zu/%zu "
            "| \033[1;37m%3d%%\033[0m "
            "| %.1f/s "
            "| \033[1;33mETA:\033[0m %02d:%02d "
            "[\033[1;32m%s\033[0m]",
            cur, _total,
            percent,
            rps,
            eta_min, eta_sec,
            bar.c_str()
        );
        std::fflush(stderr);
    }

    static int get_term_width(void)
    {
        struct winsize w;
        if (ioctl(STDERR_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0)
            return w.ws_col;
            return 80;
    }
};

#endif // H_PROGRESS_BAR