// Copyright (C) 2020 Leyuan Pan
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE or copy at
// http://www.boost.org/LICENSE_1_0.txt)

#include <fcntl.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include "boost/asio.hpp"

/// sudo ip addr add 192.168.3.1/24 dev mytap
/// sudo ip link set dev mytap up (or sudo ifconfig mytap up)
/// ping 192.168.3.1

namespace asio = boost::asio;

int TapOpen(char *dev) {
  int fd;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
    return -1;
  }

  struct ifreq ifr;
  std::memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  if (*dev) {
    std::strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    goto failed;
  }

  std::strcpy(dev, ifr.ifr_name);
  return fd;

failed:
  close(fd);
  return -1;
}

int main(int argc, char **argv) {
  char tap_name[20] = "mytap";
  int tap_fd = TapOpen(tap_name);
  if (tap_fd < 0) {
    std::cerr << "Error to open tap" << std::endl;
    return -1;
  }

  asio::io_context ioc;
  boost::asio::signal_set signals(ioc, SIGINT, SIGTERM);
  signals.async_wait([&](std::error_code const &, int) { ioc.stop(); });

  asio::posix::stream_descriptor tap(ioc, tap_fd);

  char read_buff[2048];
  std::function<void(std::error_code const &, std::size_t)> on_read;

  on_read = [&](std::error_code const &errc, std::size_t len) {
    std::cout << "Read " << std::dec << std::setw(3) << len << " bytes: ";
    for (int i = 0; i < 18; ++i) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << int{static_cast<std::uint8_t>(read_buff[i])} << ":";
    }
    std::cout << std::endl;

    tap.async_read_some(asio::buffer(read_buff), on_read);
  };
  tap.async_read_some(asio::buffer(read_buff), on_read);

  ioc.run();

  close(tap_fd);

  return 0;
}
