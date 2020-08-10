# Copyright (C) 2020 Leyuan Pan
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

cmake_minimum_required(VERSION 3.15.3)
project(asio_tuntap LANGUAGES CXX)

find_package(Boost "1.71.0" REQUIRED COMPONENTS headers)

add_executable(asio_tuntap main.cpp)
target_link_libraries(asio_tuntap PUBLIC Boost::headers pthread)
