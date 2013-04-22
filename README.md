Phlegethon & Chiron
===================

Dynamically manage firewall rules based on peer activity.

Phlegethon tracks UDP transfer rates to individual remote peers from
a given source host.  Chiron manages firewall rules.  When the rate
of data transmitted to a peer exceeds a threshold, the Chiron script
is invoked.

## Download
To download this software using git:

```$ git clone git://github.com/IronSavior/phlegethon.git```

 or

```$ git clone https://github.com/IronSavior/phlegethon.git```

## Build

You will need a C++11 compiler, Boost, and libpcap.  I wrote phlegethon
to run on Linux, but I have also successfully built it on Windows with
MinGW/gcc (but not Cygwin).  With these requirements installed, just
use `make` to start the build.

## Documentation

Phlegethon collects data regarding the transmission rates of discrete
UDP streams (per remote peer) from a source address and port that are
specified on the command line.  The number of observed peers is shown
on the screen and any peers having data transferred to it above the
given minimum threshold are listed.  If an event script is specified,
then it is executed and passed the peer information when the threshold
is exceeded.

It's not that complex.  Just read the source code.

## Why?

The guilty pay the price.

### Copyrights

Original work is Copyright (C) 2013 Erik Elmore <erik@ironsavior.net>

### License
See LICENSE file for full text.

> This program is free software: you can redistribute it and/or modify
> it under the terms of the GNU General Public License as published by
> the Free Software Foundation, either version 3 of the License, or
> (at your option) any later version.
> 
> This program is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
> GNU General Public License for more details.
> 
> You should have received a copy of the GNU General Public License
> along with this program. If not, see <http://www.gnu.org/licenses/>.
