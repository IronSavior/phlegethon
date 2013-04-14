Phlegethon & Chiron
===================

Dynamically manage firewall rules based on peer activity.

Phlegethon tracks UDP transfer rates to individual remote peers from
a given source host.  Chiron manages firewall rules.  When a the rate
of data transmitted to a peer exceeds a threshold, the Chiron script
is invoked.

## Download
To download this software using git:

```$ git clone git://github.com/IronSavior/phlegethon.git```

 or

```$ git clone https://github.com/IronSavior/phlegethon.git```

## Documentation

You will need a C++11 compiler, Boost, and libpcap.  I use this on
Linux, but I suppose you could use a different "chiron" script that
works for another platform as long as libpcap is available.

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
