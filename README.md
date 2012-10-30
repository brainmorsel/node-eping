Eping
=====

Simple node.js addon to send ICMP echo request and receive responces in EventEmitter style.

Install with:

    npm install eping

On Arch Linux or other distribution with Python 3 as system default interpreter you may need specify path to python2 executable:

    PYTHON=/usr/bin/python2 npm install eping

Usage
-----

Simple example (on coffeescript):

    {Eping} = require 'eping'
    
    p = new Eping(hosts: ['172.0.0.1', '8.8.8.8', '192.168.166.199'])
      .on('one', (host, isUp) -> console.log 'one:', host, isUp)
      .start()

You can find more detailed example in examples/ directory.
