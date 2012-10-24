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
    
    hosts = []
    for i in [1..255]
      hosts.push "172.20.0.#{i}"
    
    p = new Eping(hosts)
      .on('one', (host, isUp) -> console.log 'one:', host, isUp)
      .on('all', (status) -> console.log 'all:', status)
      .start()

