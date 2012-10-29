{Eping} = require '..'

hosts = []
for i in [1..255]
  hosts.push "172.20.0.#{i}"

p = new Eping(hosts)
  .on('one', (host, isUp, details) -> console.log 'one:', host, isUp, details)
  .on('all', (status) -> console.log 'all:', status)
  .start()
