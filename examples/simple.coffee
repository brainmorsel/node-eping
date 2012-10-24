{Eping} = require '..'

hosts = []
for i in [1..255]
  hosts.push "172.20.0.#{i}"

p = new Eping(hosts)
  .on('one', (host, isUp) -> console.log 'one:', host, isUp)
  .on('all', (status) -> console.log 'all:', status)
  .start()

