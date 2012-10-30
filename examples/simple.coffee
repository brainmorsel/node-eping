{Eping} = require '..'

hosts = []
for i in [1..255]
  hosts.push "172.20.0.#{i}"

count = (status) ->
  [up, down] = [0, 0]
  (if state then up++ else down++) for state in status
  return up: up, down: down

options =
  hosts: hosts  # list of hosts to check
  tryouts: 3    # number of attempts for each host
  wait: 1000    # time to wait between attempts (ms)
  period: 5     # how often send ICMP packets (ms)
  timout: 1000  # time to wait after last ICMP request (ms)

p = new Eping(options)
  .on('one', (host, isUp, details) -> console.log 'one:', host, isUp, details)
  .on('all', (status) -> console.log 'all:', count(status))
  .start()
