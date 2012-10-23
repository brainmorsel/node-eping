// javascript shim that lets our object inherit from EventEmitter
var Eping = require(__dirname + '/../build/Release/eping.node').Eping;
var events = require('events');

inherits(Eping, events.EventEmitter);
exports.Eping = Eping;

// extend prototype
function inherits(target, source) {
  for (var k in source.prototype)
    target.prototype[k] = source.prototype[k];
}
