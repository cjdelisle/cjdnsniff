'use strict';
const Cjdnsadmin = require('cjdnsadmin');
const Cjdnsniff = require('./index');
const Cjdnskeys = require('cjdnskeys');
const Cjdnsctrl = require('cjdnsctrl');

Cjdnsadmin.connectWithAdminInfo((cjdns) => {
    Cjdnsniff.sniffTraffic(cjdns, 'CTRL', (err, ev) => {
        if (err) { throw err; }
        ev.on('error', (e) => { console.error(e); });
        ev.on('message', (msg) => {
            msg.content = Cjdnsctrl.parse(msg.contentBytes);

            const pr = [];
            pr.push(msg.routeHeader.isIncoming ? '>' : '<');
            pr.push(msg.routeHeader.switchHeader.label);
            pr.push(msg.content.type);
            if (/P[IO]NG/.test(msg.content.type)) {
                pr.push('v' + msg.content.version);
            }
            if (/KEYP[IO]NG/.test(msg.content.type)) {
                pr.push(msg.content.key);
            }
            if (msg.content.type === 'ERROR') {
                pr.push(msg.content.errType);
                pr.push('label_at_err_node:');
                pr.push(msg.content.switchHeader.label);
                pr.push('nonce:');
                pr.push(msg.content.nonce);
            }
            console.log(pr.join(' '));
        });
    });
});
