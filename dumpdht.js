'use strict';
const Cjdnsadmin = require('cjdnsadmin');
const Cjdnsniff = require('./index');
const Cjdnskeys = require('cjdnskeys');

Cjdnsadmin.connectWithAdminInfo((cjdns) => {
    Cjdnsniff.sniffTraffic(cjdns, 'CJDHT', (err, ev) => {
        if (err) { throw err; }
        ev.on('error', (e) => { console.error(e); });
        ev.on('message', (msg) => {
            const pr = [];
            pr.push(msg.routeHeader.isIncoming ? '>' : '<');
            pr.push('v' + msg.routeHeader.version);
            pr.push(msg.routeHeader.switchHeader.label);
            pr.push(msg.routeHeader.ip);
            //console.log(msg.routeHeader);
            const qb = msg.contentBenc.q;
            if (!qb) {
                pr.push('reply');
            } else {
                const q = qb.toString('utf8');
                pr.push(q);
                if (q === 'fn') {
                    pr.push(Cjdnskeys.ip6BytesToString(msg.contentBenc.tar));
                }
            }
            console.log(pr.join(' '));
        });
    });
});
