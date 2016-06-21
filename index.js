'use strict';
const EventEmitter = require('events');
const Udp = require('dgram');
const Cjdnshdr = require('cjdnshdr');
const Bencode = require('bencode');
const nThen = require('nthen');

const connectWithNewPort = (cjdns, usock, callback) => {
    usock.on('listening', () => {
        const portNum = usock.address().port;
        cjdns.UpperDistributor_registerHandler(portNum, 256, (err, ret) => {
            if (err) {
                callback(err);
                return;
            }
            if (ret.error !== 'none') {
                callback(new Error("From cjdns: " + JSON.stringify(ret)));
                return;
            }
            usock.removeAllListeners('listening');
            callback(undefined, usock);
        });
    });
    usock.bind('::');
};

const connect = (cjdns, _callback) => {
    const usock = Udp.createSocket('udp6');
    const callback = (e, ret) => {
        const cb = _callback;
        _callback = undefined;
        if (cb) { cb(e, ret); }
    };
    let onError;
    let onListening;
    usock.on('error',  (e) => {
        onError ? onError(e) : (()=>{ callback(e); })()
    });
    usock.on('listening', () => { onListening && onListening(); });
    let portNum;

    cjdns.UpperDistributor_listHandlers(0, (err, ret) => {
        if (err) {
            callback(err);
            return;
        }
        if (ret.error !== 'none') {
            callback(new Error("From cjdns: " + JSON.stringify(ret)));
            return;
        }
        const handlers = ret.handlers;
        const next = (cb) => {
            if (!handlers.length) {
                cb();
                return;
            }
            const h = handlers.pop();
            if (h.type !== 256) { next(cb); return; }
            const portNum = h.udpPort;
            onError = (e) => {
                if (e.code !== 'EADDRINUSE') {
                    callback(e);
                    return;
                }
                //console.log(portNum + ' in use');
                // Needs to be async because the socket is "in use" until returning from the error.
                setTimeout(() => { next(cb); }, 0);
            };
            onListening = cb;
            usock.bind(portNum, '::');
        };
        next(() => {
            usock.removeAllListeners('error');
            usock.removeAllListeners('listening');
            try {
                usock.address();
                callback(undefined, usock);
            } catch (e) {
                if (e.code !== 'EINVAL') {
                    callback(e);
                    return;
                }
                // Ok no handler exists, bind a new port...
                connectWithNewPort(cjdns, usock, callback);
            }
        });
    });
};

const decodeMessage = (bytes) => {
    let x = 0;
    const routeHeaderBytes = bytes.slice(x, x += Cjdnshdr.RouteHeader.SIZE);
    const dataHeaderBytes = bytes.slice(x, x += Cjdnshdr.DataHeader.SIZE);
    const dataBytes = bytes.slice(x);
    const out = {
        routeHeader: Cjdnshdr.RouteHeader.parse(routeHeaderBytes),
        dataHeader: Cjdnshdr.DataHeader.parse(dataHeaderBytes),
        contentBytes: bytes
    };
    if (out.dataHeader.contentType === 'CJDHT') {
        out.contentBenc = Bencode.decode(dataBytes);
    }
    return out;
};

const sendMessage = (msg, sock, cb) => {
    const contentBytes = (msg.contentBenc) ? Bencode.encode(msg.contentBenc) : msg.contentBytes;
    const routeHeaderBytes = Cjdnshdr.RouteHeader.serialize(msg.routeHeader);
    const dataHeaderBytes = Cjdnshdr.DataHeader.serialize(msg.dataHeader);
    const buf = Buffer.concat([routeHeaderBytes, dataHeaderBytes, contentBytes]);
    sock.send(buf, 0, buf.length, 1, 'fc00::1', cb);
};

module.exports.sniffTraffic = (cjdns, contentType, callback) => {
    connect(cjdns, (err, usock) => {
        if (err) {
            callback(err);
            return;
        }
        const emitter = new EventEmitter();
        emitter._usock = usock;
        emitter.send = (msg, cb) => { sendMessage(msg, usock, cb); };
        usock.on('message', (bytes, rinfo) => {
            try {
                emitter.emit('message', decodeMessage(bytes));
            } catch (e) {
                emitter.emit('error', e);
            }
        });
        usock.on('error', (e) => {
            emitter.emit('error', e);
        });
        let sigint = false;
        process.on('SIGINT', () => {
            if (sigint) { process.exit(100); }
            //console.error('Disconnecting...');
            cjdns.UpperDistributor_unregisterHandler(usock.address().port, (err, ret) => {
                if (err) { throw err; }
                process.exit(0);
            });
        });
        callback(undefined, emitter);
    });
};
