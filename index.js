/*@flow*/
'use strict';
const EventEmitter = require('events');
const Udp = require('dgram');
const Cjdnshdr = require('cjdnshdr');
const Cjdnsctrl = require('cjdnsctrl');
const Bencode = require('bencode');
const nThen = require('nthen');

const NOFUN = () => {};

const connectWithNewPort = (cjdns, usock, contentTypeCode, callback) => {
    usock.on('listening', () => {
        const portNum = usock.address().port;
        cjdns.UpperDistributor_registerHandler(portNum, contentTypeCode, (err, ret) => {
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
    usock.bind(0, '::');
};

const connect = (cjdns, contentTypeCode, _callback) => {
    const usock = Udp.createSocket('udp6');
    const callback = (e, ret) => {
        const cb = _callback;
        _callback = undefined;
        if (cb) { cb(e, ret); }
    };
    let onError;
    let onListening;
    usock.on('error',  (e) => {
        if (onError) { return void onError(e); }
        callback(e);
    });
    usock.on('listening', () => {
        if (onListening) { onListening(); }
    });
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
            if (h.type !== contentTypeCode) { next(cb); return; }
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
                if (e.code !== 'EINVAL' && e.code !== 'EBADF') {
                    callback(e);
                    return;
                }
                // Ok no handler exists, bind a new port...
                connectWithNewPort(cjdns, usock, contentTypeCode, callback);
            }
        });
    });
};

const decodeMessage = (bytes) => {
    let x = 0;
    const routeHeaderBytes = bytes.slice(x, x += Cjdnshdr.RouteHeader.SIZE);
    const routeHeader = Cjdnshdr.RouteHeader.parse(routeHeaderBytes);
    const dataHeaderBytes =
        routeHeader.isCtrl ? null : bytes.slice(x, x += Cjdnshdr.DataHeader.SIZE);
    const dataHeader = dataHeaderBytes ? Cjdnshdr.DataHeader.parse(dataHeaderBytes) : null;
    const dataBytes = bytes.slice(x);
    const out = {
        routeHeader: routeHeader,
        dataHeader: dataHeader,
        contentBytes: dataBytes,
        rawBytes: bytes,
        contentBenc: undefined,
        content: undefined
    };
    if (out.dataHeader && out.dataHeader.contentType === 'CJDHT') {
        out.contentBenc = Bencode.decode(dataBytes);
    } else if (routeHeader.isCtrl) {
        try {
            out.content = Cjdnsctrl.parse(dataBytes);
        } catch (e) {
            out.content = {
                error: e.message
            };
        }
    }
    return out;
};

const sendMessage = (msg, sock, dest, cb) => {
    // Optional 'dest' argument
    if (typeof(dest) === 'function' && !cb) { cb = dest; }
    if (typeof(dest) !== 'string') { dest = 'fc00::1'; }

    let contentBytes;
    if (msg.dataHeader && msg.dataHeader.contentType === 'CJDHT' && msg.contentBenc) {
        contentBytes = Bencode.encode(msg.contentBenc);
    } else if (msg.routeHeader.isCtrl && msg.content) {
        contentBytes = Cjdnsctrl.serialize(msg.content);
    } else {
        contentBytes = msg.contentBytes;
    }
    const routeHeaderBytes = Cjdnshdr.RouteHeader.serialize(msg.routeHeader);
    const dataHeaderBytes =
        msg.dataHeader ? Cjdnshdr.DataHeader.serialize(msg.dataHeader) : new Buffer(0);
    const buf = Buffer.concat([routeHeaderBytes, dataHeaderBytes, contentBytes]);
    sock.send(buf, 0, buf.length, 1, dest, cb);
};

/*::
import type { Cjdnshdr_RouteHeader_t, Cjdnshdr_DataHeader_t } from 'cjdnshdr'
import type { Cjdnsctrl_t, Cjdnsctrl_Ping_t, Cjdnsctrl_ErrMsg_t } from 'cjdnsctrl'
declare class Cjdnsniff_GenericMsg {
    routeHeader: Cjdnshdr_RouteHeader_t;
    dataHeader: Cjdnshdr_DataHeader_t;
    contentBytes: Buffer;
    rawBytes: Buffer;
};
export type Cjdnsniff_GenericMsg_t = Cjdnsniff_GenericMsg;
declare class Cjdnsniff_BencMsg extends Cjdnsniff_GenericMsg {
    contentBenc: Object;
};
export type Cjdnsniff_BencMsg_t = Cjdnsniff_BencMsg;
declare class Cjdnsniff_CtrlMsg extends Cjdnsniff_GenericMsg {
    content: any;
};
export type Cjdnsniff_CtrlMsg_t = Cjdnsniff_CtrlMsg;
export type Cjdnsniff_t = {
    on: (event: string, listener: (any)=>void) => Cjdnsniff_t,
    send: (Object, string, ()=>void) => void
}
*/

module.exports.sniffTraffic = (
    cjdns /*:Object*/,
    contentType /*:string*/,
    callback /*:(?Error, ?Cjdnsniff_t)=>void*/) =>
{
    const contentTypeCode = Cjdnshdr.ContentType.toNum(contentType);
    if (!contentTypeCode) {
        throw new Error("invalid content type [" + contentType + "]");
    }
    connect(cjdns, contentTypeCode, (err, _usock) => {
        if (err) {
            callback(err);
            return;
        }
        if (!_usock) { throw new Error("null error and no sock, should never happen"); }
        const usock = _usock;
        const emitter = new EventEmitter();
        const out = {};
        out.on = (name, cb) => { emitter.on(name, cb); return out; };
        out._usock = usock;
        out._emitter = emitter;
        out.send = (msg, dest, cb) => { sendMessage(msg, usock, dest, cb); };
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
        out.disconnect = (cb) => {
            cb = cb || NOFUN;
            cjdns.UpperDistributor_unregisterHandler(usock.address().port, (err, ret) => {
                if (err) { throw err; }
                usock.close();
                cb();
            });
        };
        let sigint = false;
        process.on('SIGINT', () => {
            if (sigint) { process.exit(100); }
            //console.error('Disconnecting...');
            out.disconnect(() => {
                process.exit(0);
            });
        });
        callback(undefined, out);
    });
};
