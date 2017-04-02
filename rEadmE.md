# Cjdnsniff
Library for sniffing and injecting cjdns traffic.

**NOTE**: This requires cjdns v18 or higher. As of June 2016 this means you need to recompile
cjdns using the crashey branch.

## API

* sniffTraffic(cjdns, type, callback)
 * cjdns - a Cjdnadmin which is connected to an existing cjdns engine on the local machine.
 * type - the type of traffic to sniff, see ContentType in cjdnshdr (you probably want 'CJDHT')
 * callback(err, ev)
  * err - any error if one occus while connecting
  * ev - an EventEmitter which will emit 'message' and/or 'error' events.

Example:

```javascript
Cjdnsniff.sniffTraffic(cjdns, 'CJDHT', (err, ev) => {
    ev.on('message', (msg) => { console.log(msg); });
    ev.on('error', (e) => { console.error(e); });
});
```

## Message structure

```
{
    routeHeader: A RouteHeader object (see cjdnshdr)
    dataHeader: A DataHeader object (see cjdnshdr)
    contentBytes: Raw binary of the content
    contentBenc: *optional* in the event that the contentType is `CJDHT` the b-decoded content.
}
```

## Example

To see an example of this tool in usage, run `node ./dumpctrl.js` which will dump all of the
`CJDHT` control traffic.

## Using with flow

This lib defines types for the things it will give you but it will call your event handler with the
any type so that you are not constrained. In order to take advantage of type checking you need to
cast the message after you've received it. Both the message and the message.content fields
in CTRL messages will be with content type any. See dumpctrl.js and dumpdht.js for more information.

```javascript
/*::import type { Cjdnsniff_CtrlMsg_t } from 'cjdnsniff'*/
Cjdnsniff.sniffTraffic(cjdns, 'CTRL', (err, ev) => {
    ev.on('message', (msg) => {
        /*::msg = (msg:Cjdnsniff_CtrlMsg_t);*/
        if (msg.content.type === 'PING') {
            const content = (msg.content/*:Cjdnsctrl_Ping_t*/);
            console.log("got ping with version " + content.version);
        }
    });
});
```
