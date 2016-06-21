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
