import {Layer, Value, StreamChunk, Buffer, LargeBuffer} from 'dripcap';

export default class Dissector {
  static get namespaces() {
    return [/::Ethernet::\w+::TCP/];
  }

  constructor() {
    this.dec = this.decode();
  }

  analyze(packet, parentLayer, chunk) {
    if (this.dec) {
      let next = this.dec.next(chunk.attrs.payload.data);
      if (next.value === false) {
        this.dec = null;
      } else if (typeof next.value === 'object') {
        this.dec = this.decode();

        let layer = {
          items: []
        };
        layer.namespace = chunk.namespace + '::HTTP';
        layer.name = 'HTTP';
        layer.id = 'http';

        let large = new LargeBuffer();
        large.write(next.value.payload);
        layer.payload = large;

        let method = next.value.method;
        let cursor = method.length;

        layer.items.push({
          name: 'Method',
          id: 'method',
          range: '0:' + cursor,
          value: method
        });

        let path = next.value.path;
        cursor++;
        layer.items.push({
          name: 'Path',
          id: 'path',
          range: cursor + ':' + (cursor + path.length),
          value: path
        });

        let version = next.value.version;
        cursor += path.length + 1;
        layer.items.push({
          name: 'Version',
          id: 'version',
          range: cursor + ':' + (cursor + version.length),
          value: version
        });

        for (let header of next.value.headers) {
          layer.items.push({
            name: header.key,
            id: header.key,
            value: header.value,
            range: header.range
          });
        }

        layer.items.push({id: 'src', value: parentLayer.getValue('src')});
        layer.items.push({id: 'dst', value: parentLayer.getValue('dst')});

        return new Layer(layer);
      }
    }
  }

  *decode() {
    let payload = new Buffer([]);
    let http = {};
    let headerEnd = -1;
    let contentLength = -1;
    while (true) {
      let chunk = yield(true);
      payload = Buffer.concat([payload, chunk]);
      headerEnd = payload.indexOf(Buffer.from('\r\n\r\n', 'utf8'));
      if (headerEnd > 0) {
        let header = payload.slice(0, headerEnd + 4).toString('utf8');
        let re = /(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) (\S+) (HTTP\/(0\.9|1\.0|1\.1))\r\n/;
        let m = header.match(re);
        if (m != null) {
          http.method = m[1];
          http.path = m[2];
          http.version = m[3];
          http.payload = payload;
          http.headers = [];

          if (http.method === 'HEAD') {
            contentLength = 0;
          }

          let cursor = m[0].length;
          header = header.substr(cursor);
          let re = /(\S+):\s*([^\r\n]+)\r\n/;
          while (true) {
            let m = header.match(re);
            if (m == null) break;
            http.headers.push({
              key: m[1],
              value: m[2],
              range: `${cursor}:${cursor+m[0].length}`
            });
            cursor += m[0].length;
            header = header.substr(m[0].length);
            if (m[1].toLowerCase() === 'content-length') {
              contentLength = parseInt(m[2]);
            }
          }
          break;
        } else {
          yield false;
        }
      }
    }

    if (contentLength > 0) {
      let totalLength = headerEnd + 4 + contentLength;
      while (true) {
        if (http.payload.length >= totalLength) {
          http.payload = http.payload.slice(0, totalLength);
          break;
        }
        let chunk = yield(true);
        http.payload = Buffer.concat([http.payload, chunk]);
      }
    }

    yield http;
  }
};
