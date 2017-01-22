import { EventEmitter } from 'events';
import paperfilter from 'paperfilter';

export default class Session extends EventEmitter {
  constructor(pubsub, pkg) {
    super();
    this._pubsub = pubsub;
    this._pkg = pkg;
    this._dissectors = [];
    this._streamDissectors = [];
    this._filterHints = {};
  }

  get devices() {
    return paperfilter.Session.devices;
  }

  registerDissector(script) {
    this._dissectors.push({
      script
    });
  }

  registerStreamDissector(script) {
    this._streamDissectors.push({
      script
    });
  }

  unregisterDissector(script) {
    let index = this._dissectors.find(e => e.path === script);
    if (index != null) {
      this._dissectors.splice(index, 1);
    }
  }

  unregisterStreamDissector(script) {
    let index = this._streamDissectors.find(e => e.path === script);
    if (index != null) {
      this._streamDissectors.splice(index, 1);
    }
  }

  registerFilterHints(name, hints) {
    this._filterHints[name] = hints;
    this._updateFilterHints();
  }

  unregisterFilterHints(name) {
    if (delete this._filterHints[name]) {
      this._updateFilterHints();
    }
  }

  _updateFilterHints() {
    let hints = [];
    for (let key in this._filterHints) {
      hints = hints.concat(this._filterHints[key]);
    }
    hints.sort((a, b) => {
      if (a.filter === b.filter) return 0;
      return (a.filter < b.filter) ? 1 : -1;
    });
    this._pubsub.pub('core:filter-hints', hints);
  }

  async create(options = {}) {
    let option = {
      namespace: '::<Ethernet>',
      dissectors: this._dissectors,
      stream_dissectors: this._streamDissectors,
      config: this._pkg.getConfigData()
    };

    let sess = await paperfilter.Session.create(option);
    sess.interface = options.ifs || '';
    sess.name = options.name || '';

    for (let dev of paperfilter.Session.devices) {
      if (dev.id === sess.interface) {
        sess.name = dev.name;
        break;
      }
    }

    if (options.filter != null) {
      sess.setBPF(options.filter);
    }

    return sess;
  }
}
