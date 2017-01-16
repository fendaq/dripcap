<packet-view-dripcap-enum>
  <script>
    this.on('before-mount', () => { this.reset() });
    this.on('update', () => { this.reset() });

    reset() {
      let keys = Object.keys(opts.val).filter(k => !k.startsWith('_') && opts.val[k]);
      this.name = keys.length > 0 ? keys.join(', ') : '[Unknown]';
      if (opts.val._name) this.name = opts.val._name;
      this.value = opts.val._value;
    }
  </script>
  <i>{ name } ({value}) </i>
</packet-view-dripcap-enum>

<packet-view-dripcap-flags>
  <script>
    this.on('before-mount', () => { this.reset() });
    this.on('update', () => { this.reset() });

    reset() {
      let keys = Object.keys(opts.val).filter(k => !k.startsWith('_') && opts.val[k]);
      keys = keys.map(k => opts.val._name[k]);
      this.name = keys.length > 0 ? keys.join(', ') : '[None]';
      this.value = opts.val._value;
    }
  </script>
  <i>{ name } ({value}) </i>
</packet-view-dripcap-flags>

<packet-view-custom-value>
  <script>
    this.on('mount', () => {
      if (opts.tag != null) {
        riot.mount(this.root, opts.tag, {val: opts.val});
      }
    });
  </script>
</packet-view-custom-value>

<packet-view-boolean-value>
  <i class="fa fa-check-square-o" if={ opts.val }></i>
  <i class="fa fa-square-o" if={ !opts.val }></i>
</packet-view-boolean-value>

<packet-view-buffer-value>
  <i>{ opts.val.length } bytes</i>
</packet-view-buffer-value>

<packet-view-stream-value>
  <i>{ opts.val.length } bytes</i>
</packet-view-stream-value>

<packet-view-integer-value>
  <i if={ base==2 } oncontextmenu={ context }>
    <i class="base">0b</i>{ opts.val.toString(2) }</i>
  <i if={ base==8 } oncontextmenu={ context }>
    <i class="base">0</i>{ opts.val.toString(8) }</i>
  <i if={ base==10 } oncontextmenu={ context }>{ opts.val.toString(10) }</i>
  <i if={ base==16 } oncontextmenu={ context }>
    <i class="base">0x</i>{ opts.val.toString(16) }</i>
  <script>
    const { remote } = require('electron');
    const { Menu } = require('dripcap');
    this.base = 10;

    context(e) {
      Menu.popup('packet-view:numeric-value-menu', this, remote.getCurrentWindow(), {event: e});
      e.stopPropagation();
    }
  </script>
</packet-view-integer-value>

<packet-view-string-value>
  <i></i>
  <script>
    const $ = require('jquery');

    this.on('update', () => {
      if (this.opts.val != null) {
        this.root.innerHTML = $('<div/>').text(this.opts.val.toString()).html();
      }
    });
  </script>
</packet-view-string-value>

<packet-view-item>
<li>
  <p class="label list-item" onclick={ toggle } range={ field.range } oncontextmenu={ context } onmouseover={ fieldRange } onmouseout={ rangeOut }>
    <i class={ fa: true, 'fa-circle-o': !field.items.length, 'fa-arrow-circle-right': field.items.length && !show, 'fa-arrow-circle-down': field.items.length && show }></i>
    <a class="text-label">{ field.name }</a>
    <packet-view-boolean-value if={ type=='boolean' } val={ val }></packet-view-boolean-value>
    <packet-view-integer-value if={ type=='integer' } val={ val }></packet-view-integer-value>
    <packet-view-string-value if={ type=='string' } val={ val }></packet-view-string-value>
    <packet-view-buffer-value if={ type=='buffer' } val={ val }></packet-view-buffer-value>
    <packet-view-stream-value if={ type=='stream' } val={ val }></packet-view-stream-value>
    <packet-view-custom-value if={ type=='custom' } tag={ tag } val={ val }></packet-view-custom-value>
    <a class="text-label">{ field.summary }</a>
  </p>
  <ul show={ field.items.length && show }>
    <packet-view-item each={ field in field.items } if={ field.name } layer={ parent.layer } parentObject={ parent.field } parentVal={ parent.val } path={ parent.path }></packet-view-item>
  </ul>
</li>

<script>
  const { remote } = require('electron');
  const { Menu } = require('dripcap');

  this.show = false;

  toggle(e) {
    if (this.field.items.length) {
      this.show = !this.show;
    }
    e.stopPropagation();
  }

  rangeOut() {
    this.parent.rangeOut();
  }

  fieldRange(e) {
    this.parent.fieldRange(e);
  };

  context(e) {
    if (this.path) {
      switch (typeof this.val) {
        case 'boolean':
          e.filterText = (this.val ? '' : '!') + this.path;
          break;
        case 'object':
          if (this.val._filter) {
            e.filterText = `${this.path} == ${JSON.stringify(this.val._filter)}`;
          } else {
            e.filterText = this.path;
          }
          break;
        default:
          e.filterText = `${this.path} == ${JSON.stringify(this.val)}`;
          break;
      }
    }
    Menu.popup('packet-view:context-menu', this, remote.getCurrentWindow(), {event: e});
    e.stopPropagation();
  };

  this.on('before-mount', () => {
    this.reset();
  });

  this.on('mount', () => {
    this.update();
  });

  this.on('update', () => {
    this.reset();
  });

  reset() {
    this.layer = opts.layer;
    this.val = this.field.value.data;
    this.type = null;
    this.tag = null;
    let valType = this.field.value.type;

    let id = this.field.id;
    if (id) {
      this.path = opts.path + '.' + id;
      if (opts.parentobject.getValue && opts.parentobject.getValue(id)) {
        let val = opts.parentobject.getValue(id)
        this.val = val.data;
        valType = val.type;
      } else if (typeof opts.parentval === 'object' && id in opts.parentval) {
        this.val = opts.parentval[id];
      } else if (opts.parentobject.hasOwnProperty(id)) {
        this.val = opts.parentobject[id];
      }
    }

    if (valType !== '') {
      let tag = 'packet-view-' + valType.replace(/\//g, '-');
      try {
        riot.render(tag, {val: this.val});
        this.type = 'custom';
        this.tag = tag;
      } catch (e) {
        // console.warn(`tag ${tag} not registered`);
      }
    }

    if (this.type == null) {
      if (typeof this.val === 'boolean') {
        this.type = 'boolean';
      } else if (Number.isInteger(this.val)) {
        this.type = 'integer';
      } else if (Buffer.isBuffer(this.val)) {
        this.type = 'buffer';
      } else if (this.val && this.val.constructor.name === 'LargeBuffer') {
        this.type = 'buffer';
      } else {
        this.type = 'string';
      }
    }
  }
</script>

<style type="text/less">
  :scope {
    -webkit-user-select: auto;
    .text-label {
      color: var(--color-keywords);
    }
  }
</style>

</packet-view-item>
