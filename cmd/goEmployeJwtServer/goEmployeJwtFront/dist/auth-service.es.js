var ft = Object.defineProperty;
var dt = (e, t, n) => t in e ? ft(e, t, { enumerable: !0, configurable: !0, writable: !0, value: n }) : e[t] = n;
var le = (e, t, n) => dt(e, typeof t != "symbol" ? t + "" : t, n);
function je(e, t) {
  return function() {
    return e.apply(t, arguments);
  };
}
const { toString: pt } = Object.prototype, { getPrototypeOf: Se } = Object, { iterator: ne, toStringTag: $e } = Symbol, re = /* @__PURE__ */ ((e) => (t) => {
  const n = pt.call(t);
  return e[n] || (e[n] = n.slice(8, -1).toLowerCase());
})(/* @__PURE__ */ Object.create(null)), N = (e) => (e = e.toLowerCase(), (t) => re(t) === e), se = (e) => (t) => typeof t === e, { isArray: q } = Array, J = se("undefined");
function ht(e) {
  return e !== null && !J(e) && e.constructor !== null && !J(e.constructor) && x(e.constructor.isBuffer) && e.constructor.isBuffer(e);
}
const qe = N("ArrayBuffer");
function mt(e) {
  let t;
  return typeof ArrayBuffer < "u" && ArrayBuffer.isView ? t = ArrayBuffer.isView(e) : t = e && e.buffer && qe(e.buffer), t;
}
const gt = se("string"), x = se("function"), Me = se("number"), oe = (e) => e !== null && typeof e == "object", Et = (e) => e === !0 || e === !1, G = (e) => {
  if (re(e) !== "object")
    return !1;
  const t = Se(e);
  return (t === null || t === Object.prototype || Object.getPrototypeOf(t) === null) && !($e in e) && !(ne in e);
}, wt = N("Date"), yt = N("File"), St = N("Blob"), bt = N("FileList"), Rt = (e) => oe(e) && x(e.pipe), Tt = (e) => {
  let t;
  return e && (typeof FormData == "function" && e instanceof FormData || x(e.append) && ((t = re(e)) === "formdata" || // detect form-data instance
  t === "object" && x(e.toString) && e.toString() === "[object FormData]"));
}, At = N("URLSearchParams"), [Ot, _t, xt, Ut] = ["ReadableStream", "Request", "Response", "Headers"].map(N), Ct = (e) => e.trim ? e.trim() : e.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, "");
function v(e, t, { allOwnKeys: n = !1 } = {}) {
  if (e === null || typeof e > "u")
    return;
  let r, s;
  if (typeof e != "object" && (e = [e]), q(e))
    for (r = 0, s = e.length; r < s; r++)
      t.call(null, e[r], r, e);
  else {
    const o = n ? Object.getOwnPropertyNames(e) : Object.keys(e), i = o.length;
    let c;
    for (r = 0; r < i; r++)
      c = o[r], t.call(null, e[c], c, e);
  }
}
function He(e, t) {
  t = t.toLowerCase();
  const n = Object.keys(e);
  let r = n.length, s;
  for (; r-- > 0; )
    if (s = n[r], t === s.toLowerCase())
      return s;
  return null;
}
const B = typeof globalThis < "u" ? globalThis : typeof self < "u" ? self : typeof window < "u" ? window : global, Je = (e) => !J(e) && e !== B;
function he() {
  const { caseless: e } = Je(this) && this || {}, t = {}, n = (r, s) => {
    const o = e && He(t, s) || s;
    G(t[o]) && G(r) ? t[o] = he(t[o], r) : G(r) ? t[o] = he({}, r) : q(r) ? t[o] = r.slice() : t[o] = r;
  };
  for (let r = 0, s = arguments.length; r < s; r++)
    arguments[r] && v(arguments[r], n);
  return t;
}
const Nt = (e, t, n, { allOwnKeys: r } = {}) => (v(t, (s, o) => {
  n && x(s) ? e[o] = je(s, n) : e[o] = s;
}, { allOwnKeys: r }), e), kt = (e) => (e.charCodeAt(0) === 65279 && (e = e.slice(1)), e), Pt = (e, t, n, r) => {
  e.prototype = Object.create(t.prototype, r), e.prototype.constructor = e, Object.defineProperty(e, "super", {
    value: t.prototype
  }), n && Object.assign(e.prototype, n);
}, Dt = (e, t, n, r) => {
  let s, o, i;
  const c = {};
  if (t = t || {}, e == null) return t;
  do {
    for (s = Object.getOwnPropertyNames(e), o = s.length; o-- > 0; )
      i = s[o], (!r || r(i, e, t)) && !c[i] && (t[i] = e[i], c[i] = !0);
    e = n !== !1 && Se(e);
  } while (e && (!n || n(e, t)) && e !== Object.prototype);
  return t;
}, Lt = (e, t, n) => {
  e = String(e), (n === void 0 || n > e.length) && (n = e.length), n -= t.length;
  const r = e.indexOf(t, n);
  return r !== -1 && r === n;
}, It = (e) => {
  if (!e) return null;
  if (q(e)) return e;
  let t = e.length;
  if (!Me(t)) return null;
  const n = new Array(t);
  for (; t-- > 0; )
    n[t] = e[t];
  return n;
}, Ft = /* @__PURE__ */ ((e) => (t) => e && t instanceof e)(typeof Uint8Array < "u" && Se(Uint8Array)), Bt = (e, t) => {
  const r = (e && e[ne]).call(e);
  let s;
  for (; (s = r.next()) && !s.done; ) {
    const o = s.value;
    t.call(e, o[0], o[1]);
  }
}, jt = (e, t) => {
  let n;
  const r = [];
  for (; (n = e.exec(t)) !== null; )
    r.push(n);
  return r;
}, $t = N("HTMLFormElement"), qt = (e) => e.toLowerCase().replace(
  /[-_\s]([a-z\d])(\w*)/g,
  function(n, r, s) {
    return r.toUpperCase() + s;
  }
), Ae = (({ hasOwnProperty: e }) => (t, n) => e.call(t, n))(Object.prototype), Mt = N("RegExp"), ve = (e, t) => {
  const n = Object.getOwnPropertyDescriptors(e), r = {};
  v(n, (s, o) => {
    let i;
    (i = t(s, o, e)) !== !1 && (r[o] = i || s);
  }), Object.defineProperties(e, r);
}, Ht = (e) => {
  ve(e, (t, n) => {
    if (x(e) && ["arguments", "caller", "callee"].indexOf(n) !== -1)
      return !1;
    const r = e[n];
    if (x(r)) {
      if (t.enumerable = !1, "writable" in t) {
        t.writable = !1;
        return;
      }
      t.set || (t.set = () => {
        throw Error("Can not rewrite read-only method '" + n + "'");
      });
    }
  });
}, Jt = (e, t) => {
  const n = {}, r = (s) => {
    s.forEach((o) => {
      n[o] = !0;
    });
  };
  return q(e) ? r(e) : r(String(e).split(t)), n;
}, vt = () => {
}, zt = (e, t) => e != null && Number.isFinite(e = +e) ? e : t;
function Vt(e) {
  return !!(e && x(e.append) && e[$e] === "FormData" && e[ne]);
}
const Wt = (e) => {
  const t = new Array(10), n = (r, s) => {
    if (oe(r)) {
      if (t.indexOf(r) >= 0)
        return;
      if (!("toJSON" in r)) {
        t[s] = r;
        const o = q(r) ? [] : {};
        return v(r, (i, c) => {
          const f = n(i, s + 1);
          !J(f) && (o[c] = f);
        }), t[s] = void 0, o;
      }
    }
    return r;
  };
  return n(e, 0);
}, Kt = N("AsyncFunction"), Xt = (e) => e && (oe(e) || x(e)) && x(e.then) && x(e.catch), ze = ((e, t) => e ? setImmediate : t ? ((n, r) => (B.addEventListener("message", ({ source: s, data: o }) => {
  s === B && o === n && r.length && r.shift()();
}, !1), (s) => {
  r.push(s), B.postMessage(n, "*");
}))(`axios@${Math.random()}`, []) : (n) => setTimeout(n))(
  typeof setImmediate == "function",
  x(B.postMessage)
), Gt = typeof queueMicrotask < "u" ? queueMicrotask.bind(B) : typeof process < "u" && process.nextTick || ze, Qt = (e) => e != null && x(e[ne]), a = {
  isArray: q,
  isArrayBuffer: qe,
  isBuffer: ht,
  isFormData: Tt,
  isArrayBufferView: mt,
  isString: gt,
  isNumber: Me,
  isBoolean: Et,
  isObject: oe,
  isPlainObject: G,
  isReadableStream: Ot,
  isRequest: _t,
  isResponse: xt,
  isHeaders: Ut,
  isUndefined: J,
  isDate: wt,
  isFile: yt,
  isBlob: St,
  isRegExp: Mt,
  isFunction: x,
  isStream: Rt,
  isURLSearchParams: At,
  isTypedArray: Ft,
  isFileList: bt,
  forEach: v,
  merge: he,
  extend: Nt,
  trim: Ct,
  stripBOM: kt,
  inherits: Pt,
  toFlatObject: Dt,
  kindOf: re,
  kindOfTest: N,
  endsWith: Lt,
  toArray: It,
  forEachEntry: Bt,
  matchAll: jt,
  isHTMLForm: $t,
  hasOwnProperty: Ae,
  hasOwnProp: Ae,
  // an alias to avoid ESLint no-prototype-builtins detection
  reduceDescriptors: ve,
  freezeMethods: Ht,
  toObjectSet: Jt,
  toCamelCase: qt,
  noop: vt,
  toFiniteNumber: zt,
  findKey: He,
  global: B,
  isContextDefined: Je,
  isSpecCompliantForm: Vt,
  toJSONObject: Wt,
  isAsyncFn: Kt,
  isThenable: Xt,
  setImmediate: ze,
  asap: Gt,
  isIterable: Qt
};
function m(e, t, n, r, s) {
  Error.call(this), Error.captureStackTrace ? Error.captureStackTrace(this, this.constructor) : this.stack = new Error().stack, this.message = e, this.name = "AxiosError", t && (this.code = t), n && (this.config = n), r && (this.request = r), s && (this.response = s, this.status = s.status ? s.status : null);
}
a.inherits(m, Error, {
  toJSON: function() {
    return {
      // Standard
      message: this.message,
      name: this.name,
      // Microsoft
      description: this.description,
      number: this.number,
      // Mozilla
      fileName: this.fileName,
      lineNumber: this.lineNumber,
      columnNumber: this.columnNumber,
      stack: this.stack,
      // Axios
      config: a.toJSONObject(this.config),
      code: this.code,
      status: this.status
    };
  }
});
const Ve = m.prototype, We = {};
[
  "ERR_BAD_OPTION_VALUE",
  "ERR_BAD_OPTION",
  "ECONNABORTED",
  "ETIMEDOUT",
  "ERR_NETWORK",
  "ERR_FR_TOO_MANY_REDIRECTS",
  "ERR_DEPRECATED",
  "ERR_BAD_RESPONSE",
  "ERR_BAD_REQUEST",
  "ERR_CANCELED",
  "ERR_NOT_SUPPORT",
  "ERR_INVALID_URL"
  // eslint-disable-next-line func-names
].forEach((e) => {
  We[e] = { value: e };
});
Object.defineProperties(m, We);
Object.defineProperty(Ve, "isAxiosError", { value: !0 });
m.from = (e, t, n, r, s, o) => {
  const i = Object.create(Ve);
  return a.toFlatObject(e, i, function(f) {
    return f !== Error.prototype;
  }, (c) => c !== "isAxiosError"), m.call(i, e.message, t, n, r, s), i.cause = e, i.name = e.name, o && Object.assign(i, o), i;
};
const Yt = null;
function me(e) {
  return a.isPlainObject(e) || a.isArray(e);
}
function Ke(e) {
  return a.endsWith(e, "[]") ? e.slice(0, -2) : e;
}
function Oe(e, t, n) {
  return e ? e.concat(t).map(function(s, o) {
    return s = Ke(s), !n && o ? "[" + s + "]" : s;
  }).join(n ? "." : "") : t;
}
function Zt(e) {
  return a.isArray(e) && !e.some(me);
}
const en = a.toFlatObject(a, {}, null, function(t) {
  return /^is[A-Z]/.test(t);
});
function ie(e, t, n) {
  if (!a.isObject(e))
    throw new TypeError("target must be an object");
  t = t || new FormData(), n = a.toFlatObject(n, {
    metaTokens: !0,
    dots: !1,
    indexes: !1
  }, !1, function(g, h) {
    return !a.isUndefined(h[g]);
  });
  const r = n.metaTokens, s = n.visitor || u, o = n.dots, i = n.indexes, f = (n.Blob || typeof Blob < "u" && Blob) && a.isSpecCompliantForm(t);
  if (!a.isFunction(s))
    throw new TypeError("visitor must be a function");
  function l(d) {
    if (d === null) return "";
    if (a.isDate(d))
      return d.toISOString();
    if (a.isBoolean(d))
      return d.toString();
    if (!f && a.isBlob(d))
      throw new m("Blob is not supported. Use a Buffer instead.");
    return a.isArrayBuffer(d) || a.isTypedArray(d) ? f && typeof Blob == "function" ? new Blob([d]) : Buffer.from(d) : d;
  }
  function u(d, g, h) {
    let S = d;
    if (d && !h && typeof d == "object") {
      if (a.endsWith(g, "{}"))
        g = r ? g : g.slice(0, -2), d = JSON.stringify(d);
      else if (a.isArray(d) && Zt(d) || (a.isFileList(d) || a.endsWith(g, "[]")) && (S = a.toArray(d)))
        return g = Ke(g), S.forEach(function(A, D) {
          !(a.isUndefined(A) || A === null) && t.append(
            // eslint-disable-next-line no-nested-ternary
            i === !0 ? Oe([g], D, o) : i === null ? g : g + "[]",
            l(A)
          );
        }), !1;
    }
    return me(d) ? !0 : (t.append(Oe(h, g, o), l(d)), !1);
  }
  const p = [], E = Object.assign(en, {
    defaultVisitor: u,
    convertValue: l,
    isVisitable: me
  });
  function R(d, g) {
    if (!a.isUndefined(d)) {
      if (p.indexOf(d) !== -1)
        throw Error("Circular reference detected in " + g.join("."));
      p.push(d), a.forEach(d, function(S, T) {
        (!(a.isUndefined(S) || S === null) && s.call(
          t,
          S,
          a.isString(T) ? T.trim() : T,
          g,
          E
        )) === !0 && R(S, g ? g.concat(T) : [T]);
      }), p.pop();
    }
  }
  if (!a.isObject(e))
    throw new TypeError("data must be an object");
  return R(e), t;
}
function _e(e) {
  const t = {
    "!": "%21",
    "'": "%27",
    "(": "%28",
    ")": "%29",
    "~": "%7E",
    "%20": "+",
    "%00": "\0"
  };
  return encodeURIComponent(e).replace(/[!'()~]|%20|%00/g, function(r) {
    return t[r];
  });
}
function be(e, t) {
  this._pairs = [], e && ie(e, this, t);
}
const Xe = be.prototype;
Xe.append = function(t, n) {
  this._pairs.push([t, n]);
};
Xe.toString = function(t) {
  const n = t ? function(r) {
    return t.call(this, r, _e);
  } : _e;
  return this._pairs.map(function(s) {
    return n(s[0]) + "=" + n(s[1]);
  }, "").join("&");
};
function tn(e) {
  return encodeURIComponent(e).replace(/%3A/gi, ":").replace(/%24/g, "$").replace(/%2C/gi, ",").replace(/%20/g, "+").replace(/%5B/gi, "[").replace(/%5D/gi, "]");
}
function Ge(e, t, n) {
  if (!t)
    return e;
  const r = n && n.encode || tn;
  a.isFunction(n) && (n = {
    serialize: n
  });
  const s = n && n.serialize;
  let o;
  if (s ? o = s(t, n) : o = a.isURLSearchParams(t) ? t.toString() : new be(t, n).toString(r), o) {
    const i = e.indexOf("#");
    i !== -1 && (e = e.slice(0, i)), e += (e.indexOf("?") === -1 ? "?" : "&") + o;
  }
  return e;
}
class xe {
  constructor() {
    this.handlers = [];
  }
  /**
   * Add a new interceptor to the stack
   *
   * @param {Function} fulfilled The function to handle `then` for a `Promise`
   * @param {Function} rejected The function to handle `reject` for a `Promise`
   *
   * @return {Number} An ID used to remove interceptor later
   */
  use(t, n, r) {
    return this.handlers.push({
      fulfilled: t,
      rejected: n,
      synchronous: r ? r.synchronous : !1,
      runWhen: r ? r.runWhen : null
    }), this.handlers.length - 1;
  }
  /**
   * Remove an interceptor from the stack
   *
   * @param {Number} id The ID that was returned by `use`
   *
   * @returns {Boolean} `true` if the interceptor was removed, `false` otherwise
   */
  eject(t) {
    this.handlers[t] && (this.handlers[t] = null);
  }
  /**
   * Clear all interceptors from the stack
   *
   * @returns {void}
   */
  clear() {
    this.handlers && (this.handlers = []);
  }
  /**
   * Iterate over all the registered interceptors
   *
   * This method is particularly useful for skipping over any
   * interceptors that may have become `null` calling `eject`.
   *
   * @param {Function} fn The function to call for each interceptor
   *
   * @returns {void}
   */
  forEach(t) {
    a.forEach(this.handlers, function(r) {
      r !== null && t(r);
    });
  }
}
const Qe = {
  silentJSONParsing: !0,
  forcedJSONParsing: !0,
  clarifyTimeoutError: !1
}, nn = typeof URLSearchParams < "u" ? URLSearchParams : be, rn = typeof FormData < "u" ? FormData : null, sn = typeof Blob < "u" ? Blob : null, on = {
  isBrowser: !0,
  classes: {
    URLSearchParams: nn,
    FormData: rn,
    Blob: sn
  },
  protocols: ["http", "https", "file", "blob", "url", "data"]
}, Re = typeof window < "u" && typeof document < "u", ge = typeof navigator == "object" && navigator || void 0, an = Re && (!ge || ["ReactNative", "NativeScript", "NS"].indexOf(ge.product) < 0), cn = typeof WorkerGlobalScope < "u" && // eslint-disable-next-line no-undef
self instanceof WorkerGlobalScope && typeof self.importScripts == "function", ln = Re && window.location.href || "http://localhost", un = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  hasBrowserEnv: Re,
  hasStandardBrowserEnv: an,
  hasStandardBrowserWebWorkerEnv: cn,
  navigator: ge,
  origin: ln
}, Symbol.toStringTag, { value: "Module" })), O = {
  ...un,
  ...on
};
function fn(e, t) {
  return ie(e, new O.classes.URLSearchParams(), Object.assign({
    visitor: function(n, r, s, o) {
      return O.isNode && a.isBuffer(n) ? (this.append(r, n.toString("base64")), !1) : o.defaultVisitor.apply(this, arguments);
    }
  }, t));
}
function dn(e) {
  return a.matchAll(/\w+|\[(\w*)]/g, e).map((t) => t[0] === "[]" ? "" : t[1] || t[0]);
}
function pn(e) {
  const t = {}, n = Object.keys(e);
  let r;
  const s = n.length;
  let o;
  for (r = 0; r < s; r++)
    o = n[r], t[o] = e[o];
  return t;
}
function Ye(e) {
  function t(n, r, s, o) {
    let i = n[o++];
    if (i === "__proto__") return !0;
    const c = Number.isFinite(+i), f = o >= n.length;
    return i = !i && a.isArray(s) ? s.length : i, f ? (a.hasOwnProp(s, i) ? s[i] = [s[i], r] : s[i] = r, !c) : ((!s[i] || !a.isObject(s[i])) && (s[i] = []), t(n, r, s[i], o) && a.isArray(s[i]) && (s[i] = pn(s[i])), !c);
  }
  if (a.isFormData(e) && a.isFunction(e.entries)) {
    const n = {};
    return a.forEachEntry(e, (r, s) => {
      t(dn(r), s, n, 0);
    }), n;
  }
  return null;
}
function hn(e, t, n) {
  if (a.isString(e))
    try {
      return (t || JSON.parse)(e), a.trim(e);
    } catch (r) {
      if (r.name !== "SyntaxError")
        throw r;
    }
  return (n || JSON.stringify)(e);
}
const z = {
  transitional: Qe,
  adapter: ["xhr", "http", "fetch"],
  transformRequest: [function(t, n) {
    const r = n.getContentType() || "", s = r.indexOf("application/json") > -1, o = a.isObject(t);
    if (o && a.isHTMLForm(t) && (t = new FormData(t)), a.isFormData(t))
      return s ? JSON.stringify(Ye(t)) : t;
    if (a.isArrayBuffer(t) || a.isBuffer(t) || a.isStream(t) || a.isFile(t) || a.isBlob(t) || a.isReadableStream(t))
      return t;
    if (a.isArrayBufferView(t))
      return t.buffer;
    if (a.isURLSearchParams(t))
      return n.setContentType("application/x-www-form-urlencoded;charset=utf-8", !1), t.toString();
    let c;
    if (o) {
      if (r.indexOf("application/x-www-form-urlencoded") > -1)
        return fn(t, this.formSerializer).toString();
      if ((c = a.isFileList(t)) || r.indexOf("multipart/form-data") > -1) {
        const f = this.env && this.env.FormData;
        return ie(
          c ? { "files[]": t } : t,
          f && new f(),
          this.formSerializer
        );
      }
    }
    return o || s ? (n.setContentType("application/json", !1), hn(t)) : t;
  }],
  transformResponse: [function(t) {
    const n = this.transitional || z.transitional, r = n && n.forcedJSONParsing, s = this.responseType === "json";
    if (a.isResponse(t) || a.isReadableStream(t))
      return t;
    if (t && a.isString(t) && (r && !this.responseType || s)) {
      const i = !(n && n.silentJSONParsing) && s;
      try {
        return JSON.parse(t);
      } catch (c) {
        if (i)
          throw c.name === "SyntaxError" ? m.from(c, m.ERR_BAD_RESPONSE, this, null, this.response) : c;
      }
    }
    return t;
  }],
  /**
   * A timeout in milliseconds to abort a request. If set to 0 (default) a
   * timeout is not created.
   */
  timeout: 0,
  xsrfCookieName: "XSRF-TOKEN",
  xsrfHeaderName: "X-XSRF-TOKEN",
  maxContentLength: -1,
  maxBodyLength: -1,
  env: {
    FormData: O.classes.FormData,
    Blob: O.classes.Blob
  },
  validateStatus: function(t) {
    return t >= 200 && t < 300;
  },
  headers: {
    common: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": void 0
    }
  }
};
a.forEach(["delete", "get", "head", "post", "put", "patch"], (e) => {
  z.headers[e] = {};
});
const mn = a.toObjectSet([
  "age",
  "authorization",
  "content-length",
  "content-type",
  "etag",
  "expires",
  "from",
  "host",
  "if-modified-since",
  "if-unmodified-since",
  "last-modified",
  "location",
  "max-forwards",
  "proxy-authorization",
  "referer",
  "retry-after",
  "user-agent"
]), gn = (e) => {
  const t = {};
  let n, r, s;
  return e && e.split(`
`).forEach(function(i) {
    s = i.indexOf(":"), n = i.substring(0, s).trim().toLowerCase(), r = i.substring(s + 1).trim(), !(!n || t[n] && mn[n]) && (n === "set-cookie" ? t[n] ? t[n].push(r) : t[n] = [r] : t[n] = t[n] ? t[n] + ", " + r : r);
  }), t;
}, Ue = Symbol("internals");
function H(e) {
  return e && String(e).trim().toLowerCase();
}
function Q(e) {
  return e === !1 || e == null ? e : a.isArray(e) ? e.map(Q) : String(e);
}
function En(e) {
  const t = /* @__PURE__ */ Object.create(null), n = /([^\s,;=]+)\s*(?:=\s*([^,;]+))?/g;
  let r;
  for (; r = n.exec(e); )
    t[r[1]] = r[2];
  return t;
}
const wn = (e) => /^[-_a-zA-Z0-9^`|~,!#$%&'*+.]+$/.test(e.trim());
function ue(e, t, n, r, s) {
  if (a.isFunction(r))
    return r.call(this, t, n);
  if (s && (t = n), !!a.isString(t)) {
    if (a.isString(r))
      return t.indexOf(r) !== -1;
    if (a.isRegExp(r))
      return r.test(t);
  }
}
function yn(e) {
  return e.trim().toLowerCase().replace(/([a-z\d])(\w*)/g, (t, n, r) => n.toUpperCase() + r);
}
function Sn(e, t) {
  const n = a.toCamelCase(" " + t);
  ["get", "set", "has"].forEach((r) => {
    Object.defineProperty(e, r + n, {
      value: function(s, o, i) {
        return this[r].call(this, t, s, o, i);
      },
      configurable: !0
    });
  });
}
let U = class {
  constructor(t) {
    t && this.set(t);
  }
  set(t, n, r) {
    const s = this;
    function o(c, f, l) {
      const u = H(f);
      if (!u)
        throw new Error("header name must be a non-empty string");
      const p = a.findKey(s, u);
      (!p || s[p] === void 0 || l === !0 || l === void 0 && s[p] !== !1) && (s[p || f] = Q(c));
    }
    const i = (c, f) => a.forEach(c, (l, u) => o(l, u, f));
    if (a.isPlainObject(t) || t instanceof this.constructor)
      i(t, n);
    else if (a.isString(t) && (t = t.trim()) && !wn(t))
      i(gn(t), n);
    else if (a.isObject(t) && a.isIterable(t)) {
      let c = {}, f, l;
      for (const u of t) {
        if (!a.isArray(u))
          throw TypeError("Object iterator must return a key-value pair");
        c[l = u[0]] = (f = c[l]) ? a.isArray(f) ? [...f, u[1]] : [f, u[1]] : u[1];
      }
      i(c, n);
    } else
      t != null && o(n, t, r);
    return this;
  }
  get(t, n) {
    if (t = H(t), t) {
      const r = a.findKey(this, t);
      if (r) {
        const s = this[r];
        if (!n)
          return s;
        if (n === !0)
          return En(s);
        if (a.isFunction(n))
          return n.call(this, s, r);
        if (a.isRegExp(n))
          return n.exec(s);
        throw new TypeError("parser must be boolean|regexp|function");
      }
    }
  }
  has(t, n) {
    if (t = H(t), t) {
      const r = a.findKey(this, t);
      return !!(r && this[r] !== void 0 && (!n || ue(this, this[r], r, n)));
    }
    return !1;
  }
  delete(t, n) {
    const r = this;
    let s = !1;
    function o(i) {
      if (i = H(i), i) {
        const c = a.findKey(r, i);
        c && (!n || ue(r, r[c], c, n)) && (delete r[c], s = !0);
      }
    }
    return a.isArray(t) ? t.forEach(o) : o(t), s;
  }
  clear(t) {
    const n = Object.keys(this);
    let r = n.length, s = !1;
    for (; r--; ) {
      const o = n[r];
      (!t || ue(this, this[o], o, t, !0)) && (delete this[o], s = !0);
    }
    return s;
  }
  normalize(t) {
    const n = this, r = {};
    return a.forEach(this, (s, o) => {
      const i = a.findKey(r, o);
      if (i) {
        n[i] = Q(s), delete n[o];
        return;
      }
      const c = t ? yn(o) : String(o).trim();
      c !== o && delete n[o], n[c] = Q(s), r[c] = !0;
    }), this;
  }
  concat(...t) {
    return this.constructor.concat(this, ...t);
  }
  toJSON(t) {
    const n = /* @__PURE__ */ Object.create(null);
    return a.forEach(this, (r, s) => {
      r != null && r !== !1 && (n[s] = t && a.isArray(r) ? r.join(", ") : r);
    }), n;
  }
  [Symbol.iterator]() {
    return Object.entries(this.toJSON())[Symbol.iterator]();
  }
  toString() {
    return Object.entries(this.toJSON()).map(([t, n]) => t + ": " + n).join(`
`);
  }
  getSetCookie() {
    return this.get("set-cookie") || [];
  }
  get [Symbol.toStringTag]() {
    return "AxiosHeaders";
  }
  static from(t) {
    return t instanceof this ? t : new this(t);
  }
  static concat(t, ...n) {
    const r = new this(t);
    return n.forEach((s) => r.set(s)), r;
  }
  static accessor(t) {
    const r = (this[Ue] = this[Ue] = {
      accessors: {}
    }).accessors, s = this.prototype;
    function o(i) {
      const c = H(i);
      r[c] || (Sn(s, i), r[c] = !0);
    }
    return a.isArray(t) ? t.forEach(o) : o(t), this;
  }
};
U.accessor(["Content-Type", "Content-Length", "Accept", "Accept-Encoding", "User-Agent", "Authorization"]);
a.reduceDescriptors(U.prototype, ({ value: e }, t) => {
  let n = t[0].toUpperCase() + t.slice(1);
  return {
    get: () => e,
    set(r) {
      this[n] = r;
    }
  };
});
a.freezeMethods(U);
function fe(e, t) {
  const n = this || z, r = t || n, s = U.from(r.headers);
  let o = r.data;
  return a.forEach(e, function(c) {
    o = c.call(n, o, s.normalize(), t ? t.status : void 0);
  }), s.normalize(), o;
}
function Ze(e) {
  return !!(e && e.__CANCEL__);
}
function M(e, t, n) {
  m.call(this, e ?? "canceled", m.ERR_CANCELED, t, n), this.name = "CanceledError";
}
a.inherits(M, m, {
  __CANCEL__: !0
});
function et(e, t, n) {
  const r = n.config.validateStatus;
  !n.status || !r || r(n.status) ? e(n) : t(new m(
    "Request failed with status code " + n.status,
    [m.ERR_BAD_REQUEST, m.ERR_BAD_RESPONSE][Math.floor(n.status / 100) - 4],
    n.config,
    n.request,
    n
  ));
}
function bn(e) {
  const t = /^([-+\w]{1,25})(:?\/\/|:)/.exec(e);
  return t && t[1] || "";
}
function Rn(e, t) {
  e = e || 10;
  const n = new Array(e), r = new Array(e);
  let s = 0, o = 0, i;
  return t = t !== void 0 ? t : 1e3, function(f) {
    const l = Date.now(), u = r[o];
    i || (i = l), n[s] = f, r[s] = l;
    let p = o, E = 0;
    for (; p !== s; )
      E += n[p++], p = p % e;
    if (s = (s + 1) % e, s === o && (o = (o + 1) % e), l - i < t)
      return;
    const R = u && l - u;
    return R ? Math.round(E * 1e3 / R) : void 0;
  };
}
function Tn(e, t) {
  let n = 0, r = 1e3 / t, s, o;
  const i = (l, u = Date.now()) => {
    n = u, s = null, o && (clearTimeout(o), o = null), e.apply(null, l);
  };
  return [(...l) => {
    const u = Date.now(), p = u - n;
    p >= r ? i(l, u) : (s = l, o || (o = setTimeout(() => {
      o = null, i(s);
    }, r - p)));
  }, () => s && i(s)];
}
const Z = (e, t, n = 3) => {
  let r = 0;
  const s = Rn(50, 250);
  return Tn((o) => {
    const i = o.loaded, c = o.lengthComputable ? o.total : void 0, f = i - r, l = s(f), u = i <= c;
    r = i;
    const p = {
      loaded: i,
      total: c,
      progress: c ? i / c : void 0,
      bytes: f,
      rate: l || void 0,
      estimated: l && c && u ? (c - i) / l : void 0,
      event: o,
      lengthComputable: c != null,
      [t ? "download" : "upload"]: !0
    };
    e(p);
  }, n);
}, Ce = (e, t) => {
  const n = e != null;
  return [(r) => t[0]({
    lengthComputable: n,
    total: e,
    loaded: r
  }), t[1]];
}, Ne = (e) => (...t) => a.asap(() => e(...t)), An = O.hasStandardBrowserEnv ? /* @__PURE__ */ ((e, t) => (n) => (n = new URL(n, O.origin), e.protocol === n.protocol && e.host === n.host && (t || e.port === n.port)))(
  new URL(O.origin),
  O.navigator && /(msie|trident)/i.test(O.navigator.userAgent)
) : () => !0, On = O.hasStandardBrowserEnv ? (
  // Standard browser envs support document.cookie
  {
    write(e, t, n, r, s, o) {
      const i = [e + "=" + encodeURIComponent(t)];
      a.isNumber(n) && i.push("expires=" + new Date(n).toGMTString()), a.isString(r) && i.push("path=" + r), a.isString(s) && i.push("domain=" + s), o === !0 && i.push("secure"), document.cookie = i.join("; ");
    },
    read(e) {
      const t = document.cookie.match(new RegExp("(^|;\\s*)(" + e + ")=([^;]*)"));
      return t ? decodeURIComponent(t[3]) : null;
    },
    remove(e) {
      this.write(e, "", Date.now() - 864e5);
    }
  }
) : (
  // Non-standard browser env (web workers, react-native) lack needed support.
  {
    write() {
    },
    read() {
      return null;
    },
    remove() {
    }
  }
);
function _n(e) {
  return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(e);
}
function xn(e, t) {
  return t ? e.replace(/\/?\/$/, "") + "/" + t.replace(/^\/+/, "") : e;
}
function tt(e, t, n) {
  let r = !_n(t);
  return e && (r || n == !1) ? xn(e, t) : t;
}
const ke = (e) => e instanceof U ? { ...e } : e;
function $(e, t) {
  t = t || {};
  const n = {};
  function r(l, u, p, E) {
    return a.isPlainObject(l) && a.isPlainObject(u) ? a.merge.call({ caseless: E }, l, u) : a.isPlainObject(u) ? a.merge({}, u) : a.isArray(u) ? u.slice() : u;
  }
  function s(l, u, p, E) {
    if (a.isUndefined(u)) {
      if (!a.isUndefined(l))
        return r(void 0, l, p, E);
    } else return r(l, u, p, E);
  }
  function o(l, u) {
    if (!a.isUndefined(u))
      return r(void 0, u);
  }
  function i(l, u) {
    if (a.isUndefined(u)) {
      if (!a.isUndefined(l))
        return r(void 0, l);
    } else return r(void 0, u);
  }
  function c(l, u, p) {
    if (p in t)
      return r(l, u);
    if (p in e)
      return r(void 0, l);
  }
  const f = {
    url: o,
    method: o,
    data: o,
    baseURL: i,
    transformRequest: i,
    transformResponse: i,
    paramsSerializer: i,
    timeout: i,
    timeoutMessage: i,
    withCredentials: i,
    withXSRFToken: i,
    adapter: i,
    responseType: i,
    xsrfCookieName: i,
    xsrfHeaderName: i,
    onUploadProgress: i,
    onDownloadProgress: i,
    decompress: i,
    maxContentLength: i,
    maxBodyLength: i,
    beforeRedirect: i,
    transport: i,
    httpAgent: i,
    httpsAgent: i,
    cancelToken: i,
    socketPath: i,
    responseEncoding: i,
    validateStatus: c,
    headers: (l, u, p) => s(ke(l), ke(u), p, !0)
  };
  return a.forEach(Object.keys(Object.assign({}, e, t)), function(u) {
    const p = f[u] || s, E = p(e[u], t[u], u);
    a.isUndefined(E) && p !== c || (n[u] = E);
  }), n;
}
const nt = (e) => {
  const t = $({}, e);
  let { data: n, withXSRFToken: r, xsrfHeaderName: s, xsrfCookieName: o, headers: i, auth: c } = t;
  t.headers = i = U.from(i), t.url = Ge(tt(t.baseURL, t.url, t.allowAbsoluteUrls), e.params, e.paramsSerializer), c && i.set(
    "Authorization",
    "Basic " + btoa((c.username || "") + ":" + (c.password ? unescape(encodeURIComponent(c.password)) : ""))
  );
  let f;
  if (a.isFormData(n)) {
    if (O.hasStandardBrowserEnv || O.hasStandardBrowserWebWorkerEnv)
      i.setContentType(void 0);
    else if ((f = i.getContentType()) !== !1) {
      const [l, ...u] = f ? f.split(";").map((p) => p.trim()).filter(Boolean) : [];
      i.setContentType([l || "multipart/form-data", ...u].join("; "));
    }
  }
  if (O.hasStandardBrowserEnv && (r && a.isFunction(r) && (r = r(t)), r || r !== !1 && An(t.url))) {
    const l = s && o && On.read(o);
    l && i.set(s, l);
  }
  return t;
}, Un = typeof XMLHttpRequest < "u", Cn = Un && function(e) {
  return new Promise(function(n, r) {
    const s = nt(e);
    let o = s.data;
    const i = U.from(s.headers).normalize();
    let { responseType: c, onUploadProgress: f, onDownloadProgress: l } = s, u, p, E, R, d;
    function g() {
      R && R(), d && d(), s.cancelToken && s.cancelToken.unsubscribe(u), s.signal && s.signal.removeEventListener("abort", u);
    }
    let h = new XMLHttpRequest();
    h.open(s.method.toUpperCase(), s.url, !0), h.timeout = s.timeout;
    function S() {
      if (!h)
        return;
      const A = U.from(
        "getAllResponseHeaders" in h && h.getAllResponseHeaders()
      ), _ = {
        data: !c || c === "text" || c === "json" ? h.responseText : h.response,
        status: h.status,
        statusText: h.statusText,
        headers: A,
        config: e,
        request: h
      };
      et(function(F) {
        n(F), g();
      }, function(F) {
        r(F), g();
      }, _), h = null;
    }
    "onloadend" in h ? h.onloadend = S : h.onreadystatechange = function() {
      !h || h.readyState !== 4 || h.status === 0 && !(h.responseURL && h.responseURL.indexOf("file:") === 0) || setTimeout(S);
    }, h.onabort = function() {
      h && (r(new m("Request aborted", m.ECONNABORTED, e, h)), h = null);
    }, h.onerror = function() {
      r(new m("Network Error", m.ERR_NETWORK, e, h)), h = null;
    }, h.ontimeout = function() {
      let D = s.timeout ? "timeout of " + s.timeout + "ms exceeded" : "timeout exceeded";
      const _ = s.transitional || Qe;
      s.timeoutErrorMessage && (D = s.timeoutErrorMessage), r(new m(
        D,
        _.clarifyTimeoutError ? m.ETIMEDOUT : m.ECONNABORTED,
        e,
        h
      )), h = null;
    }, o === void 0 && i.setContentType(null), "setRequestHeader" in h && a.forEach(i.toJSON(), function(D, _) {
      h.setRequestHeader(_, D);
    }), a.isUndefined(s.withCredentials) || (h.withCredentials = !!s.withCredentials), c && c !== "json" && (h.responseType = s.responseType), l && ([E, d] = Z(l, !0), h.addEventListener("progress", E)), f && h.upload && ([p, R] = Z(f), h.upload.addEventListener("progress", p), h.upload.addEventListener("loadend", R)), (s.cancelToken || s.signal) && (u = (A) => {
      h && (r(!A || A.type ? new M(null, e, h) : A), h.abort(), h = null);
    }, s.cancelToken && s.cancelToken.subscribe(u), s.signal && (s.signal.aborted ? u() : s.signal.addEventListener("abort", u)));
    const T = bn(s.url);
    if (T && O.protocols.indexOf(T) === -1) {
      r(new m("Unsupported protocol " + T + ":", m.ERR_BAD_REQUEST, e));
      return;
    }
    h.send(o || null);
  });
}, Nn = (e, t) => {
  const { length: n } = e = e ? e.filter(Boolean) : [];
  if (t || n) {
    let r = new AbortController(), s;
    const o = function(l) {
      if (!s) {
        s = !0, c();
        const u = l instanceof Error ? l : this.reason;
        r.abort(u instanceof m ? u : new M(u instanceof Error ? u.message : u));
      }
    };
    let i = t && setTimeout(() => {
      i = null, o(new m(`timeout ${t} of ms exceeded`, m.ETIMEDOUT));
    }, t);
    const c = () => {
      e && (i && clearTimeout(i), i = null, e.forEach((l) => {
        l.unsubscribe ? l.unsubscribe(o) : l.removeEventListener("abort", o);
      }), e = null);
    };
    e.forEach((l) => l.addEventListener("abort", o));
    const { signal: f } = r;
    return f.unsubscribe = () => a.asap(c), f;
  }
}, kn = function* (e, t) {
  let n = e.byteLength;
  if (n < t) {
    yield e;
    return;
  }
  let r = 0, s;
  for (; r < n; )
    s = r + t, yield e.slice(r, s), r = s;
}, Pn = async function* (e, t) {
  for await (const n of Dn(e))
    yield* kn(n, t);
}, Dn = async function* (e) {
  if (e[Symbol.asyncIterator]) {
    yield* e;
    return;
  }
  const t = e.getReader();
  try {
    for (; ; ) {
      const { done: n, value: r } = await t.read();
      if (n)
        break;
      yield r;
    }
  } finally {
    await t.cancel();
  }
}, Pe = (e, t, n, r) => {
  const s = Pn(e, t);
  let o = 0, i, c = (f) => {
    i || (i = !0, r && r(f));
  };
  return new ReadableStream({
    async pull(f) {
      try {
        const { done: l, value: u } = await s.next();
        if (l) {
          c(), f.close();
          return;
        }
        let p = u.byteLength;
        if (n) {
          let E = o += p;
          n(E);
        }
        f.enqueue(new Uint8Array(u));
      } catch (l) {
        throw c(l), l;
      }
    },
    cancel(f) {
      return c(f), s.return();
    }
  }, {
    highWaterMark: 2
  });
}, ae = typeof fetch == "function" && typeof Request == "function" && typeof Response == "function", rt = ae && typeof ReadableStream == "function", Ln = ae && (typeof TextEncoder == "function" ? /* @__PURE__ */ ((e) => (t) => e.encode(t))(new TextEncoder()) : async (e) => new Uint8Array(await new Response(e).arrayBuffer())), st = (e, ...t) => {
  try {
    return !!e(...t);
  } catch {
    return !1;
  }
}, In = rt && st(() => {
  let e = !1;
  const t = new Request(O.origin, {
    body: new ReadableStream(),
    method: "POST",
    get duplex() {
      return e = !0, "half";
    }
  }).headers.has("Content-Type");
  return e && !t;
}), De = 64 * 1024, Ee = rt && st(() => a.isReadableStream(new Response("").body)), ee = {
  stream: Ee && ((e) => e.body)
};
ae && ((e) => {
  ["text", "arrayBuffer", "blob", "formData", "stream"].forEach((t) => {
    !ee[t] && (ee[t] = a.isFunction(e[t]) ? (n) => n[t]() : (n, r) => {
      throw new m(`Response type '${t}' is not supported`, m.ERR_NOT_SUPPORT, r);
    });
  });
})(new Response());
const Fn = async (e) => {
  if (e == null)
    return 0;
  if (a.isBlob(e))
    return e.size;
  if (a.isSpecCompliantForm(e))
    return (await new Request(O.origin, {
      method: "POST",
      body: e
    }).arrayBuffer()).byteLength;
  if (a.isArrayBufferView(e) || a.isArrayBuffer(e))
    return e.byteLength;
  if (a.isURLSearchParams(e) && (e = e + ""), a.isString(e))
    return (await Ln(e)).byteLength;
}, Bn = async (e, t) => {
  const n = a.toFiniteNumber(e.getContentLength());
  return n ?? Fn(t);
}, jn = ae && (async (e) => {
  let {
    url: t,
    method: n,
    data: r,
    signal: s,
    cancelToken: o,
    timeout: i,
    onDownloadProgress: c,
    onUploadProgress: f,
    responseType: l,
    headers: u,
    withCredentials: p = "same-origin",
    fetchOptions: E
  } = nt(e);
  l = l ? (l + "").toLowerCase() : "text";
  let R = Nn([s, o && o.toAbortSignal()], i), d;
  const g = R && R.unsubscribe && (() => {
    R.unsubscribe();
  });
  let h;
  try {
    if (f && In && n !== "get" && n !== "head" && (h = await Bn(u, r)) !== 0) {
      let _ = new Request(t, {
        method: "POST",
        body: r,
        duplex: "half"
      }), I;
      if (a.isFormData(r) && (I = _.headers.get("content-type")) && u.setContentType(I), _.body) {
        const [F, W] = Ce(
          h,
          Z(Ne(f))
        );
        r = Pe(_.body, De, F, W);
      }
    }
    a.isString(p) || (p = p ? "include" : "omit");
    const S = "credentials" in Request.prototype;
    d = new Request(t, {
      ...E,
      signal: R,
      method: n.toUpperCase(),
      headers: u.normalize().toJSON(),
      body: r,
      duplex: "half",
      credentials: S ? p : void 0
    });
    let T = await fetch(d, E);
    const A = Ee && (l === "stream" || l === "response");
    if (Ee && (c || A && g)) {
      const _ = {};
      ["status", "statusText", "headers"].forEach((Te) => {
        _[Te] = T[Te];
      });
      const I = a.toFiniteNumber(T.headers.get("content-length")), [F, W] = c && Ce(
        I,
        Z(Ne(c), !0)
      ) || [];
      T = new Response(
        Pe(T.body, De, F, () => {
          W && W(), g && g();
        }),
        _
      );
    }
    l = l || "text";
    let D = await ee[a.findKey(ee, l) || "text"](T, e);
    return !A && g && g(), await new Promise((_, I) => {
      et(_, I, {
        data: D,
        headers: U.from(T.headers),
        status: T.status,
        statusText: T.statusText,
        config: e,
        request: d
      });
    });
  } catch (S) {
    throw g && g(), S && S.name === "TypeError" && /Load failed|fetch/i.test(S.message) ? Object.assign(
      new m("Network Error", m.ERR_NETWORK, e, d),
      {
        cause: S.cause || S
      }
    ) : m.from(S, S && S.code, e, d);
  }
}), we = {
  http: Yt,
  xhr: Cn,
  fetch: jn
};
a.forEach(we, (e, t) => {
  if (e) {
    try {
      Object.defineProperty(e, "name", { value: t });
    } catch {
    }
    Object.defineProperty(e, "adapterName", { value: t });
  }
});
const Le = (e) => `- ${e}`, $n = (e) => a.isFunction(e) || e === null || e === !1, ot = {
  getAdapter: (e) => {
    e = a.isArray(e) ? e : [e];
    const { length: t } = e;
    let n, r;
    const s = {};
    for (let o = 0; o < t; o++) {
      n = e[o];
      let i;
      if (r = n, !$n(n) && (r = we[(i = String(n)).toLowerCase()], r === void 0))
        throw new m(`Unknown adapter '${i}'`);
      if (r)
        break;
      s[i || "#" + o] = r;
    }
    if (!r) {
      const o = Object.entries(s).map(
        ([c, f]) => `adapter ${c} ` + (f === !1 ? "is not supported by the environment" : "is not available in the build")
      );
      let i = t ? o.length > 1 ? `since :
` + o.map(Le).join(`
`) : " " + Le(o[0]) : "as no adapter specified";
      throw new m(
        "There is no suitable adapter to dispatch the request " + i,
        "ERR_NOT_SUPPORT"
      );
    }
    return r;
  },
  adapters: we
};
function de(e) {
  if (e.cancelToken && e.cancelToken.throwIfRequested(), e.signal && e.signal.aborted)
    throw new M(null, e);
}
function Ie(e) {
  return de(e), e.headers = U.from(e.headers), e.data = fe.call(
    e,
    e.transformRequest
  ), ["post", "put", "patch"].indexOf(e.method) !== -1 && e.headers.setContentType("application/x-www-form-urlencoded", !1), ot.getAdapter(e.adapter || z.adapter)(e).then(function(r) {
    return de(e), r.data = fe.call(
      e,
      e.transformResponse,
      r
    ), r.headers = U.from(r.headers), r;
  }, function(r) {
    return Ze(r) || (de(e), r && r.response && (r.response.data = fe.call(
      e,
      e.transformResponse,
      r.response
    ), r.response.headers = U.from(r.response.headers))), Promise.reject(r);
  });
}
const it = "1.10.0", ce = {};
["object", "boolean", "number", "function", "string", "symbol"].forEach((e, t) => {
  ce[e] = function(r) {
    return typeof r === e || "a" + (t < 1 ? "n " : " ") + e;
  };
});
const Fe = {};
ce.transitional = function(t, n, r) {
  function s(o, i) {
    return "[Axios v" + it + "] Transitional option '" + o + "'" + i + (r ? ". " + r : "");
  }
  return (o, i, c) => {
    if (t === !1)
      throw new m(
        s(i, " has been removed" + (n ? " in " + n : "")),
        m.ERR_DEPRECATED
      );
    return n && !Fe[i] && (Fe[i] = !0, console.warn(
      s(
        i,
        " has been deprecated since v" + n + " and will be removed in the near future"
      )
    )), t ? t(o, i, c) : !0;
  };
};
ce.spelling = function(t) {
  return (n, r) => (console.warn(`${r} is likely a misspelling of ${t}`), !0);
};
function qn(e, t, n) {
  if (typeof e != "object")
    throw new m("options must be an object", m.ERR_BAD_OPTION_VALUE);
  const r = Object.keys(e);
  let s = r.length;
  for (; s-- > 0; ) {
    const o = r[s], i = t[o];
    if (i) {
      const c = e[o], f = c === void 0 || i(c, o, e);
      if (f !== !0)
        throw new m("option " + o + " must be " + f, m.ERR_BAD_OPTION_VALUE);
      continue;
    }
    if (n !== !0)
      throw new m("Unknown option " + o, m.ERR_BAD_OPTION);
  }
}
const Y = {
  assertOptions: qn,
  validators: ce
}, k = Y.validators;
let j = class {
  constructor(t) {
    this.defaults = t || {}, this.interceptors = {
      request: new xe(),
      response: new xe()
    };
  }
  /**
   * Dispatch a request
   *
   * @param {String|Object} configOrUrl The config specific for this request (merged with this.defaults)
   * @param {?Object} config
   *
   * @returns {Promise} The Promise to be fulfilled
   */
  async request(t, n) {
    try {
      return await this._request(t, n);
    } catch (r) {
      if (r instanceof Error) {
        let s = {};
        Error.captureStackTrace ? Error.captureStackTrace(s) : s = new Error();
        const o = s.stack ? s.stack.replace(/^.+\n/, "") : "";
        try {
          r.stack ? o && !String(r.stack).endsWith(o.replace(/^.+\n.+\n/, "")) && (r.stack += `
` + o) : r.stack = o;
        } catch {
        }
      }
      throw r;
    }
  }
  _request(t, n) {
    typeof t == "string" ? (n = n || {}, n.url = t) : n = t || {}, n = $(this.defaults, n);
    const { transitional: r, paramsSerializer: s, headers: o } = n;
    r !== void 0 && Y.assertOptions(r, {
      silentJSONParsing: k.transitional(k.boolean),
      forcedJSONParsing: k.transitional(k.boolean),
      clarifyTimeoutError: k.transitional(k.boolean)
    }, !1), s != null && (a.isFunction(s) ? n.paramsSerializer = {
      serialize: s
    } : Y.assertOptions(s, {
      encode: k.function,
      serialize: k.function
    }, !0)), n.allowAbsoluteUrls !== void 0 || (this.defaults.allowAbsoluteUrls !== void 0 ? n.allowAbsoluteUrls = this.defaults.allowAbsoluteUrls : n.allowAbsoluteUrls = !0), Y.assertOptions(n, {
      baseUrl: k.spelling("baseURL"),
      withXsrfToken: k.spelling("withXSRFToken")
    }, !0), n.method = (n.method || this.defaults.method || "get").toLowerCase();
    let i = o && a.merge(
      o.common,
      o[n.method]
    );
    o && a.forEach(
      ["delete", "get", "head", "post", "put", "patch", "common"],
      (d) => {
        delete o[d];
      }
    ), n.headers = U.concat(i, o);
    const c = [];
    let f = !0;
    this.interceptors.request.forEach(function(g) {
      typeof g.runWhen == "function" && g.runWhen(n) === !1 || (f = f && g.synchronous, c.unshift(g.fulfilled, g.rejected));
    });
    const l = [];
    this.interceptors.response.forEach(function(g) {
      l.push(g.fulfilled, g.rejected);
    });
    let u, p = 0, E;
    if (!f) {
      const d = [Ie.bind(this), void 0];
      for (d.unshift.apply(d, c), d.push.apply(d, l), E = d.length, u = Promise.resolve(n); p < E; )
        u = u.then(d[p++], d[p++]);
      return u;
    }
    E = c.length;
    let R = n;
    for (p = 0; p < E; ) {
      const d = c[p++], g = c[p++];
      try {
        R = d(R);
      } catch (h) {
        g.call(this, h);
        break;
      }
    }
    try {
      u = Ie.call(this, R);
    } catch (d) {
      return Promise.reject(d);
    }
    for (p = 0, E = l.length; p < E; )
      u = u.then(l[p++], l[p++]);
    return u;
  }
  getUri(t) {
    t = $(this.defaults, t);
    const n = tt(t.baseURL, t.url, t.allowAbsoluteUrls);
    return Ge(n, t.params, t.paramsSerializer);
  }
};
a.forEach(["delete", "get", "head", "options"], function(t) {
  j.prototype[t] = function(n, r) {
    return this.request($(r || {}, {
      method: t,
      url: n,
      data: (r || {}).data
    }));
  };
});
a.forEach(["post", "put", "patch"], function(t) {
  function n(r) {
    return function(o, i, c) {
      return this.request($(c || {}, {
        method: t,
        headers: r ? {
          "Content-Type": "multipart/form-data"
        } : {},
        url: o,
        data: i
      }));
    };
  }
  j.prototype[t] = n(), j.prototype[t + "Form"] = n(!0);
});
let Mn = class at {
  constructor(t) {
    if (typeof t != "function")
      throw new TypeError("executor must be a function.");
    let n;
    this.promise = new Promise(function(o) {
      n = o;
    });
    const r = this;
    this.promise.then((s) => {
      if (!r._listeners) return;
      let o = r._listeners.length;
      for (; o-- > 0; )
        r._listeners[o](s);
      r._listeners = null;
    }), this.promise.then = (s) => {
      let o;
      const i = new Promise((c) => {
        r.subscribe(c), o = c;
      }).then(s);
      return i.cancel = function() {
        r.unsubscribe(o);
      }, i;
    }, t(function(o, i, c) {
      r.reason || (r.reason = new M(o, i, c), n(r.reason));
    });
  }
  /**
   * Throws a `CanceledError` if cancellation has been requested.
   */
  throwIfRequested() {
    if (this.reason)
      throw this.reason;
  }
  /**
   * Subscribe to the cancel signal
   */
  subscribe(t) {
    if (this.reason) {
      t(this.reason);
      return;
    }
    this._listeners ? this._listeners.push(t) : this._listeners = [t];
  }
  /**
   * Unsubscribe from the cancel signal
   */
  unsubscribe(t) {
    if (!this._listeners)
      return;
    const n = this._listeners.indexOf(t);
    n !== -1 && this._listeners.splice(n, 1);
  }
  toAbortSignal() {
    const t = new AbortController(), n = (r) => {
      t.abort(r);
    };
    return this.subscribe(n), t.signal.unsubscribe = () => this.unsubscribe(n), t.signal;
  }
  /**
   * Returns an object that contains a new `CancelToken` and a function that, when called,
   * cancels the `CancelToken`.
   */
  static source() {
    let t;
    return {
      token: new at(function(s) {
        t = s;
      }),
      cancel: t
    };
  }
};
function Hn(e) {
  return function(n) {
    return e.apply(null, n);
  };
}
function Jn(e) {
  return a.isObject(e) && e.isAxiosError === !0;
}
const ye = {
  Continue: 100,
  SwitchingProtocols: 101,
  Processing: 102,
  EarlyHints: 103,
  Ok: 200,
  Created: 201,
  Accepted: 202,
  NonAuthoritativeInformation: 203,
  NoContent: 204,
  ResetContent: 205,
  PartialContent: 206,
  MultiStatus: 207,
  AlreadyReported: 208,
  ImUsed: 226,
  MultipleChoices: 300,
  MovedPermanently: 301,
  Found: 302,
  SeeOther: 303,
  NotModified: 304,
  UseProxy: 305,
  Unused: 306,
  TemporaryRedirect: 307,
  PermanentRedirect: 308,
  BadRequest: 400,
  Unauthorized: 401,
  PaymentRequired: 402,
  Forbidden: 403,
  NotFound: 404,
  MethodNotAllowed: 405,
  NotAcceptable: 406,
  ProxyAuthenticationRequired: 407,
  RequestTimeout: 408,
  Conflict: 409,
  Gone: 410,
  LengthRequired: 411,
  PreconditionFailed: 412,
  PayloadTooLarge: 413,
  UriTooLong: 414,
  UnsupportedMediaType: 415,
  RangeNotSatisfiable: 416,
  ExpectationFailed: 417,
  ImATeapot: 418,
  MisdirectedRequest: 421,
  UnprocessableEntity: 422,
  Locked: 423,
  FailedDependency: 424,
  TooEarly: 425,
  UpgradeRequired: 426,
  PreconditionRequired: 428,
  TooManyRequests: 429,
  RequestHeaderFieldsTooLarge: 431,
  UnavailableForLegalReasons: 451,
  InternalServerError: 500,
  NotImplemented: 501,
  BadGateway: 502,
  ServiceUnavailable: 503,
  GatewayTimeout: 504,
  HttpVersionNotSupported: 505,
  VariantAlsoNegotiates: 506,
  InsufficientStorage: 507,
  LoopDetected: 508,
  NotExtended: 510,
  NetworkAuthenticationRequired: 511
};
Object.entries(ye).forEach(([e, t]) => {
  ye[t] = e;
});
function ct(e) {
  const t = new j(e), n = je(j.prototype.request, t);
  return a.extend(n, j.prototype, t, { allOwnKeys: !0 }), a.extend(n, t, null, { allOwnKeys: !0 }), n.create = function(s) {
    return ct($(e, s));
  }, n;
}
const w = ct(z);
w.Axios = j;
w.CanceledError = M;
w.CancelToken = Mn;
w.isCancel = Ze;
w.VERSION = it;
w.toFormData = ie;
w.AxiosError = m;
w.Cancel = w.CanceledError;
w.all = function(t) {
  return Promise.all(t);
};
w.spread = Hn;
w.isAxiosError = Jn;
w.mergeConfig = $;
w.AxiosHeaders = U;
w.formToJSON = (e) => Ye(a.isHTMLForm(e) ? new FormData(e) : e);
w.getAdapter = ot.getAdapter;
w.HttpStatusCode = ye;
w.default = w;
const {
  Axios: tr,
  AxiosError: nr,
  CanceledError: rr,
  isCancel: sr,
  CancelToken: or,
  VERSION: ir,
  all: ar,
  Cancel: cr,
  isAxiosError: lr,
  spread: ur,
  toFormData: fr,
  AxiosHeaders: dr,
  HttpStatusCode: pr,
  formToJSON: hr,
  getAdapter: mr,
  mergeConfig: gr
} = w, pe = function(e) {
  switch (e) {
    case 4:
      return "color: #1976d2";
    case 3:
      return "color: #3D873FFF";
    case 2:
      return "color: #ff9800";
    case 1:
      return "color: #f44336";
  }
  return "background: #dddddd; color: #000";
}, K = function(e) {
  if (typeof e > "u" || e === null)
    return "";
  {
    let t = e.replace(/^Error\s+/, "");
    return t = t.split(`
`)[1], t = t.replace(/^\s+at Object./, ""), t = t.replace(/ \(.+\)$/, ""), t = t.replace(/\@.+/, ""), t = t.replace("at ", "").trim(), t = t.replace("VueComponent.", "").trim(), t;
  }
}, X = function(e, t, n, r, ...s) {
  let o;
  switch (t.length > 1 ? o = `${e}::${t}()` : o = `${e}::`, r) {
    case 1:
      console.error(`%c ${o} ${n}`, pe(r)), console.trace();
      break;
    case 2:
      console.warn(`%c ${o} ${n}`, pe(r));
      break;
    default:
      console.log(`%c ${o} ${n}`, pe(r));
      break;
  }
  s.length > 0 && s.forEach((i) => console.log(i));
};
class Be {
  constructor(t = "", n = 4) {
    le(this, "_moduleName", "");
    le(this, "_logLevel", 4);
    this._moduleName = t, this._logLevel = n;
  }
  l(t, ...n) {
    if (this._logLevel >= 4) {
      const r = K(new Error().stack);
      X(this._moduleName, r, t, 4, ...n);
    }
  }
  t(t, ...n) {
    if (this._logLevel >= 3) {
      const r = K(new Error().stack);
      X(this._moduleName, r, t, 3, ...n);
    }
  }
  w(t, ...n) {
    if (this._logLevel >= 2) {
      const r = K(new Error().stack);
      X(this._moduleName, r, t, 2, ...n);
    }
  }
  e(t, ...n) {
    if (this._logLevel >= 1) {
      const r = K(new Error().stack);
      X(this._moduleName, r, t, 1, ...n);
    }
  }
}
var vn = {};
const lt = vn.NODE_ENV === "development", zn = new URL(location.toString()), Vn = lt ? "http://localhost:8787" : zn.origin, Wn = (e, t, n) => lt ? new Be(e, t) : new Be(e, n), Kn = 1e4, y = Wn("AuthService", 2, 1), b = {
  JWT_TOKEN: "_goapi_jwt_session_token",
  USER_ID: "_goapi_idgouser",
  USER_EXTERNAL_ID: "_goapi_user_external_id",
  NAME: "_goapi_name",
  USERNAME: "_goapi_username",
  EMAIL: "_goapi_email",
  IS_ADMIN: "_goapi_isadmin",
  DATE_EXPIRATION: "_goapi_date_expiration",
  SESSION_UUID: "_goapi_session_uuid",
  GROUPS: "_goapi_groups"
};
class V extends Error {
  constructor(t, n) {
    super(t), this.status = n, this.name = "AuthError";
  }
}
const te = (e, t) => `${e}${t}`, L = (e, t, n) => {
  sessionStorage.setItem(te(e, t), n);
}, P = (e, t) => (y.t(
  `session get called with key:${t}, appName:${te(e, t)}`
), sessionStorage.getItem(te(e, t))), Xn = (e, t) => {
  sessionStorage.removeItem(te(e, t));
}, ut = (e) => {
  Object.values(b).forEach((t) => Xn(e, t)), y.t("Session storage cleared for app:", e);
}, Gn = (e) => {
  try {
    const t = e.split(".")[1];
    if (!t) throw new Error("Invalid JWT format: Missing payload.");
    const n = t.replace(/-/g, "+").replace(/_/g, "/"), r = decodeURIComponent(
      window.atob(n).split("").map((s) => `%${`00${s.charCodeAt(0).toString(16)}`.slice(-2)}`).join("")
    );
    return JSON.parse(r);
  } catch (t) {
    throw y.e("Error parsing JWT:", t), new V(
      `Invalid JWT token: ${t instanceof Error ? t.message : String(t)}`
    );
  }
}, Er = async (e, t = 8) => {
  if (e.trim().length >= t) {
    const r = new TextEncoder().encode(e), s = await crypto.subtle.digest("SHA-256", r);
    return Array.from(new Uint8Array(s)).map((i) => i.toString(16).padStart(2, "0")).join("");
  } else
    throw new V(`Password must be at least ${t} characters long`);
}, wr = async (e, t, n, r, s) => {
  var i;
  if (!(e != null && e.trim()) || !(r != null && r.trim()) || !(s != null && s.trim()))
    throw new V("appName, username, and passwordHash are required");
  const o = `${t}${n}`;
  y.t(`# entering getToken... ${o} data:`, { username: r });
  try {
    const c = await w.post(o, {
      username: r,
      password_hash: s
    });
    y.l("getToken() axios.post Success! response:", c.data);
    const f = Gn(c.data.token);
    y.l("getToken() parsed token values:", f);
    const l = /* @__PURE__ */ new Date(0);
    return l.setUTCSeconds(f.exp), y.l(`getToken() JWT token expiration: ${l}`), L(e, b.JWT_TOKEN, c.data.token), c.data.session && L(e, b.SESSION_UUID, c.data.session), L(
      e,
      b.USER_ID,
      String(f.User.user_id)
    ), L(
      e,
      b.USER_EXTERNAL_ID,
      f.User.external_id
    ), L(e, b.NAME, f.name), L(e, b.USERNAME, f.User.login), L(e, b.EMAIL, f.User.email), L(
      e,
      b.IS_ADMIN,
      String(f.User.is_admin)
    ), L(
      e,
      b.DATE_EXPIRATION,
      String(f.exp)
    ), {
      msg: "getToken() axios.post Success.",
      err: null,
      status: c.status,
      data: c.data
    };
  } catch (c) {
    if (w.isAxiosError(c)) {
      const l = `getToken() Axios Error: ${c.message}`;
      return y.w(l, c.response), { msg: l, err: c, status: (i = c.response) == null ? void 0 : i.status, data: null };
    }
    const f = `getToken() Unexpected Error: ${c}`;
    return y.e(f), {
      msg: f,
      err: c instanceof Error ? c : new Error(String(c)),
      status: void 0,
      data: null
    };
  }
}, C = (e) => {
  y.t("# entering getUserProfile validation...");
  const t = P(e, b.JWT_TOKEN), n = P(e, b.DATE_EXPIRATION), r = P(e, b.USER_ID), s = P(e, b.EMAIL);
  if (!t || !n || !r || !s)
    return y.w(
      `# IN getUserProfile() - Missing required session keys: jwtToken: ${t}, expiration: ${n}, userId: ${r}, email: ${s}`
    ), null;
  const o = new Date(parseInt(n, 10) * 1e3), i = /* @__PURE__ */ new Date();
  if (i > o)
    return y.w(
      `# IN getUserProfile() - SESSION EXPIRED. Expiration was: ${o.toString()}`
    ), ut(e), null;
  const c = Math.floor(
    (o.getTime() - i.getTime()) / 1e3 / 60
  );
  return y.l(
    `Yes, session exists and is valid for ${c} more minutes.`
  ), {
    jwtToken: t,
    dateExpiration: parseInt(n, 10),
    userId: parseInt(r, 10),
    email: s,
    isAdmin: P(e, b.IS_ADMIN) === "true",
    name: P(e, b.NAME) ?? "",
    username: P(e, b.USERNAME) ?? "",
    userExternalId: P(e, b.USER_EXTERNAL_ID) ?? "",
    sessionUuid: P(e, b.SESSION_UUID) ?? "",
    groups: P(e, b.GROUPS)
  };
}, yr = (e) => (y.t("# entering doesCurrentSessionExist..."), C(e) !== null), Sr = async (e, t = Vn) => {
  var r;
  y.t("# entering getTokenStatus...");
  const n = C(e);
  if (!n)
    return {
      msg: "No valid session found locally.",
      err: new V("No session"),
      status: 401,
      data: null
    };
  try {
    const s = await w.get(`${t}/goapi/v1/status`, {
      headers: {
        Authorization: `Bearer ${n.jwtToken}`,
        "X-Goeland-Token": n.sessionUuid
      },
      timeout: Kn
    });
    y.l("getTokenStatus() axios.get Success! response:", s);
    const o = /* @__PURE__ */ new Date(0);
    o.setUTCSeconds(s.data.exp);
    const i = `getTokenStatus() JWT token expiration: ${o}`;
    return y.l(i), { msg: i, err: null, status: s.status, data: s.data };
  } catch (s) {
    if (w.isAxiosError(s)) {
      const i = `Error in getTokenStatus(): ${s.message}`;
      return y.w(i, s.response), { msg: i, err: s, status: (r = s.response) == null ? void 0 : r.status, data: null };
    }
    const o = `Unexpected error in getTokenStatus(): ${s}`;
    return y.e(o), {
      msg: o,
      err: s instanceof Error ? s : new Error(String(s)),
      status: void 0,
      data: null
    };
  }
}, br = async (e, t) => {
  y.t("# IN logoutAndResetToken()");
  const n = C(e);
  if (ut(e), !n) {
    y.w("logoutAndResetToken called, but no local session was found.");
    return;
  }
  try {
    const r = await w.get(`${t}/goapi/v1/logout`, {
      headers: { Authorization: `Bearer ${n.jwtToken}` }
    });
    y.l("logoutAndResetToken() Server logout Success! response:", r);
  } catch (r) {
    throw y.e("logoutAndResetToken() ## SERVER LOGOUT ERROR ##:", r), new V(
      `Server logout failed: ${r instanceof Error ? r.message : String(r)}`
    );
  }
}, Rr = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.jwtToken) ?? "";
}, Tr = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.dateExpiration) ?? 0;
}, Ar = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.email) ?? "";
}, Or = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.userId) ?? 0;
}, _r = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.name) ?? "";
}, xr = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.username) ?? "";
}, Ur = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.isAdmin) ?? !1;
}, Cr = (e) => {
  var t;
  return ((t = C(e)) == null ? void 0 : t.sessionUuid) ?? "";
}, Qn = (e) => {
  var n;
  const t = (n = C(e)) == null ? void 0 : n.groups;
  return !t || t === "null" ? null : t.split(",").map((r) => parseInt(r.trim(), 10));
}, Nr = (e) => {
  var t;
  return ((t = Qn(e)) == null ? void 0 : t[0]) ?? null;
}, kr = (e) => {
  var n;
  const t = (n = C(e)) == null ? void 0 : n.groups;
  return !!t && t !== "null";
};
export {
  yr as doesCurrentSessionExist,
  Tr as getDateExpiration,
  Rr as getLocalJwtTokenAuth,
  Er as getPasswordHashSHA256,
  Cr as getSessionId,
  wr as getToken,
  Sr as getTokenStatus,
  Ar as getUserEmail,
  Nr as getUserFirstGroups,
  Qn as getUserGroupsArray,
  Or as getUserId,
  Ur as getUserIsAdmin,
  xr as getUserLogin,
  _r as getUserName,
  C as getUserProfile,
  kr as isUserHavingGroups,
  br as logoutAndResetToken
};
