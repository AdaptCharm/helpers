/*
Simple helper functions which are globally used.


Environment variables:
+ SENTRY_DSN
+ NODE_ENV
+ PORT
+ GIT_COMMIT

*/


/********************************************* SETUP FUNCTIONS **********************************************/


//Setup error tracking.
const sentry = require("@sentry/node"), hostname = require("os").hostname(), environment = process.env.NODE_ENV || "development", release = process.env.GIT_COMMIT
if(environment == "production") {
  sentry.init({dsn: process.env.SENTRY_DSN, serverName: hostname, environment, release, attachStacktrace: true, sendDefaultPii: true})
}


//Load required packages.
const is = require("is_js")
is.base64 = require("is-base64"), is.defined = val => !is.undefined(val)
const express = require("express")
const compression = require("compression")
const bytes = require("bytes")
const ms = require("ms")
const expressFiles = require("express-fileupload")
const coBody = require("co-body")
const nanoid = require("nanoid")
const crypto = require("crypto")
const psl = require("psl")
const cookieParser = require("cookie-parser")


//Export primary functions.
var toExport = {sentry, newApp, rateLimit, shouldRateLimit, parseBody, cookieHandler, errorResponder, generate, randomBetween, delay, authKey, toEpoch, is, express, compression, bytes, ms, expressFiles, coBody, nanoid, psl, cookieParser, hostname, environment, release}
for(var name in toExport) {
  var fn = toExport[name]
  module.exports[name] = fn, global[name] = fn
}





/********************************************* APP CREATOR FUNCTIONS **********************************************/


/*
Creates a new app instance.
*/
function newApp(options = {}) {
  //Create an app instance.
  if(options.server === false) {
    var app = express.Router({strict: is.boolean(options.strict) ? options.strict : true, mergeParams: is.boolean(options.mergeParams) ? options.mergeParams : false, caseSensitive: is.boolean(options.caseSensitive) ? options.caseSensitive : true})
  }
  else {
    var app = express()
    app.disable("x-powered-by").use(sentry.Handlers.requestHandler(), compression())
    if(environment == "development") { app.set("json spaces", 2) }
    if(options.trustProxy !== false) { app.set("trust proxy", true) }

    app.server = app.listen(options.port || process.env.PORT || 1337)
  }

  //Configure app instance.
  if(!options.headers) {
    if(options.type == "api") {
      options.headers = {
        "Access-Control-Allow-Origin": options.origin || "*",
        "Access-Control-Allow-Methods": options.methods ? options.methods.join(", ") : "GET, POST, DELETE, OPTIONS, HEAD",
        "Access-Control-Allow-Credentials": true,
        "Access-Control-Expose-Headers": options.exposeHeaders ? options.exposeHeaders.join(", ") : "Request-Id",
        "Access-Control-Allow-Headers": options.allowHeaders ? options.allowHeaders.join(", ") : "Authorization, Content-Type",
        "Access-Control-Max-Age": 600,
        "Cache-Control": "no-cache, no-store"
      }
    }
    else { options.headers = {} }
  }
  if(options.poweredBy !== false) { options.headers["X-Powered-By"] = options.poweredBy || "Uncoded" }
  if(!is.undefined(options.cache)) { options.headers["Cache-Control"] = "max-age=" + (is.string(options.cache) ? Math.floor(ms(options.cache) / 1000) : options.cache) }

  //Handle CORS & headers (+ set vars).
  app.use(async (req, res, next) => {
    try {
      if(!req.started) {
        req.started = new Date(), req.user_ip = (options.trustProxy === false) ? req.ip : (req.headers["cf-connecting-ip"] || req.ip)
      }

      //Handle headers.
      if(options.headers) {
        res.set(options.headers)
        if(req.headers.origin && options.headers["Access-Control-Allow-Origin"] == "*") { res.set({"Access-Control-Allow-Origin": req.headers.origin}) }
      }

      //Handle OPTIONS requests.
      if(req.method == "OPTIONS") {
        if(!options.cache) { res.set({"Cache-Control": "max-age=600"}) }
        return res.status(200).end()
      }

      next()
    }
    catch (e) { next(e) }
  })

  //Add error responder.
  if(options.errors) {
    app.use(errorResponder(options.errors))
  }

  //Handle rate limiting.
  if(options.rateLimit) {
    if(!is.object(options.rateLimit)) { options.rateLimit = {} }
    if(!options.rateLimit.limitHandler) { options.rateLimit.limitHandler = options.type }
    app.use(rateLimit(options.rateLimit))
  }

  //Handle body parsing.
  if(options.body) {
    if(!is.object(options.body)) { options.body = {} }
    if(!options.body.limitHandler) { options.body.limitHandler = options.type }
    if(!options.body.malformHandler) { options.body.malformHandler = options.type }
    app.use(parseBody(options.body))
  }

  //Handle cookie parsing.
  if(options.cookies) {
    app.use(cookieHandler(is.object(options.cookies) ? options.cookies : {}))
  }

  //Create a callback to register error handler.
  app.errorHandler = (fn) => {
    app.errorHandlerSet = true
    if(options.server !== false) { app.use(sentry.Handlers.errorHandler()) }
    if(fn) { app.use(fn) }
  }
  setTimeout(() => { if(!app.errorHandlerSet) { app.errorHandler() } }, 2000)

  return app
}





/********************************************* REQUEST HANDLER FUNCTIONS **********************************************/


/*
Rate limits requests.
*/
function rateLimit(options = {}) {
  if(!options.per) { options.per = "1 minute" }
  if(is.string(options.per)) { options.per = Math.floor(ms(options.per) / 1000) }

  return async (req, res, next) => {
    try {
      if(await shouldRateLimit(req.user_ip || req.ip, options.limit || 100, options.per, options.type || "IP", options.redis)) {
        if(is.function(options.limitHandler)) { return await options.limitHandler(req, res, next) }
        else if(res.error && res.error.rate_limited) { return res.error.rate_limited() }
        else if(options.limitHandler == "api") { return res.status(429).json({error: {message: "You're making too many requests. Please retry after a minute", type: "rate_limit_error", code: "rate_limited"}}) }

        return res.status(429).send("You're making too many requests. Please try again later")
      }
      return next()
    }
    catch (e) { next(e) }
  }
}



/*
Boolean whether a value should be rate limited.
*/
async function shouldRateLimit(identifier, limit = 100, perSeconds = 60, type = "IP", redis) {
  //Add to the number of requests made by this resource.
  var requests = await redis.incr(type + ":" + identifier)
  if(requests == 1) { await redis.expire(type + ":" + identifier, perSeconds) }

  //Check if limit has been crossed.
  if(requests > limit) { return true }
  return false
}



/*
Parses the body.
*/
function parseBody(options = {}) {
  var limit = bytes(options.limit || "10 MB")
  return async (req, res, next) => {
    try {
      expressFiles({useTempFiles: options.tempFileDir ? true : false, tempFileDir: options.tempFileDir, uriDecodeFileNames: true, abortOnLimit: true, parseNested: true, preserveExtension: true, limitHandler: async (req, res, next) => {
        try {
          req.bodyError = true
          if(is.function(options.limitHandler)) { return await options.limitHandler(req, res, next) }
          else if(res.error && res.error.body_too_large) { return res.error.body_too_large() }
          else if(options.limitHandler == "api") { return res.status(413).json({error: {message: "Your request body is too big. Please send less data", type: "invalid_request_error", code: "body_too_large"}}) }
          return res.status(413).send("The request body is too big. Please send less data")
        }
        catch (e) { next(e) }
      }, limits: {fileSize: limit, fieldSize: limit}})
      (req, res, async (e) => {
        try {
          if(e) { return next(e) }
          if(req.bodyError) { return }
          if(!req.is("json") && !req.is("urlencoded") && !req.is("text")) { return next() }

          try {
            req.body = await coBody(req, {limit, strict: false})
            if(!is.empty(req.body)) {
              if(is.string(req.body)) { req.body = {text: req.body} }
              else if(!is.object(req.body) && !is.array(req.body)) { req.body = {} }
            }

            next()
          }
          catch (err) {
            if(err.name == "PayloadTooLargeError") {
              if(is.function(options.limitHandler)) { return await options.limitHandler(req, res, next) }
              else if(res.error && res.error.body_too_large) { return res.error.body_too_large() }
              else if(options.limitHandler == "api") { return res.status(413).json({error: {message: "Your request body is too big. Please send less data", type: "invalid_request_error", code: "body_too_large"}}) }
              return res.status(413).send("The request body is too big. Please send less data")
            }

            if(is.function(options.malformHandler)) { return await options.malformHandler(req, res, next) }
            else if(res.error && res.error.body_incorrect_format) { return res.error.body_incorrect_format() }
            else if(options.malformHandler == "api") { return res.status(422).json({error: {message: "Your request body is badly formatted", type: "invalid_request_error", code: "body_incorrect_format"}}) }
            return res.status(422).send("The request body is badly formatted")
          }
        }
        catch (e) { next(e) }
      })
    }
    catch (e) { next(e) }
  }
}



/*
Handles cookies.
*/
function cookieHandler(defaultOptions = {}) {
  var options = Object.assign({path: "/", maxAge: 3.154e+10, httpOnly: false, sameSite: false, secure: false, domain: null, signed: (defaultOptions.secret ? true : false)}, defaultOptions), domains = {}

  return async (req, res, next) => {
    try {
      if(domains[req.hostname] === undefined) {
        var domain = psl.parse(req.hostname).domain
        domains[req.hostname] = domain ? "." + domain : null
      }
      options.domain = domains[req.hostname]
      if(req.secure) { options.secure = true }

      //Parse cookies.
      cookieParser(options.secret)(req, res, function(e) {
        if(e && e.constructor && e.constructor.name == "Error") { return next(e) }

        //Create a cookie setter and delete function. Saves a cookie to the top domain for a year.
        res.cookies = {
          set: function(key, val, thisOptions = {}) {
            if(options.secret || thisOptions.signed) { req.signedCookies[key] = val } else { req.cookies[key] = val }
            return res.cookie(key, val, Object.assign({}, options, thisOptions))
          },

          delete: function(key, thisOptions = {}) {
            if(options.secret || thisOptions.signed) { delete req.signedCookies[key] } else { delete req.cookies[key] }
            return res.clearCookie(key, Object.assign({}, options, {maxAge: -10000}, thisOptions))
          }
        }

        next()
      })
    }
    catch (e) { next(e) }
  }
}



/*
Handles responding with errors.
*/
function errorResponder(errors = {}) {
  var createResponder = function(errorCode, res) {
    return (extra) => {
      var obj = {error: Object.assign({}, errors[errorCode])}, status = obj.error.status
      delete obj.error.status
      if(!obj.error.code) { obj.error.code = errorCode }

      if(is.string(extra) || is.array(extra)) {
        if(is.string(extra)) { extra = [extra] }
        for(var i in extra) { obj.error.message = obj.error.message.replace("$" + (parseFloat(i) + 1), extra[i]) }
      }
      else if(is.object(extra)) {
        obj.error = Object.assign(obj.error, extra)
      }

      if([429, 401, 403].includes(status)) {
        return setTimeout(() => res.status(status).json(obj), randomBetween(200, 1000))
      }
      return res.status(status).json(obj)
    }
  }

  return async (req, res, next) => {
    try {
      if(!res.error) { res.error = {} }
      for(var code in errors) { res.error[code] = createResponder(code, res) }
      next()
    }
    catch (e) { next(e) }
  }
}





/********************************************* OBJECT CHECKER FUNCTIONS **********************************************/


/*
Gets a value from a nested object using dotted keys.
*/
function nested(obj, key, newVal) {
  if(is.defined(obj[key]) && !is.defined(newVal)) { return obj[key] }
  var parts = String(key).split("."), prev = ""
  for(var n in parts) {
    var nestedKey = parts[n]
    if(is.undefined(obj[nestedKey])) {
      if(is.undefined(newVal)) { return undefined }
      obj[nestedKey] = {}
    }
    if(is.defined(newVal) && n == (parts.length - 1)) {
      if(is.string(obj)) { obj = prev }
      obj[nestedKey] = newVal
    }
    prev = obj, obj = obj[nestedKey]
  }

  return obj
}



/*
Checks whether an object has a dotted key.
*/
Object.defineProperty(Object.prototype, "devHas", {
  enumerable: false,
  writeable: true,
  value: function(key) {
    if(is.defined(nested(this, key))) { return true }
    return false
  }
})



/*
Returns the value of a dotted key.
*/
Object.defineProperty(Object.prototype, "devFind", {
  enumerable: false,
  writeable: true,
  value: function(key) {
    return nested(this, key)
  }
})



/*
Sets the value of a dotted key.
*/
Object.defineProperty(Object.prototype, "devSet", {
  enumerable: false,
  writeable: true,
  value: function(key, val) {
    return nested(this, key, val)
  }
})





/********************************************* HELPER FUNCTIONS **********************************************/


/*
Generates random IDs.
*/
function generate(prefix = "", min, max, set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
  if(!min || !max) {
    if(["key_", "ssn_", "nonce_"].includes(prefix)) { min = 30, max = 38 }
    else if(prefix == "rst_key_") { min = 60, max = 80 }
    else { min = 21, max = 29 }
  }

  return prefix + nanoid.customAlphabet(set, randomBetween(min, max))()
}



/*
Generates a random number between two numbers.
*/
function randomBetween(min = 1, max = 10) {
  var random = parseInt(crypto.randomBytes(8).toString("hex"), 16) / Math.pow(2, 64)
  return Math.floor(random * (max - min + 1) + min)
}



/*
Async setTimeout.
*/
function delay(ms) {
  return new Promise(function(resolve) {
    setTimeout(resolve, ms)
  })
}



/*
Extracts the authentication key from the Authorization header.
*/
function authKey(header, onlyPassword = true) {
  if(!header || typeof header !== "string") { return undefined }

  if(header.startsWith("Basic")) { header = header.replace("Basic", "") }
  else if(header.startsWith("Bearer")) { header = header.replace("Bearer", "") }
  var key = header.trim()

  if(is.base64(key)) {
    key = Buffer.from(key, "base64").toString()
  }
  if(key.includes(":") && onlyPassword) {
    var split = key.split(":")
    if(split[split.length - 1]) { key = split[split.length - 1] }
    else { key = key.replace(":", "") }
  }

  return key
}



/*
Converts date to UNIX timestamp.
*/
function toEpoch(d) {
  if(!d) { d = new Date() }
  return Math.floor(d.getTime() / 1000)
}
