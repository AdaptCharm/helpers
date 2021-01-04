/*
Simple helper functions which are globally used.


Packages required:
+ @sentry/node
+ os (inbuilt)
+ express
+ compression
+ co-body
+ nanoid
+ crypto (inbuilt)
+ psl
+ cookie-parser
+ is_js


Environment variables:
+ SENTRY_DSN
+ NODE_ENV
+ PORT
+ GIT_COMMIT

*/


/********************************************* SETUP FUNCTIONS **********************************************/


//Setup error tracking.
const sentry = require("@sentry/node"), hostname = require("os").hostname(), environment = process.env.NODE_ENV || "development", gitCommit = process.env.GIT_COMMIT
if(environment == "production") {
  sentry.init({dsn: process.env.SENTRY_DSN, serverName: hostname, environment: environment, release: gitCommit, attachStacktrace: true, sendDefaultPii: true})
}


//Load required packages.
const express = require("express")
const compression = require("compression")
const bytes = require("bytes")
const expressFiles = require("express-fileupload")
const parseBody = require("co-body")
const nanoid = require("nanoid/generate")
const crypto = require("crypto")
const psl = require("psl")
const cookieParser = require("cookie-parser")
const is = require("is_js")


//Export primary functions.
var functions = [newApp, generate, {is: is}, cookieHandler, nested, time, delay, {capture: sentry.captureException}, {hostname: hostname}, {environment: environment}, {release: gitCommit}]
for(var i in functions) {
  var fn = functions[i], name = fn.name
  if(typeof fn == "object") { for(var key in fn) { name = key, fn = fn[key]; break } }
  global[name] = fn, module.exports[name] = fn
}





/********************************************* SERVING FUNCTIONS **********************************************/


/*
Creates an express app.
+ Handles CORS.
+ Parses body.
+ Handles errors.
*/
function newApp(options = {}) {
  var app = express()
  //app.set("trust proxy", true).disable("x-powered-by").use(sentry.Handlers.requestHandler(), compression())
  if(!options.noServer && !options.noPort) { app.listen(options.port || process.env.PORT || 1337) }
  if(environment == "development") { app.set("json spaces", 2) }

  //Set headers.
  if(!options.headers) { options.headers = {} }
  else if(options.headers == "api") {
    options.headers = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS, HEAD",
      "Access-Control-Allow-Credentials": true,
      "Access-Control-Expose-Headers": "Request-ID",
      "Access-Control-Allow-Headers": "Authorization, SDK-User-Agent, Content-Type",
      "Access-Control-Max-Age": 600,
      "Cache-Control": "no-cache, no-store"
    }
  }
  options.headers["X-Powered-By"] = "www.jamie.no"

  //Configure body parsing options.
  if(options.body) {
    if(!is.object(options.body)) { options.body = {} }
    if(!options.body.limit) { options.body.limit = "1MB" }
    if(!options.body.error) {
      options.body.error = function(err, req, res, next) {
        if(err.name == "PayloadTooLargeError") { res.status(413).send("Payload Too Large") }
        else { res.status(422).send("Invalid Body") }
      }
    }

    //Add body parser.
    if(options.body.files) {
      app.use(expressFiles({uriDecodeFileNames: true, abortOnLimit: true, parseNested: true, limitHandler: function(req, res, next) { req.bodyError = true; return options.body.error({name: "PayloadTooLargeError"}, req, res, next) }, limits: {fileSize: bytes(options.body.fileLimits || options.body.limit)}}))
    }
  }

  //Set headers & handle CORS.
  app.use(async function(req, res, next) {
    try {
      if(req.bodyError) { return }
      req.started = new Date().getTime(), req.catch = sentry.captureException

      //Handle headers.
      if(options.headers) {
        res.set(options.headers)
        if(req.headers.origin && options.headers["Access-Control-Allow-Origin"] == "*") { res.set({"Access-Control-Allow-Origin": req.headers.origin}) }
      }
      if(req.method.toLowerCase() == "options") {
        return res.set({"Cache-Control": "max-age=600"}).status(200).end()
      }

      //Parse body.
      if(options.body) {
        if(req.is("json") || req.is("urlencoded") || req.is("text")) {
          try {
            req.body = await parseBody(req, {limit: options.body.limit, strict: false})

            if(!is.empty(req.body)) {
              if(is.string(req.body)) { req.body = {text: req.body} }
              else if(!is.object(req.body)) { req.body = {} }
            }
          } catch (e) { return options.body.error(e, req, res, next) }
        }
      }

      next()
    }
    catch(e) { next(e) }
  })

  //Handle cookies.
  if(options.cookies) {
    if(!is.object(options.cookies)) { options.cookies = {} }
    app.use(cookieHandler(options.cookies))
  }

  //Create a callback to register error handler.
  app.errorHandler = function(fn) {
    if(environment == "production") {
      app.use(sentry.Handlers.errorHandler())
      if(fn) { app.use(fn) }
    }
  }

  return app
}





/********************************************* ID GENERATION FUNCTIONS **********************************************/


/*
Generates random IDs.
*/
function generate(prefix = "", min, max) {
  var length = {min: min || 21, max: max || 29}
  if(["key_", "ssn_", "nonce_"].includes(prefix)) { length = {min: 30, max: 38} }
  else if(prefix == "rst_key_") { length = {min: 60, max: 80} }
  if(min) { length.min = min }
  if(max) { length.max = max }

  var random = parseInt(crypto.randomBytes(8).toString("hex"), 16) / Math.pow(2, 64)
  var randomLength = Math.floor(random * (length.max - length.min + 1) + length.min)
  return prefix + nanoid("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", randomLength)
}





/********************************************* COOKIE HANDLER FUNCTIONS **********************************************/


/*
Creates functions to easily and automatically deal with cookies.
*/
function cookieHandler(defaultOptions = {}) {
  var cookieOptions = Object.assign({path: "/", maxAge: 3.154e+10, httpOnly: false, sameSite: false, secure: false, domain: null, signed: (defaultOptions.secret ? true : false)}, defaultOptions), domains = {}

  return function(req, res, next) {
    var hostname = req.hostname
    if(domains[hostname] === undefined) {
      domains[hostname] = psl.parse(hostname).domain || null
      if(domains[hostname]) { domains[hostname] = "." + domains[hostname] }
    }
    if(domains[hostname]) { cookieOptions.domain = domains[hostname] } else { cookieOptions.domain = null }
    if(req.secure) { cookieOptions.secure = true }

    //First parse cookies.
    cookieParser(defaultOptions.secret)(req, res, function(e) {
      if(e && e.constructor && e.constructor.name == "Error") { return next(e) }

      //Create a cookie setter and delete function. Saves a cookie to the top domain for a year.
      res.cookies = {
        set: function(key, val, options = {}) {
          if(defaultOptions.secret || options.signed) { req.signedCookies[key] = val } else { req.cookies[key] = val }

          return res.cookie(key, val, Object.assign({}, cookieOptions, options))
        },

        delete: function(key, options = {}) {
          if(defaultOptions.secret || options.signed) { delete req.signedCookies[key] } else { delete req.cookies[key] }

          return res.clearCookie(key, Object.assign({}, cookieOptions, {maxAge: -10000}, options))
        }
      }

      next()
    })
  }
}





/********************************************* MISC HELPER FUNCTIONS **********************************************/


/*
Gets a value from a nested object using dotted keys.
*/
function nested(obj, key, newVal) {
  //if(obj[key]) { return obj[key] }
  var parts = String(key).split(".")
  for(var n in parts) {
    var nestedKey = parts[n]
    if(!obj[nestedKey]) { return obj[nestedKey] }
    if(typeof newVal !== "undefined" && n == (parts.length - 1)) { obj[nestedKey] = newVal }
    obj = obj[nestedKey]
  }
  return obj
}



/*
Converts date to UNIX timestamp.
*/
function time(d) {
  if(!d) { d = new Date() }
  return Math.floor(d.getTime() / 1000)
}



/*
Async setTimeout.
*/
function delay(ms) {
  return new Promise(function(resolve) {
    setTimeout(resolve, ms)
  })
}
