-- If you're not sure your plugin is executing, uncomment the line below and restart Kong
-- then it will throw an error which indicates the plugin is being loaded at least.

--assert(ngx.get_phase() == "timer", "The world is coming to an end!")

---------------------------------------------------------------------------------------------
-- In the code below, just remove the opening brackets; `[[` to enable a specific handler
--
-- The handlers are based on the OpenResty handlers, see the OpenResty docs for details
-- on when exactly they are invoked and what limitations each handler has.
---------------------------------------------------------------------------------------------



local plugin = {
  PRIORITY = 1000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1",
}

---------------------------------------------------------------------------------------------
------------------------------------- DATADOME SECTION --------------------------------------
---------------------------------------------------------------------------------------------
local DATADOME_API_ENDPOINT = "api.datadome.co"
local DATADOME_API_KEY = "YOU_DD_KEY_HERE"
local DATADOME_API_CONFIG = {
    --ssl = true,
    --port = 443,
    ssl = false,
    port = 80,
    path = "/validate-request",
    timeout = 150,
    uriRegex = "",
    uriRegexExclusion = "\\.avi|\\.flv|\\.mka|\\.mkv|\\.mov|\\.mp4|\\.mpeg|\\.mpg|\\.mp3|\\.flac|\\.ogg|\\.ogm|\\.opus|\\.wav|\\.webm|\\.webp|\\.bmp|\\.gif|\\.ico|\\.jpeg|\\.jpg|\\.png|\\.svg|\\.svgz|\\.swf|\\.eot|\\.otf|\\.ttf|\\.woff|\\.woff2|\\.css|\\.less|\\.js$"
}

local function getClientIdAndCookiesLength(request_headers)
  local cookie = request_headers["cookie"] or ""
  local len = string.len(cookie)
  local clientId = nil
  if len > 0 then
    for element in ngx.re.gmatch(cookie, "([^;= ]+)=([^;$]+)", "io") do
      if element[1] == "datadome" then
        clientId = element[2]
        break
      end
    end
  end
  return clientId, len
end

local function urlencode(str)
  if str then
    str = ngx.re.gsub(str, '\n', '\r\n', "io")
    str = ngx.re.gsub(str, '([^[:alnum:]-_.~])', function(c)
                        return string.format('%%%02X', string.byte(c[0]))
    end, "io")
  end
  return str
end

local function stringify(params)
  if type(params) == "table" then
    local fields = {}
    for key,value in pairs(params) do
      local keyString = urlencode(tostring(key)) .. '='
      if type(value) == "table" then
        for _, v in ipairs(value) do
          table.insert(fields, keyString .. urlencode(tostring(v)))
        end
      else
        table.insert(fields, keyString .. urlencode(tostring(value)))
      end
    end
    return table.concat(fields, '&')
  end
  return ''
end

local function addResponseHeaders(api_response_headers)
  local response_headers = api_response_headers['X-DataDome-Headers']

  if response_headers == nil then
      return
  end

  for header_name in ngx.re.gmatch(response_headers, "([^ ]+)", "io") do
      local header_value = api_response_headers[header_name[0]]
      if header_value ~= nil then
          if header_name[0] == 'Set-Cookie' then
              if type(ngx.header["Set-Cookie"]) == "table" then
                  ngx.header["Set-Cookie"] = { header_value, table.unpack(ngx.header["Set-Cookie"]) }
              else
                  ngx.header["Set-Cookie"] = { header_value, ngx.header["Set-Cookie"] }
              end
          else
              ngx.header[header_name[0]] = header_value
          end
      end
  end
end

local function addRequestHeaders(api_response_headers)
  local request_headers = api_response_headers['X-DataDome-Request-Headers']

  if request_headers == nil then
      return
  end

  for header_name in ngx.re.gmatch(request_headers, "([^ ]+)", "io") do
      local header_value = api_response_headers[header_name[0]]
      if header_value ~= nil then
          ngx.req.set_header(header_name[0], header_value)
      end
  end
end
---------------------------------------------------------------------------------------------

-- do initialization here, any module level code runs in the 'init_by_lua_block',
-- before worker processes are forked. So anything you add here will run once,
-- but be available in all workers.



-- handles more initialization, but AFTER the worker process has been forked/created.
-- It runs in the 'init_worker_by_lua_block'
function plugin:init_worker()

  -- your custom code here
  kong.log.debug("saying hi from the 'init_worker' handler")

end --]]



--[[ runs in the 'ssl_certificate_by_lua_block'
-- IMPORTANT: during the `certificate` phase neither `route`, `service`, nor `consumer`
-- will have been identified, hence this handler will only be executed if the plugin is
-- configured as a global plugin!
function plugin:certificate(plugin_conf)

  -- your custom code here
  kong.log.debug("saying hi from the 'certificate' handler")

end --]]



--[[ runs in the 'rewrite_by_lua_block'
-- IMPORTANT: during the `rewrite` phase neither `route`, `service`, nor `consumer`
-- will have been identified, hence this handler will only be executed if the plugin is
-- configured as a global plugin!
function plugin:rewrite(plugin_conf)

  -- your custom code here
  kong.log.debug("saying hi from the 'rewrite' handler")

end --]]



-- runs in the 'access_by_lua_block'
--https://github.com/Kong/kong/blob/master/kong/pdk/service/request.lua
function plugin:access(plugin_conf)
  kong.log.debug("[LGR] ---------------------------------------")
  kong.log.debug("[LGR] PHASE = "..ngx.get_phase())
  kong.log.debug("[LGR] ---------------------------------------")
  kong.log.debug("[LGR] ngx.req.get_headers")
  kong.log.debug("[LGR] ---------------------------------------")
  for key, valeur in pairs(ngx.req.get_headers()) do
    kong.log.debug("[LGR] "..key.." "..valeur)
  end


  local request_headers = ngx.req.get_headers()
  local clientId = ""
  local cookieLen = 10
  clientId, cookieLen = getClientIdAndCookiesLength(request_headers)


  local body = {
    ['Key']                = DATADOME_API_KEY,
    ['RequestModuleName']  = 'Kong',
    ['ModuleVersion']      = '0.0.1',
    ['ServerName']         = ngx.var.hostname,
    ['APIConnectionState'] = 'new',
    ['IP']                 = ngx.var.remote_addr,
    ['Port']               = ngx.var.server_port,
    ['TimeRequest']        = '0',--helpers.getCurrentMicroTime(),
    ['Protocol']           = string.len(ngx.var.https) == 0 and 'http' or 'https',
    ['Method']             = ngx.req.get_method(),
    ['Request']            = ngx.var.request_uri,
    ['HeadersList']        = "headerlist",
    ['Host']               = request_headers['host'],
    ['UserAgent']          = request_headers['user-agent'],
    ['Referer']            = request_headers['referer'],
    ['Accept']             = request_headers['accept'],
    ['AcceptEncoding']     = request_headers['accept-encoding'],
    ['AcceptLanguage']     = request_headers['accept-language'],
    ['AcceptCharset']      = request_headers['accept-charset'],
    ['Origin']             = request_headers['origin'],
    ['XForwaredForIP']     = request_headers['x-forwarded-for'],
    ['X-Requested-With']   = request_headers['x-requested-with'],
    ['Connection']         = request_headers['connection'],
    ['Pragma']             = request_headers['pragma'],
    ['CacheControl']       = request_headers['cache-control'],
    ['ContentType']        = request_headers['content-type'],
    ['From']               = request_headers['from'],
    ['X-Real-IP']          = request_headers['x-real-ip'],
    ['Via']                = request_headers['via'],
    ['TrueClientIP']       = request_headers['true-client-ip'],
    ['CookiesLen']         = tostring(cookieLen),
    --['AuthorizationLen']   = tostring(helpers.getAuthorizationLen(request_headers)),
    ['PostParamLen']       = request_headers['content-length'],
  }

  local datadomeHeaders = {
    ["Connection"] = "keep-alive",
    ["Content-Type"] = "application/x-www-form-urlencoded",
  }

  if request_headers['x-datadome-clientid'] ~= nil then
      body['ClientID'] = request_headers['x-datadome-clientid']
      datadomeHeaders["X-DataDome-X-Set-Cookie"] = "true"
  else
      body['ClientID'] = clientId
  end

  kong.log.debug("[LGR] ---------------------------------------")
  kong.log.debug("[LGR] body")
  kong.log.debug("[LGR] ---------------------------------------")
  for k, v in pairs(body) do
    kong.log.debug("[LGR] ",k, "=", v);
  end


  local api_protocol = DATADOME_API_CONFIG.ssl and 'https://' or 'http://'
  local options = {
      method = "POST",
      port = DATADOME_API_CONFIG.port,
      ssl_verify = DATADOME_API_CONFIG.ssl,
      keep_alive = true,
      body = stringify(body),
      headers = datadomeHeaders
  }
  local httpc = require("resty.http").new()
  httpc:set_timeout(DATADOME_API_CONFIG.timeout)

  local res, err = httpc:request_uri(api_protocol .. DATADOME_API_ENDPOINT .. "/validate-request", options)

  kong.log.debug("[LGR] ---------------------------------------")
  if err ~= nil then
      if err == "timeout" then
        kong.log.debug("[LGR] Timeout happened with connection to DataDome, skip request")
      else
        kong.log.debug("[LGR] Error occurred while connecting to DataDome API. Check DataDome configuration "..err)
      end
      --headers.addErrorHeader(err)
      return
  else 
    kong.log.debug("[LGR] Error nil")
  end

  
  local status = res.status
  kong.log.debug("[LGR] status ="..status)

  local api_response_headers = res.headers
  if api_response_headers then
    if tonumber(api_response_headers["X-DataDomeResponse"]) ~= status then
      --headers.addErrorHeader("Invalid API Key")
      kong.log.debug("[LGR] Invalid X-DataDomeResponse header, is it ApiServer response?")
      return
    else 
      kong.log.debug("[LGR] Valid X-DataDomeResponse header, code:"..status)
    end
  end

  if status == 403 or status == 401 or status == 301 or status == 302 then
    kong.log.debug("[LGR] STATUS CODE ERROR: "..status)
    addResponseHeaders(api_response_headers)
    ngx.status = status
    ngx.say(res.body)
    ngx.exit(status)
  end

  if status == 200 then
    kong.log.debug("[LGR] STATUS CODE OK: "..status)
    addRequestHeaders(api_response_headers)
    addResponseHeaders(api_response_headers)
  end


end


-- runs in the 'header_filter_by_lua_block'
function plugin:header_filter(plugin_conf)

  -- your custom code here, for example;
  kong.response.set_header(plugin_conf.response_header, "this is on the response")
  kong.response.set_header("X-DataDome-Res-Lauro", "this is on the response created by Lauro")
end --]]


--[[ runs in the 'body_filter_by_lua_block'
function plugin:body_filter(plugin_conf)

  -- your custom code here
  kong.log.debug("saying hi from the 'body_filter' handler")

end --]]


--[[ runs in the 'log_by_lua_block'
function plugin:log(plugin_conf)

  -- your custom code here
  kong.log.debug("saying hi from the 'log' handler")

end --]]


-- return our plugin object
return plugin
