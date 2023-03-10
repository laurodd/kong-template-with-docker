local plugin = {
  PRIORITY = 1000, -- set the plugin priority, which determines plugin execution order
  VERSION = "0.1",
}

---------------------------------------------------------------------------------------------
----------------------------------- DATADOME FUNCTIONS --------------------------------------
---------------------------------------------------------------------------------------------
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

local function getCurrentMicroTime()
  -- we need time up to microseccconds, but at lua we can do up to seconds :( round it
  return tostring(os.time()) .. "000000"
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

local function getAuthorizationLen(request_headers)
  return string.len(request_headers["authorization"] or "")
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

local function getHeadersList(request_headers)
  local headers = {}
  for key, _ in pairs(request_headers) do
      table.insert(headers, key)
  end
  return table.concat(headers, ",")
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

local function addErrorHeader(value)
  ngx.header['X-DataDome-Error'] = value
end

local function getBodyAndDatadomeHeaders(plugin_conf)
  local request_headers = ngx.req.get_headers()
  local clientId, cookieLen = getClientIdAndCookiesLength(request_headers)

  local body = {
    ['Key']                = plugin_conf.datadome_api_key,
    ['RequestModuleName']  = 'Kong',
    ['ModuleVersion']      = '0.0.1',
    ['ServerName']         = ngx.var.hostname,
    ['APIConnectionState'] = 'new',
    ['IP']                 = ngx.var.remote_addr,
    ['Port']               = ngx.var.server_port,
    ['TimeRequest']        = getCurrentMicroTime(),
    ['Protocol']           = string.len(ngx.var.https) == 0 and 'http' or 'https',
    ['Method']             = ngx.req.get_method(),
    ['Request']            = ngx.var.request_uri,
    ['HeadersList']        = getHeadersList(request_headers),
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
    ['AuthorizationLen']   = tostring(getAuthorizationLen(request_headers)),
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

  return body,datadomeHeaders
end

local function callDatadome(plugin_conf,body,datadomeHeaders) 
  local api_protocol = plugin_conf.datadome_api_config_ssl and 'https://' or 'http://'
  local options = {
      method = "POST",
      port = plugin_conf.datadome_api_config_port,
      ssl_verify = plugin_conf.datadome_api_config_ssl,
      keep_alive = true,
      body = stringify(body),
      headers = datadomeHeaders
  }

  local httpc = require("resty.http").new()
  httpc:set_timeout(plugin_conf.datadome_api_config_timeout)
  local res, err = httpc:request_uri(api_protocol .. plugin_conf.datadome_api_endpoint .. plugin_conf.datadome_api_config_path, options)

  return res, err
end

local function isError(err)
  if err ~= nil then
    if err == "timeout" then
      kong.log.debug("[LGR] Timeout happened with connection to DataDome, skip request")
    else
      kong.log.debug("[LGR] Error occurred while connecting to DataDome API. Check DataDome configuration "..err)
    end
    addErrorHeader(err)
    return true
  else 
    kong.log.debug("[LGR] Error nil")
  end
  return false
end

local function isXDataDomeResponseDifferentStatus(api_response_headers, status)
  if api_response_headers then
    if tonumber(api_response_headers["X-DataDomeResponse"]) ~= status then
      addErrorHeader("Invalid API Key")
      kong.log.debug("[LGR] Invalid X-DataDomeResponse header, is it ApiServer response?")
      return true
    else 
      kong.log.debug("[LGR] Valid X-DataDomeResponse header, code:"..status)
    end
  end
  return false
end

local function checkStatusCodeAndUpdateHeaders(status, api_response_headers, api_response_body)
  if status == 403 or status == 401 or status == 301 or status == 302 then
    kong.log.debug("[LGR] STATUS CODE ERROR: "..status)
    addResponseHeaders(api_response_headers)
    ngx.status = status
    ngx.say(api_response_body)
    ngx.exit(status)
  end

  if status == 200 then
    kong.log.debug("[LGR] STATUS CODE OK: "..status)
    addRequestHeaders(api_response_headers)
    addResponseHeaders(api_response_headers)
  end
end
---------------------------------------------------------------------------------------------
-------------------------- DATADOME EXECUTION : access phase --------------------------------
-- Executed for every request from a client and before it is being proxied to the upstream --
---------------------------------------------------------------------------------------------

function plugin:access(plugin_conf)
  local body, datadomeHeaders = getBodyAndDatadomeHeaders(plugin_conf)
  
  local res, err = callDatadome(plugin_conf,body,datadomeHeaders)
  local status = res.status
  local api_response_headers = res.headers
  local api_response_body = res.body

  if isError(err) then
    return
  end

  if isXDataDomeResponseDifferentStatus(api_response_headers, status) then
    return
  end

  checkStatusCodeAndUpdateHeaders(status, api_response_headers, api_response_body);

end

  --[[
  kong.log.debug("[LGR] ---------------------------------------")
  -- testing required config
  kong.log.debug("[LGR] API KEY FROM CONFIG = "..plugin_conf.datadome_api_key)
  -- testing default config
  kong.log.debug("[LGR] API ENDPOINT FROM CONFIG = "..plugin_conf.datadome_api_endpoint)
  -- testing overriding default config
  kong.log.debug("[LGR] API TIMEOUT FROM CONFIG = "..plugin_conf.datadome_api_config_timeout)
  kong.log.debug("[LGR] PHASE = "..ngx.get_phase())
  kong.log.debug("[LGR] ---------------------------------------")
  kong.log.debug("[LGR] ngx.req.get_headers")
  kong.log.debug("[LGR] ---------------------------------------")
  for key, valeur in pairs(ngx.req.get_headers()) do
    kong.log.debug("[LGR] "..key.." "..valeur)
  end
  
  local body, datadomeHeaders = getBodyAndDatadomeHeaders(plugin_conf)

  kong.log.debug("[LGR] ---------------------------------------")
  kong.log.debug("[LGR] body")
  kong.log.debug("[LGR] ---------------------------------------")
  for k, v in pairs(body) do
    kong.log.debug("[LGR] ",k, "=", v);
  end
  kong.log.debug("[LGR] ---------------------------------------")
  kong.log.debug("[LGR] datadomeHeaders ")
  for k, v in pairs(datadomeHeaders) do
    kong.log.debug("[LGR] ",k, "=", v);
  end
  kong.log.debug("[LGR] ---------------------------------------")

  local api_protocol = plugin_conf.datadome_api_config_ssl and 'https://' or 'http://'
  local options = {
      method = "POST",
      port = plugin_conf.datadome_api_config_port,
      ssl_verify = plugin_conf.datadome_api_config_ssl,
      keep_alive = true,
      body = stringify(body),
      headers = datadomeHeaders
  }

  -- call Datadome
  local httpc = require("resty.http").new()
  httpc:set_timeout(plugin_conf.datadome_api_config_timeout)
  local res, err = httpc:request_uri(api_protocol .. plugin_conf.datadome_api_endpoint .. plugin_conf.datadome_api_config_path, options)
  

  local res, err = callDatadome(plugin_conf,body,datadomeHeaders)

  ]]

  --[[
  kong.log.debug("[LGR] ---------------------------------------")
  if err ~= nil then
      if err == "timeout" then
        kong.log.debug("[LGR] Timeout happened with connection to DataDome, skip request")
      else
        kong.log.debug("[LGR] Error occurred while connecting to DataDome API. Check DataDome configuration "..err)
      end
      addErrorHeader(err)
      return
  else 
    kong.log.debug("[LGR] Error nil")
  end


  -- check response
  local status = res.status
  kong.log.debug("[LGR] status ="..status)

  local api_response_headers = res.headers


  if api_response_headers then
    if tonumber(api_response_headers["X-DataDomeResponse"]) ~= status then
      addErrorHeader("Invalid API Key")
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

  kong.log.debug("[LGR] AFTER 403 "..status)

  if status == 200 then
    kong.log.debug("[LGR] STATUS CODE OK: "..status)
    addRequestHeaders(api_response_headers)
    addResponseHeaders(api_response_headers)
  end
  
end ]]

return plugin
