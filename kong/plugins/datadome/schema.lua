local typedefs = require "kong.db.schema.typedefs"

-- Grab pluginname from module name
local plugin_name = ({...})[1]:match("^kong%.plugins%.([^%.]+)")

local schema = {
  name = plugin_name,
  fields = {
    -- the 'fields' array is the top-level entry with fields defined by Kong
    { consumer = typedefs.no_consumer },  -- this plugin cannot be configured on a consumer (typical for auth plugins)
    { protocols = typedefs.protocols_http },
    { config = {
        -- The 'config' record is the custom part of the plugin schema
        type = "record",
        fields = {
          -- a standard defined field (typedef), with some customizations
          { datadome_api_key = {
            type = "string",
            required = true } },
          { datadome_api_endpoint = {
            type = "string",
            required = true,
            default = "api.datadome.co" } },
          { datadome_api_config_http_method = {
            type = "string",
            required = true,
            default = "POST" } },
          { datadome_api_config_use_keepalive = {
            type = "boolean",
            required = true,
            default = true } },
          { datadome_api_config_ssl = {
            type = "boolean",
            required = true,
            default = false } },
          { datadome_api_config_port = {
            type = "integer",
            required = true,
            default = 80 } },
          { datadome_api_config_path = {
            type = "string",
            required = true,
            default = "/validate-request" } },
          { datadome_api_config_timeout = {
            type = "integer",
            required = true,
            default = 250 } },
          { datadome_api_config_uri_regex = {
            type = "string",
            required = true,
            default = " " } },
          { datadome_api_config_uri_regex_exclusion = {
            type = "string",
            required = true,
            default = "\\.avi|\\.flv|\\.mka|\\.mkv|\\.mov|\\.mp4|\\.mpeg|\\.mpg|\\.mp3|\\.flac|\\.ogg|\\.ogm|\\.opus|\\.wav|\\.webm|\\.webp|\\.bmp|\\.gif|\\.ico|\\.jpeg|\\.jpg|\\.png|\\.svg|\\.svgz|\\.swf|\\.eot|\\.otf|\\.ttf|\\.woff|\\.woff2|\\.css|\\.less|\\.js$" } },
        },
        entity_checks = {
          -- add some validation rules across fields
          -- the following is silly because it is always true, since they are both required
          --{ at_least_one_of = { "request_header", "response_header" }, },
          -- We specify that both header-names cannot be the same
          --{ distinct = { "request_header", "response_header"} },
        },
      },
    },
  },
}

return schema
