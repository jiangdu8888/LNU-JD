--
-- (C) 2014-18 - ntop.org
--

dirs = ntop.getDirs()

package.path = dirs.installdir .. "/scripts/lua/modules/i18n/?.lua;" .. package.path
package.path = dirs.installdir .. "/scripts/lua/modules/timeseries/?.lua;" .. package.path
package.path = dirs.installdir .. "/scripts/lua/modules/flow_dbms/?.lua;" .. package.path

require "lua_trace"
require "ntop_utils"
locales_utils = require "locales_utils"
local os_utils = require "os_utils"
local format_utils = require "format_utils"
local alert_consts = require "alert_consts"

-- ##############################################
-- TODO: replace those globals with locals everywhere

secondsToTime   = format_utils.secondsToTime
msToTime        = format_utils.msToTime
bytesToSize     = format_utils.bytesToSize
formatPackets   = format_utils.formatPackets
formatFlows     = format_utils.formatFlows
formatValue     = format_utils.formatValue
pktsToSize      = format_utils.pktsToSize
bitsToSize      = format_utils.bitsToSize
maxRateToString = format_utils.maxRateToString
round           = format_utils.round
bitsToSizeMultiplier = format_utils.bitsToSizeMultiplier

-- ##############################################

-- Note: Regexs are applied by default. Pass plain=true to disable them.
function string.contains(String,Start,plain)
   if type(String) ~= 'string' or type(Start) ~= 'string' then
      return false
   end

   local i,j = string.find(String, Start, 1, plain)

   return(i ~= nil)
end

-- ##############################################

function shortenString(name, max_len)
   if(name == nil) then return("") end

   if max_len == nil then
      max_len = ntop.getPref("ntopng.prefs.max_ui_strlen")
      max_len = tonumber(max_len)
      if(max_len == nil) then max_len = 24 end
   end

   if(string.len(name) < max_len) then
      return(name)
   else
      return(string.sub(name, 1, max_len).."...")
   end
end

-- ##############################################

function getInterfaceName(interface_id, windows_skip_description)
   local ifnames = interface.getIfNames()
   local iface = ifnames[tostring(interface_id)]

   if iface ~= nil then
      if(windows_skip_description ~= true and string.contains(iface, "{")) then -- Windows
         local old_iface = interface.getStats().id

         -- Use the interface description instead of the name
         interface.select(tostring(iface))
         iface = interface.getStats().description

         interface.select(tostring(old_iface))
      end

      return(iface)
   end

   return("")
end

-- ##############################################

function getInterfaceId(interface_name)
   local ifnames = interface.getIfNames()

   for if_id, if_name in pairs(ifnames) do
      if if_name == interface_name then
         return tonumber(if_id)
      end
   end

   return(-1)
end

-- ##############################################

function getFirstInterfaceId()
   local ifnames = interface.getIfNames()

   for if_id, if_name in pairs(ifnames) do
      return tonumber(if_id), if_name
   end

   return -1, "" -- NOTREACHED
end

-- ##############################################

-- Note that ifname can be set by Lua.cpp so don't touch it if already defined
if((ifname == nil) and (_GET ~= nil)) then
   ifname = _GET["ifid"]

   if(ifname ~= nil) then
      if(ifname.."" == tostring(tonumber(ifname)).."") then
	 -- ifname does not contain the interface name but rather the interface id
	 ifname = getInterfaceName(ifname, true)
	 if(ifname == "") then ifname = nil end
      end
   end

   if(debug_session) then traceError(TRACE_DEBUG,TRACE_CONSOLE, "Session => Session:".._SESSION["session"]) end

   if((ifname == nil) and (_SESSION ~= nil)) then
      if(debug_session) then traceError(TRACE_DEBUG,TRACE_CONSOLE, "Session => set ifname by _SESSION value") end
      ifname = _SESSION["ifname"]
      if(debug_session) then traceError(TRACE_DEBUG,TRACE_CONSOLE, "Session => ifname:"..ifname) end
   else
      if(debug_session) then traceError(TRACE_DEBUG,TRACE_CONSOLE, "Session => set ifname by _GET value") end
   end
end

--print("(((("..ifname.."))))")
l4_keys = {
  { "TCP", "tcp", 6 },
  { "UDP", "udp", 17 },
  { "ICMP", "icmp", 1 },
  { "Other IP", "other ip", -1 }
}

function __FILE__() return debug.getinfo(2,'S').source end
function __LINE__() return debug.getinfo(2, 'l').currentline end

-- ##############################################

function sendHTTPHeaderIfName(mime, ifname, maxage, content_disposition, extra_headers)
  info = ntop.getInfo(false)
  local cookie_attr = ntop.getCookieAttributes()

  print('HTTP/1.1 200 OK\r\n')
  print('Cache-Control: max-age=0, no-cache, no-store\r\n')
  print('Server: ntopng '..info["version"]..' ['.. info["platform"]..']\r\n')
  print('Pragma: no-cache\r\n')
  print('X-Frame-Options: DENY\r\n')
  print('X-Content-Type-Options: nosniff\r\n')
  if(_SESSION ~= nil) then print('Set-Cookie: session='.._SESSION["session"]..'; max-age=' .. maxage .. '; path=/; ' .. cookie_attr .. '\r\n') end
  if(ifname ~= nil) then print('Set-Cookie: ifname=' .. ifname .. '; path=/' .. cookie_attr .. '\r\n') end
  print('Content-Type: '.. mime ..'\r\n')
  if(content_disposition ~= nil) then print('Content-Disposition: '..content_disposition..'\r\n') end
  if type(extra_headers) == "table" then
     for hname, hval in pairs(extra_headers) do
	print(hname..': '..hval..'\r\n')
     end
  end
  print('Last-Modified: '..os.date("!%a, %m %B %Y %X %Z").."\r\n")
  print('\r\n')
end

-- ##############################################

function sendHTTPHeaderLogout(mime, content_disposition)
  sendHTTPHeaderIfName(mime, nil, 0, content_disposition)
end

-- ##############################################

function sendHTTPHeader(mime, content_disposition, extra_headers)
  sendHTTPHeaderIfName(mime, nil, 3600, content_disposition, extra_headers)
end

-- ##############################################

function sendHTTPContentTypeHeader(content_type, content_disposition, charset)
  local charset = charset or "utf-8"
  local mime = content_type.."; charset="..charset
  sendHTTPHeader(mime, content_disposition)
end

-- ##############################################

function printGETParameters(get)
  for key, value in pairs(get) do
    io.write(key.."="..value.."\n")
  end
end

-- ##############################################

-- Simplified checker
function isIPv6Address(ip)
  if(string.find(ip, ":") ~= nil) then
     return true
  end

    return false
end

-- ##############################################

function findString(str, tofind)
  if(str == nil) then return(nil) end
  if(tofind == nil) then return(nil) end

  str1    = string.lower(string.gsub(str, "-", "_"))
  tofind1 = string.lower(string.gsub(tofind, "-", "_"))

  return(string.find(str1, tofind1, 1))
end

-- ##############################################

function findStringArray(str, tofind)
  if(str == nil) then return(nil) end
  if(tofind == nil) then return(nil) end
  local rsp = false

  for k,v in pairs(tofind) do
    str1    = string.gsub(str, "-", "_")
    tofind1 = string.gsub(v, "-", "_")
    if(str1 == tofind1) then
      rsp = true
    end

  end

  return(rsp)
end

-- ##############################################

function printASN(asn, asname)
  asname = asname:gsub('"','')
  if(asn > 0) then
    return("<A HREF='http://as.robtex.com/as"..asn..".html' title='"..asname.."'>"..asname.."</A> <i class='fa fa-external-link fa-lg'></i>")
  else
    return(asname)
  end
end

-- ##############################################

function urlencode(str)
   str = string.gsub (str, "\r?\n", "\r\n")
   str = string.gsub (str, "([^%w%-%.%_%~ ])",
		      function (c) return string.format ("%%%02X", string.byte(c)) end)
   str = string.gsub (str, " ", "+")
   return str
end

-- ##############################################

function getPageUrl(base_url, params)
   if table.empty(params) then
      return base_url
   end

   local encoded = {}

   for k, v in pairs(params) do
      encoded[k] = urlencode(v)
   end

   local delim = "&"
   if not string.find(base_url, "?") then
     delim = "?"
   end

   return base_url .. delim .. table.tconcat(encoded, "=", "&")
end

-- ##############################################

function printIpVersionDropdown(base_url, page_params)
   local ipversion = _GET["version"]
   local ipversion_filter
   if not isEmptyString(ipversion) then
      ipversion_filter = '<span class="glyphicon glyphicon-filter"></span>'
   else
      ipversion_filter = ''
   end
   local ipversion_params = table.clone(page_params)
   ipversion_params["version"] = nil

   print[[\
      <button class="btn btn-link dropdown-toggle" data-toggle="dropdown">]] print(i18n("flows_page.ip_version")) print[[]] print(ipversion_filter) print[[<span class="caret"></span></button>\
      <ul class="dropdown-menu" role="menu" id="flow_dropdown">\
         <li><a href="]] print(getPageUrl(base_url, ipversion_params)) print[[">]] print(i18n("flows_page.all_ip_versions")) print[[</a></li>\
         <li]] if ipversion == "4" then print(' class="active"') end print[[><a href="]] ipversion_params["version"] = "4"; print(getPageUrl(base_url, ipversion_params)); print[[">]] print(i18n("flows_page.ipv4_only")) print[[</a></li>\
         <li]] if ipversion == "6" then print(' class="active"') end print[[><a href="]] ipversion_params["version"] = "6"; print(getPageUrl(base_url, ipversion_params)); print[[">]] print(i18n("flows_page.ipv6_only")) print[[</a></li>\
      </ul>]]
end

-- ##############################################

function printVLANFilterDropdown(base_url, page_params)
   local vlans = interface.getVLANsList()

   if vlans == nil then vlans = {VLANs={}} end
   vlans = vlans["VLANs"]

   local ids = {}
   for _, vlan in ipairs(vlans) do
      ids[#ids + 1] = vlan["vlan_id"]
   end

   local vlan_id = _GET["vlan"]
   local vlan_id_filter = ''
   if not isEmptyString(vlan_id) then
      vlan_id_filter = '<span class="glyphicon glyphicon-filter"></span>'
   end

   local vlan_id_params = table.clone(page_params)
   vlan_id_params["vlan"] = nil

   print[[\
      <button class="btn btn-link dropdown-toggle" data-toggle="dropdown">]] print(i18n("flows_page.vlan")) print[[]] print(vlan_id_filter) print[[<span class="caret"></span></button>\
      <ul class="dropdown-menu" role="menu" id="flow_dropdown">\
         <li><a href="]] print(getPageUrl(base_url, vlan_id_params)) print[[">]] print(i18n("flows_page.all_vlan_ids")) print[[</a></li>\]]
   for _, vid in ipairs(ids) do
      vlan_id_params["vlan"] = vid
      print[[
         <li>\
           <a href="]] print(getPageUrl(base_url, vlan_id_params)) print[[">VLAN ]] print(tostring(vid)) print[[</a></li>\]]
   end
   print[[

      </ul>]]
end


-- ##############################################

function printFlowDevicesFilterDropdown(base_url, page_params)
   if (ntop.isPro()) then
      package.path = dirs.installdir .. "/pro/scripts/lua/modules/?.lua;" .. package.path
      require "snmp_utils"
   end

   local flowdevs = interface.getFlowDevices()
   local vlans = interface.getVLANsList()

   if flowdevs == nil then flowdevs = {} end

   local devips = {}
   for dip, _ in pairsByValues(flowdevs, asc) do
      devips[#devips + 1] = dip
   end

   local cur_dev = _GET["deviceIP"]
   local cur_dev_filter = ''
   local snmp_community = ''
   if not isEmptyString(cur_dev) then
      cur_dev_filter = '<span class="glyphicon glyphicon-filter"></span>'
   end

   local dev_params = table.clone(page_params)
   for _, p in pairs({"deviceIP", "outIfIdx", "inIfIdx"}) do
      dev_params[p] = nil
   end

   print[[, '<div class="btn-group pull-right">\
      <button class="btn btn-link dropdown-toggle" data-toggle="dropdown">]] print(i18n("flows_page.device_ip")) print[[]] print(cur_dev_filter) print[[<span class="caret"></span></button>\
      <ul class="dropdown-menu" role="menu" id="flow_dropdown">\
         <li><a href="]] print(getPageUrl(base_url, dev_params)) print[[">]] print(i18n("flows_page.all_devices")) print[[</a></li>\]]
   for _, dip in ipairs(devips) do
      dev_params["deviceIP"] = dip
      local snmp_community = get_snmp_community(dip, true --[[ no default --]])
      if not isEmptyString(snmp_community) then
	 local snmp_name = get_snmp_device_name(dip, snmp_community)
	 if not isEmptyString(snmp_name) and snmp_name ~= dip then
	    dip = dip .. "["..shortenString(snmp_name).."]"
	 end
      else
	 local resname = getResolvedAddress(hostkey2hostinfo(dip))
	 if not isEmptyString(resname) and resname ~= dip then
	    dip = dip .. "["..shortenString(resname).."]"
	 end
      end

      print[[
         <li>\
           <a href="]] print(getPageUrl(base_url, dev_params)) print[[">]] print(i18n("flows_page.device_ip").." "..dip) print[[</a></li>\]]
   end
   print[[
      </ul>\
</div>']]

   if cur_dev ~= nil then -- also print dropddowns for input and output interface index
      local ports = interface.getFlowDeviceInfo(cur_dev)

      for _, direction in pairs({"outIfIdx", "inIfIdx"}) do
	 local cur_if = _GET[direction]
	 local cur_if_filter = ''
	 if not isEmptyString(cur_if) then
	    cur_if_filter = '<span class="glyphicon glyphicon-filter"></span>'
	 end

	 local if_params = table.clone(page_params)

	 if_params[direction] = nil
	    print[[, '<div class="btn-group pull-right">\
      <button class="btn btn-link dropdown-toggle" data-toggle="dropdown">]] print(i18n("flows_page."..direction)) print[[]] print(cur_if_filter) print[[<span class="caret"></span></button>\
      <ul class="dropdown-menu" role="menu" id="flow_dropdown">\
         <li><a href="]] print(getPageUrl(base_url, if_params)) print[[">]] print(i18n("flows_page.all_"..direction)) print[[</a></li>\]]

	    for portidx, _ in pairsByKeys(ports, asc) do
	       if_params[direction] = portidx
	       print[[
         <li>\
           <a href="]] print(getPageUrl(base_url, if_params)) print[[">]] print(i18n("flows_page."..direction).." "..tostring(portidx)) print[[</a></li>\]]
	    end
	    print[[
      </ul>\
</div>']]
      end

   end
end

-- ##############################################

--
-- Returns indexes to be used for string shortening. The portion of to_shorten between
-- middle_start and middle_end will be inside the bounds.
--
--    to_shorten: string to be shorten
--    middle_start: middle part begin index
--    middle_end: middle part begin index
--    maxlen: maximum length
--
function shortenInTheMiddle(to_shorten, middle_start, middle_end, maxlen)
  local maxlen = maxlen - (middle_end - middle_start)

  if maxlen <= 0 then
    return 0, string.len(to_shorten)
  end

  local left_slice = math.max(middle_start - math.floor(maxlen / 2), 1)
  maxlen = maxlen - (middle_start - left_slice - 1)
  local right_slice = math.min(middle_end + maxlen, string.len(to_shorten))

  return left_slice, right_slice
end

-- ##############################################

function shortHostName(name)
  local chunks = {name:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")}
  if(#chunks == 4) then
    return(name)
  else
    local max_len = ntop.getPref("ntopng.prefs.max_ui_strlen")
    max_len = tonumber(max_len)
    if(max_len == nil) then max_len = 24 end

    chunks = {name:match("%w+:%w+:%w+:%w+:%w+:%w+")}
    --io.write(#chunks.."\n")
    if(#chunks == 1) then
      return(name)
    end

    if(string.len(name) < max_len) then
      return(name)
    else
      tot = 0
      n = 0
      ret = ""

      for token in string.gmatch(name, "([%w-]+).") do
	if(tot < max_len) then
	  if(n > 0) then ret = ret .. "." end
	  ret = ret .. token
	  tot = tot+string.len(token)
	  n = n + 1
	end
      end

      return(ret .. "...")
    end
  end

  return(name)
end

-- ##############################################

function _handleArray(name, sev)
  local id

  for id, _ in ipairs(name) do
    local l = name[id][1]
    local key = name[id][2]

    if(string.upper(key) == string.upper(sev)) then
      return(l)
    end
  end

  return(firstToUpper(sev))
end

-- ##############################################

function l4Label(proto)
  return(_handleArray(l4_keys, proto))
end

function l4_proto_to_string(proto_id)
   proto_id = tonumber(proto_id)

   for _, proto in pairs(l4_keys) do
      if proto[3] == proto_id then
         return proto[1], proto[2]
      end
   end

   return nil
end

-- ##############################################

-- Note: make sure the maximum id for checkpoint_keys honours CONST_MAX_NUM_CHECKPOINTS
local checkpoint_keys = {
   -- following checkpoints are used for alerts
   {0, "min"},
   {1, "5mins"},
   {2, "hour"},
   {3, "day"},
}

function checkpointId(v)
   local checkpointtable = {}
   for i, t in ipairs(checkpoint_keys) do
      checkpointtable[#checkpointtable + 1] = {t[1], t[2]}
   end
   return(_handleArray(checkpointtable, v))
end

function noHtml(s)
   if s == nil then return nil end
   local cleaned = s:gsub("<[aA].->(.-)</[aA]>","%1")
      :gsub("%s*<[iI].->(.-)</[iI]>","%1")
      :gsub("<.->(.-)</.->","%1") -- note: this does not handle nested tags
      :gsub("^%s*(.-)%s*$", "%1")
   return cleaned
end

function alertSeverityLabel(v, nohtml)
   local res = _handleArray(alert_consts.alert_severity_keys, tonumber(v))
   if res ~= nil and nohtml == true then res = noHtml(res) end
   return res
end

function alertSeverity(v)
   local severity_table = {}
   for i, t in ipairs(alert_consts.alert_severity_keys) do
      severity_table[#severity_table + 1] = {t[2], t[3]}
   end
   return(_handleArray(severity_table, v))
end

function alertSeverityRaw(sev_idx)
   sev_idx = sev_idx + 2 -- -1 and 0
   if sev_idx <= #alert_consts.alert_severity_keys then
      return alert_consts.alert_severity_keys[sev_idx][3]
   end
   return nil
end

function alertTypeLabel(v, nohtml)
   local res = _handleArray(alert_consts.alert_type_keys, tonumber(v))
   if res ~= nil and nohtml == true then res = noHtml(res) end
   return res
end

function alertType(v)
   local typetable = {}
   for i, t in ipairs(alert_consts.alert_type_keys) do
      typetable[#typetable + 1] = {t[2], t[3]}
   end
   return(_handleArray(typetable, v))
end

function alertEngine(v)
   local enginetable = {}
   for i, t in ipairs(alert_consts.alert_functions_description) do
      enginetable[#enginetable + 1] = {t[2], t[3]}
   end
   return(_handleArray(enginetable, v))
end

function alertEngineLabel(v)
   return _handleArray(alert_consts.alert_functions_description, tonumber(v))
end

function alertEngineRaw(idx)
   idx = idx + 1
   if idx <= #alert_consts.alert_functions_description then
      return alert_consts.alert_functions_description[idx][3]
   end
   return nil
end

function alertLevel(v)
   local leveltable = {}

   for i, t in ipairs(alert_consts.alert_severity_keys) do
      leveltable[#leveltable + 1] = {t[2], t[3]}
   end
   return(_handleArray(leveltable, v))
end

function alertTypeRaw(alert_idx)
   if(alert_idx == nil) then return nil end

   alert_idx = alert_idx + 2 -- -1 and 0
   if alert_idx <= #alert_consts.alert_type_keys then
      return alert_consts.alert_type_keys[alert_idx][3]
   end
   return nil
end

function alertEntityLabel(v, nothml)
   local res = _handleArray(alert_consts.alert_entity_keys, tonumber(v))
   if res ~= nil and nohtml == true then res = noHtml(res) end
   return res
end

function alertEntity(v)
   local typetable = {}
   for i, t in ipairs(alert_consts.alert_entity_keys) do
      typetable[#typetable + 1] = {t[2], t[3]}
   end
   return(_handleArray(typetable, v))
end

function alertEntityRaw(entity_idx)
   entity_idx = entity_idx + 1
   if entity_idx <= #alert_consts.alert_entity_keys then
      return alert_consts.alert_entity_keys[entity_idx][3]
   end
   return nil
end

function areAlertsEnabled()
  return (ntop.getPref("ntopng.prefs.disable_alerts_generation") ~= "1")
end

function mustScanAlerts(ifstats)
   -- can't alert on view interfaces as checkpoints will collide for their underlying real interfaces
   return areAlertsEnabled() and not ifstats["isView"]
end

function hasAlertsDisabled()
  _POST = _POST or {}
  return ((_POST["disable_alerts_generation"] ~= nil) and (_POST["disable_alerts_generation"] == "1")) or
      ((_POST["disable_alerts_generation"] == nil) and (ntop.getPref("ntopng.prefs.disable_alerts_generation") == "1"))
end

function hasNagiosSupport()
  if prefs == nil then
    prefs = ntop.getPrefs()
  end
  return prefs.nagios_nsca_host ~= nil
end

--for _key, _value in pairsByKeys(vals, rev) do
--   print(_key .. "=" .. _value .. "\n")
--end

function round(num, idp)
   if(num == nil) then return(0) end
   return tonumber(string.format("%." .. (idp or 0) .. "f", num))
end
--function round(num) return math.floor(num+.5) end

function truncate(x)
   return x<0 and math.ceil(x) or math.floor(x)
end

-- Note that the function below returns a string as returning a number
-- would not help as a new float would be returned
function toint(num)
   return string.format("%u", truncate(num))
end

function capitalize(str)
  return (str:gsub("^%l", string.upper))
end

function isnumber(str)
   if((str ~= nil) and (string.len(str) > 0) and (tonumber(str) ~= nil)) then
      return(true)
   else
      return(false)
   end
end

function split(pString, pPattern)
  local Table = {}  -- NOTE: use {n = 0} in Lua-5.0
  local fpat = "(.-)" .. pPattern
  local last_end = 1
  local s, e, cap = pString:find(fpat, 1)
  while s do
    if s ~= 1 or cap ~= "" then
      table.insert(Table,cap)
    end
    last_end = e+1
    s, e, cap = pString:find(fpat, last_end)
  end
  if last_end <= #pString then
    cap = pString:sub(last_end)
    table.insert(Table, cap)
  end
  return Table
end

-- returns the MAXIMUM value found in a table t, together with the corresponding
-- index argmax. a pair argmax, max is returned.
function tmax(t)
    local argmx, mx = nil, nil
    if (type(t) ~= "table") then return nil, nil end
    for k, v in pairs(t) do
	-- first iteration
	if mx == nil and argmx == nil then
	    mx = v
	    argmx = k
	elseif (v == mx and k > argmx) or v > mx then
	-- if there is a tie, prefer the greatest argument
	-- otherwise grab the maximum
	    argmx = k
	    mx = v
	end
    end
    return argmx, mx
end

-- returns the MINIMUM value found in a table t, together with the corresponding
-- index argmin. a pair argmin, min is returned.
function tmin(t)
    local argmn, mn = nil, nil
    if (type(t) ~= "table") then return nil, nil end
    for k, v in pairs(t) do
	-- first iteration
	if mn == nil and argmn == nil then
	    mn = v
	    argmn = k
	elseif (v == mn and k > argmn) or v < mn then
	-- if there is a tie, prefer the greatest argument
	-- otherwise grab the minimum
	    argmn = k
	    mn = v
	end
    end
    return argmn, mn
end

function formatEpoch(epoch)
   return(format_utils.formatEpoch(epoch))
end

function starts(String,Start)
  return string.sub(String,1,string.len(Start))==Start
end

function ends(String,End)
  return End=='' or string.sub(String,-string.len(End))==End
end

-- #################################################################

function bit(p)
  return 2 ^ (p - 1)  -- 1-based indexing
end

-- Typical call:  if hasbit(x, bit(3)) then ...
function hasbit(x, p)
  return x % (p + p) >= p
end

function setbit(x, p)
  return hasbit(x, p) and x or x + p
end

function clearbit(x, p)
  return hasbit(x, p) and x - p or x
end

function isBroadMulticast(ip)
   if(ip == "0.0.0.0") then
      return true
   end
   -- print(ip)
   t = string.split(ip, "%.")
   -- print(table.concat(t, "\n"))
   if(t == nil) then
      return false  -- Might be an IPv6 address
   else
      if(tonumber(t[1]) >= 224)  then
	 return true
      end
   end

   return false
end

function isBroadcastMulticast(ip)
   -- check NoIP
   if(ip == "0.0.0.0") then
      return true
   end

   -- check IPv6
   t = string.split(ip, "%.")

   if(t ~= nil) then
      -- check Multicast / Broadcast
      if(tonumber(t[1]) >= 224) then
	 return true
      end
   end

   return false
end

function isIPv4(address)
  local chunks = {address:match("(%d+)%.(%d+)%.(%d+)%.(%d+)$")}

  if #chunks == 4 then
    for _, v in pairs(chunks) do
      if (tonumber(v) < 0) or (tonumber(v) > 255) then
        return false
      end
    end

    return true
  end

  return false
end

function isIPv4Network(address)
   local parts = split(address, "/")

   if #parts == 2 then
      local prefix = tonumber(parts[2])

      if (prefix == nil) or (math.floor(prefix) ~= prefix) or (prefix < 0) or (prefix > 32) then
         return false
      end
   elseif #parts ~= 1 then
      return false
   end

   return isIPv4(parts[1])
end

function addGoogleMapsScript()
   local g_maps_key = ntop.getCache('ntopng.prefs.google_apis_browser_key')
   if g_maps_key ~= nil and g_maps_key~= "" then
      g_maps_key = "&key="..g_maps_key
   else
   g_maps_key = ""
   end
   print("<script src=\"https://maps.googleapis.com/maps/api/js?v=3.exp"..g_maps_key.."\"></script>\n")
end

function addLogoSvg()
   print [[
﻿<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px" width="141px" height="139px" viewBox="0 0 141 139" enable-background="new 0 0 141 139" xml:space="preserve">  <image id="image0" width="141" height="139" x="0" y="0"
    xlink:href="data:image/png;base64,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
RU5ErkJggg==" />
</svg>
]]
end

function addGauge(name, url, maxValue, width, height)
  if(url ~= nil) then print('<A HREF="'..url..'">') end
  print [[
  <div class="progress">
       <div id="]] print(name) print [[" class="progress-bar progress-bar-warning"></div>
  </div>
  ]]
  if(url ~= nil) then print('</A>\n') end

end

-- Compute the difference in seconds between local time and UTC.
function get_timezone()
  local now = os.time()
  return os.difftime(now, os.time(os.date("!*t", now)))
end

function getCategoriesWithProtocols()
   local protocol_categories = interface.getnDPICategories()

   for k,v in pairsByKeys(protocol_categories) do
      protocol_categories[k] = {id=v, protos=interface.getnDPIProtocols(tonumber(v)), count=0}

      for proto,_ in pairs(protocol_categories[k].protos) do
         protocol_categories[k].count = protocol_categories[k].count + 1
      end
   end

   return protocol_categories
end

function isValidPoolMember(member)
  if isEmptyString(member) then
    return false
  end

  if isMacAddress(member) then
    return true
  end

  -- vlan is mandatory here
  local vlan_idx = string.find(member, "@")
  if ((vlan_idx == nil) or (vlan_idx == 1)) then
    return false
  end
  local other = string.sub(member, 1, vlan_idx-1)
  local vlan = tonumber(string.sub(member, vlan_idx+1))
  if (vlan == nil) or (vlan < 0) then
    return false
  end

  -- prefix is mandatory here
  local address, prefix = splitNetworkPrefix(other)
  if prefix == nil then
    return false
  end
  if isIPv4(address) and (tonumber(prefix) >= 0) and (tonumber(prefix) <= 32) then
    return true
  elseif isIPv6(address) and (tonumber(prefix) >= 0) and (tonumber(prefix) <= 128) then
    return true
  end

  return false
end

function host2member(ip, vlan, prefix)
  if prefix == nil then
    if isIPv4(ip) then
      prefix = 32
    else
      prefix = 128
    end
  end

  return ip .. "/" .. tostring(prefix) .. "@" .. tostring(vlan)
end

function isLocal(host_ip)
  host = interface.getHostInfo(host_ip)

  if((host == nil) or (host['localhost'] ~= true)) then
    return(false)
  else
    return(true)
  end
end

-- Return the first 'howmany' hosts
function getTopInterfaceHosts(howmany, localHostsOnly)
  hosts_stats = interface.getHostsInfo()
  hosts_stats = hosts_stats["hosts"]
  ret = {}
  sortTable = {}
  n = 0
  for k,v in pairs(hosts_stats) do
    if((not localHostsOnly) or ((v["localhost"] == true) and (v["ip"] ~= nil))) then
      sortTable[v["bytes.sent"]+v["bytes.rcvd"]+n] = k
      n = n +0.01
    end
  end

  n = 0
  for _v,k in pairsByKeys(sortTable, rev) do
    if(n < howmany) then
      ret[k] = hosts_stats[k]
      n = n+1
    else
      break
    end
  end

  return(ret)
end

function http_escape(s)
  s = string.gsub(s, "([&=+%c])", function (c)
    return string.format("%%%02X", string.byte(c))
  end)
  s = string.gsub(s, " ", "+")
  return s
end

-- Windows fixes for interfaces with "uncommon chars"
function purifyInterfaceName(interface_name)
  -- io.write(debug.traceback().."\n")
  interface_name = string.gsub(interface_name, "@", "_")
  interface_name = string.gsub(interface_name, ":", "_")
  interface_name = string.gsub(interface_name, "/", "_")
  return(interface_name)
end

-- See datatype AggregationType in ntop_typedefs.h
function aggregation2String(value)
  if(value == 0) then return("Client Name")
  elseif(value == 1) then return("Server Name")
  elseif(value == 2) then return("Domain Name")
  elseif(value == 3) then return("Operating System")
  elseif(value == 4) then return("Registrar Name")
  else return(value)
  end
end

-- #################################

-- Aggregates items below some edge
-- edge: minimum percentage value to create collision
-- min_col: minimum collision groups to aggregate
function aggregatePie(values, values_sum, edge, min_col)
   local edge = edge or 0.09
   min_col = min_col or 2
   local aggr = {}
   local other = i18n("other")
   local below_edge = {}

   -- Initial lookup
   for k,v in pairs(values) do
      if v / values_sum <= edge then
         -- too small
         below_edge[#below_edge + 1] = k
      else
         aggr[k] = v
      end
   end

   -- Decide if to aggregate
   for _,k in pairs(below_edge) do
      if #below_edge >= min_col then
         -- aggregate
         aggr[other] = aggr[other] or 0
         aggr[other] = aggr[other] + values[k]
      else
         -- do not aggregate
         aggr[k] = values[k]
      end
   end

   return aggr
end

-- #################################

function hostVisualization(ip, name)
   if (ip ~= name) and isIPv6(ip) then
      return name.." [IPv6]"
   end
   return name
end

-- #################################

-- NOTE: prefer the getResolvedAddress on this function
function resolveAddress(hostinfo, allow_empty)
   local hostname = ntop.resolveName(hostinfo["host"])
   if isEmptyString(hostname) then
      -- Not resolved
      if allow_empty == true then
         return hostname
      else
         -- this function will take care of formatting the IP
         return getResolvedAddress(hostinfo)
      end
   end
   return hostVisualization(hostinfo["host"], hostname)
end

-- #################################

function getResolvedAddress(hostinfo)
   local hostname = ntop.getResolvedName(hostinfo["host"])
   return hostVisualization(hostinfo["host"], hostname)
end

-- #################################

function getIpUrl(ip)
   if isIPv6(ip) then
      -- https://www.ietf.org/rfc/rfc2732.txt
      return "["..ip.."]"
   end
   return ip
end

-- #################################

function getOSIcon(name)
  icon = ""

  if(findString(name, "Linux") or findString(name, "Ubuntu")) then icon = '<i class=\'fa fa-linux fa-lg\'></i> '
  elseif(findString(name, "Android")) then icon = '<i class=\'fa fa-android fa-lg\'></i> '
  elseif(findString(name, "Windows") or findString(name, "Win32") or findString(name, "MSIE")) then icon = '<i class=\'fa fa-windows fa-lg\'></i> '
  elseif(findString(name, "iPhone") or findString(name, "iPad") or findString(name, "OS X") ) then icon = '<i class=\'fa fa-apple fa-lg\'></i> '
  end

  return(icon)
end

-- #################################

function getOperatingSystemName(id)
   if(id == 1) then return("Linux")
   elseif(id == 2) then return("Windows")
   elseif(id == 3) then return("MacOS")
   elseif(id == 4) then return("iOS")
   elseif(id == 5) then return("Android")
   elseif(id == 6) then return("LaserJET")
   elseif(id == 7) then return("AppleAirport")
   else
      return("") -- Unknown
   end
end

-- #################################

function getOperatingSystemIcon(id)
   if(id == 1) then return(' <i class=\'fa fa-linux fa-lg\'></i>')
   elseif(id == 2) then return(' <i class=\'fa fa-windows fa-lg\'></i>')
   elseif(id == 3) then return(' <i class=\'fa fa-apple fa-lg\'></i>')
   elseif(id == 4) then return(' <i class=\'fa fa-apple fa-lg\'></i>')
   elseif(id == 5) then return(' <i class=\'fa fa-android fa-lg\'></i>')
   elseif(id == 6) then return(' LasetJET')
   elseif(id == 7) then return(' Apple Airport')

   else return("")
   end
end

-- #################################

function getApplicationIcon(name)
  local icon = ""
  if(name == nil) then name = "" end

  if(findString(name, "Skype")) then icon = '<i class=\'fa fa-skype fa-lg\'></i>'
  elseif(findString(name, "Unknown")) then icon = '<i class=\'fa fa-question fa-lg\'></i>'
  elseif(findString(name, "Twitter")) then icon = '<i class=\'fa fa-twitter fa-lg\'></i>'
  elseif(findString(name, "DropBox")) then icon = '<i class=\'fa fa-dropbox fa-lg\'></i>'
  elseif(findString(name, "Spotify")) then icon = '<i class=\'fa fa-spotify fa-lg\'></i>'
  elseif(findString(name, "Apple")) then icon = '<i class=\'fa fa-apple fa-lg\'></i>'
  elseif(findString(name, "Google") or
    findString(name, "Chrome")) then icon = '<i class=\'fa fa-google-plus fa-lg\'></i>'
  elseif(findString(name, "FaceBook")) then icon = '<i class=\'fa fa-facebook-square fa-lg\'></i>'
  elseif(findString(name, "Youtube")) then icon = '<i class=\'fa fa-youtube-square fa-lg\'></i>'
  elseif(findString(name, "thunderbird")) then icon = '<i class=\'fa fa-paper-plane fa-lg\'></i>'
  end

  return(icon)
end

-- #################################

function getApplicationLabel(name)
  local icon = getApplicationIcon(name)

  name = name:gsub("^%l", string.upper)
  return(icon.." "..name)
end

function mapOS2Icon(name)
  if(name == nil) then
    return("")
  else
    return(getOSIcon(name) .. name)
  end
end

function getItemsNumber(n)
  tot = 0
  for k,v in pairs(n) do
    --io.write(k.."\n")
    tot = tot + 1
  end

  --io.write(tot.."\n")
  return(tot)
end

function getHostCommaSeparatedList(p_hosts)
  hosts = {}
  hosts_size = 0
  for i,host in pairs(split(p_hosts, ",")) do
    hosts[i] = host
    hosts_size = hosts_size + 1
  end
  return hosts,hosts_size
end

-- ##############################################

function splitNetworkPrefix(net)
   local prefix = tonumber(net:match("/(.+)"))
   local address = net:gsub("/.+","")
   return address, prefix
end

-- ##############################################

function splitProtocol(proto_string)
  local parts = string.split(proto_string, "%.")
  local app_proto
  local master_proto

  if parts == nil then
    master_proto = proto_string
    app_proto = nil
  else
    master_proto = parts[1]
    app_proto = parts[2]
  end

  return master_proto, app_proto
end

-- ##############################################

function getHostAltNamesKey()
   return "ntopng.host_labels"
end

-- ##############################################

function getDhcpNamesKey(ifid)
   return "ntopng.dhcp."..ifid..".cache"
end

-- ##############################################

-- Used to avoid resolving host names too many times
resolved_host_labels_cache = {}

-- host_ip can be a mac. host_mac can be null.
function getHostAltName(host_ip, host_mac)
   local alt_name = nil

   if not isEmptyString(host_ip) then
      alt_name = resolved_host_labels_cache[host_ip]
   end

   -- cache hit
   if(alt_name ~= nil) then
      return(alt_name)
   end

   alt_name = ntop.getHashCache(getHostAltNamesKey(), host_ip)
   if (isEmptyString(alt_name) and (host_mac ~= nil)) then
      alt_name = ntop.getHashCache(getHostAltNamesKey(), host_mac)
   end

   if isEmptyString(alt_name) and ifname ~= nil then
      local key = getDhcpNamesKey(getInterfaceId(ifname))

      if host_mac ~= nil then
         alt_name = ntop.getHashCache(key, host_mac)
      elseif isMacAddress(host_ip) then
         alt_name = ntop.getHashCache(key, host_ip)
      end
   end

   if isEmptyString(alt_name) then
     alt_name = host_ip
   end

   if not isEmptyString(alt_name) then
      resolved_host_labels_cache[host_ip] = alt_name
   end

   return(alt_name)
end

function setHostAltName(host_ip, alt_name)
   ntop.setHashCache(getHostAltNamesKey(), host_ip, alt_name)
end

-- Mac Addresses --

-- A function to give a useful device name
function getDeviceName(device_mac, skip_manufacturer)
   local name = getHostAltName(device_mac)

   if name == device_mac then
      -- Not found, try with first host
      local info = interface.getHostsInfo(false, nil, 1, 0, nil, nil, nil, tonumber(vlan), nil,
               nil, device_mac)

      if (info ~= nil) then
         for x, host in pairs(info.hosts) do
            if not isEmptyString(host.name) and host.name ~= host.ip and host.name ~= "NoIP" then
               name = host.name
            elseif host.ip ~= "0.0.0.0" then
               name = getHostAltName(host.ip)

               if name == host.ip then
                  name = nil
               end
            end
            break
         end
      else
         name = nil
      end
   end

   if isEmptyString(name) then
      if (not skip_manufacturer) then
         name = get_symbolic_mac(device_mac, true)
      else
         -- last resort
         name = device_mac
      end
   end

   return name
end

local specialMACs = {
  "01:00:0C",
  "01:80:C2",
  "01:00:5E",
  "01:0C:CD",
  "01:1B:19",
  "FF:FF",
  "33:33"
}
function isSpecialMac(mac)
  for _,key in pairs(specialMACs) do
     if(string.contains(mac, key)) then
        return true
     end
  end

  return false
end

-- Flow Utils --

function host2name(name, vlan)
   local orig_name = name

   vlan = tonumber(vlan or "0")

   name = getHostAltName(name)

   if(name == orig_name) then
      rname = getResolvedAddress({host=name, vlan=vlan})

      if((rname ~= nil) and (rname ~= "")) then
	 name = rname
      end
   end

   if(vlan > 0) then
      name = name .. '@' .. vlan
   end

   return name
end

function flowinfo2hostname(flow_info, host_type)
   local name
   local orig_name

   if(host_type == "srv") then
      if(flow_info["host_server_name"] ~= nil and flow_info["host_server_name"] ~= "") then
	 return(flow_info["host_server_name"])
      end
      if(flow_info["protos.ssl.certificate"] ~= nil and flow_info["protos.ssl.certificate"] ~= "") then
	 return(flow_info["protos.ssl.certificate"])
      end
   end

   name = flow_info[host_type..".host"]

   if((name == "") or (name == nil)) then
      name = flow_info[host_type..".ip"]
   end

   return(host2name(name, flow_info["vlan"]))
end


-- URL Util --

--
-- Split the host key (ip@vlan) creating a new lua table.
-- Example:
--    info = hostkey2hostinfo(key)
--    ip = info["host"]
--    vlan = info["vlan"]
--
function hostkey2hostinfo(key)
  local host = {}
  local info = split(key,"@")
  if(info[1] ~= nil) then host["host"] = info[1]           end
  if(info[2] ~= nil) then
    host["vlan"] = tonumber(info[2])
  else
    host["vlan"] = 0
  end
  return host
end

--
-- Analyze the host_info table and return the host key.
-- Example:
--    host_info = interface.getHostInfo("127.0.0.1",0)
--    key = hostinfo2hostkey(host_info)
--
function hostinfo2hostkey(host_info,host_type,show_vlan)
  local rsp = ""

  if(host_type == "cli") then

    if(host_info["cli.ip"] ~= nil) then
      rsp = rsp..host_info["cli.ip"]
    end

  elseif(host_type == "srv") then

    if(host_info["srv.ip"] ~= nil) then
      rsp = rsp..host_info["srv.ip"]
    end
  else

    if(host_info["host"] ~= nil) then
      rsp = rsp..host_info["host"]
    elseif(host_info["name"] ~= nil) then
      rsp = rsp..host_info["name"]
    elseif(host_info["ip"] ~= nil) then
      rsp = rsp..host_info["ip"]
    elseif(host_info["mac"] ~= nil) then
      rsp = rsp..host_info["mac"]
    end
  end

  if(((host_info["vlan"] ~= nil) and (host_info["vlan"] ~= 0))
     or ((show_vlan ~= nil) and show_vlan))  then
    rsp = rsp..'@'..tostring(host_info["vlan"])
  end

  if(debug_host) then traceError(TRACE_DEBUG,TRACE_CONSOLE,"HOST2URL => ".. rsp .. "\n") end
  return rsp
end

function member2visual(member)
   local info = hostkey2hostinfo(member)
   local host = info.host
   local hlen = string.len(host)

   if string.ends(host, "/32") and isIPv4(string.sub(host, 1, hlen-3)) then
    host = string.sub(host, 1, hlen-3)
  elseif string.ends(host, "/128") and isIPv6(string.sub(host, 1, hlen-4)) then
    host = string.sub(host, 1, hlen-4)
  end

  return hostinfo2hostkey({host=host, vlan=info.vlan})
end

--
-- Analyze the get_info and return a new table containing the url information about an host.
-- Example: url2host(_GET)
--
function url2hostinfo(get_info)
  local host = {}

  -- Catch when the host key is using as host url parameter
  if((get_info["host"] ~= nil) and (string.find(get_info["host"],"@"))) then
    get_info = hostkey2hostinfo(get_info["host"])
  end

  if(get_info["host"] ~= nil) then
    host["host"] = get_info["host"]
    if(debug_host) then traceError(TRACE_DEBUG,TRACE_CONSOLE,"URL2HOST => Host:"..get_info["host"].."\n") end
  end

  if(get_info["vlan"] ~= nil) then
    host["vlan"] = tonumber(get_info["vlan"])
    if(debug_host) then traceError(TRACE_DEBUG,TRACE_CONSOLE,"URL2HOST => Vlan:"..get_info["vlan"].."\n") end
  else
    host["vlan"] = 0
  end

  return host
end

--
-- Catch the main information about an host from the host_info table and return the corresponding url.
-- Example:
--          hostinfo2url(host_key), return an url based on the host_key
--          hostinfo2url(host[key]), return an url based on the host value
--          hostinfo2url(flow[key],"cli"), return an url based on the client host information in the flow table
--          hostinfo2url(flow[key],"srv"), return an url based on the server host information in the flow table
--

function hostinfo2url(host_info, host_type, novlan)
  local rsp = ''
  -- local version = 0
  local version = 1

  if(host_type == "cli") then
    if(host_info["cli.ip"] ~= nil) then
      rsp = rsp..'host='..host_info["cli.ip"]
    end

  elseif(host_type == "srv") then
    if(host_info["srv.ip"] ~= nil) then
      rsp = rsp..'host='..host_info["srv.ip"]
    end
  else

    if((type(host_info) ~= "table")) then
      host_info = hostkey2hostinfo(host_info)
    end

    if(host_info["host"] ~= nil) then
      rsp = rsp..'host='..host_info["host"]
    elseif(host_info["ip"] ~= nil) then
      rsp = rsp..'host='..host_info["ip"]
    elseif(host_info["name"] ~= nil) then
      rsp = rsp..'host='..host_info["name"]
    elseif(host_info["mac"] ~= nil) then
      rsp = rsp..'host='..host_info["mac"]
    end
  end

  if(novlan == nil) then
    if((host_info["vlan"] ~= nil) and (tonumber(host_info["vlan"]) ~= 0)) then
      if(version == 0) then
        rsp = rsp..'&vlan='..tostring(host_info["vlan"])
      elseif(version == 1) then
        rsp = rsp..'@'..tostring(host_info["vlan"])
      end
    end
  end

  if(debug_host) then traceError(TRACE_DEBUG,TRACE_CONSOLE,"HOST2URL => ".. rsp .. "\n") end

  return rsp
end


--
-- Catch the main information about an host from the host_info table and return the corresponding json.
-- Example:
--          hostinfo2json(host[key]), return a json string based on the host value
--          hostinfo2json(flow[key],"cli"), return a json string based on the client host information in the flow table
--          hostinfo2json(flow[key],"srv"), return a json string based on the server host information in the flow table
--
function hostinfo2json(host_info,host_type)
  local rsp = ''

  if(host_type == "cli") then
    if(host_info["cli.ip"] ~= nil) then
      rsp = rsp..'host: "'..host_info["cli.ip"]..'"'
    end
  elseif(host_type == "srv") then
    if(host_info["srv.ip"] ~= nil) then
      rsp = rsp..'host: "'..host_info["srv.ip"]..'"'
    end
  else
    if((type(host_info) ~= "table") and (string.find(host_info,"@"))) then
      host_info = hostkey2hostinfo(host_info)
    end

    if(host_info["host"] ~= nil) then
      rsp = rsp..'host: "'..host_info["host"]..'"'
    elseif(host_info["ip"] ~= nil) then
      rsp = rsp..'host: "'..host_info["ip"]..'"'
    elseif(host_info["name"] ~= nil) then
      rsp = rsp..'host: "'..host_info["name"] ..'"'
    elseif(host_info["mac"] ~= nil) then
      rsp = rsp..'host: "'..host_info["mac"] ..'"'
    end
  end

  if((host_info["vlan"] ~= nil) and (host_info["vlan"] ~= 0)) then
    rsp = rsp..', vlan: "'..tostring(host_info["vlan"]) .. '"'
  end

  if(debug_host) then traceError(TRACE_DEBUG,TRACE_CONSOLE,"HOST2JSON => ".. rsp .. "\n") end

  return rsp
end

--
-- Catch the main information about an host from the host_info table and return the corresponding jqueryid.
-- Example: host 192.168.1.254, vlan0  ==> 1921681254_0
function hostinfo2jqueryid(host_info,host_type)
  local rsp = ''

  if(host_type == "cli") then
    if(host_info["cli.ip"] ~= nil) then
      rsp = rsp..''..host_info["cli.ip"]
    end

  elseif(host_type == "srv") then
    if(host_info["srv.ip"] ~= nil) then
      rsp = rsp..''..host_info["srv.ip"]
    end
  else
    if((type(host_info) ~= "table") and (string.find(host_info,"@"))) then
      host_info = hostkey2hostinfo(host_info)
    end

    if(host_info["host"] ~= nil) then
      rsp = rsp..''..host_info["host"]
    elseif(host_info["ip"] ~= nil) then
      rsp = rsp..''..host_info["ip"]
    elseif(host_info["name"] ~= nil) then
      rsp = rsp..''..host_info["name"]
    elseif(host_info["mac"] ~= nil) then
      rsp = rsp..''..host_info["mac"]
    end
  end


  if((host_info["vlan"] ~= nil) and (host_info["vlan"] ~= 0)) then
    rsp = rsp..'@'..tostring(host_info["vlan"])
  end

  rsp = string.gsub(rsp, "%.", "__")
  rsp = string.gsub(rsp, "/", "___")
  rsp = string.gsub(rsp, ":", "____")

  if(debug_host) then traceError(TRACE_DEBUG,TRACE_CONSOLE,"HOST2KEY => ".. rsp .. "\n") end

  return rsp
end

-- version is major.minor.veryminor
function version2int(v)
   if(v == nil) then return(0) end

  e = string.split(v, "%.");
  if(e ~= nil) then
    major = e[1]
    minor = e[2]
    veryminor = e[3]

    if(major == nil or tonumber(major) == nil or type(major) ~= "string")     then major = 0 end
    if(minor == nil or tonumber(minor) == nil or type(minor) ~= "string")     then minor = 0 end
    if(veryminor == nil or tonumber(veryminor) == nil or type(veryminor) ~= "string") then veryminor = 0 end

    version = tonumber(major)*1000 + tonumber(minor)*100 -- + tonumber(veryminor)
    return(version)
  else
    return(0)
  end
end

function get_version_update_msg(info, latest_version)
  version_elems = split(info["version"], " ")
  new_version = version2int(latest_version)
  this_version = version2int(version_elems[1])

  if(new_version < this_version) then
   return [[<div class='alert alert-warning'><font color=red><i class='fa fa-cloud-download fa-lg'></i> A new ]]..info["product"]..[[ (v.]]..(latest_version)..[[) is available for <A HREF='http://www.ntop.org/get-started/download/'>download</A>: please upgrade.</font></div>]]
  else
   return ""
  end
end

function table.empty(table)
  if(table == nil) then return true end
  if next(table) == nil then
    return true
  end
  return false
end

function table.len(table)
 local count = 0

  if(table == nil) then return(0) end
  for k,v in pairs(table) do
    count = count + 1
  end

  return count
end

function table.slice(tbl, first, last, step)
   local sliced = {}

   for i = first or 1, last or #tbl, step or 1 do
      sliced[#sliced+1] = tbl[i]
   end

   return sliced
end

-- ############################################
-- Redis Utils
-- ############################################

-- Inpur:     General prefix (i.e ntopng.pref)
-- Output:  User based prefix, if it exists
--
-- Examples:
--                With user:  ntopng.pref.user_name
--                Without:    ntopng.pref
function getRedisPrefix(str)
  if not (isEmptyString(_SESSION["user"] )) then
    -- Login enabled
    return (str .. '.' .. _SESSION["user"])
  else
    -- Login disabled
    return (str)
  end
end

function getRedisIfacePrefix(ifid)
   return "ntopng.prefs.ifid_"..tostring(ifid)
end

-----  End of Redis Utils  ------


function isPausedInterface(current_ifname)
  state = ntop.getCache("ntopng.prefs."..current_ifname.."_not_idle")
  if(state == "0") then return true else return false end
end

function getThroughputType()
  throughput_type = ntop.getCache("ntopng.prefs.thpt_content")

  if(throughput_type == "") then
    throughput_type = "bps"
  end
  return throughput_type
end

function isLoopback(name)
  if((name == "lo") or (name == "lo0")) then
    return(true)
  else
    return(false)
  end
end

function isLocalPacketdumpEnabled()
   local nbox_integration = ntop.getCache("ntopng.prefs.nbox_integration")
   if nbox_integration == nil or nbox_integration ~= "1" then
      nbox_integration = false
   else
      nbox_integration = true
   end
   return isAdministrator() and not nbox_integration and interface.isPacketInterface() and not ntop.isnEdge()
end

function processColor(proc)
  if(proc == nil) then
    return("")
  elseif(proc["average_cpu_load"] < 33) then
    return("<font color=green>"..proc["name"].."</font>")
  elseif(proc["average_cpu_load"] < 66) then
    return("<font color=orange>"..proc["name"].."</font>")
  else
    return("<font color=red>"..proc["name"].."</font>")
  end
end

 -- Table preferences

function getDefaultTableSort(table_type)
   local table_key = getRedisPrefix("ntopng.sort.table")
   local value = nil

  if(table_type ~= nil) then
     value = ntop.getHashCache(table_key, "sort_"..table_type)
  end
  if((value == nil) or (value == "")) then value = 'column_' end
  return(value)
end

function getDefaultTableSortOrder(table_type, force_get)
   local table_key = getRedisPrefix("ntopng.sort.table")
   local value = nil

  if(table_type ~= nil) then
    value = ntop.getHashCache(table_key, "sort_order_"..table_type)
  end
  if((value == nil) or (value == "")) and (force_get ~= true) then value = 'desc' end
  return(value)
end

function getDefaultTableSize()
  table_key = getRedisPrefix("ntopng.sort.table")
  value = ntop.getHashCache(table_key, "rows_number")
  if((value == nil) or (value == "")) then value = 10 end
  return(tonumber(value))
end

function tablePreferences(key, value, force_set)
  table_key = getRedisPrefix("ntopng.sort.table")

  if((value == nil) or (value == "")) and (force_set ~= true) then
    -- Get preferences
    return ntop.getHashCache(table_key, key)
  else
    -- Set preferences
    ntop.setHashCache(table_key, key, value)
    return(value)
  end
end

function getInterfaceSpeed(ifid)
   local ifname = getInterfaceName(ifid)
   local ifspeed = ntop.getCache('ntopng.prefs.'..ifname..'.speed')
   if not isEmptyString(ifspeed) and tonumber(ifspeed) ~= nil then
      ifspeed = tonumber(ifspeed)
   else
      ifspeed = interface.getMaxIfSpeed(ifid)
   end

   return ifspeed
end

function getInterfaceRefreshRate(ifid)
   local key = getRedisIfacePrefix(ifid)..".refresh_rate"
   local refreshrate = ntop.getCache(key)

   if isEmptyString(refreshrate) or tonumber(refreshrate) == nil then
      refreshrate = 3
   else
      refreshrate = tonumber(refreshrate)
   end

   return refreshrate
end

function setInterfaceRegreshRate(ifid, refreshrate)
   local key = getRedisIfacePrefix(ifid)..".refresh_rate"

   if isEmptyString(refreshrate) then
      ntop.delCache(key)
   else
      ntop.setCache(key, tostring(refreshrate))
   end
end

local function getCustomnDPIProtoCategoriesKey(ifid)
   return getRedisIfacePrefix(ifid)..".custom_nDPI_proto_categories"
end

function getCustomnDPIProtoCategories(if_name)
   local ifid = getInterfaceId(if_name)
   local ndpi_protos = interface.getnDPIProtocols()
   local key = getCustomnDPIProtoCategoriesKey(ifid)

   local res = {}
   for _, app_id in pairs(ndpi_protos) do
      local custom_category = ntop.getHashCache(key, tostring(app_id))
      if not isEmptyString(custom_category) then
	 res[tonumber(app_id)] = tonumber(custom_category)
      end
   end

   return res
end

function initCustomnDPIProtoCategories()
   for _, ifname in pairs(interface.getIfNames()) do
      interface.select(ifname)
      local custom = getCustomnDPIProtoCategories(ifname)

      for app_id, cat_id in pairs(custom) do
	 interface.setnDPIProtoCategory(app_id, cat_id)
      end
   end
end

function setCustomnDPIProtoCategory(if_name, app_id, new_cat_id)
   interface.select(if_name)
   interface.setnDPIProtoCategory(app_id, new_cat_id)

   local ifid = getInterfaceId(if_name)
   local key = getCustomnDPIProtoCategoriesKey(ifid)

   ntop.setHashCache(key, tostring(app_id), tostring(new_cat_id));
end

-- "Some Very Long String" -> "Some Ver...g String"
function shortenCollapse(s, max_len)
   local replacement = "..."
   local r_len = string.len(replacement)
   local s_len = string.len(s)

   if max_len == nil then
      max_len = ntop.getPref("ntopng.prefs.max_ui_strlen")
      max_len = tonumber(max_len)
      if(max_len == nil) then max_len = 24 end
   end

   if max_len <= r_len then
      return replacement
   end

   if s_len > max_len then
      local half = math.floor((max_len-r_len) / 2)
      return string.sub(s, 1, half) .. replacement .. string.sub(s, s_len-half+1)
   end

   return s
end

function getHumanReadableInterfaceName(interface_name)
   local key = 'ntopng.prefs.'..interface_name..'.name'
   local custom_name = ntop.getCache(key)

   if not isEmptyString(custom_name) then
      return(shortenCollapse(custom_name))
   else
      interface.select(interface_name)
      local _ifstats = interface.getStats()

      local nm = _ifstats.name
      if(string.contains(nm, "{")) then -- Windows
	 nm = _ifstats.description
      end

      -- print(interface_name.."=".._ifstats.name)
      return(shortenCollapse(nm or ''))
   end
end

-- ##############################################

function escapeHTML(s)
   s = string.gsub(s, "([&=+%c])", function (c)
				      return string.format("%%%02X", string.byte(c))
				   end)
   s = string.gsub(s, " ", "+")
   return s
end

-- ##############################################

function unescapeHTML (s)
   local unesc = function (h)
      local res = string.char(tonumber(h, 16))
      return res
   end

   s = string.gsub(s, "+", " ")
   s = string.gsub(s, "%%(%x%x)", unesc)

   return s
end

-- ##############################################

function harvestUnusedDir(path, min_epoch)
   local files = ntop.readdir(path)

   -- print("Reading "..path.."<br>\n")

   for k,v in pairs(files) do
      if(v ~= nil) then
	 local p = os_utils.fixPath(path .. "/" .. v)
	 if(ntop.isdir(p)) then
	    harvestUnusedDir(p, min_epoch)
	 else
	    local when = ntop.fileLastChange(path)

	    if((when ~= -1) and (when < min_epoch)) then
	       os.remove(p)
	    end
	 end
      end
   end
end

 -- ##############################################

function harvestJSONTopTalkers(days)
   local when = os.time() - 86400 * days

   ifnames = interface.getIfNames()
   for _,ifname in pairs(ifnames) do
      interface.select(ifname)
      local _ifstats = interface.getStats()
      local dirs = ntop.getDirs()
      local basedir = os_utils.fixPath(dirs.workingdir .. "/" .. _ifstats.id)

      harvestUnusedDir(os_utils.fixPath(basedir .. "/top_talkers"), when)
      harvestUnusedDir(os_utils.fixPath(basedir .. "/flows"), when)
   end
end

 -- ##############################################

function isAdministrator()
   local user_group = ntop.getUserGroup()

   if(user_group == "administrator") or (user_group == "") then
      return(true)
   else
      return(false)
   end
end

 -- ##############################################

function haveAdminPrivileges()
   if(isAdministrator()) then
      return(true)
   else
      ntop.dumpFile(dirs.installdir .. "/httpdocs/inc/header.inc")
      dofile(dirs.installdir .. "/scripts/lua/inc/menu.lua")
      print("<div class=\"alert alert-danger\"><img src=".. ntop.getHttpPrefix() .. "/img/warning.png> Access forbidden</div>")
      return(false)
   end
end

 -- ##############################################

function getKeysSortedByValue(tbl, sortFunction)
  local keys = {}
  for key in pairs(tbl) do
    table.insert(keys, key)
  end

  table.sort(keys, function(a, b)
    return sortFunction(tbl[a], tbl[b])
  end)

  return keys
end

function getKeys(t, col)
  local keys = {}
  for k,v in pairs(t) do keys[tonumber(v[col])] = k end
  return keys
end

 -- ##############################################

function formatBreed(breed)
   if(breed == "Safe") then
      return("<i class='fa fa-lock' alt='Safe Protocol'></i>")
   elseif(breed == "Acceptable") then
      return("<i class='fa fa-thumbs-o-up' alt='Acceptable Protocol'></i>")
   elseif(breed == "Fun") then
      return("<i class='fa fa-smile-o' alt='Fun Protocol'></i>")
   elseif(breed == "Unsafe") then
      return("<i class='fa fa-thumbs-o-down'></i>")
   elseif(breed == "Dangerous") then
      return("<i class='fa fa-warning'></i>")
   else
      return("")
   end
end

function getFlag(country)
   if((country == nil) or (country == "")) then
      return("")
   else
      return(" <A HREF='" .. ntop.getHttpPrefix() .. "/lua/hosts_stats.lua?country=".. country .."'><img src='".. ntop.getHttpPrefix() .. "/img/blank.gif' class='flag flag-".. string.lower(country) .."'></A> ")
   end
end

-- GENERIC UTILS

-- split
function split(s, delimiter)
   result = {};
   if(s ~= nil) then
      for match in (s..delimiter):gmatch("(.-)"..delimiter) do
	 table.insert(result, match);
      end
   end
   return result;
end

-- startswith
function startswith(s, char)
   return string.sub(s, 1, string.len(s)) == char
end

-- strsplit

function strsplit(s, delimiter)
   result = {};
   for match in (s..delimiter):gmatch("(.-)"..delimiter) do
      if(match ~= "") then result[match] = true end
   end
    return result;
end

-- isempty
function isempty(array)
  local count = 0
  for _,__ in pairs(array) do
    count = count + 1
  end
  return (count == 0)
end

-- isin
function isin(s, array)
  if (s == nil or s == "" or array == nil or isempty(array)) then return false end
  for _, v in pairs(array) do
    if (s == v) then return true end
  end
  return false
end

-- hasKey
function hasKey(key, theTable)
   if((theTable == nil) or (theTable[key] == nil)) then
      return(false)
   else
      return(true)
   end
end
function getPasswordInputPattern()
  return [[^[\w\$\\!\/\(\)=\?\^\*@_\-\u0000-\u0019\u0021-\u00ff]{5,}$]]
end

function getIPv4Pattern()
  return "^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
end

function getACLPattern()
  local ipv4 = "(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
  local netmask = "(\\/([0-9]|[1-2][0-9]|3[0-2]))"
  local cidr = ipv4..netmask
  local yesorno_cidr = "[\\+\\-]"..cidr
  return "^"..yesorno_cidr.."(,"..yesorno_cidr..")*$"
end

function getMacPattern()
  return "^([0-9a-fA-F][0-9a-fA-F]:){5}[0-9a-fA-F]{2}$"
end

function getURLPattern()
  return "^https?://.+$"
end

-- get_mac_classification
function get_mac_classification(m, extended_name)
   local short_extended = ntop.getMacManufacturer(m) or {}

   if extended_name then
      return short_extended.extended or short_extended.short or m
   else
      return short_extended.short or m
   end

   return m
end

local magic_macs = {
   ["FF:FF:FF:FF:FF:FF"] = "Broadcast",
   ["01:00:0C:CC:CC:CC"] = "CDP",
   ["01:00:0C:CC:CC:CD"] = "CiscoSTP",
   ["01:80:C2:00:00:00"] = "STP",
   ["01:80:C2:00:00:00"] = "LLDP",
   ["01:80:C2:00:00:03"] = "LLDP",
   ["01:80:C2:00:00:0E"] = "LLDP",
   ["01:80:C2:00:00:08"] = "STP",
   ["01:1B:19:00:00:00"] = "PTP",
   ["01:80:C2:00:00:0E"] = "PTP"
}

local magic_short_macs = {
   ["01:00:5E"] = "IPv4mcast",
   ["33:33:"] = "IPv6mcast"
}

function macInfo(mac)
  return(' <A HREF="' .. ntop.getHttpPrefix() .. '/lua/mac_details.lua?host='.. mac ..'">'..mac..'</A> ')
end

-- get_symbolic_mac
function get_symbolic_mac(mac_address, only_symbolic)
   if(magic_macs[mac_address] ~= nil) then
      return(magic_macs[mac_address])
   else
      local m = string.sub(mac_address, 1, 8)
      local t = string.sub(mac_address, 10, 17)

      if(magic_short_macs[m] ~= nil) then
	 if(only_symbolic == true) then
	    return(magic_short_macs[m].."_"..t)
	 else
	    return(magic_short_macs[m].."_"..t.." ("..macInfo(mac_address)..")")
	 end
      else
	 local s = get_mac_classification(m)

	 if(m == s) then
	    return '<a href="' .. ntop.getHttpPrefix() .. '/lua/mac_details.lua?host='..mac_address..'">' .. get_mac_classification(m) .. ":" .. t .. '</a>'
	 else
	    if(only_symbolic == true) then
	       return(get_mac_classification(m).."_"..t)
	    else
	       return(get_mac_classification(m).."_"..t.." ("..macInfo(mac_address)..")")
	    end
	 end
      end
   end
end

function get_manufacturer_mac(mac_address)
  local m = string.sub(mac_address, 1, 8)
  local ret = get_mac_classification(m, true --[[ extended name --]])

  if(ret == m) then ret = "n/a" end

  if ret and ret ~= "" then
     ret = ret:gsub("'"," ")
  end

  return ret or "n/a"
end

-- getservbyport
function getservbyport(port_num, proto)
   if(proto == nil) then proto = "TCP" end

   port_num = tonumber(port_num)

   proto = string.lower(proto)

   -- io.write(port_num.."@"..proto.."\n")
   return(ntop.getservbyport(port_num, proto))
end

function intToIPv4(num)
   return(math.floor(num / 2^24).. "." ..math.floor((num % 2^24) / 2^16).. "." ..math.floor((num % 2^16) / 2^8).. "." ..num % 2^8)
end

function getFlowMaxRate(cli_max_rate, srv_max_rate)
   cli_max_rate = tonumber(cli_max_rate)
   srv_max_rate = tonumber(srv_max_rate)

   if((cli_max_rate == 0) or (srv_max_rate == 0)) then
      max_rate = 0
      elseif((cli_max_rate == -1) and (srv_max_rate > 0)) then
      max_rate = srv_max_rate
      elseif((cli_max_rate > 0) and (srv_max_rate == -1)) then
      max_rate = cli_max_rate
   else
      max_rate = math.min(cli_max_rate, srv_max_rate)
   end

   return(max_rate)
end

-- ###############################################

function trimSpace(what)
   if(what == nil) then return("") end
   return(string.gsub(string.gsub(what, "%s+", ""), "+%s", ""))
end

-- ###############################################

-- TODO: improve this function
function jsonencode(what)
   what = string.gsub(what, '"', "'")
   -- everything but all ASCII characters from the space to the tilde
   what = string.gsub(what, "[^ -~]", " ")
   -- cleanup line feeds and carriage returns
   what = string.gsub(what, "\n", " ")
   what = string.gsub(what, "\r", " ")
   -- escape all the remaining backslashes
   what = string.gsub(what, "\\", "\\\\")
   -- max 1 sequential whitespace
   what = string.gsub(what, " +"," ")
   return(what)
end

-- ###############################################

function formatWebSite(site)
   return("<A target=\"_blank\" HREF=\"http://"..site.."\">"..site.."</A> <i class=\"fa fa-external-link\"></i></th>")
end

-- Update Utils::flowstatus2str
function getFlowStatus(status)
  if(status == 0) then return("<font color=green>"..i18n("flow_details.normal").."</font>")
  elseif(status == 1)  then return("<font color=orange>"..i18n("flow_details.slow_tcp_connection").."</font>")
  elseif(status == 2)  then return("<font color=orange>"..i18n("flow_details.slow_application_header").."</font>")
  elseif(status == 3)  then return("<font color=orange>"..i18n("flow_details.slow_data_exchange").."</font>")
  elseif(status == 4)  then return("<font color=orange>"..i18n("flow_details.low_goodput").."</font>")
  elseif(status == 5)  then return("<font color=orange>"..i18n("flow_details.suspicious_tcp_syn_probing").."</font>")
  elseif(status == 6)  then return("<font color=orange>"..i18n("flow_details.tcp_connection_issues").."</font>")
  elseif(status == 7)  then return("<font color=orange>"..i18n("flow_details.suspicious_tcp_probing").."</font>")
  elseif(status == 8)  then return("<font color=orange>"..i18n("flow_details.flow_emitted").."</font>")
  elseif(status == 9)  then return("<font color=orange>"..i18n("flow_details.tcp_connection_refused").."</font>")
  elseif(status == 10) then return("<font color=orange>"..i18n("flow_details.ssl_certificate_mismatch").."</font>")
  elseif(status == 11) then return("<font color=orange>"..i18n("flow_details.dns_invalid_query").."</font>")
  elseif(status == 12) then return("<font color=orange>"..i18n("flow_details.remote_to_remote").."</font>")
  elseif(status == 13) then return("<font color=orange>"..i18n("flow_details.blacklisted_flow").."</font>")
  elseif(status == 14) then return(""..i18n("flow_details.flow_blocked_by_bridge").."")
  elseif(status == 15) then return(""..i18n("flow_details.web_mining_detected").."")
  else return("<font color=orange>"..i18n("flow_details.unknown_status",{status=status}).."</font>")
  end
end

-- prints purged information for hosts / flows
function purgedErrorString()
    local info = ntop.getInfo(false)
    return i18n("purged_error_message",{url=ntop.getHttpPrefix()..'/lua/admin/prefs.lua?tab=in_memory', product=info["product"]})
end

-- print TCP flags
function printTCPFlags(flags)
   if(hasbit(flags,0x01)) then print('<span class="label label-info">FIN</span> ') end
   if(hasbit(flags,0x02)) then print('<span class="label label-info">SYN</span> ')  end
   if(hasbit(flags,0x04)) then print('<span class="label label-danger">RST</span> ') end
   if(hasbit(flags,0x08)) then print('<span class="label label-info">PUSH</span> ') end
   if(hasbit(flags,0x10)) then print('<span class="label label-info">ACK</span> ')  end
   if(hasbit(flags,0x20)) then print('<span class="label label-info">URG</span> ')  end
end

-- convert the integer carrying TCP flags in a more convenient lua table
function TCPFlags2table(flags)
   local res = {["FIN"] = 0, ["SYN"] = 0, ["RST"] = 0, ["PSH"] = 0, ["ACK"] = 0, ["URG"] = 0}
   if(hasbit(flags,0x01)) then res["FIN"] = 1 end
   if(hasbit(flags,0x02)) then res["SYN"] = 1 end
   if(hasbit(flags,0x04)) then res["RST"] = 1 end
   if(hasbit(flags,0x08)) then res["PSH"] = 1 end
   if(hasbit(flags,0x10)) then res["ACK"] = 1 end
   if(hasbit(flags,0x20)) then res["URG"] = 1 end
   return res
end

-- ##########################################

function historicalProtoHostHref(ifId, host, l4_proto, ndpi_proto_id, info)
   if ntop.isPro() and ntop.getPrefs().is_dump_flows_to_mysql_enabled == true then
      local hist_url = ntop.getHttpPrefix().."/lua/pro/db_explorer.lua?search=true&ifid="..ifId
      local now    = os.time()
      local ago1h  = now - 3600

      hist_url = hist_url.."&epoch_end="..tostring(now)
      if((host ~= nil) and (host ~= "")) then hist_url = hist_url.."&"..hostinfo2url(host) end
      if((l4_proto ~= nil) and (l4_proto ~= "")) then
	 hist_url = hist_url.."&l4proto="..l4_proto
      end
      if((ndpi_proto_id ~= nil) and (ndpi_proto_id ~= "")) then hist_url = hist_url.."&protocol="..ndpi_proto_id end
      if((info ~= nil) and (info ~= "")) then hist_url = hist_url.."&info="..info end
      print('&nbsp;')
      -- print('<span class="label label-info">')
      print('<a href="'..hist_url..'&epoch_begin='..tostring(ago1h)..'" title="Flows seen in the last hour"><i class="fa fa-history fa-lg"></i></a>')
      -- print('</span>')
   end
end

-- ##########################################

_icmp_types = {
	 { 0, 0, i18n("icmp_v4_types.type_0_0_echo_reply") },
	 { 3, 0, i18n("icmp_v4_types.type_3_0_network_unreachable") },
	 { 3, 1, i18n("icmp_v4_types.type_3_1_host_unreachable") },
	 { 3, 2, i18n("icmp_v4_types.type_3_2_protocol_unreachable") },
	 { 3, 3, i18n("icmp_v4_types.type_3_3_port_unreachable") },
	 { 3, 4, i18n("icmp_v4_types.type_3_4_fragmentation_needed_but_no_fragment_bit_set") },
	 { 3, 5, i18n("icmp_v4_types.type_3_5_source_routing_failed") },
	 { 3, 6, i18n("icmp_v4_types.type_3_6_destination_network_unknown") },
	 { 3, 7, i18n("icmp_v4_types.type_3_7_destination_host_unknown") },
	 { 3, 8, i18n("icmp_v4_types.type_3_8_source_host_isolated") },
	 { 3, 9, i18n("icmp_v4_types.type_3_9_destination_network_administratively_prohibited") },
	 { 3, 10, i18n("icmp_v4_types.type_3_10_destination_host_administratively_prohibited") },
	 { 3, 11, i18n("icmp_v4_types.type_3_11_network_unreachable_for_tos") },
	 { 3, 12, i18n("icmp_v4_types.type_3_12_host_unreachable_for_tos") },
	 { 3, 13, i18n("icmp_v4_types.type_3_13_communication_administratively_prohibited_by_filtering") },
	 { 3, 14, i18n("icmp_v4_types.type_3_14_host_precedence_violation") },
	 { 3, 15, i18n("icmp_v4_types.type_3_15_precedence_cutoff_in_effect") },
	 { 4, 0, i18n("icmp_v4_types.type_4_0_source_quench") },
	 { 5, 0, i18n("icmp_v4_types.type_5_0_redirect_for_network") },
	 { 5, 1, i18n("icmp_v4_types.type_5_1_redirect_for_host") },
	 { 5, 2, i18n("icmp_v4_types.type_5_2_redirect_for_tos_and_network") },
	 { 5, 3, i18n("icmp_v4_types.type_5_3_redirect_for_tos_and_host") },
	 { 8, 0, i18n("icmp_v4_types.type_8_0_echo_request_x") },
	 { 9, 0, i18n("icmp_v4_types.type_9_0_router_advertisement") },
	 { 10, 0, i18n("icmp_v4_types.type_10_0_route_solicitation") },
	 { 11, 0, i18n("icmp_v4_types.type_11_0_ttl_equals_0_during_transit") },
	 { 11, 1, i18n("icmp_v4_types.type_11_1_ttl_equals_0_during_reassembly") },
	 { 12, 0, i18n("icmp_v4_types.type_12_0_ip_header_bad") },
	 { 12, 1, i18n("icmp_v4_types.type_12_1_required_options_missing") },
	 { 13, 0, i18n("icmp_v4_types.type_13_0_timestamp_request") },
	 { 14, 0, i18n("icmp_v4_types.type_14_0_timestamp_reply") },
	 { 15, 0, i18n("icmp_v4_types.type_15_0_information_request") },
	 { 16, 0, i18n("icmp_v4_types.type_16_0_information_reply") },
	 { 17, 0, i18n("icmp_v4_types.type_17_0_address_mask_request") },
	 { 18, 0, i18n("icmp_v4_types.type_18_0_address_mask_reply") }
}

-- Code is currently ignored on IVMPv6
_icmpv6_types = {
        { 0, i18n("icmp_v6_types.type_0_reserved") },
	{ 1, i18n("icmp_v6_types.type_1_destination_unreachable") },
	{ 2, i18n("icmp_v6_types.type_2_packet_too_big") },
	{ 3, i18n("icmp_v6_types.type_3_time_exceeded") },
	{ 4, i18n("icmp_v6_types.type_4_parameter_problem") },
	{ 100, i18n("icmp_v6_types.type_100_private_experimentation") },
	{ 101, i18n("icmp_v6_types.type_101_private_experimentation") },
	--{ 102-126, i18n("icmp_v6_types.type_102-126_unassigned") },
	{ 127, i18n("icmp_v6_types.type_127_reserved_for_expansion_of_icmpv6_error_messages") },
	{ 128, i18n("icmp_v6_types.type_128_echo_request") },
	{ 129, i18n("icmp_v6_types.type_129_echo_reply") },
	{ 130, i18n("icmp_v6_types.type_130_multicast_listener_query") },
	{ 131, i18n("icmp_v6_types.type_131_multicast_listener_report") },
	{ 132, i18n("icmp_v6_types.type_132_multicast_listener_done") },
	{ 133, i18n("icmp_v6_types.type_133_router_solicitation") },
	{ 134, i18n("icmp_v6_types.type_134_router_advertisement") },
	{ 135, i18n("icmp_v6_types.type_135_neighbor_solicitation") },
	{ 136, i18n("icmp_v6_types.type_136_neighbor_advertisement") },
	{ 137, i18n("icmp_v6_types.type_137_redirect_message") },
	{ 138, i18n("icmp_v6_types.type_138_router_renumbering") },
	{ 139, i18n("icmp_v6_types.type_139_icmp_node_information_query") },
	{ 140, i18n("icmp_v6_types.type_140_icmp_node_information_response") },
	{ 141, i18n("icmp_v6_types.type_141_inverse_neighbor_discovery_solicitation_message") },
	{ 142, i18n("icmp_v6_types.type_142_inverse_neighbor_discovery_advertisement_message") },
	{ 143, i18n("icmp_v6_types.type_143_version_2_multicast_listener_report") },
	{ 144, i18n("icmp_v6_types.type_144_home_agent_address_discovery_request_message") },
	{ 145, i18n("icmp_v6_types.type_145_home_agent_address_discovery_reply_message") },
	{ 146, i18n("icmp_v6_types.type_146_mobile_prefix_solicitation") },
	{ 147, i18n("icmp_v6_types.type_147_mobile_prefix_advertisement") },
	{ 148, i18n("icmp_v6_types.type_148_certification_path_solicitation_message") },
	{ 149, i18n("icmp_v6_types.type_149_certification_path_advertisement_message") },
	{ 150, i18n("icmp_v6_types.type_150_icmp_messages_utilized_by_experimental_mobility_protocols") },
	{ 151, i18n("icmp_v6_types.type_151_multicast_router_advertisement") },
	{ 152, i18n("icmp_v6_types.type_152_multicast_router_solicitation") },
	{ 153, i18n("icmp_v6_types.type_153_multicast_router_termination") },
	{ 154, i18n("icmp_v6_types.type_154_fmipv6_messages") },
	{ 155, i18n("icmp_v6_types.type_155_rpl_control_message") },
	{ 156, i18n("icmp_v6_types.type_156_ilnpv6_locator_update_message") },
	{ 157, i18n("icmp_v6_types.type_157_duplicate_address_request") },
	{ 158, i18n("icmp_v6_types.type_158_duplicate_address_confirmation") },
	{ 159, i18n("icmp_v6_types.type_159_mpl_control_message") },
	--{ 160-199, i18n("icmp_v6_types.type_160-199_unassigned") },
	{ 200, i18n("icmp_v6_types.type_200_private_experimentation") },
	{ 201, i18n("icmp_v6_types.type_201_private_experimentation") },
	{ 255, i18n("icmp_v6_types.type_255_reserved_for_expansion_of_icmpv6_informational_messages") }
}

-- #############################################

function getICMPV6TypeCode(icmp)
  local t = icmp.type
  local c = icmp.code

  for _, _e in ipairs(_icmpv6_types) do
    if(_e[1] == t) then
    	return(_e[2])
    end
  end

 return(t.."/"..c)
end

-- #############################################

function getICMPTypeCode(icmp)
  local t = icmp.type
  local c = icmp.code

  for _, _e in ipairs(_icmp_types) do
    if((_e[1] == t) and (_e[2] == c)) then
    	return(_e[3])
    end
  end

 return(getICMPV6TypeCode(icmp))
end

-- #############################################

-- Add here the icons you guess based on the Mac address
-- TODO move to discovery stuff
local guess_icon_keys = {
  ["dell inc."] = "fa-desktop",
  ["vmware, inc."] = "fa-desktop",
  ["xensource, inc."] = "fa-desktop",
  ["lanner electronics, inc."] = "fa-desktop",
  ["nexcom international co., ltd."] = "fa-desktop",
  ["apple, inc."] = "fa-apple",
  ["cisco systems, inc"] = "fa-arrows",
  ["juniper networks"] = "fa-arrows",
  ["brocade communications systems, inc."] = "fa-arrows",
  ["force10 networks, inc."] = "fa-arrows",
  ["huawei technologies co.,ltd"] = "fa-arrows",
  ["alcatel-lucent ipd"] = "fa-arrows",
  ["arista networks, inc."] = "fa-arrows",
  ["3com corporation"] = "fa-arrows",
  ["routerboard.com"] = "fa-arrows",
  ["extreme networks"] = "fa-arrows",
  ["xerox corporation"] = "fa-print"
}

function guessHostIcon(key)
   local m = string.lower(get_manufacturer_mac(key))
   local icon = guess_icon_keys[m]

   if((icon ~= nil) and (icon ~= "")) then
      return(" <i class='fa "..icon.." fa-lg'></i>")
   else
      return ""
   end
end

-- ####################################################

-- Functions to set/get a device type of user choice

local function getCustomDeviceKey(mac)
   return "ntopng.prefs.device_types." .. string.upper(mac)
end

function getCustomDeviceType(mac)
   return tonumber(ntop.getPref(getCustomDeviceKey(mac)))
end

function setCustomDeviceType(mac, device_type)
   ntop.setPref(getCustomDeviceKey(mac), tostring(device_type))
end

-- ####################################################

function tableToJsObject(lua_table)
   local json = require("dkjson")
   return json.encode(lua_table, nil)
end

-- ####################################################

function makeTimeStamp(d, tzoffset)
   -- tzoffset is the timezone difference between UTC and Local Time in the browser
   local pattern = "(%d+)%/(%d+)%/(%d+) (%d+):(%d+):(%d+)"
   local day,month, year, hour, minute, seconds = string.match(d, pattern);

   local timestamp = os.time({year=year, month=month, day=day, hour=hour, min=minute, sec=seconds});

   -- tprint("pre-timestamp is:"..timestamp)
   if tzoffset then
      -- from browser local time to UTC
      timestamp = timestamp - (tzoffset or 0)

      -- from UTC to machine local time
      local now = os.time()
      local local_t = os.date("*t", now)
      local utc_t = os.date("!*t", now)
      local delta = (local_t.hour - utc_t.hour)*60 + (local_t.min - utc_t.min)
      delta = delta * 60 -- to seconds

      timestamp = timestamp + (delta or 0)
      -- tprint("delta: "..delta.." tzoffset is: "..tzoffset)
      -- tprint("post-timestamp is:"..timestamp)
   end

   return timestamp.."";
end

-- ###########################################

-- IMPORTANT: keep it in sync with sortField (ntop_typedefs.h)
--            AND host_search_walker:NetworkInterface.cpp
--            AND NetworkInterface::getFlows()
looking_glass_criteria = {
   -- KEY  LABEL   Host::lua()-label  formatting
   { "uploaders", i18n("uploaders"), "upload", bytesToSize },
   { "downloaders", i18n("downloaders"), "download", bytesToSize },
   { "unknowers", i18n("unknowers"), "unknown", bytesToSize },
   { "incomingflows", i18n("incomingflows"), "incomingflows", format_utils.formatValue },
   { "outgoingflows", i18n("outgoingflows"), "outgoingflows", format_utils.formatValue },
}

function criteria2label(criteria)
  local id

  for id, _ in ipairs(looking_glass_criteria) do
    local key   = looking_glass_criteria[id][1]
    local label = looking_glass_criteria[id][2]
    local fnctn = looking_glass_criteria[id][4]

    if(key == criteria) then
      return label, fnctn
    end
  end

  return criteria, format_utils.formatValue
end

function label2criteriakey(what)
  local id

  for id, _ in ipairs(looking_glass_criteria) do
    local c        = looking_glass_criteria[id][1]
    local key      = looking_glass_criteria[id][3]
    local fnctn    = looking_glass_criteria[id][4]

    if(what == c) then
       return key, fnctn
    end
  end

  return what, format_utils.formatValue
end

function table.merge(a, b)
  local merged = {}

  for _, t in ipairs({a, b}) do
    for k,v in pairs(t) do
      merged[k] = v
    end
  end

  return merged
end

function table.clone(orig)
   local orig_type = type(orig)
   local copy

   if orig_type == 'table' then
      copy = {}
      for orig_key, orig_value in next, orig, nil do
         copy[table.clone(orig_key)] = table.clone(orig_value)
      end
      setmetatable(copy, table.clone(getmetatable(orig)))
   else -- number, string, boolean, etc
      copy = orig
   end

   return copy
end

-- From http://lua-users.org/lists/lua-l/2014-09/msg00421.html
-- Returns true if tables are equal
function table.compare(t1, t2, ignore_mt)
  local ty1 = type(t1)
  local ty2 = type(t2)

  if ty1 ~= ty2 then return false end
  if ty1 ~= 'table' and ty2 ~= 'table' then return t1 == t2 end
  local mt = getmetatable(t1)
  if not ignore_mt and mt and mt.__eq then return t1 == t2 end

  for k1,v1 in pairs(t1) do
      local v2 = t2[k1]
      if v2 == nil or not table.compare(v1, v2) then return false end
  end

  for k2,v2 in pairs(t2) do
      local v1 = t1[k2]
      if v1 == nil or not table.compare(v1, v2) then return false end
  end

  return true
end

function toboolean(s)
  if s == "true" then
    return true
  elseif s == "false" then
    return false
  else
    return nil
  end
end

--
-- Find the highest divisor which divides input value.
-- val_idx can be used to index divisors values.
-- Returns the highest_idx
--
function highestDivisor(divisors, value, val_idx, iterator_fn)
  local highest_idx = nil
  local highest_val = nil
  iterator_fn = iterator_fn or ipairs

  for i, v in iterator_fn(divisors) do
    local cmp_v
    if val_idx ~= nil then
      v = v[val_idx]
    end

    if((highest_val == nil) or ((v > highest_val) and (value % v == 0))) then
      highest_val = v
      highest_idx = i
    end
  end

  return highest_idx
end

-- ###########################################

-- Note: the base unit is Kbit/s here
FMT_TO_DATA_RATES_KBPS = {
   ["k"] = {label="kbit/s", value=1},
   ["m"] = {label="Mbit/s", value=1000},
   ["g"] = {label="Gbit/s", value=1000*1000},
}

FMT_TO_DATA_BYTES = {
  ["b"] = {label="B",  value=1},
  ["k"] = {label="KB", value=1024},
  ["m"] = {label="MB", value=1024*1024},
  ["g"] = {label="GB", value=1024*1024*1024},
}

FMT_TO_DATA_TIME = {
  ["s"] = {label=i18n("metrics.secs"),  value=1},
  ["m"] = {label=i18n("metrics.mins"),  value=60},
  ["h"] = {label=i18n("metrics.hours"), value=3600},
  ["d"] = {label=i18n("metrics.days"),  value=3600*24},
}

-- ###########################################

-- Note: use data-min and data-max to setup ranges
function makeResolutionButtons(fmt_to_data, ctrl_id, fmt, value, extra)
  local extra = extra or {}
  local html_lines = {}

  local divisors = {}

  -- fill in divisors
  if tonumber(value) ~= nil then
    -- foreach character in format
    string.gsub(fmt, ".", function(k)
      local v = fmt_to_data[k]
      if v ~= nil then
        divisors[#divisors + 1] = {k=k, v=v.value}
      end
    end)
  end

  local selected = nil
  if tonumber(value) ~= 0 then
    selected = highestDivisor(divisors, value, "v")
  end

  if selected ~= nil then
    selected = divisors[selected].k
  else
    selected = string.sub(fmt, 1, 1)
  end

  local style = table.merge({display="flex"}, extra.style or {})
  html_lines[#html_lines+1] = [[<div class="btn-group ]] .. table.concat(extra.classes or {}, "") .. [[" id="]] .. ctrl_id .. [[" data-toggle="buttons" style="]] .. table.tconcat(style, ":", "; ", ";") .. [[">]]

  -- foreach character in format
  string.gsub(fmt, ".", function(k)
    local v = fmt_to_data[k]
    if v ~= nil then
      local line = {}
      line[#line+1] = [[<label class="btn]]
      if selected == k then
	 line[#line+1] = [[ btn-primary active]]
      else
	 line[#line+1] = [[ btn-default]]
      end
      line[#line+1] = [[ btn-sm"><input data-resol="]] .. k .. [[" value="]] .. v.value .. [[" title="]] .. v.label .. [[" name="opt_resbt_]] .. k .. [[_]] .. ctrl_id .. [[" autocomplete="off" type="radio"]]
      if selected == k then line[#line+1] = [[ checked="checked"]] end
      line[#line+1] = [[/>]] .. v.label .. [[</label>]]

      html_lines[#html_lines+1] = table.concat(line, "")
    end
  end)

  html_lines[#html_lines+1] = [[</div>]]

  -- Note: no // comment below, only /* */

  local js_init_code = [[
      var _resol_inputs = [];

      function resol_selector_get_input(a_button) {
        return $("input", $(a_button).closest(".form-group")).last();
      }

      function resol_selector_get_buttons(an_input) {
        return $(".btn-group", $(an_input).closest(".form-group")).first().find("input");
      }

      /* This function scales values wrt selected resolution */
      function resol_selector_reset_input_range(selected) {
        var selected = $(selected);
        var input = resol_selector_get_input(selected);

        var raw = parseInt(input.attr("data-min"));
        if (! isNaN(raw))
          input.attr("min", Math.sign(raw) * Math.ceil(Math.abs(raw) / selected.val()));

        raw = parseInt(input.attr("data-max"));
        if (! isNaN(raw))
          input.attr("max", Math.sign(raw) * Math.ceil(Math.abs(raw) / selected.val()));

        var step = parseInt(input.attr("data-step-" + selected.attr("data-resol")));
        if (! isNaN(step)) {
          input.attr("step", step);

          /* Align value */
          input.val(input.val() - input.val() % step);
        } else
          input.attr("step", "");

        resol_recheck_input_range(input);
      }

      function resol_selector_change_selection(selected) {
         selected.attr('checked', 'checked')
          .closest("label").removeClass('btn-default').addClass('btn-primary')
          .siblings().removeClass('active').removeClass('btn-primary').addClass('btn-default').find("input").removeAttr('checked');

        resol_selector_reset_input_range(selected);
      }

      function resol_recheck_input_range(input) {
        var value = input.val();

        if (input[0].hasAttribute("min"))
          value = Math.max(value, input.attr("min"));
        if (input[0].hasAttribute("max"))
          value = Math.min(value, input.attr("max"));

        var old_val = input.val();
        if ((old_val != "") && (old_val != value))
          input.val(value);
      }

      function resol_selector_change_callback(event) {
        resol_selector_change_selection($(this));
      }

      function resol_selector_on_form_submit(event) {
        var form = $(this);

        if (event.isDefaultPrevented() || (form.find(".has-error").length > 0))
          return false;

        resol_selector_finalize(form);
        return true;
      }

      /* Helper function to set a selector value by raw value */
      function resol_selector_set_value(input_id, its_value) {
         var input = $(input_id);
         var buttons = resol_selector_get_buttons($(input_id));
         var values = [];

         buttons.each(function() {
            values.push(parseInt($(this).val()));
         });

         var new_value;
         var new_i;
         if (its_value > 0) {
            /* highest divisor */
            var highest_i = 0;
            for (var i=1; i<values.length; i++) {
              if(((values[i] > values[highest_i]) && (its_value % values[i] == 0)))
                highest_i = i;
            }

            new_value = its_value / values[highest_i];
            new_i = highest_i;
         } else {
            /* smallest value */
            new_value = Math.max(its_value, -1);
            new_i = values.indexOf(Math.min.apply(Math, values));
         }

         /* Set */
         input.val(new_value);
         resol_selector_change_selection($(buttons[new_i]));

         /* This must be set manually on initialization */
         $(buttons[new_i]).closest("label").addClass("active");
      }

      function resol_selector_get_raw(input) {
         var buttons = resol_selector_get_buttons(input);
         var selected = buttons.filter(":checked");

         return parseInt(selected.val()) * parseInt(input.val());
      }

      function resol_selector_finalize(form) {
        $.each(_resol_inputs, function(i, elem) {
          /* Skip elements which are not part of the form */
          if (! $(elem).closest("form").is(form))
            return;

          var selected = $(elem).find("input[checked]");
          var input = resol_selector_get_input(selected);
          resol_recheck_input_range(input);

          /* transform in raw units */
          var new_input = $("<input type=\"hidden\"/>");
          new_input.attr("name", input.attr("name"));
          input.removeAttr("name");
          new_input.val(resol_selector_get_raw(input));
          new_input.appendTo(form);
        });

        /* remove added input names */
        $("input[name^=opt_resbt_]", form).removeAttr("name");
      }]]

  local js_specific_code = [[
    $("#]] .. ctrl_id .. [[ input").change(resol_selector_change_callback);
    $(function() {
      var elemid = "#]] .. ctrl_id .. [[";
      _resol_inputs.push(elemid);
      var selected = $(elemid + " input[checked]");
      resol_selector_reset_input_range(selected);

      /* setup the form submit callback (only once) */
      var form = selected.closest("form");
      if (! form.attr("data-options-handler")) {
        form.attr("data-options-handler", 1);
        form.submit(resol_selector_on_form_submit);
      }
    });
  ]]

  -- join strings and strip newlines
  local html = string.gsub(table.concat(html_lines, ""), "\n", "")
  js_init_code = string.gsub(js_init_code, "\n", "")
  js_specific_code = string.gsub(js_specific_code, "\n", "")

  if tonumber(value) ~= nil then
     -- returns the new value with selected resolution
    return {html=html, init=js_init_code, js=js_specific_code, value=tonumber(value) / fmt_to_data[selected].value}
  else
    return {html=html, init=js_init_code, js=js_specific_code, value=nil}
  end
end

-- ###########################################

--
-- Extracts parameters from a lua table.
-- This function performs the inverse conversion of javascript paramsPairsEncode.
--
-- Note: plain parameters (not encoded with paramsPairsEncode) remain unchanged only
-- when strict mode is *not* enabled
--
function paramsPairsDecode(params, strict_mode)
   local res = {}

   for k,v in pairs(params) do
      local sp = split(k, "key_")
      if #sp == 2 then
         local keyid = sp[2]
         local value = "val_"..keyid
         if params[value] then
            res[v] = params[value]
         end
      end

      if((not strict_mode) and (res[v] == nil)) then
         -- this is a plain parameter
         res[k] = v
      end
   end

   return res
end

function isBridgeInterface(ifstats)
  return ifstats.inline
end

function hasBridgeInterfaces(skip_netfilter)
  local curif = ifname
  local ifnames = interface.getIfNames()
  local found = false

  for _,ifname in pairs(ifnames) do
    interface.select(ifname)

    local ifstats = interface.getStats()
    if isBridgeInterface(ifstats)
        and (skip_netfilter~=true or ifstats.type ~= "netfilter") then
      found = true
      break
    end
  end

  interface.select(curif)
  return found
end

-- Returns true if the captive portal can be started with the current configuration
function isCaptivePortalSupported(ifstats, prefs, skip_interface_check)
   if not ntop.isEnterprise() and not ntop.isnEdge() then
      return false
   end

   local is_bridge_iface

   if not skip_interface_check then
      local ifstats = ifstats or interface.getStats()
      is_bridge_iface = isBridgeInterface(ifstats)
   else
      is_bridge_iface = true
   end

   local prefs = prefs or ntop.getPrefs()
   return is_bridge_iface and (prefs["http.port"] ~= 80)
end

-- Returns true if the captive portal is active right now
function isCaptivePortalActive(ifstats, prefs)
  if not ntop.isEnterprise() then
    return false
  end

  local ifstats = ifstats or interface.getStats()
  local prefs = prefs or ntop.getPrefs()
  local is_bridge_iface = isBridgeInterface(ifstats)

  return is_bridge_iface and prefs["is_captive_portal_enabled"] and isCaptivePortalSupported(ifstats, prefs)
end

function getCaptivePortalUsers()
  local keys = ntop.getKeysCache("ntopng.user.*.host_pool_id")
  local users = {}

  for key in pairs(keys or {}) do
    local host_pool = ntop.getCache(key)

    if not isEmptyString(host_pool) then
      local username = split(key, "%.")[3]
      users[username] = host_pool
    end
  end

  return users
end

function getBridgeInitializedKey(ifid)
  return "ntopng.prefs.iface_"..ifid..".bridge_initialized"
end

function hasSnmpDevices(ifid)
  if (not ntop.isEnterprise()) or (not isAdministrator()) then
    return false
  end

  return has_snmp_devices(ifid)
end

function getTopFlowPeers(hostname_vlan, max_hits, detailed, other_options)
  local detailed = detailed or false

  local paginator_options = {
    sortColumn = "column_bytes",
    a2zSortOrder = false,
    detailedResults = detailed,
    maxHits = max_hits,
  }

  if other_options ~= nil then
    paginator_options = table.merge(paginator_options, other_options)
  end

  local res = interface.getFlowsInfo(hostname_vlan, paginator_options)
  if ((res ~= nil) and (res.flows ~= nil)) then
    return res.flows
  else
    return {}
  end
end

function stripVlan(name)
  local key = string.split(name, "@")
  if(key ~= nil) then
     return(key[1])
  else
     return(name)
  end
end

function getSafeChildIcon()
   return("&nbsp;<font color='#5cb85c'><i class='fa fa-lg fa-child' aria-hidden='true'></i></font>")
end

-- ###########################################

function printntopngRelease(info)
   if info.oem then
      return ""
   end

   if(info["version.enterprise_edition"]) or (info["version.nedge_enterprise_edition"]) then
      print(" Enterprise")
   elseif(info["version.nedge_edition"]) then
      print(" ")
   elseif(info["pro.release"]) then
      print(" Professional")
   else
      print(" Community")
   end

   if(info["version.embedded_edition"] == true) then
      print("/Embedded")
   end

   print(" Edition</td></tr>\n")
end

-- ###########################################

-- avoids manual HTTP prefix and /lua concatenation
function page_url(path)
  return ntop.getHttpPrefix().."/lua/"..path
end

-- extracts a page url from the path
function path_get_page(path)
   local prefix = ntop.getHttpPrefix() .. "/lua/"

   if string.find(path, prefix) == 1 then
      return string.sub(path, string.len(prefix) + 1)
   end

   return path
end

-- ###########################################

function swapKeysValues(tbl)
   local new_tbl = {}

   for k, v in pairs(tbl or {}) do
      new_tbl[v] = k
   end

   return new_tbl
end

-- ###########################################

-- A redis hash mac -> first_seen
function getFirstSeenDevicesHashKey(ifid)
   return "ntopng.seen_devices.ifid_" .. ifid
end

-- ###########################################

function getHideFromTopSet(ifid)
   return "ntopng.prefs.iface_" .. ifid .. ".hide_from_top"
end

-- ###########################################

function printWarningAlert(message)
   print[[<div class="alert alert-warning alert-dismissable" role="alert">]]
   print[[<a class="close" data-dismiss="alert" aria-label="close">&times;</a>]]
   print[[<i class="fa fa-warning fa-sm"></i> ]]
   print[[<strong>]] print(i18n("warning")) print[[</strong> ]]
   print(message)
   print[[</div>]]
end

-- ###########################################

function tsQueryToTags(query)
   local tags = {}

   for _, part in pairs(split(query, ",")) do
      local sep_pos = string.find(part, ":")

      if sep_pos then
         local k = string.sub(part, 1, sep_pos-1)
         local v = string.sub(part, sep_pos+1)
         tags[k] = v
      end
   end

   return tags
end

function tsTagsToQuery(tags)
   return table.tconcat(tags, ":", ",")
end

-- ###########################################

function splitUrl(url)
   local params = {}
   local parts = split(url, "?")

   if #parts == 2 then
      url = parts[1]
      parts = split(parts[2], "&")

      for _, param in pairs(parts) do
         local p = split(param, "=")

         if #p == 2 then
            params[p[1]] = p[2]
         end
      end
   end

   return {
      url = url,
      params = params,
   }
end

-- ###########################################

--
-- IMPORTANT
-- Leave it at the end so it can use the functions
-- defined in this file
--
http_lint = require "http_lint"

