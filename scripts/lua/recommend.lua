--
-- (C) 2013-18 - ntop.org
--

dirs = ntop.getDirs()
package.path = dirs.installdir .. "/scripts/lua/modules/?.lua;" .. package.path
require "lua_utils"
----------
sendHTTPContentTypeHeader('text/html')

ntop.dumpFile(dirs.installdir .. "/httpdocs/inc/header.inc")

active_page = "about"
dofile(dirs.installdir .. "/scripts/lua/inc/menu.lua")
--------------------------
if(_POST["ntopng_license"] ~= nil) then
   ntop.setCache('ntopng.license', trimSpace(_POST["ntopng_license"]))
   ntop.checkLicense()
end
----------------------
------------------
info = ntop.getInfo()
print("<hr /><h2></h2>")
print("Recommend")
print("<table class=\"table table-bordered table-striped\">\n")



-------------------------
-----------------

print("</table>\n")
-------------------
dofile(dirs.installdir .. "/scripts/lua/inc/footer.lua")




