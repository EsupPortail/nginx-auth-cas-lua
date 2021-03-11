local http = require('resty.http')

local conf = nil
local cas_uri = nil
local cookie_name = nil
local cookie_params = nil
local REMOTE_USER_header = nil
local session_lifetime = nil
local store = nil

local function init()
   conf = require(ngx.var.cas_conf or "global_cas_conf")
   cas_uri = conf.cas_uri
   cookie_name = conf.cookie_name or "NGXCAS"
   cookie_params = conf.cookie_params or "; Path=/; Secure; HttpOnly"
   REMOTE_USER_header = conf.REMOTE_USER_header or "REMOTE_USER"
   session_lifetime = conf.session_lifetime or 3600
   local store_name = conf.store_name or "cas_store"
   store = ngx.shared[store_name]
   if store == nil then
    ngx.log(ngx.ERR, 'you must configure "lua_shared_dict ' .. store_name .. '"')
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
   end
end

local function _to_table(v)
   if v == nil then
      return {}     
   elseif type(v) == "table" then
      return v
   else
      return { v }
   end
end
   
local function _set_cookie(cookie_str)    
   local h = _to_table(ngx.header['Set-Cookie'])
   table.insert(h, cookie_str)
   ngx.header['Set-Cookie'] = h
end

local function _uri_without_ticket()
   return ngx.var.scheme .. "://" .. ngx.var.host ..  ngx.re.sub(ngx.var.request_uri, "[?&]ticket=.*", "")
end

local function _cas_login()
   return cas_uri .. "/login?" .. ngx.encode_args({ service = _uri_without_ticket() })
end

local function _get_sessionId()
   return ngx.var["cookie_" .. cookie_name]
end

local function _set_our_cookie(val)
   _set_cookie(cookie_name .. "=" .. val .. cookie_params)
end

local function first_access()
   ngx.redirect(_cas_login(), ngx.HTTP_MOVED_TEMPORARILY)
end

local function with_sessionId(sessionId)
   -- does the cookie exist in our store?
   local user = store:get(sessionId);
   if user == nil then
      -- the sessionId has expired
      -- remove cookie immediately otherwise the client hits an infinite loop if the invalid cookie still exists.
      _set_our_cookie("deleted; Max-Age=0")
      first_access()
   else
      -- refresh the TTL
      store:set(sessionId, user, session_lifetime)
      
      -- export REMOTE_USER header to the application
      if REMOTE_USER_header ~= "" then
         ngx.req.set_header(REMOTE_USER_header, user)
      end
   end
end

local function _set_store_and_cookie(sessionId, user)  
   -- place cookie into cookie store
   local success, err, forcible = store:add(sessionId, user, session_lifetime)
   if success then
      if forcible then
         ngx.log(ngx.WARN, "CAS cookie store is out of memory")
      end
      _set_our_cookie(sessionId)
   else      
      if err == "no memory" then
         -- store:add will attempt to remove old entries if it is full
         -- it should only happen in case of memory segmentation
         ngx.log(ngx.EMERG, "CAS cookie store is out of memory")
      elseif err == "exists" then
         ngx.log(ngx.ERR, "Same CAS ticket validated twice, this should never happen!")
      end
   end
   return success
end

local function _validate(ticket)
   -- send a request to CAS to validate the ticket
   local httpc = http.new()
   local res, err = httpc:request_uri(cas_uri .. "/serviceValidate", { query = { ticket = ticket, service = _uri_without_ticket() } })
  
   if res and res.status == ngx.HTTP_OK and res.body ~= nil then
      if string.find(res.body, "<cas:authenticationSuccess>") then
         local m = ngx.re.match(res.body, "<cas:user>(.*?)</cas:user>");
         if m then
            return m[1]
         end
      else
         ngx.log(ngx.INFO, "CAS serviceValidate failed: " .. res.body)
      end
   else
      ngx.log(ngx.ERR, err)
      ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
   end
   return nil
end

local function validate_with_CAS(ticket)
   local user = _validate(ticket)
   if user and _set_store_and_cookie(ticket, user) then
      -- remove ticket from url
      ngx.redirect(_uri_without_ticket(), ngx.HTTP_MOVED_TEMPORARILY)
   else
      first_access()
   end
end

local function forceAuthentication()
   init()
   local sessionId = _get_sessionId()
   if sessionId ~= nil then
      return with_sessionId(sessionId)
   end

   local ticket = ngx.var.arg_ticket
   if ticket ~= nil then
      validate_with_CAS(ticket)
   else
      first_access()
   end
end

local function logout(local_logout)
   store:delete(_get_sessionId())
   _set_our_cookie("deleted; Max-Age=0")

   if not local_logout then
      -- redirect to cas logout
      ngx.redirect(cas_uri .. "/logout")
   end
end

return {
   forceAuthentication = forceAuthentication;   
   logout = logout;
}
