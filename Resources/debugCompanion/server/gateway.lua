local function readConfig(path)
    if not fileExists(path) then return nil end
    local file = fileOpen(path, true)
    if not file then return nil end
    local size = fileGetSize(file)
    local text = size <= 8192 and fileRead(file, size) or nil
    fileClose(file)
    return text and fromJSON(text) or nil
end

local credentials = readConfig("credentials.json")
local function validKey(key)
    return type(key) == "string" and #key == 64 and key:match("^[a-f0-9]+$") ~= nil
end
local ready = type(credentials) == "table" and credentials.account == "pulsar_debug_gateway"
    and validKey(credentials.apiKey)

local function reply(status, value)
    return {status = status, body = toJSON(value, true):sub(2, -2),
        headers = {["Content-Type"] = "application/json", ["Cache-Control"] = "no-store"}}
end

local logs = {}
local lastRead
local lastAction
local policy = readConfig("policy.json")
local blocked = {pulsar_debug_gateway = true, debugCompanion = true, dev_suite = true,
    pulsar_core = true, pulsar_security = true, pulsar_auth = true, admin = true,
    webadmin = true, resourcebrowser = true, resourcemanager = true, pulsar_debug_bootstrap = true}
local actions = {start = startResource, stop = stopResource, restart = restartResource}
local function resourceAction(body, tick)
    for key in pairs(body) do
        if key ~= "operation" and key ~= "resource" and key ~= "action" then
            return reply(400, {error = "Invalid arguments"})
        end
    end
    if type(body.resource) ~= "string" or #body.resource > 64 or not body.resource:match("^[a-zA-Z0-9_-]+$")
        or not actions[body.action] then return reply(400, {error = "Invalid action"}) end
    local grant = type(policy) == "table" and type(policy.actions) == "table" and policy.actions[body.resource]
    if blocked[body.resource:lower()] or body.resource:lower() == 'debugcompanion' or type(grant) ~= "table" or grant[body.action] ~= true
        or not hasObjectPermissionTo("resource." .. getResourceName(getThisResource()), "function." .. body.action .. "Resource", false) then
        return reply(403, {error = "Action denied"})
    end
    local target = getResourceFromName(body.resource)
    if not target then return reply(404, {error = "Resource not found"}) end
    if target == getThisResource() or isResourceProtected(target) then return reply(403, {error = "Protected resource"}) end
    if #getElementsByType("player") ~= 0 then return reply(409, {error = "Players online; action blocked"}) end
    if lastAction and tick - lastAction >= 0 and tick - lastAction < 5000 then
        return reply(429, {error = "Action rate limited"})
    end
    lastAction = tick
    local ok, dispatched = pcall(actions[body.action], target)
    if not ok or not dispatched then return reply(503, {error = "Action failed"}) end
    return reply(200, {accepted = true, resource = body.resource, action = body.action, state = getResourceState(target)})
end
local function sanitize(value)
    local text = tostring(value or ""):sub(1, 2048)
    text = text:gsub("[%c]", " ")
    text = text:gsub("%d+%.%d+%.%d+%.%d+", "[redacted]")
    text = text:gsub("[%w_%-]+%s*[:=]%s*[^%s,;]+", function(pair)
        local lower = pair:lower()
        if lower:find("password", 1, true) or lower:find("token", 1, true)
            or lower:find("key", 1, true) or lower:find("authorization", 1, true) then
            return "[redacted]"
        end
        return pair
    end)
    text = text:gsub("[%w_+/=%.%-]+", function(word) return #word >= 24 and "[redacted]" or word end)
    return text:sub(1, 256)
end
addEventHandler("onDebugMessage", root, function(message, level, file, line)
    if level ~= 1 and level ~= 2 then return end
    logs[#logs + 1] = {message = sanitize(message), level = level,
        file = sanitize(file), line = tonumber(line) or 0}
    if #logs > 100 then table.remove(logs, 1) end
end)

function httpGateway(request)
    if not ready or type(request) ~= "table" or not request.account
        or isGuestAccount(request.account) or getAccountName(request.account) ~= credentials.account
        or type(request.headers) ~= "table" or request.headers["api-key"] ~= credentials.apiKey then
        return reply(401, {error = "Unauthorized"})
    end
    if request.path ~= "/" then return reply(404, {error = "Not found"}) end
    if request.method ~= "POST" then return reply(405, {error = "POST required"}) end
    if type(request.body) ~= "string" or #request.body > 8192 then
        return reply(400, {error = "Invalid request"})
    end
    local tick = getTickCount()
    if lastRead and (tick - lastRead) >= 0 and (tick - lastRead) < 200 then
        return reply(429, {error = "Rate limited"})
    end
    lastRead = tick
    local body = fromJSON(request.body)
    if type(body) ~= "table" then return reply(400, {error = "Invalid operation"}) end
    if body.operation == "logs" then
        for key in pairs(body) do
            if key ~= "operation" and key ~= "lines" then return reply(400, {error = "Invalid arguments"}) end
        end
        local lines = body.lines
        if lines == nil then lines = 40 end
        if type(lines) ~= "number" or lines ~= math.floor(lines) or lines < 1 or lines > 50 then
            return reply(400, {error = "Invalid limit"})
        end
        local selected = {}
        for i = math.max(1, #logs - lines + 1), #logs do selected[#selected + 1] = logs[i] end
        return reply(200, {logs = selected, cached = #logs, untrusted = true})
    end
    if body.operation == "action" then return resourceAction(body, tick) end
    if body.operation ~= "status" then return reply(400, {error = "Invalid operation"}) end
    for key in pairs(body) do
        if key ~= "operation" and key ~= "resource" then return reply(400, {error = "Invalid arguments"}) end
    end
    if body.resource ~= nil and (type(body.resource) ~= "string" or #body.resource > 64
        or not body.resource:match("^[a-zA-Z0-9_-]+$")) then
        return reply(400, {error = "Invalid resource"})
    end
    local all = getResources()
    local resources = {}
    if body.resource then
        local target = getResourceFromName(body.resource)
        if not target then return reply(404, {error = "Resource not found"}) end
        resources[1] = {name = body.resource, state = getResourceState(target)}
    else
        table.sort(all, function(a, b) return getResourceName(a) < getResourceName(b) end)
        for i = 1, math.min(#all, 128) do
            resources[i] = {name = getResourceName(all[i]), state = getResourceState(all[i])}
        end
    end
    return reply(200, {schema = "pulsar.debug.v1", players = #getElementsByType("player"),
        tick = getTickCount(), resources = resources, totalResources = #all, truncated = not body.resource and #all > 128})
end
