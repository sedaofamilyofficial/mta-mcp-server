-- Fixed one-account bootstrap; no network events, commands or HTTP exports.
addEventHandler("onResourceStart", resourceRoot, function()
    if not fileExists("credentials.json") then return end
    local file = fileOpen("credentials.json", true)
    if not file then return end
    local size = fileGetSize(file)
    local text = size <= 1024 and fileRead(file, size) or nil
    fileClose(file)
    local config = text and fromJSON(text)
    if type(config) ~= "table" or config.account ~= "pulsar_debug_gateway"
        or type(config.password) ~= "string" or #config.password ~= 64
        or not config.password:match("^[a-f0-9]+$") then
        outputServerLog("[Pulsar Debug] Bootstrap credential invalid")
        return
    end
    if not getAccount(config.account) then addAccount(config.account, config.password) end
    if not getAccount(config.account, config.password) then
        outputServerLog("[Pulsar Debug] Bootstrap identity verification failed; no password reset attempted")
        return
    end
    local ready = fileCreate("ready.json")
    if not ready then return end
    fileWrite(ready, toJSON({account = config.account, verified = true}, true):sub(2, -2))
    fileClose(ready)
    outputServerLog("[Pulsar Debug] Dedicated HTTP identity verified")
end)
