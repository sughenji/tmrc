description = [[
Finds a webcam.
]]

-- https://www.youtube.com/watch?v=M-Uq7YSfZ4I&t=691s

categories = {"safe", "discovery"}

require("http")

function portrule(host, port)
  return port.number == 80
end

function action(host,port)
  local response

  response = http.get(host, port, "/cam.jpg")
  if response.status and response.status ~= 404
    and response.header["server"]
    and string.match(response.header["server"], "^thttpd") then
    return "webcam found."
  end
end

