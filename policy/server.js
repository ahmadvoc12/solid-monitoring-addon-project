import http from "http";
import { handleAutoAcl } from "./auto-acl.js";

const server = http.createServer(async (req, res) => {
  if (req.method === "POST" && req.url === "/_internal/auto-acl") {
    return handleAutoAcl(req, res);
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
});

server.listen(4000, () => {
  console.log("Policy server running at http://localhost:4000");
});
