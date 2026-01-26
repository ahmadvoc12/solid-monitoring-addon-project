import fs from "fs/promises";
import path from "path";

const POD_ROOT = path.resolve("data/pod");
const TARGET_CONTAINER = "private/app-data/monitor";

export async function handleAutoAcl(req, res) {
  try {
    // ===== read body =====
    let body = "";
    for await (const chunk of req) {
      body += chunk;
    }

    const consent = JSON.parse(body);

    if (!consent.userWebId) {
      res.writeHead(400);
      return res.end("userWebId missing");
    }

    const containerPath = path.join(POD_ROOT, TARGET_CONTAINER);
    const aclPath = path.join(containerPath, ".acl");

    // ensure container exists
    await fs.mkdir(containerPath, { recursive: true });

    // CSS 7.x FRIENDLY ACL
    const acl = `
@prefix acl: <http://www.w3.org/ns/auth/acl#>.

<#app>
  a acl:Authorization ;
  acl:agent <${consent.userWebId}> ;
  acl:mode acl:Read, acl:Append ;
  acl:accessTo <./> ;
  acl:default <./> .
`;

    await fs.writeFile(aclPath, acl.trim() + "\n");

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, message: "ACL generated" }));

  } catch (err) {
    console.error(err);
    res.writeHead(500);
    res.end("auto-acl failed");
  }
}
