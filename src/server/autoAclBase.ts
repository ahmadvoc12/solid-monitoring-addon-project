import { mkdir, writeFile } from "fs/promises";
import path from "path";

interface AutoAclParams {
  podRootPath: string;
  ownerWebId: string;
  appWebId: string;
}

export async function ensureBaseAcl({
  podRootPath,
  ownerWebId,
  appWebId
}: AutoAclParams) {

  const baseDir = path.join(podRootPath, "base");
  const aclFile = path.join(baseDir, ".acl");

  await mkdir(baseDir, { recursive: true });

  const aclTurtle = `
@prefix acl: <http://www.w3.org/ns/auth/acl#>.
@prefix foaf: <http://xmlns.com/foaf/0.1/>.

<#owner>
  a acl:Authorization;
  acl:agent <${ownerWebId}>;
  acl:accessTo <./>;
  acl:default <./>;
  acl:mode acl:Read, acl:Write, acl:Control.

<#authorized-app>
  a acl:Authorization;
  acl:agent <${appWebId}>;
  acl:accessTo <./>;
  acl:default <./>;
  acl:mode acl:Read, acl:Write.
`.trim();

  await writeFile(aclFile, aclTurtle, "utf8");

  console.info(
    "[AUTO-ACL] /base/.acl generated",
    { podRootPath, appWebId }
  );
}
