import { ensureBaseAcl } from "./autoAclBase";
import { getPodRootPathFromWebId } from "./utils/podPath";


export async function handleConsentSuccess(req: any) {

  // ✅ ambil data dari session secara aman
  const userWebId: string | undefined = req.session?.webId;
  const appWebId: string | undefined  = req.session?.appWebId;

  if (!userWebId) {
    throw new Error("[CONSENT] Missing user WebID in session");
  }

  if (!appWebId) {
    throw new Error("[CONSENT] Missing app WebID in session");
  }

  // ✅ derive pod root secara dinamis (TIDAK hardcode)
  const podRootPath = getPodRootPathFromWebId(userWebId);

  // 🔐 generate /base/.acl
  await ensureBaseAcl({
    podRootPath,
    ownerWebId: userWebId,
    appWebId
  });

  console.info(
    "[CONSENT] Base ACL generated",
    { podRootPath, owner: userWebId, app: appWebId }
  );
}
