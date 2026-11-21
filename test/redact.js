// Strip short-lived capability URLs and known secrets from e2e failure
// output, so a captured CI log or shared terminal cannot replay them:
// the /u/<token> one-time upload link IS the credential, and a signed
// /download URL is usable until it expires.
export function redact(s, secrets = []) {
  let out = String(s);
  out = out
    .replace(/(https?:\/\/[^\s/]+)\/u\/[\w-]+/g, "$1/u/<redacted>")
    .replace(/([?&](?:sig|token|code)=)[^\s&]+/gi, "$1<redacted>");
  for (const sec of secrets) {
    if (sec) out = out.split(sec).join("<redacted>");
  }
  return out;
}
