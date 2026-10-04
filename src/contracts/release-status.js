// Cloud status is metadata; local package verification happens before activation.
export function sanitizeRelease(value) {
  const unavailable={state:'unavailable',delivery:'pull-only',activation:'local-admin'};
  if(!value || Array.isArray(value) || value.delivery!=='pull-only' || value.activation!=='local-admin' || !['ready','missing','unavailable'].includes(value.state)) return unavailable;
  if(value.state!=='ready') return {...unavailable,state:value.state};
  if(!/^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$/.test(value.version) || !/^[a-f0-9]{64}$/.test(value.manifest_sha256)) return unavailable;
  return {...unavailable,state:'ready',version:value.version,manifest_sha256:value.manifest_sha256};
}
