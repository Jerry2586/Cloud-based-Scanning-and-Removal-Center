// Inline the deliberately bounded short entry, then quote it as one shell argument.
// The source contains complete statements except the single multiline package if.
export function oneLineInstall(entry, role) {
  if (!['local', 'cloud'].includes(role)) throw new Error('Invalid install role');
  const lines = entry.trimEnd().replace(/^#![^\n]*\n/, '').split('\n').map(line => line.trim()).filter(Boolean);
  const body = lines.map((line, i) => line + (i === lines.length - 1 ? '' : line.endsWith('; then') ? ' ' : '; ')).join('');
  const quoted = "'" + body.replaceAll("'", "'\\''") + "'";
  return 'sudo sh -c ' + quoted + ' -- ' + role;
}
