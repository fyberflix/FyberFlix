export const groupNumber = (n: string) => n.replace(/^(\d{3})(\d{3})(\d{3})$/, "$1 $2 $3");
export const NAME_RE = /^[A-Za-z0-9._-]{3,30}$/;
export const isValidNameShape = (s: string) => NAME_RE.test(s) && !/^\d+$/.test(s);
export const SITE = "FyberFlix.zeaipc.in";
