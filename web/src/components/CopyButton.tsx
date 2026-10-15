import { useState } from "react";

export default function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      /* clipboard blocked: user can select the text manually */
    }
  }
  return (
    <button type="button" className="btn small ghost" onClick={copy}>
      {done ? "Copied" : label}
    </button>
  );
}
